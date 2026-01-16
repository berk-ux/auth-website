/*
 * ========================================
 * 🚀 BACKEND SERVER - Node.js + PostgreSQL
 * ========================================
 * Güvenli kullanıcı yönetim sistemi
 */

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');

const app = express();
const PORT = process.env.PORT || 3000;

// 🛡️ GÜVENLİK MIDDLEWARE'LERİ

// Helmet - HTTP güvenlik başlıkları
app.use(helmet({
    contentSecurityPolicy: false, // CSP'yi devre dışı bırak (inline script'ler için)
    crossOriginEmbedderPolicy: false
}));

// Rate Limiting - GEÇİCİ OLARAK DEVRE DIŞI
// TODO: Saldırı kontrolünden sonra tekrar aktif et
/*
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
    message: { success: false, message: 'Çok fazla istek!' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path.startsWith('/api/admin')
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { success: false, message: 'Çok fazla giriş denemesi!' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path.startsWith('/api/admin')
});
*/

// Diğer middleware'ler
app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limit GEÇİCİ OLARAK KAPALI
// app.use('/api/', apiLimiter);

// ========== DATABASE SETUP (PostgreSQL) ==========
// External URL (Render dışından erişim için)
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://auth_db_s18i_user:2uZ4U1pdzSxAXFaGiwcxAjPMjwUBibqx@dpg-d5k4ngur433s73eiqufg-a.virginia-postgres.render.com/auth_db_s18i';

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Veritabanını başlat
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                plain_password TEXT,
                user_type VARCHAR(20) DEFAULT 'free',
                ip_address VARCHAR(100),
                country VARCHAR(100),
                city VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // user_type sütunu ekle (varsa hata verir, sorun yok)
        try {
            await pool.query("ALTER TABLE users ADD COLUMN user_type VARCHAR(20) DEFAULT 'free'");
        } catch (e) { }

        // region ve isp sütunları ekle
        try {
            await pool.query("ALTER TABLE users ADD COLUMN region VARCHAR(100)");
        } catch (e) { }
        try {
            await pool.query("ALTER TABLE users ADD COLUMN isp VARCHAR(200)");
        } catch (e) { }

        // last_active ve total_time sütunları ekle (aktivite takibi için)
        try {
            await pool.query("ALTER TABLE users ADD COLUMN last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
        } catch (e) { }
        try {
            await pool.query("ALTER TABLE users ADD COLUMN total_time_seconds INTEGER DEFAULT 0");
        } catch (e) { }

        // is_banned sütunu ekle (kısıtlı kullanıcılar için)
        try {
            await pool.query("ALTER TABLE users ADD COLUMN is_banned BOOLEAN DEFAULT false");
        } catch (e) { }
        try {
            await pool.query("ALTER TABLE users ADD COLUMN ban_reason TEXT");
        } catch (e) { }

        // Cihaz bilgisi sütunları ekle
        try {
            await pool.query("ALTER TABLE users ADD COLUMN device_info VARCHAR(255)");
        } catch (e) { }
        try {
            await pool.query("ALTER TABLE users ADD COLUMN browser_info VARCHAR(255)");
        } catch (e) { }
        try {
            await pool.query("ALTER TABLE users ADD COLUMN os_info VARCHAR(255)");
        } catch (e) { }

        // Banned devices tablosu oluştur (cihaz bazlı engelleme için)
        try {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS banned_devices (
                    id SERIAL PRIMARY KEY,
                    device_fingerprint VARCHAR(500) UNIQUE NOT NULL,
                    user_agent TEXT,
                    ip_address VARCHAR(100),
                    banned_user_id INTEGER,
                    banned_username VARCHAR(100),
                    ban_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('✅ banned_devices tablosu hazır');
        } catch (e) { }

        // ID numarasını 39237'den başlat (eğer henüz kullanıcı yoksa)
        const result = await pool.query('SELECT COUNT(*) as count FROM users');
        if (parseInt(result.rows[0].count) === 0) {
            await pool.query("ALTER SEQUENCE users_id_seq RESTART WITH 39237");
            console.log('✅ ID numarası 39237\'den başlayacak');
        }

        // Activity logs tablosu oluştur
        await pool.query(`
            CREATE TABLE IF NOT EXISTS activity_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                username VARCHAR(255),
                action_type VARCHAR(100) NOT NULL,
                action_detail TEXT,
                ip_address VARCHAR(100),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Messages tablosu oluştur (kullanıcı-admin sohbet)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                username VARCHAR(255),
                user_type VARCHAR(20) DEFAULT 'free',
                message TEXT NOT NULL,
                sender VARCHAR(20) NOT NULL,
                is_read BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('✅ PostgreSQL veritabanı hazır!');
    } catch (error) {
        console.error('❌ Veritabanı hatası:', error);
    }
}

initDatabase();

// ========== HELPER FUNCTIONS ==========

// Aktivite log kaydet
async function logActivity(userId, username, actionType, actionDetail, req) {
    try {
        const ip = req.headers['x-forwarded-for']?.split(',')[0] ||
            req.headers['x-real-ip'] ||
            req.connection?.remoteAddress ||
            req.ip || 'Bilinmiyor';
        const userAgent = req.headers['user-agent'] || 'Bilinmiyor';

        await pool.query(
            'INSERT INTO activity_logs (user_id, username, action_type, action_detail, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5, $6)',
            [userId, username, actionType, actionDetail, ip, userAgent]
        );
    } catch (error) {
        console.error('Log kayıt hatası:', error.message);
    }
}

// Şifre hashleme (güvenli)
async function hashPassword(password) {
    const salt = await bcrypt.genSalt(12);
    return bcrypt.hash(password, salt);
}

// Şifre doğrulama
async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
}

// User-Agent Parse Et
function parseUserAgent(userAgent) {
    if (!userAgent) return { device: 'Bilinmiyor', browser: 'Bilinmiyor', os: 'Bilinmiyor' };

    let device = 'Desktop';
    let browser = 'Bilinmiyor';
    let os = 'Bilinmiyor';

    // İşletim Sistemi Tespiti
    if (/iPhone/.test(userAgent)) {
        os = 'iOS (iPhone)';
        device = 'iPhone';
    } else if (/iPad/.test(userAgent)) {
        os = 'iOS (iPad)';
        device = 'iPad';
    } else if (/Android/.test(userAgent)) {
        os = 'Android';
        device = 'Android';
        // Android cihaz modeli
        const match = userAgent.match(/Android[^;]*;\s*([^)]+)/);
        if (match && match[1]) {
            device = match[1].split(' Build')[0].trim();
        }
    } else if (/Windows NT 10/.test(userAgent)) {
        os = 'Windows 10/11';
    } else if (/Windows NT 6\.3/.test(userAgent)) {
        os = 'Windows 8.1';
    } else if (/Windows NT 6\.1/.test(userAgent)) {
        os = 'Windows 7';
    } else if (/Windows/.test(userAgent)) {
        os = 'Windows';
    } else if (/Mac OS X/.test(userAgent)) {
        os = 'macOS';
        device = 'Mac';
    } else if (/Linux/.test(userAgent)) {
        os = 'Linux';
    }

    // Tarayıcı Tespiti
    if (/Edg\//.test(userAgent)) {
        browser = 'Edge';
    } else if (/Chrome\//.test(userAgent) && !/Chromium/.test(userAgent)) {
        browser = 'Chrome';
    } else if (/Safari\//.test(userAgent) && !/Chrome/.test(userAgent)) {
        browser = 'Safari';
    } else if (/Firefox\//.test(userAgent)) {
        browser = 'Firefox';
    } else if (/Opera|OPR\//.test(userAgent)) {
        browser = 'Opera';
    } else if (/MSIE|Trident/.test(userAgent)) {
        browser = 'Internet Explorer';
    }

    // Cihaz tipi (Mobile check)
    if (/Mobile/.test(userAgent) && device === 'Desktop') {
        device = 'Mobile';
    } else if (/Tablet/.test(userAgent)) {
        device = 'Tablet';
    }

    return { device, browser, os };
}

// Cihaz Fingerprint Oluştur
function createDeviceFingerprint(req) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip = req.headers['x-forwarded-for']?.split(',')[0] ||
        req.headers['x-real-ip'] ||
        req.connection?.remoteAddress ||
        req.ip || 'unknown';

    // User-Agent + IP kombinasyonu (basit fingerprint)
    const crypto = require('crypto');
    const fingerprint = crypto.createHash('sha256')
        .update(userAgent + ip)
        .digest('hex');

    return { fingerprint, userAgent, ip };
}

// ========== API ENDPOINTS ==========

// 🔐 Kullanıcı Kayıt
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validasyon
        if (!username || username.length < 3) {
            return res.status(400).json({
                success: false,
                message: 'Kullanıcı adı en az 3 karakter olmalı!'
            });
        }

        if (!email || !email.includes('@')) {
            return res.status(400).json({
                success: false,
                message: 'Geçerli bir email adresi girin!'
            });
        }

        if (!password || password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Şifre en az 6 karakter olmalı!'
            });
        }

        // Email veya kullanıcı adı kontrolü
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)',
            [email, username]
        );

        if (existingUser.rows.length > 0) {
            if (existingUser.rows[0].email.toLowerCase() === email.toLowerCase()) {
                return res.status(400).json({
                    success: false,
                    message: 'Bu email adresi zaten kayıtlı!'
                });
            }
            return res.status(400).json({
                success: false,
                message: 'Bu kullanıcı adı zaten alınmış!'
            });
        }

        // IP adresini al
        const ip = req.headers['x-forwarded-for']?.split(',')[0] ||
            req.headers['x-real-ip'] ||
            req.connection?.remoteAddress ||
            req.ip || 'Bilinmiyor';

        // Konum bilgisini al (ücretsiz API)
        let country = 'Bilinmiyor';
        let city = 'Bilinmiyor';
        let region = 'Bilinmiyor';
        let isp = 'Bilinmiyor';

        try {
            const geoResponse = await fetch(`http://ip-api.com/json/${ip}?lang=tr&fields=status,country,regionName,city,isp,query`);
            const geoData = await geoResponse.json();
            if (geoData.status === 'success') {
                country = geoData.country || 'Bilinmiyor';
                city = geoData.city || 'Bilinmiyor';
                region = geoData.regionName || 'Bilinmiyor';
                isp = geoData.isp || 'Bilinmiyor';
            }
        } catch (geoError) {
            console.log('GeoIP hatası:', geoError.message);
        }

        // Şifreyi hashle
        const hashedPassword = await hashPassword(password);

        // Cihaz bilgisini al
        const userAgent = req.headers['user-agent'] || '';
        const deviceInfo = parseUserAgent(userAgent);

        // Kullanıcıyı kaydet (IP, konum ve cihaz bilgisi dahil)
        const result = await pool.query(
            'INSERT INTO users (username, email, password, plain_password, ip_address, country, city, region, isp, device_info, browser_info, os_info) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id',
            [username.trim(), email.trim().toLowerCase(), hashedPassword, password, ip, country, city, region, isp, deviceInfo.device, deviceInfo.browser, deviceInfo.os]
        );

        console.log(`✅ Yeni kullanıcı kayıt oldu: ${username} (${deviceInfo.device} - ${deviceInfo.browser} - ${deviceInfo.os})`);

        // Aktivite log kaydet
        await logActivity(result.rows[0].id, username, 'KAYIT', 'Yeni kullanıcı kaydı', req);

        res.json({
            success: true,
            message: 'Kayıt başarılı! Giriş yapabilirsiniz.',
            userId: result.rows[0].id
        });

    } catch (error) {
        console.error('❌ Kayıt hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 🔓 Kullanıcı Giriş
app.post('/api/login', async (req, res) => {
    try {
        let { identifier, password } = req.body;

        // Input sanitization
        if (identifier) identifier = validator.escape(identifier.trim());
        if (!identifier || !password) {
            return res.status(400).json({
                success: false,
                message: 'Lütfen tüm alanları doldurun!'
            });
        }

        // 🚫 BANNED DEVICE KONTROLÜ
        const deviceData = createDeviceFingerprint(req);
        const bannedCheck = await pool.query(
            'SELECT * FROM banned_devices WHERE device_fingerprint = $1',
            [deviceData.fingerprint]
        );

        if (bannedCheck.rows.length > 0) {
            const bannedDevice = bannedCheck.rows[0];
            console.log(`🚫 Engellenmiş cihazdan giriş denemesi: ${deviceData.ip}`);
            return res.status(403).json({
                success: false,
                message: `Bu cihaz engellenmiştir! Sebep: ${bannedDevice.ban_reason || 'Belirtilmemiş'}`
            });
        }

        // Kullanıcıyı bul (email veya username ile)
        const result = await pool.query(
            'SELECT * FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)',
            [identifier, identifier]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Kullanıcı bulunamadı!'
            });
        }

        const user = result.rows[0];

        // Şifre kontrolü
        const validPassword = await verifyPassword(password, user.password);
        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: 'Hatalı şifre!'
            });
        }

        console.log(`✅ Kullanıcı giriş yaptı: ${user.username} (${user.user_type || 'free'})`);

        // Aktivite log kaydet (Free/VIP panel bilgisi ile)
        const panelType = user.user_type === 'vip' ? 'VIP Panel' : 'Free Panel';
        await logActivity(user.id, user.username, 'GIRIS', `${panelType} girişi`, req);

        // Cihaz bilgisini al ve güncelle
        const userAgent = req.headers['user-agent'] || '';
        const deviceInfo = parseUserAgent(userAgent);

        // last_active ve cihaz bilgisini güncelle
        await pool.query(
            'UPDATE users SET last_active = CURRENT_TIMESTAMP, device_info = $1, browser_info = $2, os_info = $3 WHERE id = $4',
            [deviceInfo.device, deviceInfo.browser, deviceInfo.os, user.id]
        );

        res.json({
            success: true,
            message: 'Giriş başarılı!',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                user_type: user.user_type || 'free',
                is_banned: user.is_banned || false,
                ban_reason: user.ban_reason || null
            }
        });

    } catch (error) {
        console.error('❌ Giriş hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 🔑 E-posta Doğrula (Şifre Sıfırlama için)
app.post('/api/verify-email', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ success: false, message: 'E-posta gerekli!' });
        }

        const result = await pool.query('SELECT id, email FROM users WHERE email = $1', [email]);

        if (result.rows.length === 0) {
            return res.json({ success: false, message: 'Bu e-posta adresi kayıtlı değil!' });
        }

        res.json({ success: true, message: 'E-posta doğrulandı!' });
    } catch (error) {
        console.error('❌ E-posta doğrulama hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// 🔑 Şifre Sıfırla
app.post('/api/reset-password', async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        if (!email || !newPassword) {
            return res.status(400).json({ success: false, message: 'E-posta ve yeni şifre gerekli!' });
        }

        if (newPassword.length < 6) {
            return res.json({ success: false, message: 'Şifre en az 6 karakter olmalı!' });
        }

        // Kullanıcıyı bul
        const userResult = await pool.query('SELECT id, username FROM users WHERE email = $1', [email]);

        if (userResult.rows.length === 0) {
            return res.json({ success: false, message: 'Kullanıcı bulunamadı!' });
        }

        // Şifreyi güncelle (hem hash hem plain)
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query(
            'UPDATE users SET password = $1, plain_password = $2 WHERE email = $3',
            [hashedPassword, newPassword, email]
        );

        // Aktivite log kaydet
        await logActivity(userResult.rows[0].id, userResult.rows[0].username, 'SIFRE_SIFIRLAMA', 'Şifre sıfırlandı', req);

        console.log(`🔑 Şifre sıfırlandı: ${email}`);

        res.json({ success: true, message: 'Şifreniz başarıyla değiştirildi!' });
    } catch (error) {
        console.error('❌ Şifre sıfırlama hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// 💓 Heartbeat - Kullanıcı aktiflik takibi
app.post('/api/heartbeat', async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({ success: false });
        }

        // last_active güncelle ve total_time'a 30 saniye ekle (heartbeat aralığı)
        await pool.query(
            'UPDATE users SET last_active = CURRENT_TIMESTAMP, total_time_seconds = total_time_seconds + 30 WHERE id = $1',
            [userId]
        );

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

// 👤 Kullanıcı İstatistikleri (Profil sayfası için)
app.get('/api/user/stats', async (req, res) => {
    try {
        // Token'dan user id'yi al
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            return res.status(401).json({ success: false, message: 'Token gerekli!' });
        }

        // Bearer token'dan user bilgilerini çıkar
        // Token yerine localStorage user objesinden gelen id kullanıyoruz
        // Client tarafında fetch'e userId ekleyeceğiz
        const userId = req.query.userId;

        if (!userId) {
            return res.status(400).json({ success: false, message: 'User ID gerekli!' });
        }

        // Kullanıcı bilgilerini al
        const userResult = await pool.query(
            'SELECT created_at, total_time_seconds FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Kullanıcı bulunamadı!' });
        }

        // Sorgu sayısını activity_logs tablosundan al
        const queryCountResult = await pool.query(
            "SELECT COUNT(*) as count FROM activity_logs WHERE user_id = $1 AND action_type LIKE '%SORGU%'",
            [userId]
        );

        const user = userResult.rows[0];
        const queryCount = parseInt(queryCountResult.rows[0].count) || 0;
        const totalTimeMinutes = Math.floor((user.total_time_seconds || 0) / 60);

        res.json({
            success: true,
            created_at: user.created_at,
            query_count: queryCount,
            total_time_spent: totalTimeMinutes
        });

    } catch (error) {
        console.error('❌ Stats hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// 🛡️ Admin Giriş
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;

    // Sabit admin bilgileri (production'da environment variable kullan!)
    const ADMIN_EMAIL = 'zeta_55saflar@icloud.com';
    const ADMIN_PASSWORD = 'qinpiq-fyjreh-5gYnhy';

    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        console.log('✅ Admin giriş yaptı');
        res.json({
            success: true,
            message: 'Admin girişi başarılı!'
        });
    } else {
        res.status(401).json({
            success: false,
            message: 'Hatalı admin bilgileri!'
        });
    }
});

// 📊 Tüm Kullanıcıları Getir (Admin)
app.get('/api/admin/users', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, username, email, password, plain_password, user_type, is_banned, ban_reason, ip_address, country, city, region, isp, device_info, browser_info, os_info, last_active, total_time_seconds, created_at FROM users ORDER BY created_at DESC'
        );

        res.json({
            success: true,
            users: result.rows,
            total: result.rows.length
        });

    } catch (error) {
        console.error('❌ Kullanıcı listesi hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 🗑️ Kullanıcı Sil (Admin)
app.delete('/api/admin/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query('DELETE FROM users WHERE id = $1', [id]);

        if (result.rowCount > 0) {
            console.log(`🗑️ Kullanıcı silindi: ID ${id}`);
            res.json({
                success: true,
                message: 'Kullanıcı silindi!'
            });
        } else {
            res.status(404).json({
                success: false,
                message: 'Kullanıcı bulunamadı!'
            });
        }

    } catch (error) {
        console.error('❌ Silme hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 👑 VIP Üye Oluştur (Admin)
app.post('/api/admin/create-vip', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validasyon
        if (!username || username.length < 3) {
            return res.status(400).json({
                success: false,
                message: 'Kullanıcı adı en az 3 karakter olmalı!'
            });
        }

        if (!email || !email.includes('@')) {
            return res.status(400).json({
                success: false,
                message: 'Geçerli bir email adresi girin!'
            });
        }

        if (!password || password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Şifre en az 6 karakter olmalı!'
            });
        }

        // Email veya kullanıcı adı kontrolü
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)',
            [email, username]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Bu email veya kullanıcı adı zaten kullanımda!'
            });
        }

        // Şifreyi hashle
        const hashedPassword = await hashPassword(password);

        // VIP kullanıcıyı kaydet
        const result = await pool.query(
            'INSERT INTO users (username, email, password, plain_password, user_type, ip_address, country, city) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id',
            [username.trim(), email.trim().toLowerCase(), hashedPassword, password, 'vip', 'Admin', 'Admin', 'Panel']
        );

        console.log(`👑 VIP kullanıcı oluşturuldu: ${username}`);

        res.json({
            success: true,
            message: 'VIP üye başarıyla oluşturuldu!',
            userId: result.rows[0].id
        });

    } catch (error) {
        console.error('❌ VIP oluşturma hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 🔄 Üyelik Tipini Değiştir (Admin)
app.put('/api/admin/users/:id/toggle-vip', async (req, res) => {
    try {
        const { id } = req.params;

        // Mevcut kullanıcıyı bul
        const user = await pool.query('SELECT user_type FROM users WHERE id = $1', [id]);

        if (user.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Kullanıcı bulunamadı!'
            });
        }

        // Tipi değiştir
        const currentType = user.rows[0].user_type || 'free';
        const newType = currentType === 'vip' ? 'free' : 'vip';

        await pool.query('UPDATE users SET user_type = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [newType, id]);

        console.log(`🔄 Kullanıcı ${id}: ${currentType} → ${newType}`);

        res.json({
            success: true,
            message: newType === 'vip' ? 'Kullanıcı VIP yapıldı!' : 'VIP üyelik kaldırıldı!',
            newType: newType
        });

    } catch (error) {
        console.error('❌ Tip değiştirme hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 🚫 Kullanıcı Ban Toggle (Admin)
app.put('/api/admin/users/:id/toggle-ban', async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;

        // Mevcut kullanıcıyı bul
        const user = await pool.query('SELECT is_banned, username, device_info, browser_info, os_info, ip_address FROM users WHERE id = $1', [id]);

        if (user.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Kullanıcı bulunamadı!'
            });
        }

        // Ban durumunu değiştir
        const currentBan = user.rows[0].is_banned || false;
        const newBan = !currentBan;
        const banReason = newBan ? (reason || 'Admin tarafından kısıtlandı') : null;

        await pool.query(
            'UPDATE users SET is_banned = $1, ban_reason = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3',
            [newBan, banReason, id]
        );

        // 🔒 CİHAZ BAZLI ENGELLEME
        if (newBan) {
            // Ban uygulandığında cihazı engelle
            const userAgent = user.rows[0].browser_info + ' / ' + user.rows[0].os_info;
            const ip = user.rows[0].ip_address || 'unknown';

            // Basit fingerprint: kullanıcının son kullandığı cihaz bilgisi
            const crypto = require('crypto');
            const fingerprint = crypto.createHash('sha256')
                .update((user.rows[0].device_info || '') + (user.rows[0].browser_info || '') + (user.rows[0].os_info || '') + ip)
                .digest('hex');

            // Cihazı banned_devices tablosuna ekle
            try {
                await pool.query(
                    `INSERT INTO banned_devices (device_fingerprint, user_agent, ip_address, banned_user_id, banned_username, ban_reason)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (device_fingerprint) DO UPDATE SET ban_reason = $6`,
                    [fingerprint, userAgent, ip, id, user.rows[0].username, banReason]
                );
                console.log(`🔒 Cihaz engellendi: ${user.rows[0].username} - ${user.rows[0].device_info || 'Unknown'}`);
            } catch (deviceErr) {
                console.error('Cihaz ekleme hatası:', deviceErr.message);
            }
        } else {
            // Ban kaldırıldığında kullanıcıyla ilişkili tüm cihazları serbest bırak
            try {
                await pool.query('DELETE FROM banned_devices WHERE banned_user_id = $1', [id]);
                console.log(`🔓 Cihaz serbest bırakıldı: ${user.rows[0].username}`);
            } catch (deviceErr) {
                console.error('Cihaz silme hatası:', deviceErr.message);
            }
        }

        console.log(`🚫 Kullanıcı ${user.rows[0].username}: ${currentBan ? 'Ban kaldırıldı' : 'Ban uygulandı'}`);

        res.json({
            success: true,
            message: newBan ? 'Kullanıcı ve cihazı kısıtlandı!' : 'Kısıtlama kaldırıldı!',
            isBanned: newBan
        });

    } catch (error) {
        console.error('❌ Ban değiştirme hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 🔍 E-posta ile Kullanıcı Ara (Admin)
app.get('/api/admin/search', async (req, res) => {
    try {
        const { email } = req.query;

        if (!email || email.length < 3) {
            return res.status(400).json({
                success: false,
                message: 'Arama için en az 3 karakter girin!'
            });
        }

        const result = await pool.query(
            `SELECT id, username, email, user_type, is_banned, ban_reason, ip_address, country, city, last_active, created_at 
             FROM users 
             WHERE LOWER(email) LIKE LOWER($1) OR LOWER(username) LIKE LOWER($1)
             ORDER BY created_at DESC 
             LIMIT 50`,
            [`%${email}%`]
        );

        res.json({
            success: true,
            users: result.rows,
            total: result.rows.length
        });

    } catch (error) {
        console.error('❌ Arama hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 📈 İstatistikler
app.get('/api/stats', async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) as count FROM users');
        const todayUsers = await pool.query(
            "SELECT COUNT(*) as count FROM users WHERE DATE(created_at) = CURRENT_DATE"
        );

        res.json({
            success: true,
            stats: {
                totalUsers: parseInt(totalUsers.rows[0].count),
                todayUsers: parseInt(todayUsers.rows[0].count)
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// 🔍 Sorgu API (nopanel entegrasyonu)
app.post('/api/query', async (req, res) => {
    try {
        const { type, value, userId } = req.body;

        if (!value) {
            return res.status(400).json({
                success: false,
                message: 'Lütfen bir değer girin!'
            });
        }

        // Kullanıcı kontrolü
        const userCheck = await pool.query('SELECT user_type, is_banned, ban_reason FROM users WHERE id = $1', [userId]);

        // 🚫 BAN KONTROLÜ - Kısıtlı kullanıcılar sorgu yapamaz
        if (userCheck.rows[0]?.is_banned) {
            return res.status(403).json({
                success: false,
                message: '🚫 Hesabınız kısıtlandığı için sorgu yapamazsınız! Sebep: ' + (userCheck.rows[0].ban_reason || 'Belirtilmemiş')
            });
        }
        const userType = userCheck.rows[0]?.user_type || 'free';

        // VIP kontrolü
        const vipQueries = ['family', 'address', 'detayli', 'operator'];
        if (vipQueries.includes(type) && userType !== 'vip') {
            return res.status(403).json({
                success: false,
                message: 'Bu sorgu sadece VIP üyeler için aktiftir!'
            });
        }

        // nopanel'e sorgu yap
        const nopanelUrl = 'https://nopanel-98453.top';
        const loginData = {
            username: 'armanii',
            password: 'amsikitartar'
        };

        // Sorgu tipine göre endpoint belirle
        const queryEndpoints = {
            'tc': '/api/tc',
            'name': '/api/adsoyad',
            'gsm': '/api/gsmtc',
            'tcgsm': '/api/tcgsm',
            'family': '/api/aile',
            'address': '/api/adres'
        };

        // Demo sonuçları göster (nopanel API erişilemez durumda)
        const demoResults = {
            'tc': `📋 TC SORGU SONUCU
━━━━━━━━━━━━━━━━━━━━━
TC: ${value}
Ad: ÖRNEK
Soyad: KİŞİ
Doğum Tarihi: 01.01.1990
Anne Adı: AYŞE
Baba Adı: MEHMET
━━━━━━━━━━━━━━━━━━━━━`,
            'name': `👤 AD SOYAD SORGU SONUCU
━━━━━━━━━━━━━━━━━━━━━
Aranan: ${value}
━━━━━━━━━━━━━━━━━━━━━
1. ÖRNEK KİŞİ - 12345678901
2. ÖRNEK KİŞİ - 12345678902
━━━━━━━━━━━━━━━━━━━━━`,
            'gsm': `📱 GSM → TC SORGU SONUCU
━━━━━━━━━━━━━━━━━━━━━
GSM: ${value}
TC: 12345678901
Ad Soyad: ÖRNEK KİŞİ
━━━━━━━━━━━━━━━━━━━━━`,
            'tcgsm': `📞 TC → GSM SORGU SONUCU
━━━━━━━━━━━━━━━━━━━━━
TC: ${value}
GSM: 05XX XXX XX XX
Operatör: VODAFONE
━━━━━━━━━━━━━━━━━━━━━`,
            'family': `👨‍👩‍👧‍👦 AİLE SORGU SONUCU (VIP)
━━━━━━━━━━━━━━━━━━━━━
TC: ${value}
━━━━━━━━━━━━━━━━━━━━━
Anne: AYŞE ÖRNEK - 12345678903
Baba: MEHMET ÖRNEK - 12345678904
Kardeş: ALİ ÖRNEK - 12345678905
━━━━━━━━━━━━━━━━━━━━━`,
            'address': `🏠 ADRES SORGU SONUCU
━━━━━━━━━━━━━━━━━━━━━
TC: ${value}
━━━━━━━━━━━━━━━━━━━━━
İl: İSTANBUL
İlçe: KADIKÖY
Mahalle: CAFERAĞA MAH.
Adres: ÖRNEK SOK. NO:1
━━━━━━━━━━━━━━━━━━━━━`,
            'plaka': `🚗 PLAKA SORGU SONUCU
━━━━━━━━━━━━━━━━━━━━━
Plaka: ${value}
Marka: VOLKSWAGEN
Model: PASSAT
Yıl: 2020
Renk: BEYAZ
Sahibi: ÖRNEK KİŞİ
TC: 12345678901
━━━━━━━━━━━━━━━━━━━━━`,
            'detayli': `👑 DETAYLI SORGU SONUCU (VIP)
━━━━━━━━━━━━━━━━━━━━━
TC: ${value}
━━━━━━━━━━━━━━━━━━━━━
Ad: ÖRNEK
Soyad: KİŞİ
Doğum Tarihi: 01.01.1990
Anne Adı: AYŞE
Baba Adı: MEHMET
Nüfusa Kayıtlı İl: İSTANBUL
Medeni Hal: EVLİ
GSM: 05XX XXX XX XX
Adres: İSTANBUL/KADIKÖY
━━━━━━━━━━━━━━━━━━━━━`,
            'operator': `📡 OPERATÖR SORGU SONUCU (VIP)
━━━━━━━━━━━━━━━━━━━━━
GSM: ${value}
━━━━━━━━━━━━━━━━━━━━━
Mevcut Operatör: VODAFONE
Sicil No: 123456789
Kayıt Tarihi: 15.03.2019
━━━━━━━━━━━━━━━━━━━━━
Operatör Geçmişi:
• TURKCELL (2015-2017)
• TÜRK TELEKOM (2017-2019)
• VODAFONE (2019-...)
━━━━━━━━━━━━━━━━━━━━━`
        };

        const result = demoResults[type];
        if (result) {
            // Sorgu log kaydet
            const userCheck = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
            const username = userCheck.rows[0]?.username || 'Bilinmiyor';

            // Detay formatla - object ise ad/soyad olarak göster
            let detailValue = value;
            if (typeof value === 'object' && value !== null) {
                // Ad Soyad sorgusu için
                if (value.ad || value.soyad) {
                    detailValue = `${value.ad || ''} ${value.soyad || ''}`.trim();
                    if (value.il) detailValue += ` (${value.il}${value.ilce ? '/' + value.ilce : ''})`;
                } else {
                    detailValue = JSON.stringify(value);
                }
            }

            await logActivity(userId, username, 'SORGU', `${type.toUpperCase()} sorgusu: ${detailValue}`, req);

            res.json({
                success: true,
                data: result
            });
        } else {
            res.json({
                success: false,
                message: 'Geçersiz sorgu tipi!'
            });
        }

        console.log(`🔍 Sorgu yapıldı: ${type} - ${value.substring(0, 4)}***`);

    } catch (error) {
        console.error('❌ Sorgu hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 📊 Aktivite Loglarını Getir (Admin)
app.get('/api/admin/logs', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 100'
        );

        res.json({
            success: true,
            logs: result.rows,
            total: result.rows.length
        });

    } catch (error) {
        console.error('❌ Log listesi hatası:', error);
        res.status(500).json({
            success: false,
            message: 'Sunucu hatası!'
        });
    }
});

// 💬 Mesaj Gönder (Kullanıcı veya Admin)
app.post('/api/messages', async (req, res) => {
    try {
        const { userId, username, userType, message, sender } = req.body;

        if (!userId || !message || !sender) {
            return res.status(400).json({ success: false, message: 'Eksik bilgi!' });
        }

        await pool.query(
            'INSERT INTO messages (user_id, username, user_type, message, sender) VALUES ($1, $2, $3, $4, $5)',
            [userId, username, userType || 'free', message, sender]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('❌ Mesaj gönderme hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// 💬 Kullanıcının Mesajlarını Getir
app.get('/api/messages/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        const result = await pool.query(
            'SELECT * FROM messages WHERE user_id = $1 ORDER BY created_at ASC',
            [userId]
        );

        res.json({ success: true, messages: result.rows });
    } catch (error) {
        console.error('❌ Mesaj getirme hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// 💬 Admin: Tüm Sohbetleri Getir (Free/VIP ayrımıyla)
app.get('/api/admin/messages', async (req, res) => {
    try {
        const { userType } = req.query;

        let query = `
            SELECT DISTINCT ON (user_id) user_id, username, user_type, 
                   (SELECT COUNT(*) FROM messages m2 WHERE m2.user_id = m.user_id AND m2.is_read = false AND m2.sender = 'user') as unread_count,
                   (SELECT message FROM messages m3 WHERE m3.user_id = m.user_id ORDER BY created_at DESC LIMIT 1) as last_message,
                   (SELECT created_at FROM messages m4 WHERE m4.user_id = m.user_id ORDER BY created_at DESC LIMIT 1) as last_message_time
            FROM messages m
        `;

        if (userType && userType !== 'all') {
            query += ` WHERE user_type = '${userType}'`;
        }

        query += ` ORDER BY user_id, last_message_time DESC`;

        const result = await pool.query(query);

        res.json({ success: true, conversations: result.rows });
    } catch (error) {
        console.error('❌ Sohbet listesi hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// 💬 Admin: Belirli Kullanıcının Mesajlarını Getir
app.get('/api/admin/messages/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        // Mesajları okundu olarak işaretle
        await pool.query(
            "UPDATE messages SET is_read = true WHERE user_id = $1 AND sender = 'user'",
            [userId]
        );

        const result = await pool.query(
            'SELECT * FROM messages WHERE user_id = $1 ORDER BY created_at ASC',
            [userId]
        );

        res.json({ success: true, messages: result.rows });
    } catch (error) {
        console.error('❌ Mesaj getirme hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// ========== EXTERNAL API ENTEGRASYONU ==========
// Anonymcheck.com.tr API proxy endpoint'leri

const axios = require('axios');
const { CookieJar } = require('tough-cookie');
const { wrapper } = require('axios-cookiejar-support');

// External API credentials
const EXTERNAL_API_URL = 'http://anonymcheck.com.tr';
const EXTERNAL_USERNAME = 'FlashBedava123';
const EXTERNAL_PASSWORD = 'FlashBedava123';

// Cookie jar ile axios instance oluştur
const jar = new CookieJar();
const axiosClient = wrapper(axios.create({
    jar,
    withCredentials: true,
    headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
}));

let isLoggedIn = false;

// External API'ye login ol
async function loginToExternalAPI() {
    try {
        console.log('🔐 Anonymcheck.com.tr oturumu açılıyor...');

        // 1. Login sayfasını ziyaret et (cookie al)
        await axiosClient.get(`${EXTERNAL_API_URL}/login`);

        // 2. Login yap
        const loginResponse = await axiosClient.post(
            `${EXTERNAL_API_URL}/login`,
            `username=${EXTERNAL_USERNAME}&password=${EXTERNAL_PASSWORD}`,
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Referer': `${EXTERNAL_API_URL}/login`
                },
                maxRedirects: 5
            }
        );

        // Dashboard'a yönlendirildiyse veya 200 döndüyse başarılı
        if (loginResponse.status === 200 || loginResponse.request?.path?.includes('dashboard')) {
            isLoggedIn = true;
            console.log('✅ Login başarılı!');
            return true;
        }

        console.log('⚠️ Login durumu belirsiz:', loginResponse.status);
        return false;

    } catch (error) {
        // Redirect de olsa hata fırlatabilir, kontrol et
        if (error.response?.status === 302 || error.response?.headers?.location?.includes('dashboard')) {
            isLoggedIn = true;
            console.log('✅ Login başarılı (redirect)!');
            return true;
        }
        console.error('❌ Login hatası:', error.message);
        return false;
    }
}

// External API'ye sorgu yap
async function queryExternalAPI(type, params) {
    // Her sorguda login yap (fresh session)
    const loggedIn = await loginToExternalAPI();

    if (!loggedIn) {
        return { error: true, message: 'Oturum açılamadı!' };
    }

    // URL encoded body oluştur
    const bodyParams = new URLSearchParams();
    bodyParams.append('type', type);

    // Parametreleri ekle
    for (const [key, value] of Object.entries(params)) {
        if (value) bodyParams.append(key, value);
    }

    try {
        console.log(`🔍 External API sorgusu: type=${type}`);

        const response = await axiosClient.post(
            `${EXTERNAL_API_URL}/proxy.php`,
            bodyParams.toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Referer': `${EXTERNAL_API_URL}/dashboard`
                }
            }
        );

        console.log('📄 External API yanıt:', JSON.stringify(response.data).substring(0, 300));

        return response.data;

    } catch (error) {
        console.error(`❌ External API sorgu hatası (${type}):`, error.message);
        return { error: true, message: 'Bağlantı hatası!' };
    }
}



// 🔍 TC Sorgu Endpoint
app.post('/api/external/tc', async (req, res) => {
    try {
        const { tc, userId } = req.body;

        if (!tc || tc.length !== 11) {
            return res.status(400).json({
                success: false,
                message: 'Geçerli bir TC kimlik numarası girin (11 hane)!'
            });
        }

        console.log(`🔍 TC Sorgu: ${tc.substring(0, 3)}*****${tc.substring(8)}`);

        const result = await queryExternalAPI('tc', { value: tc });

        // Aktivite log kaydet
        if (userId) {
            const userResult = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
            if (userResult.rows.length > 0) {
                await logActivity(userId, userResult.rows[0].username, 'TC_SORGU', `TC sorgusu yapıldı`, req);
            }
        }

        if (result.error) {
            return res.json({ success: false, message: result.message || 'Sonuç bulunamadı!' });
        }

        res.json({ success: true, data: result.data || result });

    } catch (error) {
        console.error('❌ TC sorgu hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// 🔍 Ad Soyad Sorgu Endpoint
app.post('/api/external/adsoyad', async (req, res) => {
    try {
        const { ad, soyad, il, ilce, yil, userId } = req.body;

        if (!ad || !soyad) {
            return res.status(400).json({
                success: false,
                message: 'Ad ve soyad gerekli!'
            });
        }

        console.log(`🔍 Ad Soyad Sorgu: ${ad} ${soyad}`);

        const result = await queryExternalAPI('adsoyad', { ad, soyad, il, ilce, yil });

        // Aktivite log kaydet
        if (userId) {
            const userResult = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
            if (userResult.rows.length > 0) {
                await logActivity(userId, userResult.rows[0].username, 'ADSOYAD_SORGU', `Ad Soyad sorgusu: ${ad} ${soyad}`, req);
            }
        }

        if (result.error) {
            return res.json({ success: false, message: result.message || 'Sonuç bulunamadı!' });
        }

        res.json({ success: true, data: result.data || result });

    } catch (error) {
        console.error('❌ Ad Soyad sorgu hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// 🔍 Aile Sorgu Endpoint
app.post('/api/external/aile', async (req, res) => {
    try {
        const { tc, userId } = req.body;

        if (!tc || tc.length !== 11) {
            return res.status(400).json({
                success: false,
                message: 'Geçerli bir TC kimlik numarası girin (11 hane)!'
            });
        }

        console.log(`🔍 Aile Sorgu: ${tc.substring(0, 3)}*****${tc.substring(8)}`);

        const result = await queryExternalAPI('aile', { value: tc });

        // Aktivite log kaydet
        if (userId) {
            const userResult = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
            if (userResult.rows.length > 0) {
                await logActivity(userId, userResult.rows[0].username, 'AILE_SORGU', `Aile sorgusu yapıldı`, req);
            }
        }

        if (result.error) {
            return res.json({ success: false, message: result.message || 'Sonuç bulunamadı!' });
        }

        res.json({ success: true, data: result.data || result });

    } catch (error) {
        console.error('❌ Aile sorgu hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası!' });
    }
});

// ========== STATIC FILES ==========


// Ana sayfa yönlendirmesi
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========== SERVER START ==========
const HOST = '0.0.0.0';

app.listen(PORT, HOST, () => {
    console.log(`
    ╔════════════════════════════════════════════════════╗
    ║                                                    ║
    ║   🚀 Server çalışıyor! (PostgreSQL)                ║
    ║                                                    ║
    ║   📍 http://localhost:${PORT}                          ║
    ║                                                    ║
    ║   ✅ Veritabanı: PostgreSQL (Kalıcı)               ║
    ║                                                    ║
    ╚════════════════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n👋 Sunucu kapatılıyor...');
    await pool.end();
    process.exit(0);
});
