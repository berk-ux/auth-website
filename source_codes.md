# 🚀 BWEB Proje Kaynak Kodları

Bu dosya projenin en güncel kodlarını içerir.


## Server (Backend) - server.js
```javascript
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
// İki yöntem: 1) Puppeteer ile otomatik login  2) Kullanıcı session cookie'si

const puppeteer = require('puppeteer');

// External API credentials
const EXTERNAL_API_URL = 'http://anonymcheck.com.tr';
const EXTERNAL_USERNAME = 'FlashBedava123';
const EXTERNAL_PASSWORD = 'FlashBedava123';

// Browser instance (reusable)
let browser = null;
let page = null;
let lastLoginTime = null;
const SESSION_TIMEOUT = 10 * 60 * 1000; // 10 dakika

// Kullanıcıların manuel girdiği session cookie'leri
const userSessionCookies = new Map();

// Puppeteer browser'ı başlat
async function initBrowser() {
    if (!browser) {
        console.log('🚀 Puppeteer browser başlatılıyor...');
        browser = await puppeteer.launch({
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--disable-gpu',
                '--window-size=1920x1080'
            ]
        });
        console.log('✅ Browser başlatıldı');
    }
    return browser;
}

// Puppeteer ile login ol
async function loginWithPuppeteer() {
    try {
        // Session hala geçerli mi kontrol et
        if (page && lastLoginTime && (Date.now() - lastLoginTime) < SESSION_TIMEOUT) {
            console.log('📦 Mevcut session kullanılıyor...');
            return true;
        }

        console.log('🔐 Puppeteer ile login yapılıyor...');

        await initBrowser();

        // Yeni sayfa veya mevcut sayfayı temizle
        if (page) {
            await page.close();
        }
        page = await browser.newPage();

        // User agent ayarla
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        // Login sayfasına git
        await page.goto(`${EXTERNAL_API_URL}/login`, { waitUntil: 'networkidle2' });

        // Form doldur
        await page.type('input[name="username"]', EXTERNAL_USERNAME);
        await page.type('input[name="password"]', EXTERNAL_PASSWORD);

        // Login butonuna tıkla
        await Promise.all([
            page.waitForNavigation({ waitUntil: 'networkidle2' }),
            page.click('button[type="submit"], input[type="submit"]')
        ]);

        // Dashboard'a yönlendirildi mi kontrol et
        const currentUrl = page.url();
        if (currentUrl.includes('dashboard') || !currentUrl.includes('login')) {
            lastLoginTime = Date.now();
            console.log('✅ Puppeteer login başarılı!');
            return true;
        }

        console.log('⚠️ Login başarısız, URL:', currentUrl);
        return false;

    } catch (error) {
        console.error('❌ Puppeteer login hatası:', error.message);
        return false;
    }
}

// Puppeteer ile sorgu yap
async function queryWithPuppeteer(type, params) {
    try {
        const loggedIn = await loginWithPuppeteer();
        if (!loggedIn) {
            return { error: true, message: 'Oturum açılamadı!' };
        }

        console.log(`🔍 Puppeteer ile sorgu: type=${type}`);

        // Sorgu sayfasına git ve form doldur
        const formData = new URLSearchParams();
        formData.append('type', type);
        for (const [key, value] of Object.entries(params)) {
            if (value) formData.append(key, value);
        }

        // proxy.php'ye POST isteği yap
        const response = await page.evaluate(async (url, data) => {
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: data,
                credentials: 'include'
            });
            return await res.text();
        }, `${EXTERNAL_API_URL}/proxy.php`, formData.toString());

        console.log('📄 Puppeteer yanıt:', response.substring(0, 300));

        try {
            return JSON.parse(response);
        } catch (e) {
            // Session hatası varsa yeniden login dene
            if (response.includes('oturum') || response.includes('giriş') || response.includes('login')) {
                lastLoginTime = null; // Session'ı sıfırla
                return await queryWithPuppeteer(type, params); // Retry
            }
            return { error: true, message: 'Geçersiz yanıt formatı' };
        }

    } catch (error) {
        console.error(`❌ Puppeteer sorgu hatası (${type}):`, error.message);
        return { error: true, message: 'Bağlantı hatası!' };
    }
}

// Kullanıcı session cookie'si ile sorgu yap
async function queryWithUserSession(sessionCookie, type, params) {
    try {
        console.log(`🔍 Kullanıcı session ile sorgu: type=${type}`);

        const formData = new URLSearchParams();
        formData.append('type', type);
        for (const [key, value] of Object.entries(params)) {
            if (value) formData.append(key, value);
        }

        const response = await fetch(`${EXTERNAL_API_URL}/proxy.php`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': `PHPSESSID=${sessionCookie}`,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            body: formData.toString()
        });

        const text = await response.text();
        console.log('📄 User session yanıt:', text.substring(0, 300));

        try {
            return JSON.parse(text);
        } catch (e) {
            if (text.includes('oturum') || text.includes('giriş')) {
                return { error: true, message: 'Session süresi dolmuş, lütfen yeni session girin!' };
            }
            return { error: true, message: 'Geçersiz yanıt formatı' };
        }

    } catch (error) {
        console.error(`❌ User session sorgu hatası (${type}):`, error.message);
        return { error: true, message: 'Bağlantı hatası!' };
    }
}

// Ana sorgu fonksiyonu - önce user session, yoksa puppeteer dene
async function queryExternalAPI(type, params, userId) {
    // Kullanıcının kayıtlı session cookie'si var mı?
    const userSession = userSessionCookies.get(userId);

    if (userSession) {
        console.log(`📦 Kullanıcı #${userId} session cookie'si kullanılıyor...`);
        const result = await queryWithUserSession(userSession, type, params);

        // Session geçerliyse sonucu döndür
        if (!result.error || !result.message?.includes('Session')) {
            return result;
        }

        // Session geçersiz, temizle
        console.log('⚠️ Kullanıcı session geçersiz, Puppeteer deneniyor...');
        userSessionCookies.delete(userId);
    }

    // Puppeteer ile dene
    return await queryWithPuppeteer(type, params);
}

// Kullanıcı session cookie kaydetme endpoint'i
app.post('/api/external/set-session', async (req, res) => {
    try {
        const { sessionCookie, userId } = req.body;

        if (!sessionCookie || !userId) {
            return res.status(400).json({
                success: false,
                message: 'Session cookie ve userId gerekli!'
            });
        }

        userSessionCookies.set(userId, sessionCookie);

        res.json({
            success: true,
            message: 'Session cookie kaydedildi!'
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Session kaydetme hatası!'
        });
    }
});




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

        const result = await queryExternalAPI('tc', { value: tc }, userId);

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

        const result = await queryExternalAPI('adsoyad', { ad, soyad, il, ilce, yil }, userId);

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

        const result = await queryExternalAPI('aile', { value: tc }, userId);

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

```

## Package - package.json
```json
{
  "name": "auth-website",
  "version": "1.0.0",
  "description": "Kullanıcı Yönetim Sistemi",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "node server.js",
    "test": "echo \"No tests\" && exit 0"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "license": "ISC",
  "type": "commonjs",
  "dependencies": {
    "axios": "^1.6.0",
    "axios-cookiejar-support": "^4.0.7",
    "bcryptjs": "^3.0.3",
    "better-sqlite3": "^12.6.0",
    "cors": "^2.8.5",
    "express": "^5.2.1",
    "express-rate-limit": "^7.5.0",
    "helmet": "^8.1.0",
    "pg": "^8.17.0",
    "puppeteer": "^21.0.0",
    "tough-cookie": "^4.1.3",
    "validator": "^13.12.0"
  }
}
```

## Dashboard - public/dashboard.html
```html
<!DOCTYPE html>
<html lang="tr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard | BWEB</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: #0a0a0f;
            min-height: 100vh;
            display: flex;
            color: white;
        }

        /* Sidebar */
        .sidebar {
            width: 280px;
            background: linear-gradient(180deg, #0f0f15 0%, #1a1a25 100%);
            border-right: 1px solid rgba(255, 255, 255, 0.05);
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            overflow-y: auto;
            z-index: 100;
            transition: all 0.3s ease;
        }

        /* Sidebar Collapsed State */
        .sidebar.collapsed {
            width: 0;
            overflow: hidden;
            padding: 0;
        }

        .sidebar.collapsed~.main-content {
            margin-left: 0;
        }

        /* Hamburger Button */
        .hamburger-btn {
            position: fixed;
            top: 20px;
            left: 225px;
            /* Sidebar açıkken sağ üst köşe */
            width: 45px;
            height: 45px;
            background: rgba(30, 30, 40, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            gap: 5px;
            cursor: pointer;
            z-index: 200;
            transition: all 0.3s ease;
        }

        /* Sidebar kapalıyken hamburger sol üstte */
        .sidebar.collapsed~.hamburger-btn,
        body:has(.sidebar.collapsed) .hamburger-btn {
            left: 20px;
        }

        .hamburger-btn:hover {
            background: rgba(50, 50, 60, 0.95);
            transform: scale(1.05);
        }

        .hamburger-btn span {
            display: block;
            width: 22px;
            height: 2px;
            background: #fff;
            border-radius: 2px;
            transition: all 0.3s ease;
        }

        /* VIP tema hamburger */
        body.vip-theme .hamburger-btn {
            background: rgba(40, 35, 25, 0.95);
            border-color: rgba(251, 191, 36, 0.3);
        }

        body.vip-theme .hamburger-btn:hover {
            background: rgba(60, 50, 35, 0.95);
            box-shadow: 0 0 15px rgba(251, 191, 36, 0.3);
        }

        body.vip-theme .hamburger-btn span {
            background: #fbbf24;
        }

        /* 👑 VIP ALTIN TEMA */
        body.vip-theme {
            background: linear-gradient(135deg, #1a1510 0%, #2d2516 50%, #1a1510 100%);
        }

        body.vip-theme .sidebar {
            background: linear-gradient(180deg, #1a1510 0%, #2d2516 100%);
            border-right: 1px solid rgba(251, 191, 36, 0.2);
        }

        body.vip-theme .user-avatar {
            background: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
            box-shadow: 0 0 20px rgba(251, 191, 36, 0.4);
        }

        body.vip-theme .menu-item:hover {
            background: rgba(251, 191, 36, 0.1);
            color: #fbbf24;
        }

        body.vip-theme .menu-item.active {
            background: rgba(251, 191, 36, 0.15);
            color: #fbbf24;
            border-right: 3px solid #fbbf24;
        }

        body.vip-theme .main-content {
            background: linear-gradient(135deg, #1a1510 0%, #2d2516 100%);
        }

        body.vip-theme .content-header {
            border-bottom-color: rgba(251, 191, 36, 0.2);
        }

        body.vip-theme .page-title {
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 50%, #d97706 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        body.vip-theme .verified-badge {
            color: #fbbf24;
        }

        body.vip-theme .online-dot {
            background: #fbbf24;
            box-shadow: 0 0 10px #fbbf24;
        }

        body.vip-theme .online-status {
            color: #fbbf24;
        }

        /* VIP Altın Parıltı Animasyonu */
        @keyframes goldShimmer {
            0% {
                background-position: -200% center;
            }

            100% {
                background-position: 200% center;
            }
        }

        body.vip-theme .vip-shimmer {
            background: linear-gradient(90deg, transparent, rgba(251, 191, 36, 0.3), transparent);
            background-size: 200% 100%;
            animation: goldShimmer 3s infinite;
        }

        .sidebar::-webkit-scrollbar {
            width: 6px;
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
        }

        /* User Profile */
        .user-profile {
            padding: 24px 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .user-avatar {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.1rem;
        }

        .user-details {
            flex: 1;
        }

        .user-name {
            font-weight: 600;
            font-size: 1rem;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .verified-badge {
            color: #3b82f6;
            font-size: 0.9rem;
        }

        .user-type-badge {
            font-size: 0.7rem;
            padding: 3px 8px;
            border-radius: 4px;
            background: rgba(99, 102, 241, 0.2);
            color: #a5b4fc;
            margin-top: 4px;
            display: inline-block;
        }

        .user-type-badge.vip {
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
            color: #000;
        }

        .online-status {
            font-size: 0.75rem;
            color: #34d399;
            display: flex;
            align-items: center;
            gap: 4px;
            margin-top: 4px;
        }

        .online-dot {
            width: 6px;
            height: 6px;
            background: #34d399;
            border-radius: 50%;
        }

        /* Menu */
        .menu-section {
            padding: 16px 0;
        }

        .menu-title {
            font-size: 0.7rem;
            font-weight: 600;
            color: #64748b;
            padding: 8px 20px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .menu-item {
            display: flex;
            align-items: center;
            padding: 12px 20px;
            color: #94a3b8;
            text-decoration: none;
            transition: all 0.2s;
            cursor: pointer;
            font-size: 0.9rem;
        }

        .menu-item:hover {
            background: rgba(255, 255, 255, 0.05);
            color: white;
        }

        .menu-item.active {
            background: rgba(99, 102, 241, 0.1);
            color: #a5b4fc;
            border-right: 3px solid #6366f1;
        }

        .menu-icon {
            width: 20px;
            margin-right: 12px;
            font-size: 1rem;
        }

        .menu-arrow {
            margin-left: auto;
            transition: transform 0.3s;
            font-size: 0.8rem;
        }

        .menu-item.open .menu-arrow {
            transform: rotate(180deg);
        }

        .menu-badge {
            margin-left: auto;
            font-size: 0.65rem;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
        }

        .menu-badge.free {
            background: #22c55e;
            color: white;
        }

        .menu-badge.vip {
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
            color: #000;
        }

        /* Submenu */
        .submenu {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
            background: rgba(0, 0, 0, 0.2);
        }

        .submenu.open {
            max-height: 500px;
        }

        .submenu-item {
            display: flex;
            align-items: center;
            padding: 10px 20px 10px 52px;
            color: #94a3b8;
            text-decoration: none;
            transition: all 0.2s;
            cursor: pointer;
            font-size: 0.85rem;
        }

        .submenu-item:hover {
            background: rgba(255, 255, 255, 0.05);
            color: white;
        }

        .submenu-item.active {
            color: #a5b4fc;
        }

        /* Premium Section */
        .premium-section {
            margin: 20px;
            padding: 16px;
            background: linear-gradient(135deg, rgba(251, 191, 36, 0.1) 0%, rgba(245, 158, 11, 0.1) 100%);
            border: 1px solid rgba(251, 191, 36, 0.3);
            border-radius: 12px;
            text-align: center;
        }

        .premium-title {
            font-size: 0.85rem;
            font-weight: 700;
            color: #fbbf24;
            margin-bottom: 8px;
        }

        .premium-btn {
            width: 100%;
            padding: 10px;
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
            border: none;
            border-radius: 8px;
            color: #000;
            font-weight: 600;
            font-size: 0.8rem;
            cursor: pointer;
        }

        /* Logout */
        .logout-btn {
            margin: 20px;
            padding: 12px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            color: #f87171;
            font-size: 0.85rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.2s;
        }

        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.2);
        }

        /* Main Content */
        .main-content {
            margin-left: 280px;
            flex: 1;
            padding: 24px;
            min-height: 100vh;
        }

        /* Header */
        .content-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .page-title {
            font-size: 1.5rem;
            font-weight: 700;
        }

        .header-badge {
            padding: 6px 12px;
            background: rgba(99, 102, 241, 0.2);
            border-radius: 8px;
            font-size: 0.8rem;
            color: #a5b4fc;
        }

        /* Query Card */
        .query-card {
            background: linear-gradient(135deg, #1a1a25 0%, #0f0f15 100%);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 32px;
            max-width: 600px;
        }

        .query-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .query-description {
            color: #64748b;
            font-size: 0.85rem;
            margin-bottom: 24px;
        }

        .query-input {
            width: 100%;
            padding: 16px 20px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            color: white;
            font-size: 1rem;
            font-family: inherit;
            margin-bottom: 16px;
        }

        .query-input::placeholder {
            color: #64748b;
        }

        .query-input:focus {
            outline: none;
            border-color: #6366f1;
        }

        .query-btn {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            border: none;
            border-radius: 12px;
            color: white;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }

        .query-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(99, 102, 241, 0.3);
        }

        .query-btn.vip {
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
            color: #000;
        }

        /* 👑 VIP TEMA - Sorgu Ekranı */
        body.vip-theme .query-card {
            background: linear-gradient(135deg, #2d2516 0%, #1a1510 100%);
            border: 1px solid rgba(251, 191, 36, 0.2);
        }

        body.vip-theme .query-input {
            background: rgba(251, 191, 36, 0.05);
            border: 1px solid rgba(251, 191, 36, 0.2);
        }

        body.vip-theme .query-input:focus {
            border-color: #fbbf24;
            box-shadow: 0 0 20px rgba(251, 191, 36, 0.2);
        }

        body.vip-theme .query-btn {
            background: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
            color: #000;
        }

        body.vip-theme .query-btn:hover {
            box-shadow: 0 8px 30px rgba(251, 191, 36, 0.4);
        }

        body.vip-theme .query-title {
            color: #fbbf24;
        }

        body.vip-theme .header-badge {
            background: rgba(251, 191, 36, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(251, 191, 36, 0.3);
        }

        body.vip-theme .result-section {
            background: rgba(251, 191, 36, 0.05);
            border: 1px solid rgba(251, 191, 36, 0.1);
        }

        body.vip-theme #chatToggle {
            background: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
            box-shadow: 0 4px 20px rgba(251, 191, 36, 0.4);
        }

        /* 🟣 FREE TEMA - Mor/Mavi Renk */
        body:not(.vip-theme) .query-title {
            color: #a78bfa;
        }

        body:not(.vip-theme) .query-card label {
            color: #a78bfa !important;
        }

        body:not(.vip-theme) .header-badge {
            background: rgba(167, 139, 250, 0.2);
            color: #a78bfa;
            border: 1px solid rgba(167, 139, 250, 0.3);
        }

        body:not(.vip-theme) .query-input:focus {
            border-color: #a78bfa;
            box-shadow: 0 0 20px rgba(167, 139, 250, 0.2);
        }

        body:not(.vip-theme) .page-title {
            background: linear-gradient(135deg, #a78bfa 0%, #8b5cf6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        /* Form Label Stilleri */
        .form-label {
            display: block;
            font-weight: 600;
            margin-bottom: 8px;
            font-size: 0.9rem;
            color: #a78bfa;
            /* FREE: Mor */
        }

        body.vip-theme .form-label {
            color: #fbbf24;
            /* VIP: Altın */
        }

        /* Result */
        .result-section {
            margin-top: 24px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            padding: 20px;
            display: none;
        }

        .result-section.show {
            display: block;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .result-content {
            font-family: 'Monaco', monospace;
            font-size: 0.85rem;
            color: #34d399;
            white-space: pre-wrap;
            line-height: 1.6;
        }

        /* Welcome Screen */
        .welcome-screen {
            text-align: center;
            padding: 60px 20px;
        }

        .welcome-icon {
            font-size: 4rem;
            margin-bottom: 20px;
        }

        .welcome-title {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 10px;
        }

        .welcome-text {
            color: #64748b;
            font-size: 1rem;
        }

        /* Footer */
        .footer {
            position: fixed;
            bottom: 0;
            left: 260px;
            right: 0;
            padding: 12px 20px;
            text-align: center;
            color: #475569;
            font-size: 0.75rem;
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(10px);
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            z-index: 100;
        }

        @media (max-width: 768px) {
            .footer {
                left: 0;
            }
        }

        /* Input Grid - responsive */
        .input-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 16px;
        }

        @media (max-width: 768px) {
            .input-grid {
                grid-template-columns: 1fr;
            }
        }

        /* 👑 VIP Hoşgeldin Animasyonu */
        .vip-welcome-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            animation: fadeIn 0.5s ease;
        }

        .vip-welcome-overlay.hide {
            animation: fadeOut 0.5s ease forwards;
        }

        .vip-crown {
            font-size: 5rem;
            animation: crownBounce 1s ease infinite;
        }

        .vip-welcome-text {
            font-size: 2rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-top: 20px;
            text-align: center;
        }

        .vip-username {
            font-size: 1.5rem;
            color: #fbbf24;
            margin-top: 10px;
            animation: pulse 1.5s ease infinite;
        }

        @keyframes crownBounce {

            0%,
            100% {
                transform: translateY(0) rotate(0deg);
            }

            25% {
                transform: translateY(-15px) rotate(-5deg);
            }

            50% {
                transform: translateY(0) rotate(0deg);
            }

            75% {
                transform: translateY(-15px) rotate(5deg);
            }
        }

        @keyframes pulse {

            0%,
            100% {
                opacity: 1;
                transform: scale(1);
            }

            50% {
                opacity: 0.7;
                transform: scale(1.05);
            }
        }

        @keyframes fadeOut {
            from {
                opacity: 1;
            }

            to {
                opacity: 0;
                visibility: hidden;
            }
        }

        /* Responsive - Mobil Optimizasyon */
        @media (max-width: 768px) {
            body {
                overflow-x: hidden;
            }

            .sidebar {
                position: fixed;
                left: -280px;
                top: 0;
                width: 280px;
                height: 100vh;
                z-index: 1000;
                transition: left 0.3s ease;
                overflow-y: auto;
            }

            .sidebar.open {
                left: 0;
            }

            .main-content {
                margin-left: 0;
                width: 100%;
                min-height: 100vh;
                padding: 16px;
            }

            /* Hamburger menü - sidebar kapalıyken görünür */
            .hamburger-btn {
                display: flex !important;
                position: fixed;
                top: 16px;
                left: 16px;
                z-index: 1002;
                background: rgba(30, 41, 59, 0.95);
                backdrop-filter: blur(10px);
            }

            /* Sidebar açıkken hamburger butonu gizle */
            .sidebar.open~.hamburger-btn,
            body:has(.sidebar.open) .hamburger-btn {
                display: none !important;
            }

            /* Sidebar açıkken hamburger sidebar içinde sağ üst köşede */
            .sidebar.open .hamburger-close {
                display: flex;
            }

            .hamburger-close {
                display: none;
                position: absolute;
                top: 12px;
                right: 12px;
                width: 36px;
                height: 36px;
                background: rgba(255, 255, 255, 0.1);
                border: none;
                border-radius: 8px;
                justify-content: center;
                align-items: center;
                cursor: pointer;
                font-size: 1.2rem;
                color: #94a3b8;
                z-index: 10;
            }

            .hamburger-close:hover {
                background: rgba(255, 255, 255, 0.2);
                color: #fff;
            }

            /* Overlay for mobile menu */
            .sidebar-overlay {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                z-index: 999;
            }

            .sidebar-overlay.show {
                display: block;
            }

            /* Query card mobil optimizasyon */
            .query-card {
                padding: 16px;
                margin: 0;
            }

            /* Grid 2 sütundan 1 sütuna */
            .query-card>div[style*="grid-template-columns: 1fr 1fr"] {
                grid-template-columns: 1fr !important;
            }

            /* Input'lar tam genişlik */
            .query-input {
                width: 100%;
                font-size: 16px;
                /* iOS zoom önleme */
            }

            /* Başlıklar */
            .page-title {
                font-size: 1.3rem;
            }

            .content-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
                padding-top: 50px;
                /* Hamburger için boşluk */
            }

            /* Sonuç bölümü */
            .result-section {
                padding: 12px;
            }

            .result-content {
                font-size: 0.8rem;
            }

            /* Chat popup mobil */
            #chatPopup {
                width: calc(100% - 32px) !important;
                right: 16px !important;
                bottom: 80px !important;
                height: 400px !important;
            }

            /* Premium section */
            .premium-section {
                padding: 12px;
            }
        }

        /* Tablet */
        @media (max-width: 1024px) and (min-width: 769px) {
            .sidebar {
                width: 200px;
            }

            .main-content {
                margin-left: 200px;
            }
        }
    </style>
</head>

<body>
    <!-- 👑 VIP Hoşgeldin Animasyonu -->
    <div id="vipWelcomeOverlay" class="vip-welcome-overlay" style="display: none;">
        <div class="vip-crown">👑</div>
        <div class="vip-welcome-text">Hoş Geldiniz!</div>
        <div class="vip-username" id="vipWelcomeUsername"></div>
    </div>

    <!-- Hamburger Menu Button -->
    <button class="hamburger-btn" id="hamburgerBtn" onclick="toggleSidebar()">
        <span></span>
        <span></span>
        <span></span>
    </button>

    <!-- Mobile Sidebar Overlay -->
    <div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>

    <!-- Sidebar -->
    <aside class="sidebar" id="sidebarMenu">
        <!-- Mobile Close Button -->
        <button class="hamburger-close" onclick="toggleSidebar()">✕</button>

        <!-- User Profile -->
        <div class="user-profile">
            <div class="user-avatar" id="userAvatar">?</div>
            <div class="user-details">
                <div class="user-name">
                    <span id="userName">Kullanıcı</span>
                    <span class="verified-badge">✓</span>
                </div>
                <span class="user-type-badge" id="userType">Free Üyelik</span>
                <div class="online-status">
                    <span class="online-dot"></span>
                    Çevrimiçi
                </div>
            </div>
        </div>

        <!-- Menu -->
        <nav class="menu-section">
            <div class="menu-item" onclick="goToHome()">
                <span class="menu-icon">🏠</span>
                Ana Sayfa
            </div>
            <div class="menu-item" onclick="showUserProfile()">
                <span class="menu-icon">👤</span>
                Kullanıcı Hakkında
            </div>
        </nav>

        <div class="menu-title">ÜCRETSİZ ÇÖZÜMLER</div>
        <nav class="menu-section">
            <!-- Mernis 2026 -->
            <div class="menu-item" onclick="toggleSubmenu('mernis')">
                <span class="menu-icon">📋</span>
                Mernis 2026
                <span class="menu-arrow">▼</span>
            </div>
            <div class="submenu" id="mernis-submenu">
                <div class="submenu-item"
                    onclick="showQuery('tc', 'TC Sorgu', 'TC kimlik numarası ile sorgulama', 'TC Kimlik No girin...')">
                    TC Sorgu
                    <span class="menu-badge free">FREE</span>
                </div>
                <div class="submenu-item" onclick="showNameQuery()">
                    Ad Soyad Sorgu
                    <span class="menu-badge free">FREE</span>
                </div>
                <div class="submenu-item"
                    onclick="showQuery('address', 'Hane/Adres Sorgu', 'TC ile adres sorgulama', 'TC Kimlik No girin...')">
                    Hane/Adres Sorgu
                    <span class="menu-badge free">FREE</span>
                </div>
                <div class="submenu-item"
                    onclick="showQuery('family', 'Aile Sorgu', 'TC ile aile bilgileri sorgulama', 'TC Kimlik No girin...')">
                    Aile Sorgu
                    <span class="menu-badge free">FREE</span>
                </div>
            </div>

            <!-- GSM Çözümleri -->
            <div class="menu-item" onclick="toggleSubmenu('gsm')">
                <span class="menu-icon">📱</span>
                GSM Çözümleri
                <span class="menu-arrow">▼</span>
            </div>
            <div class="submenu" id="gsm-submenu">
                <div class="submenu-item"
                    onclick="showQuery('gsm', 'GSM → TC', 'Telefon numarası ile TC sorgulama', '05XX XXX XX XX')">
                    GSM → TC
                    <span class="menu-badge free">FREE</span>
                </div>
                <div class="submenu-item"
                    onclick="showQuery('tcgsm', 'TC → GSM', 'TC ile telefon numarası sorgulama', 'TC Kimlik No girin...')">
                    TC → GSM
                    <span class="menu-badge free">FREE</span>
                </div>
            </div>

            <!-- Araçlar -->
            <div class="menu-item" onclick="toggleSubmenu('tools')">
                <span class="menu-icon">🔧</span>
                Araçlar
                <span class="menu-arrow">▼</span>
            </div>
            <div class="submenu" id="tools-submenu">
                <div class="submenu-item"
                    onclick="showQuery('plaka', 'Plaka Sorgu', 'Araç plakası ile sorgulama', 'Plaka girin... (34ABC123)')">
                    Plaka Sorgu
                    <span class="menu-badge free">FREE</span>
                </div>
            </div>
        </nav>

        <div class="menu-title">PREMİUM ÇÖZÜMLER</div>
        <nav class="menu-section">
            <div class="menu-item" onclick="toggleSubmenu('premium')">
                <span class="menu-icon">👑</span>
                VIP Sorgular
                <span class="menu-arrow">▼</span>
            </div>
            <div class="submenu" id="premium-submenu">
                <div class="submenu-item"
                    onclick="showQuery('detayli', 'Detaylı Sorgu', 'Tüm bilgiler tek sorguda', 'TC Kimlik No girin...', true)">
                    Detaylı Sorgu
                    <span class="menu-badge vip">VIP</span>
                </div>
                <div class="submenu-item"
                    onclick="showQuery('operator', 'Operatör Sorgu', 'Telefon operatör geçmişi', 'GSM No girin...', true)">
                    Operatör Sorgu
                    <span class="menu-badge vip">VIP</span>
                </div>
            </div>
        </nav>

        <!-- Ayarlar Menüsü -->
        <nav class="menu-section">
            <div class="menu-title">AYARLAR</div>
            <div class="menu-item" onclick="showSessionSettings()">
                <span class="menu-icon">🔐</span>
                Session Ayarları
            </div>
        </nav>

        <!-- Premium CTA -->

        <div class="premium-section" id="premiumCTA">
            <div class="premium-title">👑 PREMİUM ÇÖZÜMLER</div>
            <p style="font-size: 0.75rem; color: #94a3b8; margin-bottom: 12px;">Tüm özelliklere erişim için VIP olun</p>
            <button class="premium-btn">VIP Satın Al</button>
        </div>

        <!-- Logout -->
        <button class="logout-btn" onclick="logout()">
            🚪 Çıkış Yap
        </button>
    </aside>

    <!-- Sağ Üst Çıkış Butonu -->
    <button onclick="logout()" style="
        position: fixed;
        top: 16px;
        right: 16px;
        padding: 10px 18px;
        background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        border: none;
        border-radius: 10px;
        color: white;
        font-weight: 600;
        font-size: 0.85rem;
        cursor: pointer;
        z-index: 1001;
        display: flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        transition: transform 0.2s, box-shadow 0.2s;
    " onmouseover="this.style.transform='scale(1.05)'; this.style.boxShadow='0 6px 20px rgba(239, 68, 68, 0.4)';"
        onmouseout="this.style.transform='scale(1)'; this.style.boxShadow='0 4px 15px rgba(239, 68, 68, 0.3)';">
        🚪 Çıkış
    </button>

    <!-- Main Content -->
    <main class="main-content">
        <!-- Welcome Screen (Free Users) -->
        <div id="freeUserScreen">
            <div class="welcome-screen">
                <div class="welcome-icon">🔒</div>
                <h1 class="welcome-title">Sorgu Paneli Kilitli</h1>
                <p class="welcome-text" style="margin-bottom: 24px;">Sorgu yapmak için VIP üyelik gereklidir.</p>

                <div
                    style="background: linear-gradient(135deg, rgba(251, 191, 36, 0.1) 0%, rgba(245, 158, 11, 0.1) 100%); border: 1px solid rgba(251, 191, 36, 0.3); border-radius: 16px; padding: 32px; max-width: 400px; margin: 0 auto;">
                    <div style="font-size: 3rem; margin-bottom: 16px;">👑</div>
                    <h2 style="color: #fbbf24; font-size: 1.3rem; margin-bottom: 12px;">VIP Üyelik Avantajları</h2>
                    <ul style="text-align: left; color: #94a3b8; list-style: none; padding: 0; margin-bottom: 24px;">
                        <li style="padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">✅ Tüm sorgu
                            türlerine erişim</li>
                        <li style="padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">✅ Sınırsız sorgu
                            hakkı</li>
                        <li style="padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">✅ Öncelikli destek
                        </li>
                        <li style="padding: 8px 0;">✅ Yeni özellikler ilk sizde</li>
                    </ul>
                    <button
                        style="width: 100%; padding: 14px; background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%); border: none; border-radius: 10px; color: #000; font-weight: 700; font-size: 1rem; cursor: pointer;">
                        💳 VIP Satın Al
                    </button>
                    <p style="color: #64748b; font-size: 0.75rem; margin-top: 12px;">Admin ile iletişime geçin</p>
                </div>
            </div>
        </div>

        <!-- Welcome Screen (VIP Users) -->
        <div id="welcomeScreen" style="display: none;">
            <div class="welcome-screen">
                <div class="welcome-icon">👑</div>
                <h1 class="welcome-title">BWEB'e Hoş Geldiniz!</h1>
                <p class="welcome-text">Sol menüden bir sorgu seçerek başlayın.</p>
            </div>
        </div>

        <!-- Session Settings Screen -->
        <div id="sessionSettingsScreen" style="display: none;">
            <div class="content-header">
                <h1 class="page-title">🔐 Session Ayarları</h1>
                <span class="header-badge">AYARLAR</span>
            </div>

            <div class="query-card" style="max-width: 700px;">
                <h2 class="query-title">
                    <span>🍪</span>
                    <span>External API Session Cookie</span>
                </h2>
                <p class="query-description">
                    Anonymcheck.com.tr sitesinden aldığınız PHPSESSID cookie değerini buraya girin.
                    Bu sayede kendi oturumunuzla sorgu yapabilirsiniz.
                </p>

                <div
                    style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 12px; padding: 16px; margin-bottom: 20px;">
                    <h4 style="color: #60a5fa; margin-bottom: 10px;">📋 Session Cookie Nasıl Alınır?</h4>
                    <ol style="color: #94a3b8; font-size: 0.85rem; padding-left: 20px; line-height: 1.8;">
                        <li><a href="http://anonymcheck.com.tr/login" target="_blank"
                                style="color: #60a5fa;">anonymcheck.com.tr</a>'ye giriş yapın</li>
                        <li>Tarayıcınızda <strong>F12</strong> tuşuna basın (Developer Tools)</li>
                        <li><strong>Application</strong> → <strong>Cookies</strong> →
                            <strong>anonymcheck.com.tr</strong>
                        </li>
                        <li><strong>PHPSESSID</strong> değerini kopyalayın</li>
                        <li>Aşağıdaki alana yapıştırın</li>
                    </ol>
                </div>

                <label class="form-label">PHPSESSID Cookie Değeri</label>
                <input type="text" class="query-input" id="sessionCookieInput" placeholder="Örn: abc123def456...">

                <button class="query-btn" onclick="saveSessionCookie()" style="margin-bottom: 16px;">
                    💾 Session Cookie Kaydet
                </button>

                <div id="sessionStatus" style="padding: 12px; border-radius: 8px; margin-top: 10px; display: none;">
                </div>

                <div style="margin-top: 24px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.1);">
                    <p style="color: #64748b; font-size: 0.8rem;">
                        ⚠️ <strong>Not:</strong> Session cookie'ler belirli bir süre sonra geçersiz olur.
                        Eğer "oturum süresi doldu" hatası alırsanız yeni cookie alıp tekrar girin.
                    </p>
                </div>
            </div>
        </div>

        <!-- Query Screen -->

        <div id="queryScreen" style="display: none;">
            <div class="content-header">
                <h1 class="page-title" id="pageTitle">Sorgu</h1>
                <span class="header-badge" id="queryBadge">FREE</span>
            </div>

            <div class="query-card">
                <h2 class="query-title" id="queryTitle">
                    <span id="queryIcon">🔍</span>
                    <span id="queryName">Sorgu</span>
                </h2>
                <p class="query-description" id="queryDescription">Sorgu açıklaması</p>

                <!-- Standart Tek Input -->
                <div id="singleInputSection">
                    <label id="inputLabel"
                        style="display: block; color: #fbbf24; font-weight: 600; margin-bottom: 8px; font-size: 0.9rem;">TC</label>
                    <input type="text" class="query-input" id="queryInput" placeholder="Değer girin...">
                </div>

                <!-- Ad Soyad Özel Inputlar - Grid Layout -->
                <div id="nameInputSection" style="display: none;">
                    <!-- Ad ve Soyad Yan Yana -->
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
                        <div>
                            <label
                                style="display: block; color: #fbbf24; font-weight: 600; margin-bottom: 8px; font-size: 0.9rem;">Ad
                                <span style="color: #94a3b8; font-weight: 400;">(Zorunlu)</span></label>
                            <input type="text" class="query-input" id="nameInput" placeholder="Ad"
                                style="margin-bottom: 0;">
                        </div>
                        <div>
                            <label
                                style="display: block; color: #fbbf24; font-weight: 600; margin-bottom: 8px; font-size: 0.9rem;">Soyad
                                <span style="color: #94a3b8; font-weight: 400;">(Zorunlu)</span></label>
                            <input type="text" class="query-input" id="surnameInput" placeholder="Soyad"
                                style="margin-bottom: 0;">
                        </div>
                    </div>
                    <!-- İl ve İlçe Yan Yana -->
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
                        <div>
                            <label
                                style="display: block; color: #fbbf24; font-weight: 600; margin-bottom: 8px; font-size: 0.9rem;">İl
                                <span style="color: #94a3b8; font-weight: 400;">(Opsiyonel)</span></label>
                            <input type="text" class="query-input" id="cityInput" placeholder="İl"
                                style="margin-bottom: 0;">
                        </div>
                        <div>
                            <label
                                style="display: block; color: #fbbf24; font-weight: 600; margin-bottom: 8px; font-size: 0.9rem;">İlçe
                                <span style="color: #94a3b8; font-weight: 400;">(Opsiyonel)</span></label>
                            <input type="text" class="query-input" id="districtInput" placeholder="İlçe"
                                style="margin-bottom: 0;">
                        </div>
                    </div>
                </div>

                <button class="query-btn" id="queryBtn" onclick="executeQuery()">🔍 Sorgula</button>

                <div class="result-section" id="resultSection">
                    <div
                        style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <span style="color: #64748b; font-size: 0.8rem;">📋 Sonuç</span>
                        <button class="copy-btn" onclick="copyQueryResult('resultContent')"
                            style="padding: 6px 14px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); border: none; border-radius: 8px; color: white; font-size: 0.75rem; cursor: pointer; display: flex; align-items: center; gap: 6px;">
                            📋 Kopyala
                        </button>
                    </div>
                    <div class="result-content" id="resultContent"></div>
                </div>
            </div>
        </div>

        <!-- AD SOYAD SORGU SCREEN (Ayrı) -->
        <div id="nameQueryScreen" style="display: none; padding: 24px;">
            <div class="content-header">
                <h1 class="page-title">👤 Ad Soyad Sorgu</h1>
                <span class="header-badge">FREE</span>
            </div>

            <div class="query-card">
                <h2 class="query-title">
                    <span>👤</span>
                    <span>Ad Soyad Sorgulama</span>
                </h2>
                <p class="query-description">Ad ve soyad girmek zorunludur.</p>

                <!-- Ad ve Soyad Yan Yana -->
                <div class="input-grid">
                    <div>
                        <label class="form-label">Ad
                            <span style="color: #94a3b8; font-weight: 400;">(Zorunlu)</span></label>
                        <input type="text" class="query-input" id="adInput" placeholder="Ad">
                    </div>
                    <div>
                        <label class="form-label">Soyad
                            <span style="color: #94a3b8; font-weight: 400;">(Zorunlu)</span></label>
                        <input type="text" class="query-input" id="soyadInput" placeholder="Soyad">
                    </div>
                </div>

                <!-- İl ve İlçe Yan Yana -->
                <div class="input-grid">
                    <div>
                        <label class="form-label">İl
                            <span style="color: #94a3b8; font-weight: 400;">(Opsiyonel)</span></label>
                        <input type="text" class="query-input" id="ilInput" placeholder="İl">
                    </div>
                    <div>
                        <label class="form-label">İlçe
                            <span style="color: #94a3b8; font-weight: 400;">(Opsiyonel)</span></label>
                        <input type="text" class="query-input" id="ilceInput" placeholder="İlçe">
                    </div>
                </div>


                <button class="query-btn" onclick="executeNameQuery()">🔍 Sorgula</button>

                <div class="result-section" id="nameResultSection">
                    <div
                        style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <span style="color: #64748b; font-size: 0.8rem;">📋 Sonuç</span>
                        <button class="copy-btn" onclick="copyQueryResult('nameResultContent')"
                            style="padding: 6px 14px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); border: none; border-radius: 8px; color: white; font-size: 0.75rem; cursor: pointer; display: flex; align-items: center; gap: 6px;">
                            📋 Kopyala
                        </button>
                    </div>
                    <div class="result-content" id="nameResultContent"></div>
                </div>
            </div>
        </div>

        <!-- 👤 KULLANICI HAKKINDA SCREEN -->
        <div id="userProfileScreen" style="display: none; padding: 24px;">
            <div class="content-header">
                <h1 class="page-title">👤 Kullanıcı Hakkında</h1>
            </div>

            <div class="query-card" style="max-width: 600px;">
                <div style="text-align: center; margin-bottom: 24px;">
                    <div id="profileAvatar"
                        style="width: 80px; height: 80px; border-radius: 50%; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); display: flex; align-items: center; justify-content: center; font-size: 2rem; color: white; margin: 0 auto 16px; font-weight: bold;">
                        ?</div>
                    <h2 id="profileUsername" style="color: #e2e8f0; margin: 0 0 4px 0;">Kullanıcı</h2>
                    <span id="profileBadge"
                        style="display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; background: rgba(99, 102, 241, 0.2); color: #818cf8;">Free
                        Üyelik</span>
                </div>

                <div style="display: flex; flex-direction: column; gap: 16px;">
                    <!-- Kayıt Tarihi -->
                    <div
                        style="background: rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 16px; display: flex; align-items: center; gap: 16px;">
                        <div
                            style="width: 48px; height: 48px; border-radius: 12px; background: rgba(99, 102, 241, 0.2); display: flex; align-items: center; justify-content: center; font-size: 1.5rem;">
                            📅</div>
                        <div>
                            <div style="color: #64748b; font-size: 0.75rem; margin-bottom: 4px;">Kayıt Tarihi</div>
                            <div id="profileRegDate" style="color: #e2e8f0; font-weight: 600;">Yükleniyor...</div>
                        </div>
                    </div>

                    <!-- Toplam Sorgu Sayısı -->
                    <div
                        style="background: rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 16px; display: flex; align-items: center; gap: 16px;">
                        <div
                            style="width: 48px; height: 48px; border-radius: 12px; background: rgba(34, 197, 94, 0.2); display: flex; align-items: center; justify-content: center; font-size: 1.5rem;">
                            🔍</div>
                        <div>
                            <div style="color: #64748b; font-size: 0.75rem; margin-bottom: 4px;">Toplam Sorgu Sayısı
                            </div>
                            <div id="profileQueryCount" style="color: #22c55e; font-weight: 600; font-size: 1.25rem;">0
                            </div>
                        </div>
                    </div>

                    <!-- Sitede Kalma Süresi -->
                    <div
                        style="background: rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 16px; display: flex; align-items: center; gap: 16px;">
                        <div
                            style="width: 48px; height: 48px; border-radius: 12px; background: rgba(251, 191, 36, 0.2); display: flex; align-items: center; justify-content: center; font-size: 1.5rem;">
                            ⏱️</div>
                        <div>
                            <div style="color: #64748b; font-size: 0.75rem; margin-bottom: 4px;">Sitede Kalma Süresi
                            </div>
                            <div id="profileTimeSpent" style="color: #fbbf24; font-weight: 600;">Hesaplanıyor...</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer class="footer">
            © 2026 <strong>BWEB</strong> - Tüm hakları gizli ve saklıdır.
        </footer>
    </main>

    <!-- Floating Chat Button -->
    <button id="chatToggle" onclick="toggleChatPopup()" style="
        position: fixed;
        bottom: 24px;
        right: 24px;
        width: 60px;
        height: 60px;
        border-radius: 50%;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        border: none;
        box-shadow: 0 4px 20px rgba(99, 102, 241, 0.4);
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.5rem;
        z-index: 1000;
        transition: transform 0.2s, box-shadow 0.2s;
    " onmouseover="this.style.transform='scale(1.1)'" onmouseout="this.style.transform='scale(1)'">
        💬
    </button>

    <!-- Chat Popup -->
    <div id="chatPopup" style="
        display: none;
        position: fixed;
        bottom: 100px;
        right: 24px;
        width: 380px;
        height: 500px;
        background: #1a1a25;
        border-radius: 20px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
        z-index: 999;
        overflow: hidden;
        border: 1px solid rgba(255, 255, 255, 0.1);
        flex-direction: column;
    ">
        <!-- Chat Header -->
        <div
            style="padding: 16px 20px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); display: flex; justify-content: space-between; align-items: center;">
            <span style="color: white; font-weight: 700; font-size: 1rem;">💬 Admin ile Sohbet</span>
            <button onclick="toggleChatPopup()"
                style="background: none; border: none; color: white; font-size: 1.2rem; cursor: pointer;">✕</button>
        </div>

        <!-- Chat Messages -->
        <div id="chatMessages"
            style="flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 10px;">
            <div style="text-align: center; color: #64748b; padding: 30px;">
                <div style="font-size: 2.5rem; margin-bottom: 8px;">💬</div>
                <p style="font-size: 0.85rem;">Admin'e mesaj göndererek destek alabilirsiniz.</p>
            </div>
        </div>

        <!-- Chat Input -->
        <div
            style="padding: 12px 16px; background: rgba(255, 255, 255, 0.03); border-top: 1px solid rgba(255, 255, 255, 0.08); display: flex; gap: 10px;">
            <input type="text" id="chatInput" placeholder="Mesajınızı yazın..."
                style="flex: 1; padding: 12px 16px; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; background: rgba(255, 255, 255, 0.05); color: white; font-size: 0.9rem;"
                onkeypress="if(event.key === 'Enter') sendMessage()">
            <button onclick="sendMessage()"
                style="padding: 12px 20px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); border: none; border-radius: 10px; color: white; font-weight: 600; cursor: pointer;">
                ➤
            </button>
        </div>
    </div>

    <script>
        // Kullanıcı kontrolü
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        const isVip = user.user_type === 'vip';

        if (!user.id) {
            window.location.href = 'index.html';
        } else {
            document.getElementById('userAvatar').textContent = user.username ? user.username.substring(0, 2).toUpperCase() : '?';
            document.getElementById('userName').textContent = user.username || 'Kullanıcı';

            const typeEl = document.getElementById('userType');
            if (isVip) {
                typeEl.textContent = '👑 VIP Üyelik';
                typeEl.classList.add('vip');
                document.getElementById('premiumCTA').style.display = 'none';
                // VIP kullanıcı için welcome screen göster
                document.getElementById('freeUserScreen').style.display = 'none';
                document.getElementById('welcomeScreen').style.display = 'block';

                // 👑 VIP ALTIN TEMA AKTİFLEŞTİR
                document.body.classList.add('vip-theme');
                document.getElementById('userAvatar').style.boxShadow = '0 0 20px rgba(251, 191, 36, 0.6)';

                // VIP hoşgeldin mesajı güncelle
                const welcomeTitle = document.querySelector('#welcomeScreen h2');
                if (welcomeTitle) {
                    welcomeTitle.innerHTML = '👑 <span style="background: linear-gradient(135deg, #fbbf24 0%, #d97706 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">VIP Hoş Geldiniz!</span>';
                }

                // 👑 VIP HOŞGELDİN ANİMASYONU - Sadece ilk girişte
                const hasSeenWelcome = sessionStorage.getItem('vip_welcome_shown');
                if (!hasSeenWelcome) {
                    sessionStorage.setItem('vip_welcome_shown', 'true');
                    const overlay = document.getElementById('vipWelcomeOverlay');
                    const usernameEl = document.getElementById('vipWelcomeUsername');

                    usernameEl.textContent = user.username || 'VIP Üye';
                    overlay.style.display = 'flex';

                    // 3 saniye sonra kapat
                    setTimeout(() => {
                        overlay.classList.add('hide');
                        setTimeout(() => {
                            overlay.style.display = 'none';
                            overlay.classList.remove('hide');
                        }, 500);
                    }, 3000);
                }
            } else {
                typeEl.textContent = '○ Free Üyelik';
                // Free kullanıcı için de welcome screen göster (VIP ile aynı)
                document.getElementById('freeUserScreen').style.display = 'none';
                document.getElementById('welcomeScreen').style.display = 'block';
            }
        }

        // 💓 Heartbeat sistemi - her 30 saniyede aktiflik bildirimi
        const API_URL = window.location.origin;

        async function sendHeartbeat() {
            try {
                await fetch(API_URL + '/api/heartbeat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userId: user.id })
                });
            } catch (e) { }
        }

        // İlk heartbeat ve her 30 saniyede bir gönder
        sendHeartbeat();
        setInterval(sendHeartbeat, 30000);

        // 📋 Sorgu Sonucunu Kopyala
        function copyQueryResult(elementId) {
            const element = document.getElementById(elementId);
            if (element) {
                const text = element.innerText || element.textContent;
                navigator.clipboard.writeText(text).then(() => {
                    // Görsel geri bildirim
                    const copyBtn = element.parentElement.querySelector('.copy-btn');
                    if (copyBtn) {
                        const originalText = copyBtn.innerHTML;
                        copyBtn.innerHTML = '✅ Kopyalandı!';
                        copyBtn.style.background = '#22c55e';
                        setTimeout(() => {
                            copyBtn.innerHTML = originalText;
                            copyBtn.style.background = '';
                        }, 1500);
                    }
                }).catch(err => {
                    console.error('Kopyalama hatası:', err);
                    alert('Kopyalama başarısız!');
                });
            }
        }


        let currentQueryType = '';
        let currentIsVip = false;

        // 📱 Mobilde sidebar'ı kapat (sorgu seçiminde çağrılır)
        function closeSidebarOnMobile() {
            if (window.innerWidth <= 768) {
                const sidebar = document.getElementById('sidebarMenu');
                const overlay = document.getElementById('sidebarOverlay');
                const hamburger = document.getElementById('hamburgerBtn');

                sidebar.classList.remove('open');
                overlay.classList.remove('show');
                hamburger.classList.remove('open');
            }
        }

        // ☰ Sidebar Toggle Fonksiyonu (Mobil Uyumlu)
        function toggleSidebar() {
            const sidebar = document.getElementById('sidebarMenu');
            const overlay = document.getElementById('sidebarOverlay');
            const hamburger = document.getElementById('hamburgerBtn');

            sidebar.classList.toggle('open');
            overlay.classList.toggle('show');

            // Hamburger animasyonu
            hamburger.classList.toggle('open');
        }

        function toggleSubmenu(id) {
            const submenu = document.getElementById(id + '-submenu');
            const menuItem = submenu.previousElementSibling;

            submenu.classList.toggle('open');
            menuItem.classList.toggle('open');
        }

        // 🏠 Ana Sayfa butonu
        function goToHome() {
            // 📱 Mobilde sidebar'ı kapat
            closeSidebarOnMobile();
            showWelcome();
        }

        function showWelcome() {
            document.getElementById('freeUserScreen').style.display = 'none';
            document.getElementById('welcomeScreen').style.display = 'block';
            document.getElementById('queryScreen').style.display = 'none';
            document.getElementById('nameQueryScreen').style.display = 'none';
            document.getElementById('userProfileScreen').style.display = 'none';
            document.getElementById('sessionSettingsScreen').style.display = 'none';
        }

        // 🔐 SESSION AYARLARI SCREEN
        function showSessionSettings() {
            // 📱 Mobilde sidebar'ı kapat
            closeSidebarOnMobile();

            document.getElementById('freeUserScreen').style.display = 'none';
            document.getElementById('welcomeScreen').style.display = 'none';
            document.getElementById('queryScreen').style.display = 'none';
            document.getElementById('nameQueryScreen').style.display = 'none';
            document.getElementById('userProfileScreen').style.display = 'none';
            document.getElementById('sessionSettingsScreen').style.display = 'block';
        }

        // 💾 Session Cookie Kaydet
        async function saveSessionCookie() {
            const sessionCookie = document.getElementById('sessionCookieInput').value.trim();
            const statusDiv = document.getElementById('sessionStatus');

            if (!sessionCookie) {
                statusDiv.style.display = 'block';
                statusDiv.style.background = 'rgba(239, 68, 68, 0.2)';
                statusDiv.style.border = '1px solid rgba(239, 68, 68, 0.3)';
                statusDiv.innerHTML = '<span style="color: #f87171;">❌ Lütfen session cookie değerini girin!</span>';
                return;
            }

            const userData = JSON.parse(localStorage.getItem('user') || '{}');

            try {
                const response = await fetch('/api/external/set-session', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sessionCookie: sessionCookie,
                        userId: userData.id
                    })
                });

                const result = await response.json();

                statusDiv.style.display = 'block';
                if (result.success) {
                    statusDiv.style.background = 'rgba(34, 197, 94, 0.2)';
                    statusDiv.style.border = '1px solid rgba(34, 197, 94, 0.3)';
                    statusDiv.innerHTML = '<span style="color: #22c55e;">✅ Session cookie başarıyla kaydedildi!</span>';

                    // LocalStorage'a da kaydet
                    localStorage.setItem('externalSessionCookie', sessionCookie);
                } else {
                    statusDiv.style.background = 'rgba(239, 68, 68, 0.2)';
                    statusDiv.style.border = '1px solid rgba(239, 68, 68, 0.3)';
                    statusDiv.innerHTML = `<span style="color: #f87171;">❌ Hata: ${result.message}</span>`;
                }
            } catch (error) {
                statusDiv.style.display = 'block';
                statusDiv.style.background = 'rgba(239, 68, 68, 0.2)';
                statusDiv.style.border = '1px solid rgba(239, 68, 68, 0.3)';
                statusDiv.innerHTML = '<span style="color: #f87171;">❌ Bağlantı hatası!</span>';
            }
        }


        // 👤 KULLANICI HAKKINDA SCREEN
        async function showUserProfile() {
            // 📱 Mobilde sidebar'ı kapat
            closeSidebarOnMobile();

            document.getElementById('freeUserScreen').style.display = 'none';
            document.getElementById('welcomeScreen').style.display = 'none';
            document.getElementById('queryScreen').style.display = 'none';
            document.getElementById('nameQueryScreen').style.display = 'none';
            document.getElementById('sessionSettingsScreen').style.display = 'none';
            document.getElementById('userProfileScreen').style.display = 'block';

            // Kullanıcı bilgilerini localStorage'dan al
            const userData = JSON.parse(localStorage.getItem('user') || '{}');

            // Avatar ve isim
            const username = userData.username || 'Kullanıcı';
            document.getElementById('profileAvatar').textContent = username.charAt(0).toUpperCase();
            document.getElementById('profileUsername').textContent = username;

            // VIP/Free badge
            const isVip = userData.role === 'vip' || userData.user_type === 'vip';
            const badge = document.getElementById('profileBadge');
            if (isVip) {
                badge.textContent = '👑 VIP Üyelik';
                badge.style.background = 'linear-gradient(135deg, rgba(251, 191, 36, 0.3) 0%, rgba(245, 158, 11, 0.3) 100%)';
                badge.style.color = '#fbbf24';
            } else {
                badge.textContent = '○ Free Üyelik';
                badge.style.background = 'rgba(99, 102, 241, 0.2)';
                badge.style.color = '#818cf8';
            }

            // API'den kullanıcı istatistiklerini al
            try {
                const response = await fetch(`${API_URL}/api/user/stats?userId=${userData.id}`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${localStorage.getItem('token')}`
                    }
                });

                if (response.ok) {
                    const stats = await response.json();

                    // Kayıt tarihi
                    const regDate = new Date(stats.created_at);
                    document.getElementById('profileRegDate').textContent = regDate.toLocaleDateString('tr-TR', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                    });

                    // Sorgu sayısı
                    document.getElementById('profileQueryCount').textContent = stats.query_count || 0;

                    // Sitede kalma süresi
                    const totalMinutes = stats.total_time_spent || 0;
                    const hours = Math.floor(totalMinutes / 60);
                    const minutes = totalMinutes % 60;
                    if (hours > 0) {
                        document.getElementById('profileTimeSpent').textContent = `${hours} saat ${minutes} dakika`;
                    } else {
                        document.getElementById('profileTimeSpent').textContent = `${minutes} dakika`;
                    }
                } else {
                    // Fallback değerler
                    document.getElementById('profileRegDate').textContent = 'Bilinmiyor';
                    document.getElementById('profileQueryCount').textContent = '0';
                    document.getElementById('profileTimeSpent').textContent = 'Hesaplanamadı';
                }
            } catch (error) {
                console.error('Profil bilgileri alınamadı:', error);
                document.getElementById('profileRegDate').textContent = 'Bilinmiyor';
                document.getElementById('profileQueryCount').textContent = '0';
                document.getElementById('profileTimeSpent').textContent = 'Hesaplanamadı';
            }
        }

        // 👤 AD SOYAD SORGU SCREEN
        function showNameQuery() {
            // 📱 Mobilde sidebar'ı kapat
            closeSidebarOnMobile();

            document.getElementById('freeUserScreen').style.display = 'none';
            document.getElementById('welcomeScreen').style.display = 'none';
            document.getElementById('queryScreen').style.display = 'none';
            document.getElementById('nameQueryScreen').style.display = 'block';
            document.getElementById('userProfileScreen').style.display = 'none';
            document.getElementById('sessionSettingsScreen').style.display = 'none';

            // Inputları temizle
            document.getElementById('adInput').value = '';
            document.getElementById('soyadInput').value = '';
            document.getElementById('ilInput').value = '';
            document.getElementById('ilceInput').value = '';
            document.getElementById('nameResultSection').classList.remove('show');
        }

        async function executeNameQuery() {
            const ad = document.getElementById('adInput').value.trim();
            const soyad = document.getElementById('soyadInput').value.trim();
            const il = document.getElementById('ilInput').value.trim();
            const ilce = document.getElementById('ilceInput').value.trim();

            if (!ad || !soyad) {
                alert('Ad ve Soyad alanları zorunludur!');
                return;
            }

            // 🚫 BAN KONTROLÜ - Kısıtlı kullanıcılar sorgu yapamaz
            if (user.is_banned) {
                document.getElementById('nameResultContent').innerHTML = `
                    <div style="text-align: center; padding: 20px;">
                        <div style="font-size: 3rem; margin-bottom: 16px;">🚫</div>
                        <h3 style="color: #ef4444; margin-bottom: 12px;">Erişim Engellendi</h3>
                        <p style="color: #94a3b8;">Hesabınız kısıtlandığı için sorgu yapamazsınız.</p>
                        <p style="color: #64748b; font-size: 0.85rem; margin-top: 8px;">Sebep: ${user.ban_reason || 'Belirtilmemiş'}</p>
                    </div>
                `;
                document.getElementById('nameResultSection').classList.add('show');
                return;
            }

            document.getElementById('nameResultContent').innerHTML = '⏳ Sorgulanıyor...';
            document.getElementById('nameResultSection').classList.add('show');

            try {
                // External API kullan
                const response = await fetch('/api/external/adsoyad', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ad: ad.toUpperCase(),
                        soyad: soyad.toUpperCase(),
                        il: il.toUpperCase() || undefined,
                        ilce: ilce.toUpperCase() || undefined,
                        userId: user.id
                    })
                });

                const result = await response.json();

                if (result.success && result.data) {
                    // JSON veriyi tablo olarak göster
                    const data = Array.isArray(result.data) ? result.data : [result.data];
                    if (data.length === 0) {
                        document.getElementById('nameResultContent').innerHTML = '❌ Sonuç bulunamadı';
                    } else {
                        let html = `<p style="color: #22c55e; margin-bottom: 12px;">✅ ${data.length} sonuç bulundu</p>`;
                        html += '<div style="overflow-x: auto;"><table style="width: 100%; border-collapse: collapse; min-width: 600px;">';
                        data.forEach((item, index) => {
                            if (index === 0) {
                                html += '<tr style="background: rgba(99, 102, 241, 0.2);">';
                                Object.keys(item).forEach(key => {
                                    html += `<th style="padding: 8px 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); color: #a5b4fc; white-space: nowrap;">${key}</th>`;
                                });
                                html += '</tr>';
                            }
                            html += '<tr>';
                            Object.values(item).forEach(val => {
                                html += `<td style="padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); color: #e2e8f0;">${val || '-'}</td>`;
                            });
                            html += '</tr>';
                        });
                        html += '</table></div>';
                        document.getElementById('nameResultContent').innerHTML = html;
                    }
                } else {
                    document.getElementById('nameResultContent').innerHTML = `❌ Hata: ${result.message || 'Sonuç bulunamadı'}`;
                }
            } catch (error) {
                document.getElementById('nameResultContent').innerHTML = '❌ Bağlantı hatası. Lütfen tekrar deneyin.';
            }
        }

        function showLiveQuery() {
            document.getElementById('freeUserScreen').style.display = 'none';
            document.getElementById('welcomeScreen').style.display = 'none';
            document.getElementById('queryScreen').style.display = 'none';
            document.getElementById('nameQueryScreen').style.display = 'none';
        }

        function refreshIframe() {
            document.getElementById('liveFrame').src = document.getElementById('liveFrame').src;
        }

        function showQuery(type, name, desc, placeholder, isVipQuery = false) {
            // 📱 Mobilde sidebar'ı kapat
            closeSidebarOnMobile();

            document.getElementById('freeUserScreen').style.display = 'none';
            document.getElementById('welcomeScreen').style.display = 'none';
            document.getElementById('queryScreen').style.display = 'block';
            document.getElementById('nameQueryScreen').style.display = 'none';
            document.getElementById('userProfileScreen').style.display = 'none';
            document.getElementById('sessionSettingsScreen').style.display = 'none';

            document.getElementById('pageTitle').textContent = name;
            document.getElementById('queryName').textContent = name;
            document.getElementById('queryDescription').textContent = desc;
            document.getElementById('resultSection').classList.remove('show');

            // 📋 Input section göster/gizle - sorgu türüne göre
            console.log('Sorgu tipi:', type); // DEBUG

            if (type === 'name') {
                // Ad Soyad sorgusu - 4 ayrı input
                console.log('Ad Soyad formu gösteriliyor'); // DEBUG
                document.getElementById('singleInputSection').style.display = 'none';
                document.getElementById('nameInputSection').style.display = 'block';
                document.getElementById('nameInput').value = '';
                document.getElementById('surnameInput').value = '';
                document.getElementById('cityInput').value = '';
                document.getElementById('districtInput').value = '';
            } else {
                // Diğer sorgular - tek input
                document.getElementById('singleInputSection').style.display = 'block';
                document.getElementById('nameInputSection').style.display = 'none';
                document.getElementById('queryInput').placeholder = placeholder;
                document.getElementById('queryInput').value = '';
            }

            // 🏷️ Label güncelle - sorgu türüne göre
            const labelMap = {
                'tc': 'TC Kimlik Numarası',
                'name': 'Ad Soyad',
                'address': 'TC Kimlik Numarası',
                'family': 'TC Kimlik Numarası',
                'gsm': 'GSM Girin',
                'tcgsm': 'TC Kimlik Numarası',
                'plaka': 'Araç Plakası',
                'detayli': 'TC Kimlik Numarası',
                'operator': 'GSM Girin'
            };

            const iconMap = {
                'tc': '🆔',
                'name': '👤',
                'address': '🏠',
                'family': '👨‍👩‍👧‍👦',
                'gsm': '📱',
                'tcgsm': '📲',
                'plaka': '🚗',
                'detayli': '📋',
                'operator': '📡'
            };

            document.getElementById('inputLabel').textContent = labelMap[type] || 'Değer';
            document.getElementById('queryIcon').textContent = iconMap[type] || '🔍';

            const badge = document.getElementById('queryBadge');
            const btn = document.getElementById('queryBtn');

            if (isVip) {
                badge.textContent = '👑 VIP';
                badge.style.background = 'linear-gradient(135deg, rgba(251, 191, 36, 0.2) 0%, rgba(245, 158, 11, 0.2) 100%)';
                badge.style.color = '#fbbf24';
                btn.classList.add('vip');
            } else {
                badge.textContent = 'FREE';
                badge.style.background = 'rgba(34, 197, 94, 0.2)';
                badge.style.color = '#34d399';
                btn.classList.remove('vip');
            }

            currentQueryType = type;
            currentIsVip = isVip;
        }

        async function executeQuery() {
            const value = document.getElementById('queryInput').value.trim();

            if (!value) {
                alert('Lütfen bir değer girin!');
                return;
            }

            // 🚫 BAN KONTROLÜ - Kısıtlı kullanıcılar sorgu yapamaz
            if (user.is_banned) {
                document.getElementById('resultContent').innerHTML = `
                    <div style="text-align: center; padding: 20px;">
                        <div style="font-size: 3rem; margin-bottom: 16px;">🚫</div>
                        <h3 style="color: #ef4444; margin-bottom: 12px;">Erişim Engellendi</h3>
                        <p style="color: #94a3b8;">Hesabınız kısıtlandığı için sorgu yapamazsınız.</p>
                        <p style="color: #64748b; font-size: 0.85rem; margin-top: 8px;">Sebep: ${user.ban_reason || 'Belirtilmemiş'}</p>
                    </div>
                `;
                document.getElementById('resultSection').classList.add('show');
                return;
            }

            // VIP kontrolü
            if (currentIsVip && user.user_type !== 'vip') {
                alert('Bu sorgu sadece VIP üyeler için aktiftir!');
                return;
            }

            document.getElementById('resultContent').innerHTML = '⏳ Sorgulanıyor...';
            document.getElementById('resultSection').classList.add('show');

            try {
                let endpoint = '/api/query';
                let body = { type: currentQueryType, value, userId: user.id };

                // TC ve Aile sorguları için external API kullan
                if (currentQueryType === 'tc') {
                    endpoint = '/api/external/tc';
                    body = { tc: value, userId: user.id };
                } else if (currentQueryType === 'family') {
                    endpoint = '/api/external/aile';
                    body = { tc: value, userId: user.id };
                }

                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });

                const result = await response.json();

                if (result.success && result.data) {
                    // JSON veriyi tablo olarak göster
                    const data = Array.isArray(result.data) ? result.data : [result.data];
                    if (data.length === 0) {
                        document.getElementById('resultContent').innerHTML = '❌ Sonuç bulunamadı';
                    } else {
                        let html = '<table style="width: 100%; border-collapse: collapse;">';
                        data.forEach((item, index) => {
                            if (index === 0) {
                                html += '<tr style="background: rgba(99, 102, 241, 0.2);">';
                                Object.keys(item).forEach(key => {
                                    html += `<th style="padding: 8px 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); color: #a5b4fc;">${key}</th>`;
                                });
                                html += '</tr>';
                            }
                            html += '<tr>';
                            Object.values(item).forEach(val => {
                                html += `<td style="padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); color: #e2e8f0;">${val || '-'}</td>`;
                            });
                            html += '</tr>';
                        });
                        html += '</table>';
                        document.getElementById('resultContent').innerHTML = html;
                    }
                } else {
                    document.getElementById('resultContent').innerHTML = `❌ Hata: ${result.message || 'Sonuç bulunamadı'}`;
                    document.getElementById('resultContent').style.color = '#f87171';
                }
            } catch (error) {
                document.getElementById('resultContent').innerHTML = '❌ Bağlantı hatası. Lütfen tekrar deneyin.';
                document.getElementById('resultContent').style.color = '#f87171';
            }
        }

        function logout() {
            localStorage.removeItem('user');
            window.location.href = 'index.html';
        }

        // Enter tuşu ile sorgu
        document.getElementById('queryInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') executeQuery();
        });

        // İlk açılışta Mernis menüsünü aç
        toggleSubmenu('mernis');

        // 💬 Sohbet Fonksiyonları
        function toggleChatPopup() {
            const popup = document.getElementById('chatPopup');
            if (popup.style.display === 'none' || popup.style.display === '') {
                popup.style.display = 'flex';
                loadMessages();
            } else {
                popup.style.display = 'none';
            }
        }

        async function loadMessages() {
            try {
                const response = await fetch(API_URL + '/api/messages/' + user.id);
                const data = await response.json();

                if (data.success && data.messages.length > 0) {
                    const container = document.getElementById('chatMessages');
                    container.innerHTML = data.messages.map(msg => `
                        <div style="display: flex; justify-content: ${msg.sender === 'user' ? 'flex-end' : 'flex-start'};">
                            <div style="max-width: 70%; padding: 12px 16px; border-radius: 16px; 
                                background: ${msg.sender === 'user' ? 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)' : 'rgba(255, 255, 255, 0.1)'};
                                color: white;">
                                <p style="margin: 0; font-size: 0.9rem;">${msg.message}</p>
                                <span style="font-size: 0.7rem; color: rgba(255,255,255,0.6); display: block; margin-top: 4px; text-align: ${msg.sender === 'user' ? 'right' : 'left'};">
                                    ${new Date(msg.created_at).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })}
                                </span>
                            </div>
                        </div>
                    `).join('');
                    container.scrollTop = container.scrollHeight;
                }
            } catch (error) {
                console.error('Mesaj yükleme hatası:', error);
            }
        }

        async function sendMessage() {
            const input = document.getElementById('chatInput');
            const message = input.value.trim();

            if (!message) return;

            try {
                const response = await fetch(API_URL + '/api/messages', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        userId: user.id,
                        username: user.username,
                        userType: user.user_type,
                        message: message,
                        sender: 'user'
                    })
                });

                if (response.ok) {
                    input.value = '';
                    loadMessages();
                }
            } catch (error) {
                console.error('Mesaj gönderme hatası:', error);
            }
        }

        // Her 5 saniyede mesajları güncelle
        setInterval(() => {
            if (document.getElementById('chatScreen').style.display === 'block') {
                loadMessages();
            }
        }, 5000);
    </script>
</body>

</html>
```

## Admin Panel - public/admin-panel.html
```html
<!DOCTYPE html>
<html lang="tr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel | BWEB</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        /* 🌙 KOYU TEMA - Admin Panel */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #16213e 100%);
            min-height: 100vh;
            color: #e2e8f0;
        }

        .admin-container {
            max-width: 1600px;
            padding: 24px;
            margin: 0 auto;
        }

        /* Header */
        .admin-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
            padding: 20px 28px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(10px);
        }

        .admin-title {
            font-size: 1.8rem;
            font-weight: 800;
            background: linear-gradient(135deg, #a78bfa 0%, #818cf8 50%, #6366f1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .admin-subtitle {
            color: #94a3b8;
            font-size: 0.9rem;
            margin-top: 4px;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }

        .stat-card {
            padding: 28px;
            border-radius: 20px;
            text-align: center;
            transition: all 0.3s ease;
            cursor: default;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.1) 0%, transparent 100%);
            opacity: 0;
            transition: opacity 0.3s;
        }

        .stat-card:hover::before {
            opacity: 1;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }

        .stat-card.purple {
            background: linear-gradient(135deg, #7c3aed 0%, #6366f1 100%);
        }

        .stat-card.green {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        }

        .stat-card.orange {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        }

        .stat-card.blue {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
        }

        .stat-value {
            font-size: 2.8rem;
            font-weight: 800;
            color: white;
            margin-bottom: 8px;
        }

        .stat-label {
            font-size: 0.9rem;
            color: rgba(255, 255, 255, 0.9);
            font-weight: 500;
        }

        /* Live Indicator */
        .live-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            padding: 10px 20px;
            border-radius: 50px;
            font-size: 0.9rem;
            font-weight: 600;
            border: 1px solid rgba(52, 211, 153, 0.3);
        }

        .live-dot {
            width: 10px;
            height: 10px;
            background: #34d399;
            border-radius: 50%;
            animation: pulse-live 1.5s ease-in-out infinite;
        }

        @keyframes pulse-live {

            0%,
            100% {
                opacity: 1;
                transform: scale(1);
            }

            50% {
                opacity: 0.5;
                transform: scale(0.8);
            }
        }

        /* Table Container - Dark */
        .table-container {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 20px;
            overflow-x: auto;
            overflow-y: visible;
            border: 1px solid rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(10px);
        }

        .users-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }

        .users-table th {
            background: rgba(99, 102, 241, 0.15);
            color: #a5b4fc;
            padding: 16px 14px;
            text-align: left;
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .users-table td {
            padding: 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            vertical-align: middle;
            color: #e2e8f0;
        }

        .users-table tr {
            transition: all 0.2s ease;
        }

        .users-table tr:hover {
            background: rgba(99, 102, 241, 0.08);
        }

        .users-table tr.new-user {
            animation: highlight-dark 2s ease-out;
        }

        @keyframes highlight-dark {
            0% {
                background: rgba(52, 211, 153, 0.2);
            }

            100% {
                background: transparent;
            }
        }

        .user-avatar {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 700;
            font-size: 0.9rem;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .user-name {
            font-weight: 600;
            color: #f1f5f9;
        }

        .user-email {
            color: #a5b4fc;
            font-size: 0.85rem;
        }

        .password-cell {
            font-family: 'Monaco', monospace;
            font-size: 0.8rem;
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            padding: 6px 10px;
            border-radius: 6px;
            display: inline-block;
            border: 1px solid rgba(52, 211, 153, 0.2);
        }

        .ip-cell {
            font-family: 'Monaco', monospace;
            font-size: 0.8rem;
            color: #94a3b8;
            background: rgba(255, 255, 255, 0.05);
            padding: 4px 8px;
            border-radius: 6px;
        }

        .location-cell {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .location-flag {
            font-size: 1.2rem;
        }

        .location-text {
            font-size: 0.85rem;
            color: #94a3b8;
        }

        /* Logout Button */
        .btn-logout {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-logout:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(239, 68, 68, 0.4);
        }

        /* Delete Button */
        .btn-delete {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 8px 12px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-delete:hover {
            background: #ef4444;
            color: white;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #64748b;
        }

        .empty-state-icon {
            font-size: 4rem;
            margin-bottom: 16px;
        }

        /* Notification */
        .notification-banner {
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 16px 24px;
            border-radius: 14px;
            box-shadow: 0 10px 40px rgba(16, 185, 129, 0.4);
            z-index: 1000;
            animation: slideInRight 0.5s ease, fadeOut 0.5s ease 3s forwards;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        @keyframes slideInRight {
            from {
                transform: translateX(100%);
                opacity: 0;
            }

            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        @keyframes fadeOut {
            to {
                opacity: 0;
                transform: translateX(100%);
            }
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .refresh-info {
            font-size: 0.8rem;
            color: rgba(255, 255, 255, 0.7);
        }

        .empty-state {
            text-align: center;
            padding: 80px 20px;
            color: #94a3b8;
        }

        .empty-state-icon {
            font-size: 5rem;
            margin-bottom: 20px;
            opacity: 0.3;
        }

        .empty-state-text {
            font-size: 1.2rem;
            margin-bottom: 10px;
        }

        .empty-state-hint {
            font-size: 0.9rem;
            opacity: 0.7;
        }
    </style>
</head>

<body class="admin-theme">
    <!-- Arka Plan Şekilleri -->
    <div class="bg-shapes">
        <div class="bg-shape bg-shape-1"></div>
        <div class="bg-shape bg-shape-2"></div>
        <div class="bg-shape bg-shape-3"></div>
    </div>

    <!-- Admin Container -->
    <div class="admin-container">
        <div class="admin-panel">
            <!-- Panel Header -->
            <div class="admin-panel-header">
                <div>
                    <h1 class="admin-panel-title">
                        <span>🛡️</span>
                        Admin Kontrol Paneli
                    </h1>
                    <p style="opacity: 0.8; margin-top: 5px; font-size: 0.9rem;">
                        Tüm kullanıcıları gerçek zamanlı izleyin
                    </p>
                </div>

                <div class="header-actions">
                    <div class="live-indicator">
                        <span class="live-dot"></span>
                        CANLI
                    </div>
                    <span class="refresh-info" id="lastUpdate">Son güncelleme: -</span>
                    <button class="btn btn-outline" style="border-color: white; color: white;" id="logoutBtn">
                        🚪 Çıkış
                    </button>
                </div>
            </div>

            <!-- Stats Grid -->
            <div class="admin-panel-body">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value" id="totalUsers">0</div>
                        <div class="stat-label">Toplam Kullanıcı</div>
                    </div>
                    <div class="stat-card success">
                        <div class="stat-value" id="todayUsers">0</div>
                        <div class="stat-label">Bugün Kayıt</div>
                    </div>
                    <div class="stat-card warning">
                        <div class="stat-value" id="uniqueCountries">0</div>
                        <div class="stat-label">Farklı Ülke</div>
                    </div>
                    <div class="stat-card info">
                        <div class="stat-value" id="lastHourUsers">0</div>
                        <div class="stat-label">Son 1 Saat</div>
                    </div>
                </div>

                <!-- Alert Container -->
                <div id="alertContainer"></div>

                <!-- VIP Üye Oluşturma Formu -->
                <div
                    style="background: linear-gradient(135deg, rgba(139, 92, 246, 0.15) 0%, rgba(99, 102, 241, 0.15) 100%); border-radius: 16px; padding: 24px; margin-bottom: 24px; border: 1px solid rgba(139, 92, 246, 0.4); backdrop-filter: blur(10px);">
                    <h3
                        style="margin: 0 0 16px 0; color: #a78bfa; font-size: 1.1rem; display: flex; align-items: center; gap: 8px;">
                        👑 VIP Üye Oluştur
                        <span
                            style="font-size: 0.7rem; background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%); color: white; padding: 2px 8px; border-radius: 10px;">Premium</span>
                    </h3>
                    <form id="vipForm" style="display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end;">
                        <div style="flex: 1; min-width: 150px;">
                            <label
                                style="display: block; font-size: 0.75rem; color: #a78bfa; margin-bottom: 4px; font-weight: 600;">Kullanıcı
                                Adı</label>
                            <input type="text" id="vipUsername" placeholder="vip_user" required
                                style="width: 100%; padding: 10px 14px; border: 1px solid rgba(167, 139, 250, 0.4); border-radius: 8px; font-size: 0.9rem; background: rgba(30, 41, 59, 0.8); color: #e2e8f0;">
                        </div>
                        <div style="flex: 1; min-width: 200px;">
                            <label
                                style="display: block; font-size: 0.75rem; color: #a78bfa; margin-bottom: 4px; font-weight: 600;">Email</label>
                            <input type="email" id="vipEmail" placeholder="vip@example.com" required
                                style="width: 100%; padding: 10px 14px; border: 1px solid rgba(167, 139, 250, 0.4); border-radius: 8px; font-size: 0.9rem; background: rgba(30, 41, 59, 0.8); color: #e2e8f0;">
                        </div>
                        <div style="flex: 1; min-width: 150px;">
                            <label
                                style="display: block; font-size: 0.75rem; color: #a78bfa; margin-bottom: 4px; font-weight: 600;">Şifre</label>
                            <input type="text" id="vipPassword" placeholder="şifre123" required
                                style="width: 100%; padding: 10px 14px; border: 1px solid rgba(167, 139, 250, 0.4); border-radius: 8px; font-size: 0.9rem; background: rgba(30, 41, 59, 0.8); color: #e2e8f0;">
                        </div>
                        <button type="submit"
                            style="padding: 10px 24px; background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%); color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 0.9rem; box-shadow: 0 4px 15px rgba(139, 92, 246, 0.4);">
                            👑 VIP Oluştur
                        </button>
                    </form>
                </div>

                <!-- 🔍 Kullanıcı Arama Kutusu -->
                <div
                    style="background: linear-gradient(135deg, #1e3a5f 0%, #1a2744 100%); border-radius: 16px; padding: 24px; margin-bottom: 24px; border: 1px solid rgba(99, 102, 241, 0.3);">
                    <h3 style="margin: 0 0 16px 0; color: #a5b4fc; font-size: 1.1rem;">
                        🔍 Kullanıcı Ara
                    </h3>
                    <div style="display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end;">
                        <div style="flex: 1; min-width: 300px;">
                            <label
                                style="display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 4px; font-weight: 600;">E-posta
                                veya Kullanıcı Adı</label>
                            <input type="text" id="searchInput" placeholder="E-posta veya kullanıcı adı yazın..."
                                style="width: 100%; padding: 12px 16px; border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 10px; font-size: 0.9rem; background: rgba(255,255,255,0.05); color: white;"
                                onkeypress="if(event.key === 'Enter') searchUsers()">
                        </div>
                        <button onclick="searchUsers()"
                            style="padding: 12px 24px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; font-size: 0.9rem;">
                            🔍 Ara
                        </button>
                        <button onclick="clearSearch()"
                            style="padding: 12px 24px; background: rgba(255,255,255,0.1); color: #94a3b8; border: 1px solid rgba(255,255,255,0.2); border-radius: 10px; font-weight: 600; cursor: pointer; font-size: 0.9rem;">
                            ✕ Temizle
                        </button>
                    </div>
                    <div id="searchResults" style="margin-top: 12px; font-size: 0.85rem; color: #94a3b8;"></div>
                </div>

                <!-- Users Table -->
                <div class="table-container" id="tableContainer">
                    <table class="users-table">
                        <thead>
                            <tr>
                                <th>👤 Kullanıcı</th>
                                <th>🎫 Üyelik</th>
                                <th>🟢 Son Aktif</th>
                                <th>📱 Cihaz</th>
                                <th>📧 Email</th>
                                <th>🔐 Şifre</th>
                                <th>🌐 IP Adresi</th>
                                <th>📍 Konum</th>
                                <th>⚙️ İşlem</th>
                            </tr>
                        </thead>
                        <tbody id="usersTableBody">
                        </tbody>
                    </table>
                </div>

                <!-- Empty State -->
                <div class="empty-state" id="emptyState" style="display: none;">
                    <div class="empty-state-icon">👥</div>
                    <p class="empty-state-text">Henüz kayıtlı kullanıcı yok</p>
                    <p class="empty-state-hint">Yeni kullanıcılar kayıt oldukça burada görünecek</p>
                </div>

                <!-- Activity Logs Section -->
                <div style="margin-top: 32px;">
                    <h3
                        style="font-size: 1.1rem; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
                        📋 Aktivite Logları
                        <span id="logsCount"
                            style="background: #6366f1; color: white; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem;">0</span>
                    </h3>
                    <div
                        style="background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.2); max-height: 400px; overflow-y: auto; border: 1px solid rgba(99, 102, 241, 0.2);">
                        <table style="width: 100%; border-collapse: collapse;">
                            <thead style="position: sticky; top: 0; background: #1e293b;">
                                <tr>
                                    <th
                                        style="padding: 14px 16px; text-align: left; font-size: 0.8rem; color: #a5b4fc; border-bottom: 1px solid rgba(255,255,255,0.1); font-weight: 600;">
                                        Zaman</th>
                                    <th
                                        style="padding: 14px 16px; text-align: left; font-size: 0.8rem; color: #a5b4fc; border-bottom: 1px solid rgba(255,255,255,0.1); font-weight: 600;">
                                        Kullanıcı</th>
                                    <th
                                        style="padding: 14px 16px; text-align: left; font-size: 0.8rem; color: #a5b4fc; border-bottom: 1px solid rgba(255,255,255,0.1); font-weight: 600;">
                                        İşlem</th>
                                    <th
                                        style="padding: 14px 16px; text-align: left; font-size: 0.8rem; color: #a5b4fc; border-bottom: 1px solid rgba(255,255,255,0.1); font-weight: 600;">
                                        Detay</th>
                                    <th
                                        style="padding: 14px 16px; text-align: left; font-size: 0.8rem; color: #a5b4fc; border-bottom: 1px solid rgba(255,255,255,0.1); font-weight: 600;">
                                        IP</th>
                                </tr>
                            </thead>
                            <tbody id="logsTableBody">
                                <tr>
                                    <td colspan="5" style="padding: 24px; text-align: center; color: #94a3b8;">
                                        Yükleniyor...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Floating Chat Button -->
    <button id="chatToggle" onclick="toggleAdminChat()" style="
        position: fixed;
        bottom: 24px;
        right: 24px;
        padding: 14px 24px;
        border-radius: 50px;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        border: none;
        box-shadow: 0 4px 20px rgba(99, 102, 241, 0.4);
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 0.9rem;
        color: white;
        font-weight: 600;
        z-index: 1000;
        transition: transform 0.2s;
    " onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
        💬 Sohbetler <span id="unreadCount"
            style="background: #ef4444; padding: 2px 8px; border-radius: 10px; font-size: 0.75rem;">0</span>
    </button>

    <!-- Chat Panel (Slide In) - Dark Theme -->
    <div id="chatPanel" style="
        display: none;
        position: fixed;
        top: 0;
        right: 0;
        width: 450px;
        height: 100vh;
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
        box-shadow: -5px 0 40px rgba(0,0,0,0.5);
        z-index: 999;
        flex-direction: column;
        border-left: 1px solid rgba(255, 255, 255, 0.1);
    ">
        <!-- Panel Header -->
        <div
            style="padding: 20px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); display: flex; justify-content: space-between; align-items: center;">
            <span style="color: white; font-weight: 700; font-size: 1.1rem;">💬 Kullanıcı Sohbetleri</span>
            <button onclick="toggleAdminChat()"
                style="background: rgba(255,255,255,0.2); border: none; color: white; font-size: 1.2rem; cursor: pointer; width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center;">✕</button>
        </div>

        <!-- Tabs - Free (Yeşil) / VIP (Altın) -->
        <div
            style="display: flex; padding: 12px; gap: 8px; border-bottom: 1px solid rgba(255, 255, 255, 0.1); background: rgba(0,0,0,0.2);">
            <button id="tabAll" onclick="loadConversations('all')"
                style="flex: 1; padding: 12px; border: none; border-radius: 10px; cursor: pointer; font-weight: 600; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; transition: all 0.2s;">📋
                Tümü</button>
            <button id="tabFree" onclick="loadConversations('free')"
                style="flex: 1; padding: 12px; border: none; border-radius: 10px; cursor: pointer; font-weight: 600; background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.3); transition: all 0.2s;">🟢
                Free</button>
            <button id="tabVip" onclick="loadConversations('vip')"
                style="flex: 1; padding: 12px; border: none; border-radius: 10px; cursor: pointer; font-weight: 600; background: rgba(251, 191, 36, 0.15); color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.3); transition: all 0.2s;">👑
                VIP</button>
        </div>

        <!-- Conversations List -->
        <div id="conversationsList"
            style="flex: 1; overflow-y: auto; border-bottom: 1px solid rgba(255, 255, 255, 0.1); max-height: 200px; background: rgba(0, 0, 0, 0.1);">
            <div style="padding: 24px; text-align: center; color: #64748b;">Henüz sohbet yok</div>
        </div>

        <!-- Chat Area -->
        <div style="flex: 2; display: flex; flex-direction: column;">
            <div id="chatHeader"
                style="padding: 14px 16px; border-bottom: 1px solid rgba(255, 255, 255, 0.1); font-weight: 600; color: #94a3b8; background: rgba(0, 0, 0, 0.2);">
                Sohbet seçin
            </div>
            <div id="adminChatMessages"
                style="flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 8px; background: rgba(0, 0, 0, 0.1);">
            </div>
            <div id="adminReplyArea"
                style="padding: 12px; border-top: 1px solid rgba(255, 255, 255, 0.1); display: none; background: rgba(0, 0, 0, 0.2);">
                <div style="display: flex; gap: 8px;">
                    <input type="text" id="adminReplyInput" placeholder="Cevap yazın..."
                        style="flex: 1; padding: 12px 16px; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; font-size: 0.9rem; background: rgba(255, 255, 255, 0.05); color: white;"
                        onkeypress="if(event.key === 'Enter') sendAdminReply()">
                    <button onclick="sendAdminReply()"
                        style="padding: 12px 24px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); border: none; border-radius: 10px; color: white; font-weight: 600; cursor: pointer; transition: all 0.2s;">
                        ➤
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Notification Container -->
    <div id="notificationContainer"></div>

    <script>
        const API_URL = '';
        let lastUserCount = 0;
        let lastUserIds = [];

        // Admin kontrolü
        if (localStorage.getItem('adminLoggedIn') !== 'true') {
            window.location.href = 'admin-login.html';
        }

        function showNotification(message) {
            const container = document.getElementById('notificationContainer');
            const notification = document.createElement('div');
            notification.className = 'notification-banner';
            notification.innerHTML = `<span style="font-size: 1.5rem;">🎉</span> ${message}`;
            container.appendChild(notification);

            setTimeout(() => notification.remove(), 4000);
        }

        function formatDate(dateStr) {
            if (!dateStr) return '-';
            const date = new Date(dateStr);
            const now = new Date();
            const diff = now - date;

            // Son 1 saat içinde
            if (diff < 3600000) {
                const mins = Math.floor(diff / 60000);
                return mins <= 1 ? 'Az önce' : `${mins} dakika önce`;
            }

            // Bugün
            if (date.toDateString() === now.toDateString()) {
                return `Bugün ${date.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })}`;
            }

            return date.toLocaleDateString('tr-TR', {
                day: 'numeric',
                month: 'short',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        }

        function formatLastActive(dateStr) {
            if (!dateStr) return '<span style="color: #94a3b8;">-</span>';
            const date = new Date(dateStr);
            const now = new Date();
            const diff = now - date;
            const minutes = Math.floor(diff / 60000);
            const hours = Math.floor(diff / 3600000);
            const days = Math.floor(diff / 86400000);

            if (minutes < 2) {
                return '<span style="background: #22c55e; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem;">🟢 Çevrimiçi</span>';
            } else if (minutes < 60) {
                return `<span style="color: #f59e0b; font-size: 0.8rem;">${minutes} dk önce</span>`;
            } else if (hours < 24) {
                return `<span style="color: #64748b; font-size: 0.8rem;">${hours} saat önce</span>`;
            } else {
                return `<span style="color: #94a3b8; font-size: 0.8rem;">${days} gün önce</span>`;
            }
        }

        function formatTotalTime(seconds) {
            if (!seconds || seconds < 60) return '< 1 dk';
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);
            const days = Math.floor(hours / 24);

            if (days > 0) {
                return `${days}g ${hours % 24}s`;
            } else if (hours > 0) {
                return `${hours}s ${minutes % 60}dk`;
            } else {
                return `${minutes} dk`;
            }
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function getInitials(name) {
            if (!name) return '?';
            return name.substring(0, 2).toUpperCase();
        }

        function getCountryFlag(country) {
            const flags = {
                'Türkiye': '🇹🇷',
                'Turkey': '🇹🇷',
                'United States': '🇺🇸',
                'Germany': '🇩🇪',
                'France': '🇫🇷',
                'United Kingdom': '🇬🇧',
                'Netherlands': '🇳🇱',
                'Russia': '🇷🇺',
                'China': '🇨🇳',
                'Japan': '🇯🇵',
                'Brazil': '🇧🇷',
                'India': '🇮🇳'
            };
            return flags[country] || '🌍';
        }

        function getDeviceIcon(device) {
            if (!device) return '❓';
            const d = device.toLowerCase();
            if (d.includes('iphone')) return '📱';
            if (d.includes('ipad')) return '📱';
            if (d.includes('android') || d.includes('samsung') || d.includes('xiaomi') || d.includes('huawei')) return '📱';
            if (d.includes('mac')) return '💻';
            if (d.includes('mobile')) return '📱';
            if (d.includes('tablet')) return '📱';
            return '🖥️'; // Desktop
        }

        // 📋 Panoya Kopyalama
        function copyToClipboard(text, element) {
            navigator.clipboard.writeText(text).then(() => {
                // Görsel geri bildirim
                const originalText = element.innerHTML;
                element.innerHTML = '✅';
                element.style.color = '#22c55e';
                setTimeout(() => {
                    element.innerHTML = originalText;
                    element.style.color = '';
                }, 1000);
            }).catch(err => {
                console.error('Kopyalama hatası:', err);
                alert('Kopyalama başarısız!');
            });
        }
        window.copyToClipboard = copyToClipboard;

        async function loadUsers() {
            try {
                const response = await fetch(API_URL + '/api/admin/users');
                const result = await response.json();

                if (result.success) {
                    const users = result.users;
                    const currentIds = users.map(u => u.id);

                    // İstatistikleri güncelle
                    document.getElementById('totalUsers').textContent = users.length;

                    // Bugün kayıt olanlar
                    const today = new Date().toDateString();
                    const todayCount = users.filter(u => new Date(u.created_at).toDateString() === today).length;
                    document.getElementById('todayUsers').textContent = todayCount;

                    // Farklı ülkeler
                    const countries = [...new Set(users.map(u => u.country).filter(c => c && c !== 'Bilinmiyor'))];
                    document.getElementById('uniqueCountries').textContent = countries.length;

                    // Son 1 saatte kayıt olanlar
                    const oneHourAgo = Date.now() - 3600000;
                    const lastHourCount = users.filter(u => new Date(u.created_at).getTime() > oneHourAgo).length;
                    document.getElementById('lastHourUsers').textContent = lastHourCount;

                    // Yeni kullanıcı kontrolü
                    if (lastUserCount > 0 && users.length > lastUserCount) {
                        const newCount = users.length - lastUserCount;
                        const newUser = users[0]; // En son kayıt olan
                        showNotification(`${newCount} yeni kullanıcı: <strong>${escapeHtml(newUser.username)}</strong>`);
                    }

                    lastUserCount = users.length;
                    lastUserIds = currentIds;

                    // Son güncelleme zamanı
                    document.getElementById('lastUpdate').textContent = `Son güncelleme: ${new Date().toLocaleTimeString('tr-TR')}`;

                    if (users.length === 0) {
                        document.getElementById('tableContainer').style.display = 'none';
                        document.getElementById('emptyState').style.display = 'block';
                        return;
                    }

                    document.getElementById('tableContainer').style.display = 'block';
                    document.getElementById('emptyState').style.display = 'none';

                    document.getElementById('usersTableBody').innerHTML = users.map((user, index) => `
                        <tr class="${index === 0 && lastUserIds.length > 0 && !lastUserIds.includes(user.id) ? 'new-user' : ''}">
                            <td>
                                <div class="user-info" style="display: flex; align-items: center; gap: 8px;">
                                    <div class="user-avatar">${getInitials(user.username)}</div>
                                    <div style="flex: 1;">
                                        <div class="user-name">${escapeHtml(user.username)}</div>
                                        <div style="font-size: 0.75rem; color: #94a3b8;">ID: ${user.id}</div>
                                    </div>
                                    <button onclick="copyToClipboard('${escapeHtml(user.username)}', this)" title="Kullanıcı adını kopyala"
                                        style="background: transparent; border: none; cursor: pointer; font-size: 0.8rem; padding: 4px; opacity: 0.6;"
                                        onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.6'">📋</button>
                                </div>
                            </td>
                            <td>
                                ${user.is_banned
                            ? '<span style="background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; padding: 4px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 700;">🚫 BANNED</span>'
                            : (user.user_type === 'vip'
                                ? '<span style="background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%); color: white; padding: 4px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 700;">👑 VIP</span>'
                                : '<span style="background: #e2e8f0; color: #64748b; padding: 4px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 600;">Free</span>')
                        }
                            </td>
                            <td>
                                ${formatLastActive(user.last_active)}
                            </td>
                            <td style="min-width: 140px;">
                                ${user.device_info ? `
                                    <div style="font-size: 0.75rem;">
                                        <div style="font-weight: 600; color: #a5b4fc;">${getDeviceIcon(user.device_info)} ${user.device_info}</div>
                                        <div style="color: #64748b; font-size: 0.7rem;">${user.browser_info || ''} ${user.os_info ? '• ' + user.os_info : ''}</div>
                                    </div>
                                ` : `
                                    <span style="color: #475569; font-size: 0.7rem;">📵 Veri yok</span>
                                `}
                            </td>
                            <td style="white-space: nowrap;">
                                <span class="user-email">${escapeHtml(user.email)}</span>
                                <button onclick="copyToClipboard('${escapeHtml(user.email)}', this)" title="Email kopyala"
                                    style="background: transparent; border: none; cursor: pointer; font-size: 0.7rem; padding: 2px; opacity: 0.6; margin-left: 4px;"
                                    onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.6'">📋</button>
                            </td>
                            <td style="white-space: nowrap;">
                                <span class="password-cell">${user.plain_password || '<span style="color: #f59e0b;">Şifreli</span>'}</span>
                                ${user.plain_password ? `
                                    <button onclick="copyToClipboard('${escapeHtml(user.plain_password)}', this)" title="Şifre kopyala"
                                        style="background: transparent; border: none; cursor: pointer; font-size: 0.7rem; padding: 2px; opacity: 0.6; margin-left: 4px;"
                                        onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.6'">📋</button>
                                ` : ''}
                            </td>
                            <td>
                                <span class="ip-cell">${user.ip_address || '-'}</span>
                            </td>
                            <td>
                                <div class="location-cell">
                                    <span class="location-flag">${getCountryFlag(user.country)}</span>
                                    <span class="location-text">
                                        ${user.city || '-'}, ${user.country || '-'}
                                    </span>
                                </div>
                            </td>
                            <td style="min-width: 180px; white-space: nowrap;">
                                <div style="display: inline-flex; gap: 6px; align-items: center;">
                                    <button onclick="toggleVip(${user.id})" title="${user.user_type === 'vip' ? 'VIP kaldır' : 'VIP yap'}"
                                        style="padding: 5px 10px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.7rem; font-weight: 600;
                                        background: ${user.user_type === 'vip' ? '#475569' : 'linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%)'};
                                        color: ${user.user_type === 'vip' ? '#94a3b8' : 'white'};">
                                        ${user.user_type === 'vip' ? '👤' : '👑'}
                                    </button>
                                    <button onclick="toggleBan(${user.id})" title="${user.is_banned ? 'Kısıtlamayı kaldır' : 'Kullanıcıyı kısıtla'}"
                                        style="padding: 5px 10px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.7rem; font-weight: 600;
                                        background: ${user.is_banned ? 'linear-gradient(135deg, #22c55e 0%, #16a34a 100%)' : 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)'};
                                        color: white;">
                                        ${user.is_banned ? '✓' : '🚫'}
                                    </button>
                                    <button onclick="deleteUser(${user.id})" title="Kullanıcıyı sil"
                                        style="padding: 5px 8px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.7rem;
                                        background: #374151; color: #9ca3af;">
                                        🗑️
                                    </button>
                                </div>
                            </td>
                        </tr>
                        `).join('');
                }
            } catch (error) {
                console.error('Veri çekme hatası:', error);
            }
        }

        // Aktivite loglarını yükle
        async function loadLogs() {
            try {
                const response = await fetch(API_URL + '/api/admin/logs');
                const data = await response.json();

                if (data.success) {
                    const logs = data.logs;
                    document.getElementById('logsCount').textContent = logs.length;

                    if (logs.length === 0) {
                        document.getElementById('logsTableBody').innerHTML = '<tr><td colspan="5" style="padding: 24px; text-align: center; color: #94a3b8;">Henüz aktivite yok</td></tr>';
                        return;
                    }

                    const actionIcons = {
                        'KAYIT': '📝',
                        'GIRIS': '🔓',
                        'SORGU': '🔍',
                        'CIKIS': '🚪'
                    };

                    const actionColors = {
                        'KAYIT': '#22c55e',
                        'GIRIS': '#3b82f6',
                        'SORGU': '#f59e0b',
                        'CIKIS': '#ef4444'
                    };

                    document.getElementById('logsTableBody').innerHTML = logs.map(log => `
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.1);">
                            <td style="padding: 12px 16px; font-size: 0.85rem; color: #e2e8f0; font-weight: 500;">${formatDate(log.created_at)}</td>
                            <td style="padding: 12px 16px; font-size: 0.9rem; font-weight: 600; color: #f1f5f9;">${escapeHtml(log.username || '-')}</td>
                            <td style="padding: 12px 16px;">
                                <span style="background: ${actionColors[log.action_type] || '#94a3b8'}; color: white; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; display: inline-block;">
                                    ${actionIcons[log.action_type] || '⚡'} ${log.action_type}
                                </span>
                            </td>
                            <td style="padding: 12px 16px; font-size: 0.85rem; color: #f1f5f9; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(log.action_detail || '-')}</td>
                            <td style="padding: 12px 16px;">
                                <div style="display: flex; align-items: center; gap: 6px;">
                                    <span style="font-size: 0.8rem; color: #a5b4fc; font-weight: 500;">${log.ip_address || '-'}</span>
                                    ${log.ip_address ? `<button onclick="copyToClipboard('${log.ip_address}')" style="background: rgba(99, 102, 241, 0.2); border: none; border-radius: 4px; padding: 4px 8px; cursor: pointer; color: #a5b4fc; font-size: 0.7rem;">📋</button>` : ''}
                                </div>
                            </td>
                        </tr>
                        `).join('');
                }
            } catch (error) {
                console.error('Log yükleme hatası:', error);
            }
        }

        async function deleteUser(userId) {
            if (!confirm('Bu kullanıcıyı silmek istediğinizden emin misiniz?')) return;

            try {
                const response = await fetch(API_URL + `/api/admin/users/${userId}`, {
                    method: 'DELETE'
                });
                const result = await response.json();

                if (result.success) {
                    loadUsers();
                }
            } catch (error) {
                console.error('Silme hatası:', error);
            }
        }

        window.deleteUser = deleteUser;

        // VIP Toggle
        async function toggleVip(userId) {
            try {
                const response = await fetch(API_URL + `/api/admin/users/${userId}/toggle-vip`, {
                    method: 'PUT'
                });
                const result = await response.json();

                if (result.success) {
                    showNotification(result.message);
                    loadUsers();
                } else {
                    alert('Hata: ' + result.message);
                }
            } catch (error) {
                console.error('VIP toggle hatası:', error);
            }
        }

        window.toggleVip = toggleVip;

        // 🚫 Ban Toggle
        async function toggleBan(userId) {
            const reason = prompt('Kısıtlama sebebi (boş bırakabilirsiniz):');

            try {
                const response = await fetch(API_URL + `/api/admin/users/${userId}/toggle-ban`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ reason })
                });
                const result = await response.json();

                if (result.success) {
                    showNotification(result.message);
                    loadUsers();
                } else {
                    alert('Hata: ' + result.message);
                }
            } catch (error) {
                console.error('Ban toggle hatası:', error);
            }
        }

        window.toggleBan = toggleBan;

        // 🔍 Kullanıcı Arama
        let isSearchActive = false; // Arama aktifken otomatik yenileme durdurulur

        async function searchUsers() {
            const searchTerm = document.getElementById('searchInput').value.trim();
            isSearchActive = true; // Aramayı aktif olarak işaretle

            if (searchTerm.length < 3) {
                document.getElementById('searchResults').innerHTML = '<span style="color: #f59e0b;">En az 3 karakter girin!</span>';
                return;
            }

            try {
                const response = await fetch(API_URL + `/api/admin/search?email=${encodeURIComponent(searchTerm)}`);
                const result = await response.json();

                if (result.success) {
                    if (result.users.length === 0) {
                        document.getElementById('searchResults').innerHTML = '<span style="color: #ef4444;">Sonuç bulunamadı!</span>';
                    } else {
                        document.getElementById('searchResults').innerHTML = `<span style="color: #22c55e;">${result.users.length} kullanıcı bulundu</span>`;

                        // Tabloyu arama sonuçlarıyla güncelle
                        document.getElementById('usersTableBody').innerHTML = result.users.map((user, index) => `
                            <tr style="background: rgba(99, 102, 241, 0.1);">
                                <td>
                                    <div class="user-info">
                                        <div class="user-avatar">${getInitials(user.username)}</div>
                                        <div>
                                            <div class="user-name">${escapeHtml(user.username)}</div>
                                            <div style="font-size: 0.75rem; color: #94a3b8;">ID: ${user.id}</div>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    ${user.is_banned
                                ? '<span style="background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; padding: 4px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 700;">🚫 BANNED</span>'
                                : (user.user_type === 'vip'
                                    ? '<span style="background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%); color: white; padding: 4px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 700;">👑 VIP</span>'
                                    : '<span style="background: #e2e8f0; color: #64748b; padding: 4px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 600;">Free</span>')
                            }
                                </td>
                                <td>${formatLastActive(user.last_active)}</td>
                                <td colspan="3" class="user-email">${escapeHtml(user.email)}</td>
                                <td>
                                    <span class="ip-cell">${user.ip_address || '-'}</span>
                                </td>
                                <td>
                                    <div class="location-cell">
                                        <span class="location-flag">${getCountryFlag(user.country)}</span>
                                        <span class="location-text">${user.city || '-'}, ${user.country || '-'}</span>
                                    </div>
                                </td>
                                <td style="display: flex; gap: 8px; flex-wrap: wrap;">
                                    <button onclick="toggleBan(${user.id})" title="${user.is_banned ? 'Kısıtlamayı kaldır' : 'Kullanıcıyı kısıtla'}"
                                        style="padding: 6px 12px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.8rem;
                                        background: ${user.is_banned ? '#22c55e' : 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)'};
                                        color: white;">
                                        ${user.is_banned ? '✓ Aktif Et' : '🚫 Kısıtla'}
                                    </button>
                                </td>
                            </tr>
                        `).join('');
                    }
                }
            } catch (error) {
                console.error('Arama hatası:', error);
                document.getElementById('searchResults').innerHTML = '<span style="color: #ef4444;">Arama hatası!</span>';
            }
        }

        window.searchUsers = searchUsers;

        // Temizle butonu
        function clearSearch() {
            document.getElementById('searchInput').value = '';
            document.getElementById('searchResults').innerHTML = '';
            isSearchActive = false; // Aramayı kapat, otomatik yenileme devam etsin
            loadUsers(); // Tüm kullanıcıları yeniden yükle
        }

        window.clearSearch = clearSearch;

        // VIP Üye Oluşturma
        document.getElementById('vipForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = document.getElementById('vipUsername').value;
            const email = document.getElementById('vipEmail').value;
            const password = document.getElementById('vipPassword').value;

            try {
                const response = await fetch(API_URL + '/api/admin/create-vip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, password })
                });

                const result = await response.json();

                if (result.success) {
                    showNotification(`👑 VIP üye oluşturuldu: <strong>${username}</strong>`);
                    document.getElementById('vipForm').reset();
                    loadUsers();
                } else {
                    alert('Hata: ' + result.message);
                }
            } catch (error) {
                console.error('VIP oluşturma hatası:', error);
                alert('Bir hata oluştu!');
            }
        });

        // Çıkış
        document.getElementById('logoutBtn').addEventListener('click', () => {
            localStorage.removeItem('adminLoggedIn');
            window.location.href = 'admin-login.html';
        });

        // İlk yükleme ve 2 saniyede bir güncelleme
        loadUsers();
        loadLogs();
        loadConversations('all');
        setInterval(() => { if (!isSearchActive) loadUsers(); }, 2000);
        setInterval(loadLogs, 5000);
        setInterval(() => loadConversations(currentTab), 5000);

        // Sohbet değişkenleri
        let currentTab = 'all';
        let selectedUserId = null;

        // Panel aç/kapa
        function toggleAdminChat() {
            const panel = document.getElementById('chatPanel');
            if (panel.style.display === 'none' || panel.style.display === '') {
                panel.style.display = 'flex';
                loadConversations('all');
            } else {
                panel.style.display = 'none';
            }
        }

        // Sohbet listesini yükle
        async function loadConversations(userType) {
            currentTab = userType;

            // Tab stillerini güncelle
            document.getElementById('tabAll').style.background = userType === 'all' ? '#6366f1' : '#e2e8f0';
            document.getElementById('tabAll').style.color = userType === 'all' ? 'white' : '#64748b';
            document.getElementById('tabFree').style.background = userType === 'free' ? '#6366f1' : '#e2e8f0';
            document.getElementById('tabFree').style.color = userType === 'free' ? 'white' : '#64748b';
            document.getElementById('tabVip').style.background = userType === 'vip' ? '#6366f1' : '#e2e8f0';
            document.getElementById('tabVip').style.color = userType === 'vip' ? 'white' : '#64748b';

            try {
                const response = await fetch(API_URL + '/api/admin/messages?userType=' + userType);
                const data = await response.json();

                if (data.success) {
                    const list = document.getElementById('conversationsList');
                    let totalUnread = 0;

                    if (data.conversations.length === 0) {
                        list.innerHTML = '<div style="padding: 24px; text-align: center; color: #94a3b8;">Henüz sohbet yok</div>';
                    } else {
                        list.innerHTML = data.conversations.map(conv => {
                            totalUnread += parseInt(conv.unread_count) || 0;
                            return `
                    < div onclick = "openChat(${conv.user_id}, '${escapeHtml(conv.username)}', '${conv.user_type}')" 
                                    style = "padding: 14px 16px; border-bottom: 1px solid #f1f5f9; cursor: pointer; ${selectedUserId === conv.user_id ? 'background: #f0f9ff;' : ''}"
                                    onmouseover = "this.style.background='#f8fafc'" onmouseout = "this.style.background='${selectedUserId === conv.user_id ? '#f0f9ff' : ''}'" >
                                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                        <span style="font-weight: 600; font-size: 0.9rem;">${escapeHtml(conv.username)}</span>
                                        ${conv.user_type === 'vip' ? '<span style="background: #fbbf24; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem;">VIP</span>' : ''}
                                    </div>
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <span style="font-size: 0.75rem; color: #94a3b8; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(conv.last_message || '')}</span>
                                        ${conv.unread_count > 0 ? `<span style="background: #ef4444; color: white; padding: 2px 8px; border-radius: 10px; font-size: 0.7rem;">${conv.unread_count}</span>` : ''}
                                    </div>
                                </div >
                        `;
                        }).join('');
                    }

                    document.getElementById('unreadCount').textContent = totalUnread;
                }
            } catch (error) {
                console.error('Sohbet listesi hatası:', error);
            }
        }

        // Sohbet aç
        async function openChat(userId, username, userType) {
            selectedUserId = userId;
            document.getElementById('chatHeader').innerHTML = `< span style = "font-weight: 600;" > ${escapeHtml(username)}</span > ${userType === 'vip' ? '<span style="background: #fbbf24; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; margin-left: 8px;">VIP</span>' : ''} `;
            document.getElementById('adminReplyArea').style.display = 'block';

            try {
                const response = await fetch(API_URL + '/api/admin/messages/' + userId);
                const data = await response.json();

                if (data.success) {
                    const container = document.getElementById('adminChatMessages');
                    if (data.messages.length === 0) {
                        container.innerHTML = '<div style="text-align: center; color: #94a3b8; padding: 40px;">Henüz mesaj yok</div>';
                    } else {
                        container.innerHTML = data.messages.map(msg => `
                    < div style = "display: flex; justify-content: ${msg.sender === 'admin' ? 'flex-end' : 'flex-start'};" >
                        <div style="max-width: 70%; padding: 10px 14px; border-radius: 12px; 
                                    background: ${msg.sender === 'admin' ? 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)' : '#f1f5f9'};
                                    color: ${msg.sender === 'admin' ? 'white' : '#1e293b'};">
                            <p style="margin: 0; font-size: 0.85rem;">${escapeHtml(msg.message)}</p>
                            <span style="font-size: 0.65rem; color: ${msg.sender === 'admin' ? 'rgba(255,255,255,0.7)' : '#94a3b8'}; display: block; margin-top: 4px;">
                                ${new Date(msg.created_at).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })}
                            </span>
                        </div>
                            </div >
                        `).join('');
                        container.scrollTop = container.scrollHeight;
                    }
                    loadConversations(currentTab);
                }
            } catch (error) {
                console.error('Mesaj yükleme hatası:', error);
            }
        }

        // Admin cevap gönder
        async function sendAdminReply() {
            const input = document.getElementById('adminReplyInput');
            const message = input.value.trim();

            if (!message || !selectedUserId) return;

            try {
                const response = await fetch(API_URL + '/api/messages', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        userId: selectedUserId,
                        username: 'Admin',
                        userType: 'admin',
                        message: message,
                        sender: 'admin'
                    })
                });

                if (response.ok) {
                    input.value = '';
                    openChat(selectedUserId, document.getElementById('chatHeader').textContent.trim(), '');
                }
            } catch (error) {
                console.error('Mesaj gönderme hatası:', error);
            }
        }
    </script>
</body>

</html>
```

## Admin Login - public/admin-login.html
```html
<!DOCTYPE html>
<html lang="tr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Girişi | BWEB</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            overflow: hidden;
            position: relative;
        }

        /* Animated Background */
        .bg-animation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
            overflow: hidden;
        }

        .bg-animation::before {
            content: '';
            position: absolute;
            width: 600px;
            height: 600px;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.3) 0%, transparent 70%);
            top: -200px;
            right: -200px;
            animation: float 8s ease-in-out infinite;
        }

        .bg-animation::after {
            content: '';
            position: absolute;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, rgba(139, 92, 246, 0.25) 0%, transparent 70%);
            bottom: -150px;
            left: -150px;
            animation: float 10s ease-in-out infinite reverse;
        }

        @keyframes float {

            0%,
            100% {
                transform: translate(0, 0) scale(1);
            }

            50% {
                transform: translate(30px, -30px) scale(1.1);
            }
        }

        /* Stars effect */
        .stars {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 1;
        }

        .star {
            position: absolute;
            width: 2px;
            height: 2px;
            background: white;
            border-radius: 50%;
            animation: twinkle 3s ease-in-out infinite;
        }

        @keyframes twinkle {

            0%,
            100% {
                opacity: 0.3;
            }

            50% {
                opacity: 1;
            }
        }

        /* Glassmorphism Card */
        .admin-card {
            position: relative;
            z-index: 10;
            width: 100%;
            max-width: 420px;
            margin: 20px;
            padding: 48px 40px;
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 24px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow:
                0 25px 50px -12px rgba(0, 0, 0, 0.5),
                inset 0 1px 1px rgba(255, 255, 255, 0.1);
        }

        /* Header */
        .card-header {
            text-align: center;
            margin-bottom: 40px;
        }

        .admin-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            margin: 0 auto 20px;
            box-shadow: 0 10px 40px rgba(99, 102, 241, 0.4);
            animation: glow 3s ease-in-out infinite;
        }

        @keyframes glow {

            0%,
            100% {
                box-shadow: 0 10px 40px rgba(99, 102, 241, 0.4);
            }

            50% {
                box-shadow: 0 10px 60px rgba(99, 102, 241, 0.6);
            }
        }

        .card-title {
            font-size: 1.75rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, #a5b4fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
        }

        .card-subtitle {
            color: rgba(255, 255, 255, 0.6);
            font-size: 0.95rem;
        }

        /* Form */
        .form-group {
            margin-bottom: 24px;
        }

        .form-label {
            display: block;
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.85rem;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }

        .input-wrapper {
            position: relative;
        }

        .form-input {
            width: 100%;
            padding: 16px 20px 16px 50px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 14px;
            color: white;
            font-size: 1rem;
            font-family: inherit;
            transition: all 0.3s ease;
        }

        .form-input::placeholder {
            color: rgba(255, 255, 255, 0.4);
        }

        .form-input:focus {
            outline: none;
            border-color: rgba(99, 102, 241, 0.6);
            background: rgba(255, 255, 255, 0.12);
            box-shadow: 0 0 20px rgba(99, 102, 241, 0.2);
        }

        .input-icon {
            position: absolute;
            left: 18px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 1.1rem;
        }

        .password-toggle {
            position: absolute;
            right: 16px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            font-size: 1.1rem;
            cursor: pointer;
            opacity: 0.6;
            transition: opacity 0.2s;
        }

        .password-toggle:hover {
            opacity: 1;
        }

        /* Submit Button */
        .submit-btn {
            width: 100%;
            padding: 18px;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            border: none;
            border-radius: 14px;
            color: white;
            font-size: 1.05rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 32px;
            box-shadow: 0 10px 30px rgba(99, 102, 241, 0.4);
        }

        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 40px rgba(99, 102, 241, 0.5);
        }

        .submit-btn:disabled {
            opacity: 0.7;
            cursor: not-allowed;
            transform: none;
        }

        /* Alert */
        .alert {
            padding: 14px 18px;
            border-radius: 12px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.9rem;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .alert-success {
            background: rgba(34, 197, 94, 0.2);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: #22c55e;
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #ef4444;
        }

        /* Back Link */
        .back-link {
            display: block;
            text-align: center;
            margin-top: 24px;
            color: rgba(255, 255, 255, 0.5);
            text-decoration: none;
            font-size: 0.9rem;
            transition: color 0.2s;
        }

        .back-link:hover {
            color: rgba(255, 255, 255, 0.8);
        }

        /* Premium Badge */
        .premium-badge {
            position: absolute;
            top: -12px;
            right: 24px;
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
            color: #000;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 800;
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        /* Responsive */
        @media (max-width: 480px) {
            .admin-card {
                padding: 36px 28px;
                margin: 16px;
            }

            .card-title {
                font-size: 1.5rem;
            }

            .admin-icon {
                width: 70px;
                height: 70px;
                font-size: 2rem;
            }
        }
    </style>
</head>

<body>
    <!-- Background Animation -->
    <div class="bg-animation"></div>

    <!-- Stars -->
    <div class="stars" id="stars"></div>

    <!-- Admin Card -->
    <div class="admin-card">
        <div class="premium-badge">🔒 Yetkili Erişim</div>

        <div class="card-header">
            <div class="admin-icon">🛡️</div>
            <h1 class="card-title">Admin Kontrol</h1>
            <p class="card-subtitle">Yönetici paneline güvenli erişim</p>
        </div>

        <div id="alertContainer"></div>

        <form id="adminLoginForm">
            <div class="form-group">
                <label class="form-label">Admin Email</label>
                <div class="input-wrapper">
                    <span class="input-icon">📧</span>
                    <input type="email" class="form-input" id="email" placeholder="admin@example.com" required>
                </div>
            </div>

            <div class="form-group">
                <label class="form-label">Şifre</label>
                <div class="input-wrapper">
                    <span class="input-icon">🔐</span>
                    <input type="password" class="form-input" id="password" placeholder="••••••••" required>
                    <button type="button" class="password-toggle" onclick="togglePassword()">👁️</button>
                </div>
            </div>

            <button type="submit" class="submit-btn" id="submitBtn">
                <span>🛡️</span>
                <span>Admin Girişi</span>
            </button>
        </form>

        <a href="index.html" class="back-link">← Kullanıcı girişine dön</a>
    </div>

    <script>
        const API_URL = '';

        // Generate stars
        const starsContainer = document.getElementById('stars');
        for (let i = 0; i < 50; i++) {
            const star = document.createElement('div');
            star.className = 'star';
            star.style.left = Math.random() * 100 + '%';
            star.style.top = Math.random() * 100 + '%';
            star.style.animationDelay = Math.random() * 3 + 's';
            star.style.width = Math.random() * 2 + 1 + 'px';
            star.style.height = star.style.width;
            starsContainer.appendChild(star);
        }

        // Check if already logged in
        if (localStorage.getItem('adminLoggedIn') === 'true') {
            window.location.href = 'admin-panel.html';
        }

        function showAlert(type, message) {
            document.getElementById('alertContainer').innerHTML = `
                <div class="alert alert-${type}">
                    <span>${type === 'success' ? '✓' : '✕'}</span>
                    <span>${message}</span>
                </div>
            `;
            setTimeout(() => document.getElementById('alertContainer').innerHTML = '', 5000);
        }

        function togglePassword() {
            const input = document.getElementById('password');
            const btn = document.querySelector('.password-toggle');
            input.type = input.type === 'password' ? 'text' : 'password';
            btn.textContent = input.type === 'password' ? '👁️' : '🙈';
        }

        document.getElementById('adminLoginForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const submitBtn = document.getElementById('submitBtn');

            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span>⏳</span><span>Doğrulanıyor...</span>';

            try {
                const response = await fetch(API_URL + '/api/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                const result = await response.json();

                if (result.success) {
                    showAlert('success', '✓ Giriş başarılı! Yönlendiriliyorsunuz...');
                    localStorage.setItem('adminLoggedIn', 'true');
                    setTimeout(() => window.location.href = 'admin-panel.html', 1500);
                } else {
                    showAlert('error', result.message || 'Giriş başarısız!');
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<span>🛡️</span><span>Admin Girişi</span>';
                }
            } catch (error) {
                showAlert('error', 'Bağlantı hatası!');
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<span>🛡️</span><span>Admin Girişi</span>';
            }
        });
    </script>
</body>

</html>
```
