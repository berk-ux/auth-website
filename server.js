/*
 * ========================================
 * 🚀 BACKEND SERVER - Node.js + SQLite
 * ========================================
 * Güvenli kullanıcı yönetim sistemi
 */

const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ========== DATABASE SETUP ==========
const db = new Database('users.db');

// Kullanıcılar tablosu oluştur
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

console.log('✅ Veritabanı hazır!');

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
        const existingUser = db.prepare(
            'SELECT * FROM users WHERE email = ? OR username = ?'
        ).get(email.toLowerCase(), username.toLowerCase());

        if (existingUser) {
            if (existingUser.email === email.toLowerCase()) {
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

        // Şifreyi hashle
        const hashedPassword = await hashPassword(password);

        // Kullanıcıyı kaydet
        const stmt = db.prepare(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)'
        );
        const result = stmt.run(username.trim(), email.trim().toLowerCase(), hashedPassword);

        console.log(`✅ Yeni kullanıcı kayıt oldu: ${username}`);

        res.json({
            success: true,
            message: 'Kayıt başarılı! Giriş yapabilirsiniz.',
            userId: result.lastInsertRowid
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
        const user = db.prepare(
            'SELECT * FROM users WHERE email = ? OR username = ?'
        ).get(identifier.toLowerCase(), identifier.toLowerCase());

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Kullanıcı bulunamadı!'
            });
        }

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
app.get('/api/admin/users', (req, res) => {
    try {
        const users = db.prepare(
            'SELECT id, username, email, password, created_at FROM users ORDER BY created_at DESC'
        ).all();

        res.json({
            success: true,
            users: users,
            total: users.length
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
app.delete('/api/admin/users/:id', (req, res) => {
    try {
        const { id } = req.params;

        const stmt = db.prepare('DELETE FROM users WHERE id = ?');
        const result = stmt.run(id);

        if (result.changes > 0) {
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
app.get('/api/stats', (req, res) => {
    try {
        const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
        const todayUsers = db.prepare(
            "SELECT COUNT(*) as count FROM users WHERE date(created_at) = date('now')"
        ).get();

        res.json({
            success: true,
            stats: {
                totalUsers: totalUsers.count,
                todayUsers: todayUsers.count
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
const HOST = '0.0.0.0'; // Tüm ağ arayüzlerinden erişim

app.listen(PORT, HOST, () => {
    // Yerel IP adresini bul
    const os = require('os');
    const networkInterfaces = os.networkInterfaces();
    let localIP = 'localhost';

    for (const name of Object.keys(networkInterfaces)) {
        for (const net of networkInterfaces[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                localIP = net.address;
                break;
            }
        }
    }

    console.log(`
    ╔════════════════════════════════════════════════════╗
    ║                                                    ║
    ║   🚀 Server çalışıyor!                             ║
    ║                                                    ║
    ║   📍 Yerel:     http://localhost:${PORT}               ║
    ║   📍 Ağ:        http://${localIP}:${PORT}         ║
    ║                                                    ║
    ║   ☝️  Diğer cihazlardan "Ağ" adresini kullanın     ║
    ║                                                    ║
    ║   Admin: admin@admin.com / admin123                ║
    ║                                                    ║
    ╚════════════════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n👋 Sunucu kapatılıyor...');
    db.close();
    process.exit(0);
});
