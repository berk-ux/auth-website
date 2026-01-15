/*
 * ========================================
 * 🔐 AUTHENTICATION SYSTEM - JavaScript
 * ========================================
 * localStorage tabanlı kullanıcı yönetimi
 */

// ========== CONFIGURATION ==========
const CONFIG = {
    USERS_KEY: 'auth_users',
    SESSION_KEY: 'auth_session',
    ADMIN_SESSION_KEY: 'admin_session',
    ADMIN_CREDENTIALS: {
        email: 'admin@admin.com',
        password: 'admin123'
    }
};

// ========== UTILITY FUNCTIONS ==========

/**
 * Benzersiz ID oluştur
 */
function generateId() {
    return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

/**
 * Tarihi formatla
 */
function formatDate(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleDateString('tr-TR', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Basit şifre hashleme (demo amaçlı - gerçek projede güçlü hash kullanın!)
 */
function hashPassword(password) {
    // Basit base64 encoding - PRODUCTION'DA KULLANMAYIN!
    return btoa(password + '_secure_salt_2024');
}

/**
 * Şifre doğrulama
 */
function verifyPassword(password, hash) {
    return hashPassword(password) === hash;
}

// ========== USER MANAGEMENT ==========

/**
 * Tüm kullanıcıları getir
 */
function getUsers() {
    const users = localStorage.getItem(CONFIG.USERS_KEY);
    return users ? JSON.parse(users) : [];
}

/**
 * Kullanıcıları kaydet
 */
function saveUsers(users) {
    localStorage.setItem(CONFIG.USERS_KEY, JSON.stringify(users));
}

/**
 * Kullanıcı bul (email veya kullanıcı adına göre)
 */
function findUser(identifier) {
    const users = getUsers();
    return users.find(user => 
        user.email.toLowerCase() === identifier.toLowerCase() || 
        user.username.toLowerCase() === identifier.toLowerCase()
    );
}

/**
 * Email var mı kontrol et
 */
function emailExists(email) {
    const users = getUsers();
    return users.some(user => user.email.toLowerCase() === email.toLowerCase());
}

/**
 * Kullanıcı adı var mı kontrol et
 */
function usernameExists(username) {
    const users = getUsers();
    return users.some(user => user.username.toLowerCase() === username.toLowerCase());
}

/**
 * Yeni kullanıcı kaydet
 */
function registerUser(username, email, password) {
    // Validasyonlar
    if (!username || username.length < 3) {
        return { success: false, message: 'Kullanıcı adı en az 3 karakter olmalı!' };
    }
    
    if (!email || !email.includes('@')) {
        return { success: false, message: 'Geçerli bir email adresi girin!' };
    }
    
    if (!password || password.length < 6) {
        return { success: false, message: 'Şifre en az 6 karakter olmalı!' };
    }
    
    if (emailExists(email)) {
        return { success: false, message: 'Bu email adresi zaten kayıtlı!' };
    }
    
    if (usernameExists(username)) {
        return { success: false, message: 'Bu kullanıcı adı zaten alınmış!' };
    }
    
    // Kullanıcı oluştur
    const newUser = {
        id: generateId(),
        username: username.trim(),
        email: email.trim().toLowerCase(),
        password: hashPassword(password),
        createdAt: Date.now(),
        updatedAt: Date.now()
    };
    
    // Kaydet
    const users = getUsers();
    users.push(newUser);
    saveUsers(users);
    
    return { success: true, message: 'Kayıt başarılı! Giriş yapabilirsiniz.', user: newUser };
}

/**
 * Kullanıcı girişi
 */
function loginUser(identifier, password) {
    if (!identifier || !password) {
        return { success: false, message: 'Lütfen tüm alanları doldurun!' };
    }
    
    const user = findUser(identifier);
    
    if (!user) {
        return { success: false, message: 'Kullanıcı bulunamadı!' };
    }
    
    if (!verifyPassword(password, user.password)) {
        return { success: false, message: 'Hatalı şifre!' };
    }
    
    // Session oluştur
    const session = {
        userId: user.id,
        username: user.username,
        email: user.email,
        loginAt: Date.now()
    };
    
    localStorage.setItem(CONFIG.SESSION_KEY, JSON.stringify(session));
    
    return { success: true, message: 'Giriş başarılı!', user: user };
}

/**
 * Kullanıcı çıkışı
 */
function logoutUser() {
    localStorage.removeItem(CONFIG.SESSION_KEY);
}

/**
 * Mevcut oturumu kontrol et
 */
function getCurrentSession() {
    const session = localStorage.getItem(CONFIG.SESSION_KEY);
    return session ? JSON.parse(session) : null;
}

/**
 * Kullanıcı giriş yapmış mı?
 */
function isLoggedIn() {
    return getCurrentSession() !== null;
}

/**
 * Kullanıcıyı sil
 */
function deleteUser(userId) {
    const users = getUsers();
    const filteredUsers = users.filter(user => user.id !== userId);
    saveUsers(filteredUsers);
    return { success: true, message: 'Kullanıcı silindi!' };
}

// ========== ADMIN MANAGEMENT ==========

/**
 * Admin girişi
 */
function adminLogin(email, password) {
    if (!email || !password) {
        return { success: false, message: 'Lütfen tüm alanları doldurun!' };
    }
    
    if (email === CONFIG.ADMIN_CREDENTIALS.email && password === CONFIG.ADMIN_CREDENTIALS.password) {
        const adminSession = {
            isAdmin: true,
            loginAt: Date.now()
        };
        localStorage.setItem(CONFIG.ADMIN_SESSION_KEY, JSON.stringify(adminSession));
        return { success: true, message: 'Admin girişi başarılı!' };
    }
    
    return { success: false, message: 'Hatalı admin bilgileri!' };
}

/**
 * Admin çıkışı
 */
function adminLogout() {
    localStorage.removeItem(CONFIG.ADMIN_SESSION_KEY);
}

/**
 * Admin oturumunu kontrol et
 */
function isAdminLoggedIn() {
    const session = localStorage.getItem(CONFIG.ADMIN_SESSION_KEY);
    return session !== null;
}

// ========== UI HELPERS ==========

/**
 * Alert göster
 */
function showAlert(container, type, message) {
    const iconMap = {
        success: '✓',
        error: '✕',
        warning: '⚠'
    };
    
    const alertHtml = `
        <div class="alert alert-${type}">
            <span class="alert-icon">${iconMap[type]}</span>
            <span>${message}</span>
        </div>
    `;
    
    // Mevcut alertleri kaldır
    const existingAlerts = container.querySelectorAll('.alert');
    existingAlerts.forEach(alert => alert.remove());
    
    // Yeni alert ekle
    container.insertAdjacentHTML('afterbegin', alertHtml);
    
    // 5 saniye sonra otomatik kaldır
    setTimeout(() => {
        const alert = container.querySelector('.alert');
        if (alert) {
            alert.style.animation = 'slideUp 0.3s ease-out reverse';
            setTimeout(() => alert.remove(), 300);
        }
    }, 5000);
}

/**
 * Input hata stili ekle/kaldır
 */
function setInputError(input, hasError) {
    if (hasError) {
        input.classList.add('error');
        input.classList.remove('success');
    } else {
        input.classList.remove('error');
        input.classList.add('success');
    }
}

/**
 * Butonu loading durumuna al
 */
function setButtonLoading(button, isLoading) {
    if (isLoading) {
        button.classList.add('btn-loading');
        button.disabled = true;
    } else {
        button.classList.remove('btn-loading');
        button.disabled = false;
    }
}

/**
 * Şifre göster/gizle toggle
 */
function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    const isPassword = input.type === 'password';
    
    input.type = isPassword ? 'text' : 'password';
    button.innerHTML = isPassword ? '🙈' : '👁️';
}

// ========== PAGE INITIALIZATION ==========

/**
 * Sayfa yüklendiğinde çalışır
 */
document.addEventListener('DOMContentLoaded', function() {
    // Şifre toggle butonları
    document.querySelectorAll('.password-toggle').forEach(button => {
        button.addEventListener('click', function() {
            const inputId = this.getAttribute('data-input');
            togglePasswordVisibility(inputId, this);
        });
    });
    
    console.log('🔐 Auth System initialized!');
    console.log('📊 Total users:', getUsers().length);
});

// ========== EXPORTS (Global scope) ==========
window.AuthSystem = {
    // User functions
    registerUser,
    loginUser,
    logoutUser,
    getUsers,
    deleteUser,
    findUser,
    isLoggedIn,
    getCurrentSession,
    
    // Admin functions
    adminLogin,
    adminLogout,
    isAdminLoggedIn,
    
    // UI Helpers
    showAlert,
    setInputError,
    setButtonLoading,
    togglePasswordVisibility,
    
    // Utils
    formatDate
};
