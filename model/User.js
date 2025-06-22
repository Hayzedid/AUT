const bcrypt = require('bcryptjs');
const { executeQuery, getOne } = require('../config/database');

class User {
    // Create new user
    static async create(userData) {
        const { email, password } = userData;
        
        // Hash password
        const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        const query = `
            INSERT INTO users (email, password_hash, created_at, updated_at)
            VALUES (?, ?, NOW(), NOW())
        `;
        
        const result = await executeQuery(query, [email, passwordHash]);
        return result.insertId;
    }

    // Find user by email
    static async findByEmail(email) {
        const query = `
            SELECT id, email, password_hash, email_verified, account_status,
                   last_login_at, failed_login_attempts, locked_until,
                   created_at, updated_at
            FROM users 
            WHERE email = ? AND account_status != 'deleted'
        `;
        
        return await getOne(query, [email]);
    }

    // Find user by ID
    static async findById(id) {
        const query = `
            SELECT id, email, email_verified, account_status,
                   last_login_at, failed_login_attempts, locked_until,
                   created_at, updated_at
            FROM users 
            WHERE id = ? AND account_status != 'deleted'
        `;
        
        return await getOne(query, [id]);
    }

    // Verify password
    static async verifyPassword(plainPassword, hashedPassword) {
        return await bcrypt.compare(plainPassword, hashedPassword);
    }

    // Check if user exists
    static async exists(email) {
        const query = 'SELECT COUNT(*) as count FROM users WHERE email = ?';
        const result = await getOne(query, [email]);
        return result.count > 0;
    }

    // Update last login
    static async updateLastLogin(userId, ipAddress) {
        const query = `
            UPDATE users 
            SET last_login_at = NOW(), failed_login_attempts = 0, locked_until = NULL
            WHERE id = ?
        `;
        
        await executeQuery(query, [userId]);
        
        // Log successful login attempt
        await this.logLoginAttempt(null, ipAddress, true, userId);
    }

    // Handle failed login attempt
    static async handleFailedLogin(email, ipAddress) {
        const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
        const lockoutHours = parseInt(process.env.LOCKOUT_TIME_HOURS) || 1;
        
        // Increment failed attempts
        const query = `
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE 
                    WHEN failed_login_attempts + 1 >= ? 
                    THEN DATE_ADD(NOW(), INTERVAL ? HOUR)
                    ELSE locked_until 
                END
            WHERE email = ?
        `;
        
        await executeQuery(query, [maxAttempts, lockoutHours, email]);
        
        // Log failed login attempt
        await this.logLoginAttempt(email, ipAddress, false);
        
        // Return updated user data
        return await this.findByEmail(email);
    }

    // Check if account is locked
    static async isAccountLocked(user) {
        if (!user.locked_until) return false;
        
        const now = new Date();
        const lockoutEnd = new Date(user.locked_until);
        
        if (now < lockoutEnd) {
            return true;
        } else {
            // Unlock account if lockout period has passed
            await this.unlockAccount(user.id);
            return false;
        }
    }

    // Unlock account
    static async unlockAccount(userId) {
        const query = `
            UPDATE users 
            SET failed_login_attempts = 0, locked_until = NULL
            WHERE id = ?
        `;
        
        await executeQuery(query, [userId]);
    }

    // Log login attempt
    static async logLoginAttempt(email, ipAddress, wasSuccessful, userId = null) {
        const query = `
            INSERT INTO login_attempts (email, ip_address, attempted_at, was_successful)
            VALUES (?, ?, NOW(), ?)
        `;
        
        await executeQuery(query, [email, ipAddress, wasSuccessful]);
    }

    // Get recent failed login attempts (for rate limiting)
    static async getRecentFailedAttempts(email, ipAddress, minutes = 15) {
        const query = `
            SELECT COUNT(*) as count
            FROM login_attempts
            WHERE (email = ? OR ip_address = ?)
            AND was_successful = FALSE
            AND attempted_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)
        `;
        
        const result = await getOne(query, [email, ipAddress, minutes]);
        return result.count;
    }

    // Update user profile
    static async updateProfile(userId, updates) {
        const allowedFields = ['email', 'email_verified'];
        const setClause = [];
        const values = [];
        
        for (const [key, value] of Object.entries(updates)) {
            if (allowedFields.includes(key)) {
                setClause.push(`${key} = ?`);
                values.push(value);
            }
        }
        
        if (setClause.length === 0) {
            throw new Error('No valid fields to update');
        }
        
        values.push(userId);
        
        const query = `
            UPDATE users 
            SET ${setClause.join(', ')}, updated_at = NOW()
            WHERE id = ?
        `;
        
        await executeQuery(query, values);
    }

    // Change password
    static async changePassword(userId, newPassword) {
        const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
        const passwordHash = await bcrypt.hash(newPassword, saltRounds);
        
        const query = `
            UPDATE users 
            SET password_hash = ?, updated_at = NOW()
            WHERE id = ?
        `;
        
        await executeQuery(query, [passwordHash, userId]);
    }

    // Soft delete user
    static async softDelete(userId) {
        const query = `
            UPDATE users 
            SET account_status = 'deleted', updated_at = NOW()
            WHERE id = ?
        `;
        
        await executeQuery(query, [userId]);
    }
}

module.exports = User;