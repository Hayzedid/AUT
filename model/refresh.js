// models/RefreshToken.js

const crypto = require('crypto');
const db = require('../config/database');

/**
 * RefreshToken Model
 * 
 * This model manages refresh tokens which are long-lived tokens that allow users
 * to obtain new access tokens without re-authenticating. We implement several
 * security features:
 * 
 * 1. Token Rotation: Each refresh generates a new token and invalidates the old one
 * 2. Token Families: Groups of tokens that can be invalidated together if compromise is detected
 * 3. Device Tracking: Track which device/browser is using each token
 * 4. Automatic Cleanup: Remove expired and revoked tokens
 */

class RefreshToken {
  constructor() {
    // Token configuration - these values balance security with usability
    this.TOKEN_LENGTH = 64; // Length in bytes for cryptographically secure tokens
    this.EXPIRY_DAYS = 30; // How long refresh tokens last (30 days is common)
    this.CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // Clean up expired tokens every 24 hours
    
    // Start the cleanup process when the model is instantiated
    this.startCleanupScheduler();
  }

  /**
   * Generate a cryptographically secure refresh token
   * We use crypto.randomBytes for true randomness, not Math.random()
   */
  generateToken() {
    return crypto.randomBytes(this.TOKEN_LENGTH).toString('hex');
  }

  /**
   * Generate a token family ID
   * Token families help us detect token replay attacks. When we suspect
   * a token has been compromised, we can invalidate the entire family.
   */
  generateFamilyId() {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Hash a token for secure storage
   * We never store raw tokens in the database - only their hashes.
   * This way, even if our database is compromised, the actual tokens remain secret.
   */
  hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Extract device information from request headers
   * This helps users identify which devices have access to their account
   */
  extractDeviceInfo(req) {
    const userAgent = req.get('User-Agent') || 'Unknown';
    const ip = req.ip || req.connection.remoteAddress || 'Unknown';
    
    // Parse user agent to extract meaningful device info
    const deviceInfo = {
      userAgent: userAgent.substring(0, 500), // Limit length to prevent abuse
      ip: ip,
      browser: this.parseBrowser(userAgent),
      os: this.parseOS(userAgent),
      device: this.parseDevice(userAgent)
    };
    
    return deviceInfo;
  }

  /**
   * Simple browser detection from user agent
   * This is not foolproof but gives users a general idea of their devices
   */
  parseBrowser(userAgent) {
    if (userAgent.includes('Chrome')) return 'Chrome';
    if (userAgent.includes('Firefox')) return 'Firefox';
    if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) return 'Safari';
    if (userAgent.includes('Edge')) return 'Edge';
    if (userAgent.includes('Opera')) return 'Opera';
    return 'Unknown';
  }

  /**
   * Simple OS detection from user agent
   */
  parseOS(userAgent) {
    if (userAgent.includes('Windows')) return 'Windows';
    if (userAgent.includes('Mac OS')) return 'macOS';
    if (userAgent.includes('Linux')) return 'Linux';
    if (userAgent.includes('Android')) return 'Android';
    if (userAgent.includes('iOS')) return 'iOS';
    return 'Unknown';
  }

  /**
   * Simple device type detection
   */
  parseDevice(userAgent) {
    if (userAgent.includes('Mobile')) return 'Mobile';
    if (userAgent.includes('Tablet')) return 'Tablet';
    return 'Desktop';
  }

  /**
   * Create a new refresh token
   * This is called when a user logs in or when we rotate an existing token
   */
  async create(userId, req, familyId = null) {
    const connection = await db.getConnection();
    
    try {
      // Generate a new token and family ID if not provided
      const token = this.generateToken();
      const tokenHash = this.hashToken(token);
      const actualFamilyId = familyId || this.generateFamilyId();
      
      // Extract device information for user visibility
      const deviceInfo = this.extractDeviceInfo(req);
      
      // Calculate expiration date
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + this.EXPIRY_DAYS);
      
      // Insert the new refresh token record
      const query = `
        INSERT INTO refresh_tokens (
          user_id, token_hash, family_id, expires_at,
          user_agent, ip_address, browser, os, device,
          created_at, last_used_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
      `;
      
      const [result] = await connection.execute(query, [
        userId,
        tokenHash,
        actualFamilyId,
        expiresAt,
        deviceInfo.userAgent,
        deviceInfo.ip,
        deviceInfo.browser,
        deviceInfo.os,
        deviceInfo.device
      ]);
      
      // Return the token ID and the actual token (not the hash)
      // The calling code needs the actual token to send to the client
      return {
        id: result.insertId,
        token: token, // This is the raw token that gets sent to the client
        familyId: actualFamilyId,
        expiresAt: expiresAt
      };
      
    } catch (error) {
      console.error('Error creating refresh token:', error);
      throw new Error('Failed to create refresh token');
    } finally {
      connection.release();
    }
  }

  /**
   * Find a refresh token by its value
   * This is used during the token refresh process
   */
  async findByToken(token) {
    const connection = await db.getConnection();
    
    try {
      const tokenHash = this.hashToken(token);
      
      // Join with users table to get user information
      const query = `
        SELECT 
          rt.*,
          u.email,
          u.username,
          u.status as user_status
        FROM refresh_tokens rt
        JOIN users u ON rt.user_id = u.id
        WHERE rt.token_hash = ?
          AND rt.is_revoked = FALSE
          AND rt.expires_at > NOW()
      `;
      
      const [rows] = await connection.execute(query, [tokenHash]);
      
      if (rows.length === 0) {
        return null; // Token not found, expired, or revoked
      }
      
      // Update the last_used_at timestamp
      await this.updateLastUsed(rows[0].id);
      
      return rows[0];
      
    } catch (error) {
      console.error('Error finding refresh token:', error);
      throw new Error('Failed to find refresh token');
    } finally {
      connection.release();
    }
  }

  /**
   * Update the last_used_at timestamp
   * This helps with security monitoring and cleanup
   */
  async updateLastUsed(tokenId) {
    const connection = await db.getConnection();
    
    try {
      const query = `
        UPDATE refresh_tokens 
        SET last_used_at = NOW()
        WHERE id = ?
      `;
      
      await connection.execute(query, [tokenId]);
      
    } catch (error) {
      console.error('Error updating last used timestamp:', error);
      // Don't throw here - this is not critical to the main operation
    } finally {
      connection.release();
    }
  }

  /**
   * Rotate a refresh token
   * This creates a new token and revokes the old one. Token rotation
   * is a security best practice that limits the window of opportunity
   * if a token is compromised.
   */
  async rotate(oldToken, req) {
    const connection = await db.getConnection();
    
    try {
      await connection.beginTransaction();
      
      // Find the existing token
      const existingToken = await this.findByToken(oldToken);
      if (!existingToken) {
        throw new Error('Invalid refresh token');
      }
      
      // Check if the user account is still active
      if (existingToken.user_status !== 'active') {
        throw new Error('User account is not active');
      }
      
      // Revoke the old token
      await this.revokeToken(oldToken);
      
      // Create a new token in the same family
      const newTokenData = await this.create(
        existingToken.user_id, 
        req, 
        existingToken.family_id
      );
      
      await connection.commit();
      
      return {
        ...newTokenData,
        userId: existingToken.user_id,
        email: existingToken.email,
        username: existingToken.username
      };
      
    } catch (error) {
      await connection.rollback();
      console.error('Error rotating refresh token:', error);
      throw error;
    } finally {
      connection.release();
    }
  }

  /**
   * Revoke a single refresh token
   * This marks the token as revoked without deleting it (for audit purposes)
   */
  async revokeToken(token) {
    const connection = await db.getConnection();
    
    try {
      const tokenHash = this.hashToken(token);
      
      const query = `
        UPDATE refresh_tokens 
        SET is_revoked = TRUE, revoked_at = NOW()
        WHERE token_hash = ?
      `;
      
      const [result] = await connection.execute(query, [tokenHash]);
      
      return result.affectedRows > 0;
      
    } catch (error) {
      console.error('Error revoking refresh token:', error);
      throw new Error('Failed to revoke refresh token');
    } finally {
      connection.release();
    }
  }

  /**
   * Revoke all tokens in a family
   * This is used when we detect a potential security breach
   */
  async revokeFamilyTokens(familyId) {
    const connection = await db.getConnection();
    
    try {
      const query = `
        UPDATE refresh_tokens 
        SET is_revoked = TRUE, revoked_at = NOW()
        WHERE family_id = ? AND is_revoked = FALSE
      `;
      
      const [result] = await connection.execute(query, [familyId]);
      
      return result.affectedRows;
      
    } catch (error) {
      console.error('Error revoking family tokens:', error);
      throw new Error('Failed to revoke family tokens');
    } finally {
      connection.release();
    }
  }

  /**
   * Revoke all tokens for a user
   * This is used during logout or when a user wants to log out all devices
   */
  async revokeAllUserTokens(userId) {
    const connection = await db.getConnection();
    
    try {
      const query = `
        UPDATE refresh_tokens 
        SET is_revoked = TRUE, revoked_at = NOW()
        WHERE user_id = ? AND is_revoked = FALSE
      `;
      
      const [result] = await connection.execute(query, [userId]);
      
      return result.affectedRows;
      
    } catch (error) {
      console.error('Error revoking all user tokens:', error);
      throw new Error('Failed to revoke user tokens');
    } finally {
      connection.release();
    }
  }

  /**
   * Get all active sessions for a user
   * This allows users to see which devices have access to their account
   */
  async getUserSessions(userId) {
    const connection = await db.getConnection();
    
    try {
      const query = `
        SELECT 
          id, browser, os, device, ip_address,
          created_at, last_used_at, expires_at
        FROM refresh_tokens
        WHERE user_id = ? 
          AND is_revoked = FALSE 
          AND expires_at > NOW()
        ORDER BY last_used_at DESC
      `;
      
      const [rows] = await connection.execute(query, [userId]);
      
      return rows;
      
    } catch (error) {
      console.error('Error getting user sessions:', error);
      throw new Error('Failed to get user sessions');
    } finally {
      connection.release();
    }
  }

  /**
   * Clean up expired and old revoked tokens
   * This prevents the database from growing indefinitely
   */
  async cleanup() {
    const connection = await db.getConnection();
    
    try {
      // Delete tokens that expired more than 7 days ago
      // We keep them for a week for audit purposes
      const cleanupDate = new Date();
      cleanupDate.setDate(cleanupDate.getDate() - 7);
      
      const query = `
        DELETE FROM refresh_tokens 
        WHERE (expires_at < ? OR revoked_at < ?)
      `;
      
      const [result] = await connection.execute(query, [cleanupDate, cleanupDate]);
      
      if (result.affectedRows > 0) {
        console.log(`Cleaned up ${result.affectedRows} old refresh tokens`);
      }
      
      return result.affectedRows;
      
    } catch (error) {
      console.error('Error during token cleanup:', error);
      // Don't throw - cleanup failures shouldn't break the application
    } finally {
      connection.release();
    }
  }

  /**
   * Start the automatic cleanup scheduler
   * This runs cleanup periodically in the background
   */
  startCleanupScheduler() {
    // Run cleanup immediately on startup
    this.cleanup();
    
    // Then run it periodically
    setInterval(() => {
      this.cleanup();
    }, this.CLEANUP_INTERVAL);
    
    console.log('Refresh token cleanup scheduler started');
  }

  /**
   * Get token statistics for monitoring
   * Useful for understanding usage patterns and detecting anomalies
   */
  async getTokenStats() {
    const connection = await db.getConnection();
    
    try {
      const query = `
        SELECT 
          COUNT(*) as total_tokens,
          COUNT(CASE WHEN is_revoked = FALSE AND expires_at > NOW() THEN 1 END) as active_tokens,
          COUNT(CASE WHEN is_revoked = TRUE THEN 1 END) as revoked_tokens,
          COUNT(CASE WHEN expires_at <= NOW() THEN 1 END) as expired_tokens,
          COUNT(DISTINCT user_id) as users_with_tokens,
          COUNT(DISTINCT family_id) as token_families
        FROM refresh_tokens
      `;
      
      const [rows] = await connection.execute(query);
      
      return rows[0];
      
    } catch (error) {
      console.error('Error getting token statistics:', error);
      throw new Error('Failed to get token statistics');
    } finally {
      connection.release();
    }
  }
}

// Export a singleton instance
module.exports = new RefreshToken();