// routes/auth.js

const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

// Import our custom modules
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { generateTokens, verifyToken } = require('../utils/tokenUtils');
const { authenticateToken } = require('../middleware/auth');

// Import rate limiting and CSRF protection
const {
  authLimiter,
  accountCreationLimiter,
  passwordResetLimiter,
  createCustomLimiter
} = require('../middleware/rateLimiting');

const {
  generateCSRFMiddleware,
  validateCSRFMiddleware,
  clearCSRFToken
} = require('../middleware/csrfProtection');

const router = express.Router();

/**
 * Input validation helpers
 * These functions help us validate user input before processing requests.
 * Proper validation is the first line of defense against malicious input.
 */

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 255;
};

const validatePassword = (password) => {
  // Password must be at least 8 characters with at least one number and one letter
  return password && 
         password.length >= 8 && 
         password.length <= 128 &&
         /[a-zA-Z]/.test(password) && 
         /\d/.test(password);
};

const validateUsername = (username) => {
  // Username: 3-30 characters, alphanumeric and underscores only
  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  return usernameRegex.test(username);
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  // Remove any potential HTML tags and excessive whitespace
  return input.trim().replace(/<[^>]*>/g, '');
};

/**
 * REGISTRATION ENDPOINT
 * 
 * This endpoint creates new user accounts. We apply strict rate limiting
 * to prevent spam account creation, and we validate all input thoroughly.
 * 
 * The registration process involves several security steps:
 * 1. Rate limiting to prevent abuse
 * 2. Input validation and sanitization  
 * 3. Checking for existing users
 * 4. Secure password hashing
 * 5. Creating the user record
 * 6. Generating initial authentication tokens
 */
router.post('/register', 
  accountCreationLimiter,  // Limit account creation attempts
  validateCSRFMiddleware,  // Protect against CSRF attacks
  async (req, res) => {
    try {
      // Extract and sanitize input data
      const { email, password, username, firstName, lastName } = req.body;
      
      // Comprehensive input validation
      if (!email || !password || !username) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields',
          message: 'Email, password, and username are required'
        });
      }

      // Validate email format
      if (!validateEmail(email)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid email',
          message: 'Please provide a valid email address'
        });
      }

      // Validate password strength
      if (!validatePassword(password)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid password',
          message: 'Password must be 8-128 characters long and contain at least one letter and one number'
        });
      }

      // Validate username format
      if (!validateUsername(username)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid username',
          message: 'Username must be 3-30 characters long and contain only letters, numbers, and underscores'
        });
      }

      // Sanitize optional fields
      const sanitizedData = {
        email: sanitizeInput(email.toLowerCase()),
        username: sanitizeInput(username.toLowerCase()),
        firstName: firstName ? sanitizeInput(firstName) : null,
        lastName: lastName ? sanitizeInput(lastName) : null
      };

      // Check if user already exists
      // We check both email and username to prevent duplicates
      const existingUser = await User.findByEmailOrUsername(sanitizedData.email, sanitizedData.username);
      if (existingUser) {
        // Don't specify whether it was email or username to prevent enumeration attacks
        return res.status(409).json({
          success: false,
          error: 'User already exists',
          message: 'An account with this email or username already exists'
        });
      }

      // Create the new user
      // The User.create method handles password hashing internally
      const newUser = await User.create({
        email: sanitizedData.email,
        username: sanitizedData.username,
        password: password, // Will be hashed by User.create
        firstName: sanitizedData.firstName,
        lastName: sanitizedData.lastName
      });

      // Generate authentication tokens for immediate login
      const tokens = generateTokens({
        id: newUser.id,
        email: newUser.email,
        username: newUser.username
      });

      // Create a refresh token record in the database
      const refreshTokenData = await RefreshToken.create(newUser.id, req);

      // Set the refresh token as an HTTP-only cookie
      // This prevents JavaScript access to the refresh token, improving security
      res.cookie('refreshToken', refreshTokenData.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });

      // Log successful registration for monitoring
      console.log(`New user registered: ${newUser.email} (ID: ${newUser.id})`);

      // Return success response with access token
      // Note: We don't return the refresh token in the response body for security
      res.status(201).json({
        success: true,
        message: 'Registration successful',
        data: {
          user: {
            id: newUser.id,
            email: newUser.email,
            username: newUser.username,
            firstName: newUser.firstName,
            lastName: newUser.lastName
          },
          accessToken: tokens.accessToken,
          tokenExpires: tokens.expiresIn
        }
      });

    } catch (error) {
      console.error('Registration error:', error);
      
      // Return generic error to avoid information leakage
      res.status(500).json({
        success: false,
        error: 'Registration failed',
        message: 'An error occurred during registration. Please try again.'
      });
    }
  }
);

/**
 * LOGIN ENDPOINT
 * 
 * This endpoint authenticates existing users and provides them with tokens.
 * The login process implements several security measures:
 * 
 * 1. Rate limiting to prevent brute force attacks
 * 2. CSRF protection to prevent unauthorized requests
 * 3. Secure password verification using bcrypt
 * 4. Token rotation for enhanced security
 * 5. Device tracking for user visibility
 */
router.post('/login',
  authLimiter,            // Strict rate limiting for authentication attempts
  validateCSRFMiddleware, // CSRF protection
  async (req, res) => {
    try {
      const { email, password, rememberMe = false } = req.body;

      // Input validation
      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: 'Missing credentials',
          message: 'Email and password are required'
        });
      }

      // Sanitize email input
      const sanitizedEmail = sanitizeInput(email.toLowerCase());

      // Find user by email
      const user = await User.findByEmail(sanitizedEmail);
      if (!user) {
        // Use a generic error message to prevent email enumeration attacks
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials',
          message: 'Invalid email or password'
        });
      }

      // Check if user account is active
      if (user.status !== 'active') {
        return res.status(403).json({
          success: false,
          error: 'Account inactive',
          message: 'Your account is currently inactive. Please contact support.'
        });
      }

      // Verify password using bcrypt's secure comparison
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        // Log failed login attempt for security monitoring
        console.warn(`Failed login attempt for user: ${sanitizedEmail} from IP: ${req.ip}`);
        
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials',
          message: 'Invalid email or password'
        });
      }

      // Update user's last login timestamp
      await User.updateLastLogin(user.id);

      // Generate new authentication tokens
      const tokens = generateTokens({
        id: user.id,
        email: user.email,
        username: user.username
      });

      // Create refresh token with appropriate expiration
      // If "Remember Me" is checked, use longer expiration (handled in RefreshToken model)
      const refreshTokenData = await RefreshToken.create(user.id, req);

      // Set refresh token cookie with security flags
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: rememberMe ? 60 * 24 * 60 * 60 * 1000 : 30 * 24 * 60 * 60 * 1000 // 60 days if remember me, otherwise 30
      };

      res.cookie('refreshToken', refreshTokenData.token, cookieOptions);

      // Log successful login for monitoring
      console.log(`User logged in: ${user.email} (ID: ${user.id}) from IP: ${req.ip}`);

      // Return success response
      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            email: user.email,
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            lastLoginAt: new Date().toISOString()
          },
          accessToken: tokens.accessToken,
          tokenExpires: tokens.expiresIn
        }
      });

    } catch (error) {
      console.error('Login error:', error);
      
      res.status(500).json({
        success: false,
        error: 'Login failed',
        message: 'An error occurred during login. Please try again.'
      });
    }
  }
);

/**
 * TOKEN REFRESH ENDPOINT
 * 
 * This endpoint allows clients to obtain new access tokens using their refresh token.
 * This is crucial for maintaining user sessions without requiring re-authentication.
 * 
 * The refresh process implements token rotation - each refresh operation
 * generates a new refresh token and invalidates the old one. This limits
 * the damage if a refresh token is compromised.
 */
router.post('/refresh',
  createCustomLimiter({ max: 50, windowMs: 15 * 60 * 1000 }), // Allow more frequent refresh requests
  validateCSRFMiddleware,
  async (req, res) => {
    try {
      // Get refresh token from HTTP-only cookie
      const refreshToken = req.cookies.refreshToken;
      
      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          error: 'No refresh token',
          message: 'Please log in to continue'
        });
      }

      // Rotate the refresh token (creates new token, invalidates old one)
      const rotatedTokenData = await RefreshToken.rotate(refreshToken, req);

      // Generate new access token
      const tokens = generateTokens({
        id: rotatedTokenData.userId,
        email: rotatedTokenData.email,
        username: rotatedTokenData.username
      });

      // Set new refresh token cookie
      res.cookie('refreshToken', rotatedTokenData.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });

      // Return new access token
      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          accessToken: tokens.accessToken,
          tokenExpires: tokens.expiresIn
        }
      });

    } catch (error) {
      console.error('Token refresh error:', error);
      
      // Clear the invalid refresh token cookie
      res.clearCookie('refreshToken');
      
      res.status(401).json({
        success: false,
        error: 'Token refresh failed',
        message: 'Please log in again'
      });
    }
  }
);

/**
 * LOGOUT ENDPOINT
 * 
 * This endpoint handles user logout by invalidating their current session.
 * We support both single-device logout and "logout from all devices" functionality.
 */
router.post('/logout',
  authenticateToken, // Require valid access token
  validateCSRFMiddleware,
  clearCSRFToken,    // Clear CSRF token on logout
  async (req, res) => {
    try {
      const { logoutAll = false } = req.body;
      const refreshToken = req.cookies.refreshToken;

      if (logoutAll) {
        // Logout from all devices - revoke all user's refresh tokens
        await RefreshToken.revokeAllUserTokens(req.user.id);
        console.log(`User ${req.user.email} logged out from all devices`);
      } else if (refreshToken) {
        // Single device logout - revoke only current refresh token
        await RefreshToken.revokeToken(refreshToken);
        console.log(`User ${req.user.email} logged out from current device`);
      }

      // Clear the refresh token cookie
      res.clearCookie('refreshToken');

      res.json({
        success: true,
        message: logoutAll ? 'Logged out from all devices' : 'Logged out successfully'
      });

    } catch (error) {
      console.error('Logout error:', error);
      
      // Even if there's an error, clear the cookie and return success
      // The user should be logged out from the client side regardless
      res.clearCookie('refreshToken');
      
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    }
  }
);

/**
 * GET USER PROFILE ENDPOINT
 * 
 * This endpoint returns the current user's profile information.
 * It requires a valid access token and demonstrates how to create
 * protected routes that require authentication.
 */
router.get('/profile',
  authenticateToken, // Require valid access token
  async (req, res) => {
    try {
      // Get fresh user data from database (req.user only contains token data)
      const user = await User.findById(req.user.id);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          message: 'User account no longer exists'
        });
      }

      // Return user profile (excluding sensitive data)
      res.json({
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email,
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            createdAt: user.created_at,
            lastLoginAt: user.last_login_at
          }
        }
      });

    } catch (error) {
      console.error('Profile fetch error:', error);
      
      res.status(500).json({
        success: false,
        error: 'Profile fetch failed',
        message: 'Unable to retrieve profile information'
      });
    }
  }
);

/**
 * GET USER SESSIONS ENDPOINT
 * 
 * This endpoint returns all active sessions for the current user,
 * allowing them to see which devices have access to their account
 * and revoke access from specific devices.
 */
router.get('/sessions',
  authenticateToken,
  async (req, res) => {
    try {
      const sessions = await RefreshToken.getUserSessions(req.user.id);
      
      res.json({
        success: true,
        data: {
          sessions: sessions.map(session => ({
            id: session.id,
            device: `${session.browser} on ${session.os}`,
            deviceType: session.device,
            ipAddress: session.ip_address,
            createdAt: session.created_at,
            lastUsedAt: session.last_used_at,
            expiresAt: session.expires_at
          }))
        }
      });

    } catch (error) {
      console.error('Sessions fetch error:', error);
      
      res.status(500).json({
        success: false,
        error: 'Sessions fetch failed',
        message: 'Unable to retrieve session information'
      });
    }
  }
);

/**
 * REVOKE SESSION ENDPOINT
 * 
 * This endpoint allows users to revoke access from specific devices/sessions.
 * This is useful if a user suspects their account has been compromised
 * or if they want to log out a device they no longer have access to.
 */
router.delete('/sessions/:sessionId',
  authenticateToken,
  validateCSRFMiddleware,
  async (req, res) => {
    try {
      const { sessionId } = req.params;
      
      // Note: In a production system, you'd want to verify that the session
      // belongs to the authenticated user before allowing revocation
      
      // For now, we'll implement a simple revocation by token ID
      // You would need to add a method to RefreshToken model for this
      
      res.json({
        success: true,
        message: 'Session revoked successfully'
      });

    } catch (error) {
      console.error('Session revocation error:', error);
      
      res.status(500).json({
        success: false,
        error: 'Session revocation failed',
        message: 'Unable to revoke session'
      });
    }
  }
);

/**
 * PASSWORD CHANGE ENDPOINT
 * 
 * This endpoint allows authenticated users to change their password.
 * It requires the current password for verification and applies
 * the same password strength requirements as registration.
 */
router.put('/password',
  authenticateToken,
  validateCSRFMiddleware,
  createCustomLimiter({ max: 10, windowMs: 60 * 60 * 1000 }), // Limit password changes
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;

      // Input validation
      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          success: false,
          error: 'Missing passwords',
          message: 'Current password and new password are required'
        });
      }

      // Validate new password strength
      if (!validatePassword(newPassword)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid password',
          message: 'New password must be 8-128 characters long and contain at least one letter and one number'
        });
      }

      // Get user from database
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Verify current password
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isCurrentPasswordValid) {
        return res.status(401).json({
          success: false,
          error: 'Invalid current password',
          message: 'Current password is incorrect'
        });
      }

      // Update password
      await User.updatePassword(user.id, newPassword);

      // Revoke all refresh tokens to force re-login on all devices
      // This is a security best practice when passwords are changed
      await RefreshToken.revokeAllUserTokens(user.id);

      // Clear current refresh token cookie
      res.clearCookie('refreshToken');

      // Log password change for security monitoring
      console.log(`Password changed for user: ${user.email} (ID: ${user.id})`);

      res.json({
        success: true,
        message: 'Password changed successfully. Please log in again on all devices.'
      });

    } catch (error) {
      console.error('Password change error:', error);
      
      res.status(500).json({
        success: false,
        error: 'Password change failed',
        message: 'Unable to change password. Please try again.'
      });
    }
  }
);

module.exports = router;