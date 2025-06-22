const { verifyAccessToken, extractTokenFromHeader } = require('../utils/tokenUtils');
const User = require('../models/User');

// Middleware to authenticate requests using access tokens
const authenticateToken = async (req, res, next) => {
    try {
        // Extract token from Authorization header
        const authHeader = req.headers.authorization;
        const token = extractTokenFromHeader(authHeader);

        // Verify token
        const decoded = verifyAccessToken(token);

        // Get fresh user data from database
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if account is active
        if (user.account_status !== 'active') {
            return res.status(401).json({
                success: false,
                message: 'Account is not active'
            });
        }

        // Check if account is locked
        const isLocked = await User.isAccountLocked(user);
        if (isLocked) {
            return res.status(401).json({
                success: false,
                message: 'Account is temporarily locked'
            });
        }

        // Attach user info to request object
        req.user = {
            id: user.id,
            email: user.email,
            accountStatus: user.account_status,
            emailVerified: user.email_verified
        };

        next();

    } catch (error) {
        console.error('Authentication error:', error.message);
        
        // Determine specific error type
        if (error.message.includes('expired')) {
            return res.status(401).json({
                success: false,
                message: 'Token expired',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        if (error.message.includes('invalid')) {
            return res.status(401).json({
                success: false,
                message: 'Invalid token',
                code: 'INVALID_TOKEN'
            });
        }

        return res.status(401).json({
            success: false,
            message: 'Authentication failed',
            code: 'AUTH_FAILED'
        });
    }
};

// Optional authentication (doesn't fail if no token)
const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader) {
            req.user = null;
            return next();
        }

        const token = extractTokenFromHeader(authHeader);
        const decoded = verifyAccessToken(token);
        const user = await User.findById(decoded.userId);

        if (user && user.account_status === 'active') {
            req.user = {
                id: user.id,
                email: user.email,
                accountStatus: user.account_status,
                emailVerified: user.email_verified
            };
        } else {
            req.user = null;
        }

        next();

    } catch (error) {
        // For optional auth, we don't fail on token errors
        req.user = null;
        next();
    }
};

// Middleware to check if user's email is verified
const requireEmailVerification = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }

    if (!req.user.emailVerified) {
        return res.status(403).json({
            success: false,
            message: 'Email verification required',
            code: 'EMAIL_NOT_VERIFIED'
        });
    }

    next();
};

// Middleware to check user roles (for future use)
const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        // For now, we'll just check if user is active
        // You can extend this when you add role-based permissions
        if (req.user.accountStatus !== 'active') {
            return res.status(403).json({
                success: false,
                message: 'Insufficient permissions'
            });
        }

        next();
    };
};

// Get user IP address (considering proxies)
const getClientIP = (req) => {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
           req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] ||
           'unknown';
};

// Get user agent
const getUserAgent = (req) => {
    return req.headers['user-agent'] || 'unknown';
};

module.exports = {
    authenticateToken,
    optionalAuth,
    requireEmailVerification,
    requireRole,
    getClientIP,
    getUserAgent
};