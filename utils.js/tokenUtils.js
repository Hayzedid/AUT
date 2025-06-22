const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Generate access token (short-lived, stored in memory)
const generateAccessToken = (user) => {
    const payload = {
        userId: user.id,
        email: user.email,
        accountStatus: user.account_status,
        tokenType: 'access'
    };

    return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRY || '15m',
        issuer: 'your-app-name',
        audience: 'your-app-users'
    });
};

// Generate refresh token family (unique identifier for token rotation)
const generateTokenFamily = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Generate refresh token (long-lived, stored in HTTP-only cookie)
const generateRefreshToken = (user, tokenFamily) => {
    const payload = {
        userId: user.id,
        tokenFamily: tokenFamily,
        tokenType: 'refresh'
    };

    return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRY || '7d',
        issuer: 'your-app-name',
        audience: 'your-app-users'
    });
};

// Verify access token
const verifyAccessToken = (token) => {
    try {
        return jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
            issuer: 'your-app-name',
            audience: 'your-app-users'
        });
    } catch (error) {
        throw new Error(`Invalid access token: ${error.message}`);
    }
};

// Verify refresh token
const verifyRefreshToken = (token) => {
    try {
        return jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
            issuer: 'your-app-name',
            audience: 'your-app-users'
        });
    } catch (error) {
        throw new Error(`Invalid refresh token: ${error.message}`);
    }
};

// Extract token from Authorization header
const extractTokenFromHeader = (authHeader) => {
    if (!authHeader) {
        throw new Error('No authorization header provided');
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        throw new Error('Invalid authorization header format');
    }

    return parts[1];
};

// Generate CSRF token
const generateCSRFToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Get token expiration time in seconds
const getTokenExpirationTime = (token) => {
    try {
        const decoded = jwt.decode(token);
        return decoded.exp;
    } catch (error) {
        return null;
    }
};

// Check if token is about to expire (within 5 minutes)
const isTokenNearExpiry = (token, bufferMinutes = 5) => {
    const exp = getTokenExpirationTime(token);
    if (!exp) return true;
    
    const now = Math.floor(Date.now() / 1000);
    const bufferSeconds = bufferMinutes * 60;
    
    return (exp - now) <= bufferSeconds;
};

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    generateTokenFamily,
    verifyAccessToken,
    verifyRefreshToken,
    extractTokenFromHeader,
    generateCSRFToken,
    getTokenExpirationTime,
    isTokenNearExpiry
};