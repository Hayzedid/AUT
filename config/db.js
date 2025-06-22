const mysql = require('mysql2/promise');

// Create connection pool for better performance
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    acquireTimeout: 60000,
    timeout: 60000,
    reconnect: true
});

// Test the connection
const testConnection = async () => {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Database connected successfully');
        connection.release();
        return true;
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        return false;
    }
};

// Helper function to execute queries
const executeQuery = async (query, params = []) => {
    try {
        const [rows] = await pool.execute(query, params);
        return rows;
    } catch (error) {
        console.error('Database query error:', error);
        throw error;
    }
};

// Helper function to get single row
const getOne = async (query, params = []) => {
    try {
        const [rows] = await pool.execute(query, params);
        return rows[0] || null;
    } catch (error) {
        console.error('Database query error:', error);
        throw error;
    }
};

// Cleanup function for graceful shutdown
const closePool = async () => {
    try {
        await pool.end();
        console.log('Database pool closed');
    } catch (error) {
        console.error('Error closing database pool:', error);
    }
};

module.exports = {
    pool,
    executeQuery,
    getOne,
    testConnection,
    closePool
};