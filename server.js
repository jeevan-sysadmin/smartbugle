require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;
const AUTH_KEY = process.env.AUTH_KEY;
const TOKEN_EXPIRY = '1h';

// Basic env check
if (!SECRET_KEY) {
    console.error('Missing JWT_SECRET in environment. Exiting.');
    process.exit(1);
}
if (!AUTH_KEY) {
    console.warn('No AUTH_KEY set in environment. Consider setting one to restrict token generation.');
}

// MySQL connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'heartrate_monitor',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
(async () => {
    try {
        const connection = await pool.getConnection();
        console.log('Connected to MySQL database');
        connection.release();
    } catch (error) {
        console.error('MySQL connection error:', error);
        process.exit(1);
    }
})();

// Heart Rate Status Classification
const classifyHeartRate = (heartRate) => {
    if (heartRate < 60) return 'low';
    if (heartRate > 100) return 'high';
    return 'normal';
};

// Middleware
app.use(cors());
app.use(express.json());

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader || null;

    if (!token) {
        return res.status(401).json({ status: 'error', message: 'Token missing' });
    }

    jwt.verify(token, SECRET_KEY, (err, payload) => {
        if (err) {
            return res.status(403).json({ status: 'error', message: 'Invalid or expired token' });
        }
        req.user = payload;
        next();
    });
};

/**
 * Token Generation API
 * Requires a server-side authKey to prevent abuse
 */
app.post('/api/generate-token', async (req, res) => {
    const { userName, authKey, role } = req.body;

    if (!userName || !authKey) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'Missing required fields (userName, authKey)' 
        });
    }

    // Validate authKey
    if (AUTH_KEY && authKey !== AUTH_KEY) {
        return res.status(403).json({ status: 'error', message: 'Invalid authKey' });
    }

    try {
        const payload = { userName, role: role || 'user' };
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });
        res.json({ 
            status: 'success', 
            data: token, 
            expiresIn: TOKEN_EXPIRY 
        });
    } catch (error) {
        res.status(500).json({ status: 'error', message: 'Token generation failed' });
    }
});

/**
 * User Registration
 */
app.post('/api/register', async (req, res) => {
    const { name, email, phone, password, confirmPassword } = req.body;

    try {
        if (!name || !email || !phone || !password || !confirmPassword) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'All fields are required' 
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Passwords do not match' 
            });
        }

        // Check if user already exists
        const [existingUsers] = await pool.execute(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'User already exists' 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert new user
        const [result] = await pool.execute(
            'INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)',
            [name, email, phone, hashedPassword]
        );

        res.json({
            status: 'success',
            message: 'User registered successfully',
            userId: result.insertId
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ status: 'error', message: 'Registration failed' });
    }
});

/**
 * User Login
 */
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'Email and password required' 
        });
    }

    try {
        // Find user by email
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'User not found' 
            });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Invalid credentials' 
            });
        }

        const payload = { 
            userId: user.id, 
            email: user.email, 
            name: user.name,
            role: 'user' 
        };
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });

        res.json({
            status: 'success',
            message: 'Login successful',
            data: {
                id: user.id,
                name: user.name,
                email: user.email,
                token
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ status: 'error', message: 'Server error' });
    }
});

/**
 * 1. Live Heart Rate API
 * Stores and returns current heart rate with status
 */
app.post('/api/heart-rate/live', authenticateToken, async (req, res) => {
    const { userId, heartRate } = req.body;
    
    if (!userId || !heartRate) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'userId and heartRate are required' 
        });
    }

    if (isNaN(heartRate) || heartRate < 30 || heartRate > 220) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'Heart rate must be a number between 30 and 220' 
        });
    }

    try {
        // Check if user exists
        const [users] = await pool.execute(
            'SELECT id FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'User not found' 
            });
        }

        const status = classifyHeartRate(heartRate);
        
        // Insert heart rate record
        const [result] = await pool.execute(
            'INSERT INTO heart_rates (user_id, heart_rate, status) VALUES (?, ?, ?)',
            [userId, heartRate, status]
        );

        res.json({
            status: 'success',
            message: 'Heart rate recorded successfully',
            data: {
                heartRate,
                status,
                timestamp: new Date()
            }
        });
    } catch (error) {
        console.error('Live heart rate error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to record heart rate' });
    }
});

/**
 * GET Live Heart Rate API
 * Retrieves the latest heart rate for display
 */
app.get('/api/heart-rate/live/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    
    if (!userId) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'userId is required' 
        });
    }

    try {
        // Check if user exists
        const [users] = await pool.execute(
            'SELECT id FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'User not found' 
            });
        }

        // Get the latest heart rate record
        const [heartRates] = await pool.execute(
            'SELECT heart_rate, status, timestamp FROM heart_rates WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1',
            [userId]
        );
            
        if (heartRates.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'No heart rate data found for this user' 
            });
        }

        res.json({
            status: 'success',
            message: 'Latest heart rate retrieved successfully',
            data: heartRates[0]
        });
    } catch (error) {
        console.error('Get live heart rate error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to retrieve heart rate' });
    }
});

/**
 * 2. Heart Rate History API
 * Returns historical heart rate data for a user with filtering options
 */
app.get('/api/heart-rate/history/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    const { startDate, endDate, limit = 100, page = 1 } = req.query;
    
    if (!userId) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'userId is required' 
        });
    }

    try {
        // Build query
        let query = 'SELECT heart_rate, status, timestamp FROM heart_rates WHERE user_id = ?';
        let queryParams = [userId];
        
        // Add date range if provided
        if (startDate || endDate) {
            if (startDate) {
                query += ' AND timestamp >= ?';
                queryParams.push(new Date(startDate));
            }
            if (endDate) {
                query += ' AND timestamp <= ?';
                queryParams.push(new Date(endDate));
            }
        }

        // Add ordering and pagination
        query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
        const offset = (parseInt(page) - 1) * parseInt(limit);
        queryParams.push(parseInt(limit), offset);
        
        // Get heart rate records
        const [heartRates] = await pool.execute(query, queryParams);
            
        // Get total count for pagination
        let countQuery = 'SELECT COUNT(*) as totalCount FROM heart_rates WHERE user_id = ?';
        let countParams = [userId];
        
        if (startDate || endDate) {
            if (startDate) {
                countQuery += ' AND timestamp >= ?';
                countParams.push(new Date(startDate));
            }
            if (endDate) {
                countQuery += ' AND timestamp <= ?';
                countParams.push(new Date(endDate));
            }
        }
        
        const [countResult] = await pool.execute(countQuery, countParams);
        const totalCount = countResult[0].totalCount;
        const totalPages = Math.ceil(totalCount / limit);

        res.json({
            status: 'success',
            data: heartRates,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                totalCount,
                totalPages
            }
        });
    } catch (error) {
        console.error('Heart rate history error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch heart rate history' });
    }
});

/**
 * Heart Rate Statistics API
 * Returns statistics for a user's heart rate over a period
 */
app.get('/api/heart-rate/stats/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    const { startDate, endDate } = req.query;
    
    if (!userId) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'userId is required' 
        });
    }

    try {
        // Build query
        let query = `
            SELECT 
                AVG(heart_rate) as average,
                MIN(heart_rate) as min,
                MAX(heart_rate) as max,
                COUNT(*) as count,
                SUM(CASE WHEN status = 'low' THEN 1 ELSE 0 END) as lowCount,
                SUM(CASE WHEN status = 'normal' THEN 1 ELSE 0 END) as normalCount,
                SUM(CASE WHEN status = 'high' THEN 1 ELSE 0 END) as highCount
            FROM heart_rates 
            WHERE user_id = ?
        `;
        let queryParams = [userId];
        
        // Add date range if provided
        if (startDate || endDate) {
            if (startDate) {
                query += ' AND timestamp >= ?';
                queryParams.push(new Date(startDate));
            }
            if (endDate) {
                query += ' AND timestamp <= ?';
                queryParams.push(new Date(endDate));
            }
        }

        const [stats] = await pool.execute(query, queryParams);

        if (stats[0].count === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'No heart rate data found for the specified period' 
            });
        }

        res.json({
            status: 'success',
            data: stats[0]
        });
    } catch (error) {
        console.error('Heart rate stats error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch heart rate statistics' });
    }
});

/**
 * Fall Detection API
 * Records fall direction and severity
 */
app.post('/api/fall-detection', authenticateToken, async (req, res) => {
    const { userId, direction, severity } = req.body;
    
    if (!userId || !direction || !severity) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'userId, direction, and severity are required' 
        });
    }

    if (!['forward', 'backward', 'left', 'right'].includes(direction)) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'Direction must be one of: forward, backward, left, right' 
        });
    }

    if (!['mild', 'moderate', 'severe'].includes(severity)) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'Severity must be one of: mild, moderate, severe' 
        });
    }

    try {
        // Check if user exists
        const [users] = await pool.execute(
            'SELECT id FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'User not found' 
            });
        }

        // Insert fall detection record
        const [result] = await pool.execute(
            'INSERT INTO fall_detections (user_id, direction, severity) VALUES (?, ?, ?)',
            [userId, direction, severity]
        );

        res.json({
            status: 'success',
            message: 'Fall detection recorded successfully',
            data: {
                direction,
                severity,
                timestamp: new Date()
            }
        });
    } catch (error) {
        console.error('Fall detection error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to record fall detection' });
    }
});

/**
 * Fall Detection History API
 * Returns historical fall detection data for a user
 */
app.get('/api/fall-detection/history/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    const { startDate, endDate, limit = 100, page = 1 } = req.query;
    
    if (!userId) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'userId is required' 
        });
    }

    try {
        // Build query
        let query = 'SELECT direction, severity, timestamp FROM fall_detections WHERE user_id = ?';
        let queryParams = [userId];
        
        // Add date range if provided
        if (startDate || endDate) {
            if (startDate) {
                query += ' AND timestamp >= ?';
                queryParams.push(new Date(startDate));
            }
            if (endDate) {
                query += ' AND timestamp <= ?';
                queryParams.push(new Date(endDate));
            }
        }

        // Add ordering and pagination
        query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
        const offset = (parseInt(page) - 1) * parseInt(limit);
        queryParams.push(parseInt(limit), offset);
        
        // Get fall detection records
        const [fallDetections] = await pool.execute(query, queryParams);
            
        // Get total count for pagination
        let countQuery = 'SELECT COUNT(*) as totalCount FROM fall_detections WHERE user_id = ?';
        let countParams = [userId];
        
        if (startDate || endDate) {
            if (startDate) {
                countQuery += ' AND timestamp >= ?';
                countParams.push(new Date(startDate));
            }
            if (endDate) {
                countQuery += ' AND timestamp <= ?';
                countParams.push(new Date(endDate));
            }
        }
        
        const [countResult] = await pool.execute(countQuery, countParams);
        const totalCount = countResult[0].totalCount;
        const totalPages = Math.ceil(totalCount / limit);

        res.json({
            status: 'success',
            data: fallDetections,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                totalCount,
                totalPages
            }
        });
    } catch (error) {
        console.error('Fall detection history error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch fall detection history' });
    }
});

/**
 * Test Data Generation Endpoint
 * Creates sample heart rate and fall detection data for testing
 */
app.post('/api/test-data/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    const { count = 50 } = req.body;
    
    if (!userId) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'userId is required' 
        });
    }

    try {
        // Check if user exists
        const [users] = await pool.execute(
            'SELECT id FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'User not found' 
            });
        }

        // Delete existing test data for this user
        await pool.execute('DELETE FROM heart_rates WHERE user_id = ?', [userId]);
        await pool.execute('DELETE FROM fall_detections WHERE user_id = ?', [userId]);
        
        // Generate test heart rate data
        const heartRateValues = [];
        const now = new Date();
        const directions = ['forward', 'backward', 'left', 'right'];
        const severities = ['mild', 'moderate', 'severe'];
        
        for (let i = 0; i < count; i++) {
            // Generate random heart rate between 50 and 130
            const heartRate = Math.floor(Math.random() * 80) + 50;
            const status = classifyHeartRate(heartRate);
            
            // Create timestamp (spread over the last 7 days)
            const timestamp = new Date(now - (i * 1000 * 60 * 60 * 24 * 7 / count));
            
            heartRateValues.push([userId, heartRate, status, timestamp]);
        }
        
        // Insert test heart rate data
        if (heartRateValues.length > 0) {
            await pool.query(
                'INSERT INTO heart_rates (user_id, heart_rate, status, timestamp) VALUES ?',
                [heartRateValues]
            );
        }
        
        // Generate test fall detection data (about 10% of heart rate records)
        const fallDetectionValues = [];
        const fallCount = Math.floor(count * 0.1);
        
        for (let i = 0; i < fallCount; i++) {
            const direction = directions[Math.floor(Math.random() * directions.length)];
            const severity = severities[Math.floor(Math.random() * severities.length)];
            const timestamp = new Date(now - (i * 1000 * 60 * 60 * 24 * 7 / fallCount));
            
            fallDetectionValues.push([userId, direction, severity, timestamp]);
        }
        
        // Insert test fall detection data
        if (fallDetectionValues.length > 0) {
            await pool.query(
                'INSERT INTO fall_detections (user_id, direction, severity, timestamp) VALUES ?',
                [fallDetectionValues]
            );
        }
        
        res.json({
            status: 'success',
            message: `Generated ${count} test heart rate records and ${fallCount} fall detection records`,
            heartRateCount: count,
            fallDetectionCount: fallCount
        });
    } catch (error) {
        console.error('Test data generation error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to generate test data' });
    }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        await pool.execute('SELECT 1');
        res.json({ 
            status: 'success', 
            message: 'API and database are running', 
            timestamp: new Date().toISOString() 
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            message: 'Database connection failed',
            timestamp: new Date().toISOString() 
        });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Heart Rate Monitor API running on http://localhost:${PORT}`);
});