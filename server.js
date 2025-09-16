require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();
const PORT = process.env.PORT || 3000;

// MySQL connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'smartbugle',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test DB connection on startup
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

// Utility: classify heart rate
const classifyHeartRate = (heartRate) => {
    if (heartRate < 60) return 'low';
    if (heartRate > 100) return 'high';
    return 'normal';
};

// Middleware
app.use(cors());
app.use(express.json());

/**
 * GET /api/health
 * Health check for API + DB
 */
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

/**
 * POST /api/register
 * Register new user (password hashed)
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

        // Check if user exists
        const [existingUsers] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({
                status: 'error',
                message: 'User already exists'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

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
 * POST /api/login
 * Validate user credentials (no tokens returned)
 */
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ status: 'error', message: 'Email and password required' });
    }

    try {
        const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
        }

        // Return user info only (no token)
        res.json({
            status: 'success',
            message: 'Login successful',
            data: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ status: 'error', message: 'Server error' });
    }
});

/**
 * POST /api/heart-rate/live
 * Save current heart rate. Body: { userId, heartRate }
 */
app.post('/api/heart-rate/live', async (req, res) => {
    const { userId, heartRate } = req.body;

    if (!userId || heartRate === undefined) {
        return res.status(400).json({ status: 'error', message: 'userId and heartRate are required' });
    }

    if (isNaN(heartRate) || heartRate < 30 || heartRate > 220) {
        return res.status(400).json({ status: 'error', message: 'Heart rate must be a number between 30 and 220' });
    }

    try {
        const [users] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        const status = classifyHeartRate(Number(heartRate));
        await pool.execute(
            'INSERT INTO heart_rates (user_id, heart_rate, status, timestamp) VALUES (?, ?, ?, ?)',
            [userId, heartRate, status, new Date()]
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
 * GET /api/heart-rate/live/:userId
 * Get latest heart rate for user
 */
app.get('/api/heart-rate/live/:userId', async (req, res) => {
    const { userId } = req.params;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'userId is required' });
    }

    try {
        const [users] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        const [heartRates] = await pool.execute(
            'SELECT heart_rate, status, timestamp FROM heart_rates WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1',
            [userId]
        );

        if (heartRates.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No heart rate data found for this user' });
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
 * GET /api/heart-rate/history/:userId
 * Query params: startDate (ISO), endDate (ISO), limit, page
 */
app.get('/api/heart-rate/history/:userId', async (req, res) => {
    const { userId } = req.params;
    let { startDate, endDate, limit = 100, page = 1 } = req.query;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'userId is required' });
    }

    limit = parseInt(limit);
    page = parseInt(page);
    const offset = (page - 1) * limit;

    try {
        const [users] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        let query = 'SELECT heart_rate, status, timestamp FROM heart_rates WHERE user_id = ?';
        const params = [userId];

        if (startDate) {
            query += ' AND timestamp >= ?';
            params.push(new Date(startDate));
        }
        if (endDate) {
            query += ' AND timestamp <= ?';
            params.push(new Date(endDate));
        }

        // ⚡ FIX: Inject limit & offset as raw integers
        query += ` ORDER BY timestamp DESC LIMIT ${limit} OFFSET ${offset}`;

        const [heartRates] = await pool.execute(query, params);

        // Count for pagination
        let countQuery = 'SELECT COUNT(*) as totalCount FROM heart_rates WHERE user_id = ?';
        const countParams = [userId];
        if (startDate) {
            countQuery += ' AND timestamp >= ?';
            countParams.push(new Date(startDate));
        }
        if (endDate) {
            countQuery += ' AND timestamp <= ?';
            countParams.push(new Date(endDate));
        }
        const [countResult] = await pool.execute(countQuery, countParams);
        const totalCount = countResult[0].totalCount;
        const totalPages = Math.ceil(totalCount / limit);

        res.json({
            status: 'success',
            data: heartRates,
            pagination: { page, limit, totalCount, totalPages }
        });
    } catch (error) {
        console.error('Heart rate history error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch heart rate history' });
    }
});


/**
 * GET /api/heart-rate/stats/:userId
 * Query params: startDate, endDate
 */
app.get('/api/heart-rate/stats/:userId', async (req, res) => {
    const { userId } = req.params;
    const { startDate, endDate } = req.query;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'userId is required' });
    }

    try {
        const [users] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

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
        const params = [userId];

        if (startDate) {
            query += ' AND timestamp >= ?';
            params.push(new Date(startDate));
        }
        if (endDate) {
            query += ' AND timestamp <= ?';
            params.push(new Date(endDate));
        }

        const [stats] = await pool.execute(query, params);

        if (stats[0].count === 0) {
            return res.status(404).json({ status: 'error', message: 'No heart rate data found for the specified period' });
        }

        res.json({ status: 'success', data: stats[0] });
    } catch (error) {
        console.error('Heart rate stats error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch heart rate statistics' });
    }
});

/**
 * POST /api/fall-detection
 * Body: { userId, direction, severity }
 */
app.post('/api/fall-detection', async (req, res) => {
    const { userId, direction, severity } = req.body;

    if (!userId || !direction || !severity) {
        return res.status(400).json({ status: 'error', message: 'userId, direction, and severity are required' });
    }

    if (!['forward', 'backward', 'left', 'right'].includes(direction)) {
        return res.status(400).json({ status: 'error', message: 'Direction must be one of: forward, backward, left, right' });
    }

    if (!['mild', 'moderate', 'severe'].includes(severity)) {
        return res.status(400).json({ status: 'error', message: 'Severity must be one of: mild, moderate, severe' });
    }

    try {
        const [users] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        await pool.execute(
            'INSERT INTO fall_detections (user_id, direction, severity, timestamp) VALUES (?, ?, ?, ?)',
            [userId, direction, severity, new Date()]
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
 * GET /api/fall-detection/history/:userId
 * Query params: startDate, endDate, limit, page
 */
app.get('/api/fall-detection/history/:userId', async (req, res) => {
    const { userId } = req.params;
    let { startDate, endDate, limit = 10, page = 1 } = req.query;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'userId is required' });
    }

    limit = parseInt(limit);
    page = parseInt(page);
    const offset = (page - 1) * limit;

    try {
        const [users] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        let query = 'SELECT id, direction, severity, timestamp FROM fall_detections WHERE user_id = ?';
        const params = [userId];

        if (startDate) {
            query += ' AND timestamp >= ?';
            params.push(new Date(startDate));
        }
        if (endDate) {
            query += ' AND timestamp <= ?';
            params.push(new Date(endDate));
        }

        // ⚡ FIX: use integers directly
        query += ` ORDER BY timestamp DESC LIMIT ${limit} OFFSET ${offset}`;

        const [fallDetections] = await pool.execute(query, params);

        // Count query
        let countQuery = 'SELECT COUNT(*) as totalCount FROM fall_detections WHERE user_id = ?';
        const countParams = [userId];
        if (startDate) {
            countQuery += ' AND timestamp >= ?';
            countParams.push(new Date(startDate));
        }
        if (endDate) {
            countQuery += ' AND timestamp <= ?';
            countParams.push(new Date(endDate));
        }
        const [countResult] = await pool.execute(countQuery, countParams);
        const totalCount = countResult[0].totalCount;
        const totalPages = Math.ceil(totalCount / limit);

        res.json({
            status: 'success',
            data: fallDetections,
            pagination: { page, limit, totalCount, totalPages }
        });
    } catch (error) {
        console.error('Fall detection history error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch fall detection history' });
    }
});


/**
 * POST /api/test-data/:userId
 * Generate sample heart rate and fall detection records for testing
 * Body: { count } (optional, default 50)
 */
app.post('/api/test-data/:userId', async (req, res) => {
    const { userId } = req.params;
    const { count = 50 } = req.body;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'userId is required' });
    }

    try {
        const [users] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        // Delete existing test data for this user
        await pool.execute('DELETE FROM heart_rates WHERE user_id = ?', [userId]);
        await pool.execute('DELETE FROM fall_detections WHERE user_id = ?', [userId]);

        // Generate heart rates
        const heartRateValues = [];
        const now = Date.now();
        for (let i = 0; i < count; i++) {
            const hr = Math.floor(Math.random() * 80) + 50; // 50 - 129
            const status = classifyHeartRate(hr);
            // spread over last 7 days
            const timestamp = new Date(now - (i * 1000 * 60 * 60 * 24 * 7 / count));
            heartRateValues.push([userId, hr, status, timestamp]);
        }

        if (heartRateValues.length > 0) {
            await pool.query(
                'INSERT INTO heart_rates (user_id, heart_rate, status, timestamp) VALUES ?',
                [heartRateValues]
            );
        }

        // Fall detections ~10% of count
        const fallDetectionValues = [];
        const fallCount = Math.floor(count * 0.1);
        const directions = ['forward','backward','left','right'];
        const severities = ['mild','moderate','severe'];
        for (let i = 0; i < fallCount; i++) {
            const direction = directions[Math.floor(Math.random() * directions.length)];
            const severity = severities[Math.floor(Math.random() * severities.length)];
            const timestamp = new Date(now - (i * 1000 * 60 * 60 * 24 * 7 / Math.max(1, fallCount)));
            fallDetectionValues.push([userId, direction, severity, timestamp]);
        }

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

// Start server
app.listen(PORT, () => {
    console.log(`Heart Rate Monitor API running on http://localhost:${PORT}`);
});