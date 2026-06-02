const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Multer Configuration for File Upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
    }
});
const upload = multer({ storage: storage });

// Database Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'acsc_thailand',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test Database Connection
pool.getConnection().then(conn => {
    console.log('✅ Database Connected Successfully');
    conn.release();
}).catch(err => {
    console.log('❌ Database Connection Failed:', err);
});

// ===== AUTHENTICATION =====

// Admin Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password required' });
        }

        const conn = await pool.getConnection();
        const [users] = await conn.query('SELECT * FROM admins WHERE username = ?', [username]);
        conn.release();

        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET || 'your_secret_key', { expiresIn: '24h' });

        res.json({
            message: 'Login successful',
            token: token,
            user: { id: user.id, username: user.username }
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Verify Token Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        req.user = decoded;
        next();
    });
};

// ===== CASE ENDPOINTS =====

// Create Case (Report Fraud)
app.post('/api/cases', upload.single('evidence'), async (req, res) => {
    try {
        const {
            fullName,
            email,
            phone,
            address,
            incidentType,
            incidentDate,
            platform,
            description,
            suspectInfo,
            lossAmount,
            bankInfo,
            consent
        } = req.body;

        if (!fullName || !email || !phone || !description || !consent) {
            return res.status(400).json({ message: 'Required fields missing' });
        }

        const conn = await pool.getConnection();
        
        // Generate Case Number
        const caseYear = new Date().getFullYear();
        const [result] = await conn.query('SELECT COUNT(*) as count FROM cases WHERE YEAR(reportDate) = ?', [caseYear]);
        const caseNumber = `CASE-${caseYear}-${String(result[0].count + 1).padStart(5, '0')}`;

        // Insert Case
        const [insertResult] = await conn.query(
            `INSERT INTO cases 
            (caseNumber, fullName, email, phone, address, incidentType, incidentDate, platform, 
             description, suspectInfo, lossAmount, bankInfo, evidenceFile, status, reportDate, createdAt) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW(), NOW())`,
            [caseNumber, fullName, email, phone, address, incidentType, incidentDate, platform, 
             description, suspectInfo, lossAmount || 0, bankInfo, req.file ? req.file.filename : null]
        );

        conn.release();

        res.status(201).json({
            message: 'Case created successfully',
            caseNumber: caseNumber,
            caseId: insertResult.insertId
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get All Cases (Admin Only)
app.get('/api/cases', verifyToken, async (req, res) => {
    try {
        const { status, search } = req.query;
        let query = 'SELECT * FROM cases WHERE 1=1';
        let params = [];

        if (status) {
            query += ' AND status = ?';
            params.push(status);
        }

        if (search) {
            query += ' AND (caseNumber LIKE ? OR fullName LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }

        query += ' ORDER BY createdAt DESC';

        const conn = await pool.getConnection();
        const [cases] = await conn.query(query, params);
        conn.release();

        res.json({
            total: cases.length,
            cases: cases
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get Case by ID
app.get('/api/cases/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const conn = await pool.getConnection();
        const [cases] = await conn.query('SELECT * FROM cases WHERE id = ?', [id]);
        conn.release();

        if (cases.length === 0) {
            return res.status(404).json({ message: 'Case not found' });
        }

        res.json(cases[0]);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get Case by Case Number and Email (User Status Check)
app.post('/api/cases/check', async (req, res) => {
    try {
        const { caseNumber, email } = req.body;

        if (!caseNumber || !email) {
            return res.status(400).json({ message: 'Case number and email required' });
        }

        const conn = await pool.getConnection();
        const [cases] = await conn.query(
            'SELECT * FROM cases WHERE caseNumber = ? AND email = ?',
            [caseNumber, email]
        );
        conn.release();

        if (cases.length === 0) {
            return res.status(404).json({ message: 'Case not found' });
        }

        res.json(cases[0]);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Update Case Status (Admin Only)
app.put('/api/cases/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, notes, summary } = req.body;

        if (!status) {
            return res.status(400).json({ message: 'Status required' });
        }

        const conn = await pool.getConnection();
        
        const [updateResult] = await conn.query(
            'UPDATE cases SET status = ?, notes = ?, summary = ?, updatedAt = NOW() WHERE id = ?',
            [status, notes || '', summary || '', id]
        );

        conn.release();

        if (updateResult.affectedRows === 0) {
            return res.status(404).json({ message: 'Case not found' });
        }

        res.json({
            message: 'Case updated successfully'
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get Statistics (Admin Only)
app.get('/api/statistics', verifyToken, async (req, res) => {
    try {
        const conn = await pool.getConnection();

        const [stats] = await conn.query(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'investigating' THEN 1 ELSE 0 END) as investigating,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                SUM(lossAmount) as totalLoss
            FROM cases
        `);

        conn.release();

        res.json(stats[0]);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get Report by Date Range (Admin Only)
app.get('/api/reports', verifyToken, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;

        if (!startDate || !endDate) {
            return res.status(400).json({ message: 'Start date and end date required' });
        }

        const conn = await pool.getConnection();

        const [cases] = await conn.query(
            'SELECT * FROM cases WHERE DATE(reportDate) BETWEEN ? AND ? ORDER BY reportDate DESC',
            [startDate, endDate]
        );

        // Calculate summary by type
        const byType = {};
        cases.forEach(c => {
            if (!byType[c.incidentType]) {
                byType[c.incidentType] = 0;
            }
            byType[c.incidentType]++;
        });

        // Calculate summary by status
        const byStatus = {
            pending: 0,
            investigating: 0,
            completed: 0
        };
        cases.forEach(c => {
            byStatus[c.status]++;
        });

        const totalLoss = cases.reduce((sum, c) => sum + (c.lossAmount || 0), 0);

        conn.release();

        res.json({
            period: `${startDate} to ${endDate}`,
            total: cases.length,
            totalLoss: totalLoss,
            byType: byType,
            byStatus: byStatus,
            cases: cases
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ message: 'Backend server is running' });
});

// Error Handling
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: 'Server error', error: err.message });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📝 API Documentation: http://localhost:${PORT}/api/docs`);
});
