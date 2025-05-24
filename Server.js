// server.js
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based API for async/await
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // Import cors middleware

const app = express();
const PORT = process.env.PORT || 5000; // Use port 5000 for backend

// Middleware to parse JSON bodies
app.use(express.json());

// Enable CORS for all origins (for development)
// In production, you should restrict this to your frontend's domain.
app.use(cors());

// MySQL Database Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
pool.getConnection()
    .then(connection => {
        console.log('Successfully connected to MySQL database!');
        connection.release(); // Release the connection
    })
    .catch(err => {
        console.error('Error connecting to MySQL database:', err.message);
        process.exit(1); // Exit process if database connection fails
    });

// --- User Model/Service (Simplified for this example) ---
const findUserByUsername = async (username) => {
    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
    return rows[0]; // Return the first user found, or undefined
};

const createUser = async (username, hashedPassword, role = 'user') => {
    const [result] = await pool.execute(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        [username, hashedPassword, role]
    );
    return result.insertId; // Return the ID of the newly created user
};

// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // No token

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Invalid token
        req.user = user; // Attach user payload to request
        next();
    });
};

const authorizeRole = (roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied.' }); // Forbidden
        }
        next();
    };
};

// --- Authentication Controller/Routes ---

// User Registration
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        // Check if user already exists
        const existingUser = await findUserByUsername(username);
        if (existingUser) {
            return res.status(409).json({ message: 'Username already exists.' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds: 10

        // Create user in database with 'user' role
        const userId = await createUser(username, hashedPassword, 'user');

        res.status(201).json({ message: 'User registered successfully!', userId });

    } catch (error) {
        console.error('Error during user registration:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// User Login (for regular users)
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        // Find user by username
        const user = await findUserByUsername(username);
        if (!user || user.role !== 'user') { // Ensure it's a regular user
            return res.status(401).json({ message: 'Invalid credentials or not a user account.' });
        }

        // Compare provided password with hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.status(200).json({ message: 'Login successful!', token, role: user.role });

    } catch (error) {
        console.error('Error during user login:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// Admin Login
app.post('/api/auth/admin-login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        const user = await findUserByUsername(username);
        // Check if user exists and has 'admin' role
        if (!user || user.role !== 'admin') {
            return res.status(401).json({ message: 'Invalid credentials or not an admin account.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({ message: 'Admin login successful!', token, role: user.role });

    } catch (error) {
        console.error('Error during admin login:', error);
        res.status(500).json({ message: 'Server error during admin login.' });
    }
});

// Example of a protected route (only for authenticated users)
app.get('/api/protected-user-data', authenticateToken, authorizeRole(['user', 'admin']), (req, res) => {
    res.json({ message: `Welcome, ${req.user.username}! This is protected user data. Your role is ${req.user.role}.` });
});

// Example of a protected admin route (only for authenticated admins)
app.get('/api/protected-admin-data', authenticateToken, authorizeRole(['admin']), (req, res) => {
    res.json({ message: `Welcome, Admin ${req.user.username}! This is highly confidential admin data.` });
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Admin Registration (NEW ENDPOINT)
app.post('/api/auth/admin-register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        // Check if user already exists
        const existingUser = await findUserByUsername(username);
        if (existingUser) {
            return res.status(409).json({ message: 'Username already exists.' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds: 10

        // Create user in database with 'admin' role
        const userId = await createUser(username, hashedPassword, 'admin'); // Explicitly set role to 'admin'

        res.status(201).json({ message: 'Admin registered successfully!', userId });

    } catch (error) {
        console.error('Error during admin registration:', error);
        res.status(500).json({ message: 'Server error during admin registration.' });
    }
});