// File: index.js

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRATION = '1h'; // Access token expiration
const JWT_REFRESH_EXPIRATION = '7d'; // Refresh token expiration

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {

});

// User schema and model
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// BlacklistedToken schema and model
const blacklistedTokenSchema = new mongoose.Schema({
    token: { type: String, required: true },
    expiresAt: { type: Date, required: true },
});

const BlacklistedToken = mongoose.model('BlacklistedToken', blacklistedTokenSchema);

// Middleware to check for a blacklisted token
const checkBlacklistedToken = async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const blacklisted = await BlacklistedToken.findOne({ token });
    if (blacklisted) {
        return res.status(401).json({ error: 'Token is blacklisted' });
    }
    next();
};

// Middleware to authenticate JWT
const authenticateJWT = async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const user = jwt.verify(token, JWT_SECRET);
        req.user = user;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Registration route
app.post(
    '/register',
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            email,
            password: hashedPassword,
        });

        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    }
);

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    const accessToken = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
        expiresIn: JWT_EXPIRATION,
    });
    const refreshToken = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
        expiresIn: JWT_REFRESH_EXPIRATION,
    });

    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true });
    res.json({ accessToken });
});

// Refresh token route
app.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const user = jwt.verify(refreshToken, JWT_SECRET);

        const newAccessToken = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRATION }
        );

        res.json({ accessToken: newAccessToken });
    } catch (err) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

// Logout route
app.post('/logout', authenticateJWT, async (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    const expirationDate = jwt.decode(token).exp * 1000;

    const blacklistedToken = new BlacklistedToken({
        token,
        expiresAt: new Date(expirationDate),
    });

    await blacklistedToken.save();
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out successfully' });
});

// Protected route example
app.get('/protected', authenticateJWT, checkBlacklistedToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
