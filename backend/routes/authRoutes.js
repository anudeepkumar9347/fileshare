// 📦 Import required packages and modules
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { authLimiter } = require('../middleware/rateLimiter');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const sanitize = require('mongo-sanitize'); // 🧼 Prevent NoSQL injections

// 🔐 Load secret key for JWT token signing
const JWT_SECRET = process.env.JWT_SECRET || 'fallbacksecret';


// 🚀 POST /register — Create new user account
router.post(
  '/register',
  authLimiter, // 🛡️ Apply rate limiter to prevent spam signups
  [
    // 🧪 Validate input
    body('username').isString().trim().isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req); // 🧾 Check for validation errors
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      // 🧼 Sanitize input to prevent MongoDB injections
      const username = sanitize(req.body.username);
      const password = req.body.password;

      // 🔍 Check if username already exists
      const existingUser = await User.findOne({ username }).lean();
      if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' });
      }

      // 🆕 Create and save new user
      const user = new User({ username, password });
      await user.save();

      res.json({ message: 'User registered successfully' }); // ✅ Success response
    } catch (err) {
      res.status(500).json({ message: 'Server error' }); // ❌ Catch server errors
    }
  }
);


// 🔐 POST /login — Authenticate and return JWT
router.post(
  '/login',
  authLimiter, // 🛡️ Apply rate limiter to prevent brute-force login
  [
    // 🧪 Validate input
    body('username').isString().trim().notEmpty().withMessage('Username is required'),
    body('password').isString().notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req); // 🧾 Check for validation errors
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      // 🧼 Sanitize input
      const username = sanitize(req.body.username);
      const password = req.body.password;

      // 🔍 Look up user by username
      const user = await User.findOne({ username: { $eq: username } }).select('+password');
      if (!user) {
        return res.status(400).json({ message: 'Invalid username or password' }); // ❌ Username not found
      }

      // 🔐 Compare provided password with hashed password
      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid username or password' }); // ❌ Password wrong
      }

      // 🧾 Generate and send JWT token
      const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1d' });
      res.json({ token }); // ✅ Auth success
    } catch (err) {
      res.status(500).json({ message: 'Server error' }); // ❌ Unexpected error
    }
  }
);

module.exports = router; // 📤 Export for use in server.js
