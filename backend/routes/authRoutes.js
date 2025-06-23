const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { authLimiter } = require('../middleware/rateLimiter');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const sanitize = require('mongo-sanitize'); // << Add this line

const JWT_SECRET = process.env.JWT_SECRET || 'fallbacksecret';

// REGISTER
router.post(
  '/register',
  authLimiter,
  [
    body('username').isString().trim().isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      // Sanitize user input here
      const username = sanitize(req.body.username);
      const password = req.body.password;

      const existingUser = await User.findOne({ username }).lean();

      if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' });
      }

      const user = new User({ username, password });
      await user.save();

      res.json({ message: 'User registered successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// LOGIN
router.post(
  '/login',
  authLimiter,
  [
    body('username').isString().trim().notEmpty().withMessage('Username is required'),
    body('password').isString().notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      // Sanitize user input here
      const username = sanitize(req.body.username);
      const password = req.body.password;

      const user = await User.findOne({ username: { $eq: username } }).select('+password');

      if (!user) {
        return res.status(400).json({ message: 'Invalid username or password' });
      }

      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid username or password' });
      }

      const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1d' });
      res.json({ token });
    } catch (err) {
      res.status(500).json({ message: 'Server error' });
    }
  }
);

module.exports = router;
