// 📦 Import required packages and modules
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const File = require('../models/File');
const { fileLimiter } = require('../middleware/rateLimiter');
const { param, validationResult } = require('express-validator');

// 🚦 Apply rate limiter globally to all routes in this router (extra layer of protection)
router.use(fileLimiter);

// 🛡️ Auth middleware to verify JWT token
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // 🔍 Extract token from header
  if (!token) return res.status(401).json({ message: 'Auth token missing' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallbacksecret'); // 🔐 Decode token
    req.user = decoded; // 👤 Attach user info to request
    next(); // ✅ Proceed to next middleware/route
  } catch {
    return res.status(403).json({ message: 'Invalid or expired token' }); // ❌ Token invalid
  }
};

// 📂 Setup multer for file uploads (defines storage location and filename)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '../uploads'); // 🗂️ Target uploads folder
    if (!fs.existsSync(dir)) fs.mkdirSync(dir); // 🛠️ Create folder if it doesn't exist
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + file.originalname; // 🏷️ Unique file name
    cb(null, uniqueName);
  }
});
const upload = multer({ storage }); // 🎒 Final upload middleware

// 🚀 POST /upload — Upload a file
router.post('/upload', auth, fileLimiter, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' }); // ❌ No file provided

  const file = new File({
    originalName: req.file.originalname, // 📝 Original file name
    storedName: req.file.filename, // 🗄️ Saved file name
    user: req.user.id // 👤 Belongs to this user
  });

  await file.save(); // 💾 Save to MongoDB
  res.json({
    fileId: file._id,
    fileName: file.originalName,
    filePath: `/api/files/download/${file._id}` // 📥 Return download link
  });
});

// 📄 GET / — List all files for this user
router.get('/', auth, fileLimiter, async (req, res) => {
  const files = await File.find({ user: req.user.id }); // 📦 Find files for this user
  res.json(files.map(f => ({
    fileId: f._id,
    fileName: f.originalName,
    downloadLink: `/api/files/download/${f._id}` // 📎 Download link
  })));
});

// 📥 GET /download/:id — Download a specific file
router.get(
  '/download/:id',
  auth,
  fileLimiter,
  param('id').isMongoId().withMessage('Invalid file ID'), // ✅ Validate MongoDB ID
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() }); // ❌ Invalid input

    const file = await File.findById(req.params.id); // 🔍 Find file
    if (!file || file.user.toString() !== req.user.id) {
      return res.status(404).json({ message: 'File not found or unauthorized' }); // 🚫 Not yours or missing
    }

    const filePath = path.join(__dirname, '../uploads', file.storedName); // 🗂️ Get full path
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'File is missing on server' }); // ❌ File missing on disk
    }

    res.download(filePath, file.originalName); // 📦 Send download
  }
);

// 🗑️ DELETE /:id — Delete a specific file
router.delete(
  '/:id',
  auth,
  fileLimiter,
  param('id').isMongoId().withMessage('Invalid file ID'), // ✅ Validate ID
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() }); // ❌ Validation failed

    const file = await File.findOne({ _id: req.params.id, user: req.user.id }); // 🔍 Ensure it's user's file
    if (!file) return res.status(404).json({ message: 'File not found' });

    const fullPath = path.join(__dirname, '../uploads', file.storedName);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath); // 🧹 Remove from disk

    await file.deleteOne(); // ❌ Remove from DB
    res.json({ message: 'File deleted' }); // ✅ Done
  }
);

module.exports = router; // 📤 Export router for backend
