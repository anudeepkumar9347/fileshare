const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const File = require('../models/File');
const { fileLimiter } = require('../middleware/rateLimiter');
const { param, validationResult } = require('express-validator');

// JWT middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Auth token missing' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallbacksecret');
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '../uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + file.originalname;
    cb(null, uniqueName);
  }
});
const upload = multer({ storage });

// Upload a file
router.post('/upload', auth, fileLimiter, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

  const file = new File({
    originalName: req.file.originalname,
    storedName: req.file.filename,
    user: req.user.id
  });

  await file.save();
  res.json({
    fileId: file._id,
    fileName: file.originalName,
    filePath: `/api/files/download/${file._id}`
  });
});

// List user's files
router.get('/', auth, fileLimiter, async (req, res) => {
  const files = await File.find({ user: req.user.id });
  res.json(files.map(f => ({
    fileId: f._id,
    fileName: f.originalName,
    downloadLink: `/api/files/download/${f._id}`
  })));
});

// Download a file with validation
router.get(
  '/download/:id',
  auth,
  fileLimiter,
  param('id').isMongoId().withMessage('Invalid file ID'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const file = await File.findById(req.params.id);
    if (!file || file.user.toString() !== req.user.id) {
      return res.status(404).json({ message: 'File not found or unauthorized' });
    }

    const filePath = path.join(__dirname, '../uploads', file.storedName);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'File is missing on server' });
    }

    res.download(filePath, file.originalName);
  }
);

// Delete a file with validation
router.delete(
  '/:id',
  auth,
  fileLimiter,
  param('id').isMongoId().withMessage('Invalid file ID'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const file = await File.findOne({ _id: req.params.id, user: req.user.id });
    if (!file) return res.status(404).json({ message: 'File not found' });

    const fullPath = path.join(__dirname, '../uploads', file.storedName);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);

    await file.deleteOne();
    res.json({ message: 'File deleted' });
  }
);

module.exports = router;
