// backend/server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto'); // 🔐 Webhook signature verification

// 🔧 Automation logic
const { applyFix } = require('./bot/fixer');
const { dismissAlert } = require('./bot/dismissAlert');

// 🌱 Load env variables
dotenv.config();

const app = express();
app.set('trust proxy', 1); // ✅ Needed for express-rate-limit
app.use(cors());

// 👁️ Use raw body for GitHub signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// 🔌 MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ MongoDB connected');
}).catch(err => {
  console.error('❌ MongoDB connection failed:', err.message);
});

// 📁 Static file hosting
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 🔗 Routes
const fileRoutes = require('./routes/fileRoutes');
const authRoutes = require('./routes/authRoutes');
app.use('/api/files', fileRoutes);
app.use('/api/auth', authRoutes);

// 📡 GitHub Webhook Endpoint
app.post('/webhook', async (req, res) => {
  try {
    const signature = req.headers['x-hub-signature-256'];
    const hmac = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET);
    const digest = 'sha256=' + hmac.update(req.rawBody).digest('hex');

    if (signature !== digest) {
      console.log('❌ Invalid webhook signature');
      return res.status(401).send('Invalid signature');
    }

    const payload = req.body;

    if (payload.action === 'created' && payload.alert) {
      const alertPath = payload.alert.most_recent_instance.location.path;
      const alertLine = payload.alert.most_recent_instance.location.start_line;
      const alertNumber = payload.alert.number;
      const repoOwner = payload.repository.owner.login;
      const repoName = payload.repository.name;

      console.log(`🔍 Fixing alert in ${alertPath} at line ${alertLine}`);

      // 🔎 Try multiple paths
      const projectRoot = path.resolve(__dirname, '..');
      const alertRelativePath = alertPath.replace(/^\.?\//, ''); // normalize path
      
      const possiblePaths = [
        path.resolve(projectRoot, alertRelativePath),                    
        path.resolve(projectRoot, 'backend', alertRelativePath),         
        path.resolve(__dirname, alertRelativePath),                      
        path.resolve(__dirname, 'backend', alertRelativePath),          
      
      // 🔍 Log all possible paths to help debug
console.log('🔍 Trying paths:\n' + possiblePaths.join('\n'));

// patched by GPT-bot ✅
      let foundPath = possiblePaths.find(p => fs.existsSync(p));

      if (!foundPath) {
        console.error(`❌ File not found: Tried ${possiblePaths.join(', ')}`);
        return res.status(404).send('Source file not found');
      }

      // 🧩 Apply fix
      applyFix(foundPath, alertLine - 1, `// patched by GPT-bot ✅`);

      // ✅ Dismiss the alert
      await dismissAlert(repoOwner, repoName, alertNumber);

      console.log(`✅ Alert #${alertNumber} handled and dismissed.`);
      return res.status(200).send('Alert handled');
    } else {
      return res.status(200).send('Ignored non-CodeQL event');
    }
  } catch (err) {
    console.error("❌ Error in webhook handler:", err.stack || err.message);
    return res.status(500).send('Webhook error');
  }
});

// 🚀 Launch server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () =>  {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log('🤖 GPT-bot is running and listening for GitHub CodeQL alerts...');
});
