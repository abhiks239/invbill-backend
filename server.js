const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cors());

// Tumhara Sahi MongoDB URL
const MONGO_URI = 'mongodb+srv://admin:Abhi1996@abhishek.qs5mdz0.mongodb.net/invbill?retryWrites=true&w=majority';
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('DB Error:', err));

// User Schema (Database me aisa dikhega)
const UserSchema = new mongoose.Schema({
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  deviceId: { type: String, default: null },
  isLocked: { type: Boolean, default: false }
});
const User = mongoose.model('User', UserSchema);

// 1. Register API
app.post('/api/register', async (req, res) => {
  try {
    const { phone, password } = req.body;
    let user = await User.findOne({ phone });
    if (user) return res.status(400).json({ error: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ phone, password: hashedPassword });
    await user.save();
    res.json({ message: 'Registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Login API (Device Lock Check)
app.post('/api/login', async (req, res) => {
  try {
    const { phone, password, deviceId } = req.body;
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: 'Invalid password' });

    // Anti-Sharing Logic
    if (user.deviceId && user.deviceId !== deviceId) {
      return res.status(403).json({ error: 'Account locked to another device.' });
    }
    
    if (!user.deviceId) {
      user.deviceId = deviceId;
      await user.save();
    }

    res.json({ message: 'Success', userId: user._id, isLocked: user.isLocked });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. App Status Check API (Kya user locked hai?)
app.post('/api/check-status', async (req, res) => {
  try {
    const { userId, deviceId } = req.body;
    const user = await User.findById(userId);
    
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.deviceId !== deviceId) {
      return res.json({ status: 'expired' });
    }

    if (user.isLocked) {
      return res.json({ status: 'expired' });
    }

    res.json({ status: 'active' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. ADMIN API (Lock/Unlock User)
app.post('/api/admin/lock', async (req, res) => {
  const { adminSecret, userId, lock } = req.body;
  if (adminSecret !== 'Abhi@19969555') return res.status(403).json({ error: 'Unauthorized' });
  
  await User.findByIdAndUpdate(userId, { isLocked: lock });
  res.json({ success: true });
});

// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
