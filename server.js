const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

// आपका डेटाबेस URL
const MONGO_URI = 'mongodb+srv://admin:Abhi1996@abhishek.qs5mdz0.mongodb.net/invbill?retryWrites=true&w=majority';
const SECRET_SALT = "DhanvishtaSecretKey@1996"; // चाबी बनाने का राज

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('DB Error:', err));

// यूजर का डेटा कैसा दिखेगा
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, unique: true, sparse: true },
  email: { type: String, unique: true, sparse: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  deviceId: { type: String, default: null },
  isActivated: { type: Boolean, default: false }, // एक्टिवेशन स्टेटस
  isLocked: { type: Boolean, default: false } // एडमिन लॉक
});
const User = mongoose.model('User', UserSchema);

// 1. रजिस्टर करने का रास्ता
app.post('/api/register', async (req, res) => {
  try {
    const { name, phone, email, password } = req.body;
    let user = await User.findOne({ $or: [{ phone }, { email }] });
    if (user) return res.status(400).json({ error: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    user = new User({ name, phone, email, password: hashedPassword });
    await user.save();
    res.json({ message: 'Registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. लॉगिन करने का रास्ता
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password, deviceId } = req.body;
    const user = await User.findOne({ $or: [{ phone }, { email }] });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: 'Invalid password' });

    if (user.deviceId && user.deviceId !== deviceId) {
      return res.status(403).json({ error: 'Account locked to another device.' });
    }
    if (!user.deviceId) {
      user.deviceId = deviceId;
      await user.save();
    }
    res.json({ message: 'Success', userId: user._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. ऐप खुलते ही चेक करने का रास्ता (एक्टिवेटेड है या नहीं)
app.post('/api/check-activation', async (req, res) => {
  try {
    const { userId, deviceId } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.deviceId && user.deviceId !== deviceId) {
      return res.json({ status: 'new_device', deviceId: deviceId });
    }
    if (!user.deviceId) {
      user.deviceId = deviceId;
      await user.save();
    }
    if (!user.isActivated) {
      return res.json({ status: 'not_activated', deviceId: deviceId });
    }
    if (user.isLocked) {
      return res.json({ status: 'locked' });
    }
    res.json({ status: 'active' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. चाबी (Key) बनाने का रास्ता (सिर्फ एडमिन के लिए)
app.post('/api/admin/generate-key', (req, res) => {
  const { deviceId, adminSecret } = req.body;
  if (adminSecret !== 'Abhi@19969555') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  const key = crypto.createHash('md5').update(deviceId + SECRET_SALT).digest('hex').substring(0, 8).toUpperCase();
  res.json({ activationKey: key });
});

// 5. चाबी से ऐप एक्टिवेट करने का रास्ता
app.post('/api/activate-device', async (req, res) => {
  try {
    const { userId, deviceId, activationKey } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const expectedKey = crypto.createHash('md5').update(deviceId + SECRET_SALT).digest('hex').substring(0, 8).toUpperCase();
    
    if (activationKey === expectedKey) {
      user.isActivated = true;
      user.deviceId = deviceId;
      await user.save();
      res.json({ message: 'Device activated successfully!' });
    } else {
      res.status(400).json({ error: 'Invalid Activation Key' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. एडमिन लॉक/अनलॉक करने का रास्ता
app.post('/api/admin/lock', async (req, res) => {
  const { adminSecret, userId, lock } = req.body;
  if (adminSecret !== 'Abhi@19969555') return res.status(403).json({ error: 'Unauthorized' });
  await User.findByIdAndUpdate(userId, { isLocked: lock });
  res.json({ success: true });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server on port ${PORT}`));
