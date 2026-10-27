// =====================================================================
//  Dhanvishta Billing - Backend (server.js)  -- FIXED VERSION
//  Passwords ab code me nahi hain. Render > Environment me daalne hain:
//     MONGO_URI        (zaroori)  - MongoDB connection link
//     ADMIN_SECRET     (zaroori)  - admin password (Abhi@19969555)
// =====================================================================
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const MONGO_URI = process.env.MONGO_URI;
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// Frontend wala salt (Zaroori: Frontend aur backend ka salt same hona chahiye)
const ACTIVATION_SALT = "DhanvishtaSecretKey@1996"; 

if (!MONGO_URI || !ADMIN_SECRET) {
  console.error('ERROR: Render > Environment me MONGO_URI aur ADMIN_SECRET daalna zaroori hai.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(cors());

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('DB Error:', err.message));

// ---------------- User model ----------------
const UserSchema = new mongoose.Schema({
  name: { type: String, default: '' },
  phone: { type: String, unique: true, sparse: true },
  email: { type: String, unique: true, sparse: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  deviceId: { type: String, default: null },
  isActivated: { type: Boolean, default: false },
  isLocked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date, default: null }
});
const User = mongoose.model('User', UserSchema);

// ---------------- Helpers ----------------
const cleanPhone = (v) => {
  let d = String(v || '').replace(/\D/g, '');
  if (d.length > 10) d = d.slice(-10);
  return d;
};

// FIX: Ab MD5 use ho raha hai (Frontend Key Generator se match karne ke liye)
const makeKey = (deviceId) => {
  return crypto.createHash('md5').update(String(deviceId) + ACTIVATION_SALT).digest('hex').substring(0, 8).toUpperCase();
};

const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

const findByPhone = (raw) => {
  const c = cleanPhone(raw);
  return User.findOne({ phone: { $in: [c, String(raw || '').trim()] } });
};

// Simple brute-force roak (15 min me 10 galat koshish)
const fails = new Map();
const WINDOW = 15 * 60 * 1000;
function tooMany(key) {
  const now = Date.now();
  const a = (fails.get(key) || []).filter(t => now - t < WINDOW);
  fails.set(key, a);
  return a.length >= 10;
}
function noteFail(key) { const a = fails.get(key) || []; a.push(Date.now()); fails.set(key, a); }
setInterval(() => fails.clear(), 60 * 60 * 1000);

function serverError(res, err) {
  console.error(err);
  if (err && err.code === 11000) return res.status(400).json({ error: 'User already exists' });
  res.status(500).json({ error: 'Server error. Thodi der baad try karein.' });
}

// ---------------- Health check (Render ko jagaye rakhne ke liye) ----------------
app.get('/', (req, res) => res.send('Dhanvishta server running'));

// ---------------- 1. Register ----------------
app.post('/api/register', async (req, res) => {
  try {
    const phone = cleanPhone(req.body.phone);
    const password = String(req.body.password || '');
    const name = String(req.body.name || '').trim() || phone;
    if (phone.length !== 10) return res.status(400).json({ error: 'Sahi 10 digit mobile number daalein' });
    if (password.length < 4) return res.status(400).json({ error: 'Password kam se kam 4 akshar ka rakhein' });

    const exists = await User.findOne({ phone });
    if (exists) return res.status(400).json({ error: 'Ye number pehle se registered hai. Login karein.' });

    const hashed = await bcrypt.hash(password, 10);
    await new User({ name, phone, password: hashed }).save();
    res.json({ message: 'Registered successfully' });
  } catch (err) { serverError(res, err); }
});

// ---------------- 2. Login ----------------
app.post('/api/login', async (req, res) => {
  try {
    const { phone: rawPhone, password, deviceId } = req.body;
    if (!rawPhone || !password || !deviceId) return res.status(400).json({ error: 'Phone, password aur device chahiye' });

    const key = req.ip + '|' + cleanPhone(rawPhone);
    if (tooMany(key)) return res.status(429).json({ error: 'Bahut zyada galat koshish. 15 minute baad try karein.' });

    const user = await findByPhone(rawPhone);
    const ok = user && await bcrypt.compare(String(password), user.password);
    if (!ok) { noteFail(key); return res.status(400).json({ error: 'Mobile number ya password galat hai' }); }

    // Agar user ka device pehle se set hai aur naya device alag hai
    if (user.deviceId && user.deviceId !== deviceId) {
      return res.status(403).json({ error: 'Account locked to another device.' });
    }
    
    if (!user.deviceId) user.deviceId = deviceId;
    user.lastLoginAt = new Date();
    await user.save();
    fails.delete(key);
    res.json({ message: 'Success', userId: user._id, activated: user.isActivated, locked: user.isLocked });
  } catch (err) { serverError(res, err); }
});

// ---------------- 3. Status check (app kholte hi) ----------------
app.post('/api/check-status', async (req, res) => {
  try {
    const { userId, deviceId } = req.body;
    if (!mongoose.isValidObjectId(userId) || !deviceId) return res.json({ status: 'invalid' });
    const user = await User.findById(userId);
    if (!user) return res.json({ status: 'invalid' });

    if (user.deviceId && user.deviceId !== deviceId) return res.json({ status: 'new_device' });
    if (!user.deviceId) { user.deviceId = deviceId; await user.save(); }

    if (user.isLocked) return res.json({ status: 'expired' });
    if (!user.isActivated) return res.json({ status: 'not_activated' });
    res.json({ status: 'active' });
  } catch (err) { serverError(res, err); }
});

// ---------------- 4. Key se activate ----------------
app.post('/api/activate-device', async (req, res) => {
  try {
    const { userId, deviceId, activationKey } = req.body;
    if (!mongoose.isValidObjectId(userId) || !deviceId || !activationKey) return res.status(400).json({ error: 'Invalid request' });

    const fkey = 'act|' + userId;
    if (tooMany(fkey)) return res.status(429).json({ error: 'Bahut zyada galat koshish. 15 minute baad try karein.' });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Agar ID alag hai par activate karna hai (is case me frontend check karega)
    if (!safeEq(String(activationKey).trim().toUpperCase(), makeKey(deviceId))) {
      noteFail(fkey);
      return res.status(400).json({ error: 'Invalid Activation Key' });
    }
    
    user.isActivated = true;
    user.deviceId = deviceId;
    await user.save();
    res.json({ message: 'Device activated successfully!' });
  } catch (err) { serverError(res, err); }
});

// ====================== ADMIN ======================
const adminOnly = (req, res, next) => {
  if (!safeEq(req.get('x-admin-secret') || '', ADMIN_SECRET)) return res.status(403).json({ error: 'Galat admin password' });
  next();
};
const validId = (req, res) => {
  if (!mongoose.isValidObjectId(req.body.id)) { res.status(400).json({ error: 'Invalid id' }); return false; }
  return true;
};

app.post('/api/admin/users', adminOnly, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ _id: -1 }).lean();
    res.json({ users });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/reset-device', adminOnly, async (req, res) => {
  try {
    if (!validId(req, res)) return;
    await User.findByIdAndUpdate(req.body.id, { deviceId: null, isActivated: false });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/activate', adminOnly, async (req, res) => {
  try {
    if (!validId(req, res)) return;
    await User.findByIdAndUpdate(req.body.id, { isActivated: !!req.body.activated });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/lock', adminOnly, async (req, res) => {
  try {
    if (!validId(req, res)) return;
    await User.findByIdAndUpdate(req.body.id, { isLocked: !!req.body.lock });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/delete-user', adminOnly, async (req, res) => {
  try {
    if (!validId(req, res)) return;
    await User.findByIdAndDelete(req.body.id);
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/generate-key', adminOnly, (req, res) => {
  const deviceId = String(req.body.deviceId || '').trim();
  if (!deviceId) return res.status(400).json({ error: 'Device ID daalein' });
  res.json({ key: makeKey(deviceId) });
});

// ---------------- Admin Panel (browser me kholo: /admin) ----------------
const ADMIN_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dhanvishta Admin</title>
<style>
body{font-family:Arial,sans-serif;background:#f5f6fb;margin:0;padding:14px;color:#111}
h2{color:#1e1b4b;margin:4px 0 12px}
input{padding:11px;border:1.5px solid #ddd;border-radius:9px;font-size:15px;width:100%;box-sizing:border-box;margin-bottom:8px}
button{padding:9px 12px;border:0;border-radius:8px;background:#4f46e5;color:#fff;font-size:13px;font-weight:bold;margin:3px 4px 3px 0}
button.del{background:#dc2626}
.card{background:#fff;border-radius:12px;padding:12px;margin-bottom:10px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.sm{font-size:12px;color:#555;margin:4px 0;word-break:break-all}
.ok{color:#059669;font-weight:bold}.bad{color:#dc2626;font-weight:bold}
.box{background:#fff;border-radius:12px;padding:12px;margin-bottom:12px}
</style></head><body>
<h2>Dhanvishta Admin</h2>
<div id="login" class="box"><input id="sec" type="password" placeholder="Admin Password"><button onclick="openPanel()">Open</button></div>
<div id="panel" style="display:none">
  <div class="box"><b>Key banao (Device ID se)</b><input id="dev" placeholder="DEV-XXXXXXXX"><button onclick="act('/api/admin/generate-key',{deviceId:$('dev').value.trim()})">Make Key</button></div>
  <input id="q" placeholder="Search phone / name" oninput="draw()">
  <button onclick="load()">Refresh</button>
  <div id="list"></div>
</div>
<script>
var S='',U=[];
function $(i){return document.getElementById(i);}
function api(p,b){return fetch(p,{method:'POST',headers:{'Content-Type':'application/json','x-admin-secret':S},body:JSON.stringify(b||{})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||'Error');return d;});});}
function openPanel(){S=$('sec').value;load();}
function load(){api('/api/admin/users').then(function(d){U=d.users;$('login').style.display='none';$('panel').style.display='block';draw();}).catch(function(e){alert(e.message);});}
function act(path,body,ask){if(ask&&!confirm(ask))return;api(path,body).then(function(d){if(d.key)prompt('Activation Key (copy karein):',d.key);load();}).catch(function(e){alert(e.message);});}
function mk(t,txt,cls){var e=document.createElement(t);if(txt!==undefined&&txt!==null)e.textContent=txt;if(cls)e.className=cls;return e;}
function btn(label,fn,cls){var b=mk('button',label,cls);b.onclick=fn;return b;}
function draw(){
  var q=$('q').value.toLowerCase(),box=$('list');box.innerHTML='';
  U.filter(function(u){return !q||((u.phone||'')+' '+(u.name||'')).toLowerCase().indexOf(q)>-1;}).forEach(function(u){
    var c=mk('div',null,'card');
    c.appendChild(mk('b',u.phone||u.email||'-'));
    c.appendChild(mk('div','Device: '+(u.deviceId||'-- linked nahi --'),'sm'));
    var st=mk('div',null,'sm');
    st.appendChild(mk('span',u.isActivated?'Activated':'Not activated',u.isActivated?'ok':'bad'));
    st.appendChild(document.createTextNode(' | '));
    st.appendChild(mk('span',u.isLocked?'LOCKED':'Unlocked',u.isLocked?'bad':'ok'));
    c.appendChild(st);
    var r=mk('div');
    r.appendChild(btn('Reset Device',function(){act('/api/admin/reset-device',{id:u._id},'Device reset karein? User ko naye phone par dobara activate karna hoga.');}));
    r.appendChild(btn(u.isActivated?'Deactivate':'Activate',function(){act('/api/admin/activate',{id:u._id,activated:!u.isActivated});}));
    r.appendChild(btn(u.isLocked?'Unlock':'Lock',function(){act('/api/admin/lock',{id:u._id,lock:!u.isLocked});}));
    if(u.deviceId)r.appendChild(btn('Get Key',function(){act('/api/admin/generate-key',{deviceId:u.deviceId});}));
    r.appendChild(btn('Delete',function(){act('/api/admin/delete-user',{id:u._id},'Ye user hamesha ke liye delete hoga. Pakka?');},'del'));
    c.appendChild(r);
    box.appendChild(c);
  });
  if(!box.children.length)box.appendChild(mk('div','Koi user nahi mila','sm'));
}
</script></body></html>`;
app.get('/admin', (req, res) => res.type('html').send(ADMIN_HTML));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log('Server on port ' + PORT));// =====================================================================
//  Dhanvishta Billing - Backend (server.js)  -- FIXED VERSION
//  Passwords ab code me nahi hain. Render > Environment me daalne hain:
//     MONGO_URI        (zaroori)  - MongoDB connection link
//     ADMIN_SECRET     (zaroori)  - admin password
//     ACTIVATION_SALT  (optional) - activation key banane ka raaz
// =====================================================================
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const MONGO_URI = process.env.MONGO_URI;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const ACTIVATION_SALT = process.env.ACTIVATION_SALT || ADMIN_SECRET;

if (!MONGO_URI || !ADMIN_SECRET) {
  console.error('ERROR: Render > Environment me MONGO_URI aur ADMIN_SECRET daalna zaroori hai.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(cors());

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('DB Error:', err.message));

// ---------------- User model ----------------
const UserSchema = new mongoose.Schema({
  name: { type: String, default: '' },                 // ab zaroori nahi (pehle ki wajah se register fail hota tha)
  phone: { type: String, unique: true, sparse: true },
  email: { type: String, unique: true, sparse: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  deviceId: { type: String, default: null },
  isActivated: { type: Boolean, default: false },
  isLocked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date, default: null }
});
const User = mongoose.model('User', UserSchema);

// ---------------- Helpers ----------------
const cleanPhone = (v) => {
  let d = String(v || '').replace(/\D/g, '');
  if (d.length > 10) d = d.slice(-10);
  return d;
};
const makeKey = (deviceId) =>
  crypto.createHmac('sha256', ACTIVATION_SALT).update(String(deviceId)).digest('hex').substring(0, 8).toUpperCase();
const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};
const findByPhone = (raw) => {
  const c = cleanPhone(raw);
  return User.findOne({ phone: { $in: [c, String(raw || '').trim()] } });
};

// Simple brute-force roak (15 min me 10 galat koshish)
const fails = new Map();
const WINDOW = 15 * 60 * 1000;
function tooMany(key) {
  const now = Date.now();
  const a = (fails.get(key) || []).filter(t => now - t < WINDOW);
  fails.set(key, a);
  return a.length >= 10;
}
function noteFail(key) { const a = fails.get(key) || []; a.push(Date.now()); fails.set(key, a); }
setInterval(() => fails.clear(), 60 * 60 * 1000);

function serverError(res, err) {
  console.error(err);
  if (err && err.code === 11000) return res.status(400).json({ error: 'User already exists' });
  res.status(500).json({ error: 'Server error. Thodi der baad try karein.' });
}

// ---------------- Health check (Render ko jagaye rakhne ke liye) ----------------
app.get('/', (req, res) => res.send('Dhanvishta server running'));

// ---------------- 1. Register ----------------
app.post('/api/register', async (req, res) => {
  try {
    const phone = cleanPhone(req.body.phone);
    const password = String(req.body.password || '');
    const name = String(req.body.name || '').trim() || phone;
    if (phone.length !== 10) return res.status(400).json({ error: 'Sahi 10 digit mobile number daalein' });
    if (password.length < 4) return res.status(400).json({ error: 'Password kam se kam 4 akshar ka rakhein' });

    const exists = await User.findOne({ phone });
    if (exists) return res.status(400).json({ error: 'Ye number pehle se registered hai. Login karein.' });

    const hashed = await bcrypt.hash(password, 10);
    await new User({ name, phone, password: hashed }).save();
    res.json({ message: 'Registered successfully' });
  } catch (err) { serverError(res, err); }
});

// ---------------- 2. Login ----------------
app.post('/api/login', async (req, res) => {
  try {
    const { phone: rawPhone, password, deviceId } = req.body;
    if (!rawPhone || !password || !deviceId) return res.status(400).json({ error: 'Phone, password aur device chahiye' });

    const key = req.ip + '|' + cleanPhone(rawPhone);
    if (tooMany(key)) return res.status(429).json({ error: 'Bahut zyada galat koshish. 15 minute baad try karein.' });

    const user = await findByPhone(rawPhone);
    const ok = user && await bcrypt.compare(String(password), user.password);
    if (!ok) { noteFail(key); return res.status(400).json({ error: 'Mobile number ya password galat hai' }); }

    if (user.deviceId && user.deviceId !== deviceId) {
      return res.status(403).json({ error: 'Ye account kisi doosre phone par lock hai. Admin se device reset karwayein.' });
    }
    if (!user.deviceId) user.deviceId = deviceId;
    user.lastLoginAt = new Date();
    await user.save();
    fails.delete(key);
    res.json({ message: 'Success', userId: user._id, activated: user.isActivated, locked: user.isLocked });
  } catch (err) { serverError(res, err); }
});

// ---------------- 3. Status check (app kholte hi) ----------------
// status: active | not_activated | expired | new_device | invalid
app.post('/api/check-status', async (req, res) => {
  try {
    const { userId, deviceId } = req.body;
    if (!mongoose.isValidObjectId(userId) || !deviceId) return res.json({ status: 'invalid' });
    const user = await User.findById(userId);
    if (!user) return res.json({ status: 'invalid' });

    if (user.deviceId && user.deviceId !== deviceId) return res.json({ status: 'new_device' });
    if (!user.deviceId) { user.deviceId = deviceId; await user.save(); }

    if (user.isLocked) return res.json({ status: 'expired' });
    if (!user.isActivated) return res.json({ status: 'not_activated' });
    res.json({ status: 'active' });
  } catch (err) { serverError(res, err); }
});

// ---------------- 4. Key se activate ----------------
app.post('/api/activate-device', async (req, res) => {
  try {
    const { userId, deviceId, activationKey } = req.body;
    if (!mongoose.isValidObjectId(userId) || !deviceId || !activationKey) return res.status(400).json({ error: 'Invalid request' });

    const fkey = 'act|' + userId;
    if (tooMany(fkey)) return res.status(429).json({ error: 'Bahut zyada galat koshish. 15 minute baad try karein.' });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.deviceId && user.deviceId !== deviceId) return res.status(403).json({ error: 'Ye account kisi doosre phone par lock hai.' });

    if (!safeEq(String(activationKey).trim().toUpperCase(), makeKey(deviceId))) {
      noteFail(fkey);
      return res.status(400).json({ error: 'Invalid Activation Key' });
    }
    user.isActivated = true;
    user.deviceId = deviceId;
    await user.save();
    res.json({ message: 'Device activated successfully!' });
  } catch (err) { serverError(res, err); }
});

// ====================== ADMIN ======================
const adminOnly = (req, res, next) => {
  if (!safeEq(req.get('x-admin-secret') || '', ADMIN_SECRET)) return res.status(403).json({ error: 'Galat admin password' });
  next();
};
const validId = (req, res) => {
  if (!mongoose.isValidObjectId(req.body.id)) { res.status(400).json({ error: 'Invalid id' }); return false; }
  return true;
};

app.post('/api/admin/users', adminOnly, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ _id: -1 }).lean();
    res.json({ users });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/reset-device', adminOnly, async (req, res) => {
  try {
    if (!validId(req, res)) return;
    await User.findByIdAndUpdate(req.body.id, { deviceId: null, isActivated: false });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/activate', adminOnly, async (req, res) => {
  try {
    if (!validId(req, res)) return;
    await User.findByIdAndUpdate(req.body.id, { isActivated: !!req.body.activated });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/lock', adminOnly, async (req, res) => {
  try {
    if (!validId(req, res)) return;
    await User.findByIdAndUpdate(req.body.id, { isLocked: !!req.body.lock });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/delete-user', adminOnly, async (req, res) => {
  try {
    if (!validId(req, res)) return;
    await User.findByIdAndDelete(req.body.id);
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.post('/api/admin/generate-key', adminOnly, (req, res) => {
  const deviceId = String(req.body.deviceId || '').trim();
  if (!deviceId) return res.status(400).json({ error: 'Device ID daalein' });
  res.json({ key: makeKey(deviceId) });
});

// ---------------- Admin Panel (browser me kholo: /admin) ----------------
const ADMIN_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dhanvishta Admin</title>
<style>
body{font-family:Arial,sans-serif;background:#f5f6fb;margin:0;padding:14px;color:#111}
h2{color:#1e1b4b;margin:4px 0 12px}
input{padding:11px;border:1.5px solid #ddd;border-radius:9px;font-size:15px;width:100%;box-sizing:border-box;margin-bottom:8px}
button{padding:9px 12px;border:0;border-radius:8px;background:#4f46e5;color:#fff;font-size:13px;font-weight:bold;margin:3px 4px 3px 0}
button.del{background:#dc2626}
.card{background:#fff;border-radius:12px;padding:12px;margin-bottom:10px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.sm{font-size:12px;color:#555;margin:4px 0;word-break:break-all}
.ok{color:#059669;font-weight:bold}.bad{color:#dc2626;font-weight:bold}
.box{background:#fff;border-radius:12px;padding:12px;margin-bottom:12px}
</style></head><body>
<h2>Dhanvishta Admin</h2>
<div id="login" class="box"><input id="sec" type="password" placeholder="Admin Password"><button onclick="openPanel()">Open</button></div>
<div id="panel" style="display:none">
  <div class="box"><b>Key banao (Device ID se)</b><input id="dev" placeholder="DEV-XXXXXXXX"><button onclick="act('/api/admin/generate-key',{deviceId:$('dev').value.trim()})">Make Key</button></div>
  <input id="q" placeholder="Search phone / name" oninput="draw()">
  <button onclick="load()">Refresh</button>
  <div id="list"></div>
</div>
<script>
var S='',U=[];
function $(i){return document.getElementById(i);}
function api(p,b){return fetch(p,{method:'POST',headers:{'Content-Type':'application/json','x-admin-secret':S},body:JSON.stringify(b||{})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||'Error');return d;});});}
function openPanel(){S=$('sec').value;load();}
function load(){api('/api/admin/users').then(function(d){U=d.users;$('login').style.display='none';$('panel').style.display='block';draw();}).catch(function(e){alert(e.message);});}
function act(path,body,ask){if(ask&&!confirm(ask))return;api(path,body).then(function(d){if(d.key)prompt('Activation Key (copy karein):',d.key);load();}).catch(function(e){alert(e.message);});}
function mk(t,txt,cls){var e=document.createElement(t);if(txt!==undefined&&txt!==null)e.textContent=txt;if(cls)e.className=cls;return e;}
function btn(label,fn,cls){var b=mk('button',label,cls);b.onclick=fn;return b;}
function draw(){
  var q=$('q').value.toLowerCase(),box=$('list');box.innerHTML='';
  U.filter(function(u){return !q||((u.phone||'')+' '+(u.name||'')).toLowerCase().indexOf(q)>-1;}).forEach(function(u){
    var c=mk('div',null,'card');
    c.appendChild(mk('b',u.phone||u.email||'-'));
    c.appendChild(mk('div','Device: '+(u.deviceId||'-- linked nahi --'),'sm'));
    var st=mk('div',null,'sm');
    st.appendChild(mk('span',u.isActivated?'Activated':'Not activated',u.isActivated?'ok':'bad'));
    st.appendChild(document.createTextNode(' | '));
    st.appendChild(mk('span',u.isLocked?'LOCKED':'Unlocked',u.isLocked?'bad':'ok'));
    c.appendChild(st);
    var r=mk('div');
    r.appendChild(btn('Reset Device',function(){act('/api/admin/reset-device',{id:u._id},'Device reset karein? User ko naye phone par dobara activate karna hoga.');}));
    r.appendChild(btn(u.isActivated?'Deactivate':'Activate',function(){act('/api/admin/activate',{id:u._id,activated:!u.isActivated});}));
    r.appendChild(btn(u.isLocked?'Unlock':'Lock',function(){act('/api/admin/lock',{id:u._id,lock:!u.isLocked});}));
    if(u.deviceId)r.appendChild(btn('Get Key',function(){act('/api/admin/generate-key',{deviceId:u.deviceId});}));
    r.appendChild(btn('Delete',function(){act('/api/admin/delete-user',{id:u._id},'Ye user hamesha ke liye delete hoga. Pakka?');},'del'));
    c.appendChild(r);
    box.appendChild(c);
  });
  if(!box.children.length)box.appendChild(mk('div','Koi user nahi mila','sm'));
}
</script></body></html>`;
app.get('/admin', (req, res) => res.type('html').send(ADMIN_HTML));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log('Server on port ' + PORT));
