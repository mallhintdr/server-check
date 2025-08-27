require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const crypto = require('crypto');

const nodemailer = require('nodemailer');

const PORT = process.env.PORT;
const SECRET_KEY = process.env.SECRET_KEY;
const CORS_ORIGIN = process.env.CORS_ORIGIN;
const MONGO_URI = process.env.MONGO_URI;

// If you have a folder named 'MurabbaData' in the same directory, use:
const ROOT        = path.join(__dirname, '..');        // geo-dashboard/
const PUBLIC_ROOT = path.join(ROOT, 'public');         // geo-dashboard/public
const GEO_ROOT    = path.join(PUBLIC_ROOT, 'JSON Murabba');
const TILE_ROOT   = path.join(PUBLIC_ROOT, 'Shajra Parcha');
// Middleware Configuration
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// app.use('/JSON Murabba',  express.static(GEO_ROOT));
app.use('/Shajra Parcha', express.static(TILE_ROOT));

// MongoDB Connection
mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((error) => console.error('MongoDB connection error:', error));

// Sub‐schema for session tracking
const sessionSchema = new mongoose.Schema({
  start: Date,
  end: Date,
  duration: Number,        // in seconds
  ipAddress: String
}, { _id: false });

// Sub‐schema for renewal history
const renewalEntrySchema = new mongoose.Schema({
  date: { type: Date,   required: true },
  type: { type: String, required: true }
}, { _id: false });

// User Schema
const userSchema = new mongoose.Schema({
  userName: String,
  userId: { type: String, unique: true, required: true },
  password: String,
  tehsil: String,
  mobileNumber: String,
  mauzaList: [String],
  startDate: Date,
  subscriptionType: String,
  endDate: Date,
  daysRemaining: Number,
  status: String,
  userType: { type: String, enum: ['user', 'admin'], default: 'user' },
email: { type: String, unique: true, sparse: true }
, // recommended for identification
resetPasswordToken: { type: String },
resetPasswordExpires: { type: Date },
  fee: { type: Number, default: 1000 },
  renewalHistory: { type: [renewalEntrySchema], default: [] },
  renewalCount: { type: Number, default: 0 },
  sessions: [sessionSchema]
});

// --- GeoJSON Schema & Model ---
const geoJsonSchema = new mongoose.Schema({
  tehsil: { type: String, required: true, index: true },
  mauza:  { type: String, required: true, index: true },
  data:   { type: mongoose.Schema.Types.Mixed, required: true },
  defaultBounds: { type: [[Number]], default: null } // [[swLat, swLng], [neLat, neLng]]
});
const GeoJson = mongoose.model('GeoJson', geoJsonSchema);


// Helper: Calculate End Date, Days Remaining, and Status
const calculateDatesAndStatus = (startDate, subscriptionType) => {
  const subscriptionDays = {
    Trial: 5,
    Monthly: 30,
    Quarterly: 90,
    Biannual: 180,
    Annual: 365
  };
  const days = subscriptionDays[subscriptionType] || 0;
  const start = new Date(startDate);
  const endDate = new Date(start);
  endDate.setDate(endDate.getDate() + days);

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const daysRemaining = Math.max(
    Math.ceil((endDate - today) / (1000 * 60 * 60 * 24)),
    0
  );
  const status = daysRemaining > 0 ? 'Active' : 'Inactive';

  return { endDate, daysRemaining, status };
};


const FEET_TO_METERS = 0.3048;

function shiftCoordinates(coords, dx, dy) {
  if (typeof coords[0] === 'number') {
    const lat = coords[1];
    // Equirectangular approximation
    const dLat = dy / 111320;
    const dLon = dx / (111320 * Math.cos(lat * Math.PI / 180));
    return [coords[0] + dLon, coords[1] + dLat];
  }
  return coords.map(c => shiftCoordinates(c, dx, dy));
}

function getGeoJsonBounds(features) {
  // Returns [[minLat, minLng], [maxLat, maxLng]]
  const coords = [];
  features.forEach(f => {
    let arr = [];
    if (f.geometry?.type === "Polygon") arr = f.geometry.coordinates.flat();
    if (f.geometry?.type === "MultiPolygon") arr = f.geometry.coordinates.flat(2);
    coords.push(...arr);
  });
  if (!coords.length) return null;
  const lats = coords.map(c => c[1]);
  const lngs = coords.map(c => c[0]);
  return [
    [Math.min(...lats), Math.min(...lngs)],
    [Math.max(...lats), Math.max(...lngs)]
  ];
}

// Find shift required to move current bounds to default bounds
function computeShift(current, target) {
  // Move SW corner
  const [curLat, curLng] = current[0];
  const [tgtLat, tgtLng] = target[0];
  // Approximate meters delta
  const dLat = tgtLat - curLat;
  const dLng = tgtLng - curLng;
  // Convert degrees to meters
  const metersY = dLat * 111320;
  const metersX = dLng * 111320 * Math.cos(curLat * Math.PI / 180);
  return { dx: metersX, dy: metersY };
}

// Middleware: Hash Password and Calculate Status before Save
userSchema.pre('save', async function (next) {
  try {
    if (this.isModified('password')) {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
    }
    const { endDate, daysRemaining, status } = calculateDatesAndStatus(
      this.startDate,
      this.subscriptionType
    );
    this.endDate = endDate;
    this.daysRemaining = daysRemaining;
    this.status = status;
    next();
  } catch (error) {
    next(error);
  }
});

const User = mongoose.model('User', userSchema);



app.get('/api/public/check-userid/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const user = await User.findOne({ userId });
    if (user) return res.json({ exists: true });
    else return res.json({ exists: false });
  } catch (err) {
    return res.status(500).json({ exists: false });
  }
});


// --- Auth Middleware ---

// 1) Verify token, subscription, and attach full user to req

const isAuthenticated = async (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ message: 'Not authenticated' });

  jwt.verify(token, SECRET_KEY, async (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid or expired token' });

    try {
      const user = await User.findOne({ userId: decoded.userId });
      if (!user) return res.status(404).json({ message: 'User not found' });

      const { status } = calculateDatesAndStatus(
        user.startDate,
        user.subscriptionType
      );
      if (status === 'Inactive') {
        res.clearCookie('authToken');
        return res.status(403).json({ message: 'Subscription Expired' });
      }

      req.user = user;
      next();
    } catch (error) {
      console.error('Error in isAuthenticated middleware:', error.message);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
};

// 2) Role-check middleware
const isAdmin = (req, res, next) => {
  if (req.user.userType !== 'admin') {
    return res.status(403).json({ message: 'Forbidden: admins only' });
  }
  next();
};

const isSelfOrAdmin = (req, res, next) => {
  if (req.user.userType === 'admin' || req.user.userId === req.params.userId) {
    return next();
  }
  res.status(403).json({ message: 'Forbidden' });
};

// --- Routes ---

// dynamic GeoJSON from MongoDB
app.get('/api/geojson/:tehsil/:mauza', async (req, res) => {
  const { tehsil, mauza } = req.params;
  const reqTime = new Date().toISOString();
  console.log(`[${reqTime}] GeoJSON fetch requested: tehsil="${tehsil}", mauza="${mauza}"`);
  try {
    const doc = await GeoJson.findOne({ tehsil, mauza });
    if (!doc) {
      console.log(`[${reqTime}] GeoJSON NOT FOUND for: tehsil="${tehsil}", mauza="${mauza}"`);
      return res.status(404).json({ message: 'GeoJSON not found' });
    }
    // Log stats about the data, e.g. feature count if FeatureCollection
    let featuresCount = 0;
    if (doc.data && doc.data.features && Array.isArray(doc.data.features)) {
      featuresCount = doc.data.features.length;
    }
    console.log(`[${reqTime}] GeoJSON FOUND for: tehsil="${tehsil}", mauza="${mauza}". Features: ${featuresCount}`);
    res.json(doc.data);
  } catch (err) {
    console.error(`[${reqTime}] Error fetching GeoJSON for tehsil="${tehsil}", mauza="${mauza}":`, err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login

app.post('/login', async (req, res) => {
  const { userId, password } = req.body;

  try {
    // 1. Lookup user
    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(401).json({ message: 'Invalid user ID or password.' });
    }

    // 2. Check subscription status
    const { status, endDate, daysRemaining } = calculateDatesAndStatus(
      user.startDate,
      user.subscriptionType
    );
    if (status === 'Inactive') {
      return res.status(403).json({
        message: 'Subscription Expired',
        userDetails: {
          userName:     user.userName,
          startDate:    user.startDate,
          endDate,
          daysRemaining
        }
      });
    }

    // 3. Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid user ID or password.' });
    }

    // 4. Sign a 30-day JWT
    const token = jwt.sign(
      { userId: user.userId },
      SECRET_KEY,
      { expiresIn: '30d' }
    );

    // 5. Prune sessions older than 30 days, then add this login
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    // keep only sessions started within the last 30 days
    user.sessions = user.sessions.filter(s => s.start.getTime() >= cutoff);
    // record the new session
    user.sessions.push({
      start:     new Date(),
      ipAddress: req.ip
    });
    await user.save();

    // 6. Set cookie and return success
    return res
      .cookie('authToken', token, {
        httpOnly: true,
        secure:   process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge:   30 * 24 * 60 * 60 * 1000
      })
      .json({ message: 'Login successful' });

  } catch (error) {
    console.error('Login error:', error.message);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// 2. Forgot Password endpoint
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      // Always send success message to prevent email enumeration
      return res.json({ message: 'If this email is registered, a reset link has been sent.' });
    }

    // Generate a reset token (valid for 1 hour)
    const resetToken = jwt.sign(
      { userId: user.userId },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    // Construct reset link (adjust frontend URL as needed)
const resetLink = `${process.env.CORS_ORIGIN}/reset-password?token=${resetToken}`;
    // Send email (adjust sender, subject, and message as desired)
    let transporter = nodemailer.createTransport({
      // Use your SMTP settings (for your domain or Gmail)
      host: 'smtp.stackmail.com', // or 'smtp.gmail.com'
      port: 465, // 587 for TLS, 587 for SSL
      secure: true,
      auth: {
        user: process.env.SMTP_USER, // your email, e.g., reset-password@naqsha-zameen.pk
        pass: process.env.SMTP_PASS, // your email password or app password
      },
    });

    await transporter.sendMail({
      from: `"Naqsha Zameen" <${process.env.SMTP_USER}>`,
      to: user.email,
      subject: 'Reset your password',
      html: `
        <p>Dear ${user.userName},</p>
        <p>To reset your password, please click the link below. This link is valid for 1 hour:</p>
        <a href="${resetLink}">${resetLink}</a>
        <p>If you did not request this, please ignore this email.</p>
      `,
    });

    res.json({ message: 'If this email is registered, a reset link has been sent.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Failed to send reset email.' });
  }
});


// POST /api/auth/request-reset
app.post('/api/auth/request-reset', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required.' });

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'No user with this email.' });

  // Generate token & set expiry
  const token = crypto.randomBytes(32).toString('hex');
  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 1000 * 60 * 60; // 1 hour
  await user.save();

  // Construct reset link
  const resetLink = `${process.env.FRONTEND_URL}/reset-password/${token}`;

  // Email setup
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: 'Reset your password',
    html: `<p>Click the link below to reset your password (valid for 1 hour):<br>
           <a href="${resetLink}">${resetLink}</a></p>`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ message: 'Password reset link sent. Please check your email.' });
  } catch (err) {
    console.error('Reset email error:', err);
    res.status(500).json({ message: 'Failed to send email.' });
  }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ message: 'Invalid request.' });

  try {
    // Verify JWT token
    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await User.findOne({ userId: decoded.userId });
    if (!user) return res.status(400).json({ message: 'Invalid token/user.' });

    user.password = password; // Will be hashed by pre-save
    await user.save();

    res.json({ message: 'Password reset successful. You can now log in.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(400).json({ message: 'Token invalid or expired.' });
  }
});


// Logout
app.post('/logout', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.user.userId });
    if (user && user.sessions.length) {
      const lastSession = user.sessions[user.sessions.length - 1];
      if (!lastSession.end) {
        lastSession.end = new Date();
        lastSession.duration = Math.ceil((lastSession.end - lastSession.start) / 1000);
        await user.save();
      }
    }
  } catch (error) {
    console.error('Logout session error:', error);
  } finally {
    res.clearCookie('authToken', { httpOnly: true, path: '/' })
       .json({ message: 'Logout successful' });
  }
});

// Register (open)
app.post('/register', async (req, res) => {
  try {
    const { password, ...userData } = req.body;
    const newUser = new User({
      ...userData,
      password,
      mauzaList: req.body.mauzaList.map(m => m.trim()),
    });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    console.error('Registration failed:', error.message);
    res.status(400).json({ error: 'Registration failed', details: error.message });
  }
});

// Renewal
app.post('/users/:userId/renew', isAuthenticated, async (req, res) => {
  try {
    const { subscriptionType } = req.body;
    const now = new Date();
    const user = await User.findOne({ userId: req.params.userId });
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.renewalHistory.push({ date: now, type: subscriptionType });
    user.renewalCount++;
    user.startDate = now;
    user.subscriptionType = subscriptionType;
    const { endDate, daysRemaining, status } = calculateDatesAndStatus(now, subscriptionType);
    user.endDate = endDate;
    user.daysRemaining = daysRemaining;
    user.status = status;
    await user.save();

    res.json({ message: 'Subscription renewed', user });
  } catch (error) {
    console.error('Renewal error:', error);
    res.status(500).json({ message: 'Failed to renew subscription' });
  }
});

// Change Password (requires authentication)
app.post('/change-password', isAuthenticated, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  try {
    const user = await User.findOne({ userId: req.user.userId });
    if (!user) return res.status(404).json({ message: 'User not found.' });

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Incorrect old password.' });

    user.password = newPassword;
    await user.save();
    res.clearCookie('authToken', { httpOnly: true, path: '/' })
       .status(200)
       .json({ message: 'Password changed successfully. Please log in again.' });
  } catch (error) {
    console.error('Password change error:', error.message);
    res.status(500).json({ message: 'Failed to change password.' });
  }
});

// Profile
app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.user.userId }).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.status(200).json(user);
  } catch (error) {
    console.error('Failed to fetch profile:', error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// --- Protected CRUD Routes ---

app.get('/api/users/search', isAuthenticated, isAdmin, async (req, res) => {
  const query = req.query.query?.toLowerCase() || '';
  if (!query) return res.json([]);
  try {
    const users = await User.find({
      $or: [
        { userId:   { $regex: query, $options: 'i' } },
        { userName: { $regex: query, $options: 'i' } }
      ]
    }).limit(15).select('userId userName -_id');
    res.json(users);
  } catch (err) {
    console.error('User search error:', err);
    res.status(500).json([]);
  }
});

app.get('/api/tehsil-list', async (req, res) => {
  try {
    const tehsils = await GeoJson.distinct('tehsil');
    res.json(tehsils.sort((a, b) => a.localeCompare(b)));
  } catch (err) {
    console.error('tehsil-list error:', err);
    res.status(500).json([]);
  }
});

// GET all users (admin only)
app.get('/users', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const users = await User.find();
    res.status(200).json(users);
  } catch (error) {
    console.error('Failed to fetch users:', error.message);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET user by ID (self or admin)
app.get('/users/:userId', isAuthenticated, isSelfOrAdmin, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.params.userId });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.status(200).json(user);
  } catch (error) {
    console.error('Error fetching user:', error.message);
    res.status(500).json({ message: 'Failed to fetch user' });
  }
});

// UPDATE user (self or admin)
app.put('/users/:userId', isAuthenticated, isSelfOrAdmin, async (req, res) => {
  try {
    const updateData = { ...req.body };
    if (!updateData.password || !updateData.password.trim()) {
  delete updateData.password;
}


    // Fetch existing user to check for renewal
    const user = await User.findOne({ userId: req.params.userId });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Detect subscriptionType or startDate change
    let isRenewal = false;
    if (
      (updateData.subscriptionType && updateData.subscriptionType !== user.subscriptionType) ||
      (updateData.startDate && new Date(updateData.startDate).getTime() !== new Date(user.startDate).getTime())
    ) {
      isRenewal = true;
    }

    // Actually update the fields
    Object.assign(user, updateData);

    // If it's a renewal (and not during user creation), push to history
    if (isRenewal) {
      user.renewalHistory.push({
        date: new Date(),
        type: user.subscriptionType
      });
      user.renewalCount = (user.renewalCount || 0) + 1;
    }

    await user.save();

    res.status(200).json({ message: 'User updated successfully', user });
  } catch (error) {
    console.error('Failed to update user:', error.message);
    res.status(500).json({ message: 'Failed to update user' });
  }
});


// DELETE user (admin only)
app.delete('/users/:userId', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const user = await User.findOneAndDelete({ userId: req.params.userId });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.status(200).json({ message: 'User deleted successfully!' });
  } catch (error) {
    console.error('Failed to delete user:', error.message);
    res.status(500).json({ message: 'Failed to delete user' });
  }
});

// Stats (public)
app.get('/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const onlineAgg = await User.aggregate([
      { $unwind: '$sessions' },
      { $match: { 'sessions.end': { $exists: false } } },
      { $count: 'onlineCount' }
    ]);
    const totalOnline = onlineAgg[0]?.onlineCount || 0;
    const cutoff = new Date(Date.now() - 30*24*60*60*1000);
    const sessions = await User.aggregate([
      { $unwind: '$sessions' },
      { $match: { 'sessions.start': { $gte: cutoff } } },
      { $project: { start: '$sessions.start', end: '$sessions.end' } }
    ]);
    res.json({ totalUsers, totalOnline, sessions });
  } catch (err) {
    console.error('Stats error', err);
    res.status(500).json({ error: 'Unable to fetch statistics' });
  }
});

/* ------------------------------------------------------------------
   FULL mauza list  =  geojson names  ∪  folder names
------------------------------------------------------------------ */
app.get('/api/mauza-list/:tehsil', async (req, res) => {
  const fsP    = require('fs/promises');
  const tehsil = req.params.tehsil.trim();

  // robust path construction (works on Windows & *nix)
  const geoDir  = path.resolve(GEO_ROOT,  tehsil);
  const tileDir = path.resolve(TILE_ROOT, tehsil);

  try {
    const [geoFiles, tileDirents] = await Promise.all([
      fsP.readdir(geoDir).catch(() => []),
      fsP.readdir(tileDir, { withFileTypes: true }).catch(() => [])
    ]);

    const geoNames  = geoFiles
      .filter(f => f.toLowerCase().endsWith('.geojson'))
      .map(f => path.parse(f).name);

    const tileNames = tileDirents
      .filter(d => d.isDirectory())
      .map(d => d.name);

    const names = new Set([...geoNames, ...tileNames]);

    console.log('[mauza‑list]', tehsil,
                'geo:', geoNames.length,
                'tiles:', tileNames.length,
                'total:', names.size);

    res.json([...names].sort((a, b) => a.localeCompare(b)));
  } catch (err) {
    console.error('mauza‑list error:', err);
    res.json([]);   // fail soft
  }
});
/* ------------------------------------------------------------------
   LIVE list of users whose last session has no `end` timestamp
------------------------------------------------------------------ */
app.get('/online-users', isAuthenticated /* or isAdmin */, async (_req, res) => {
  try {
    const list = await User.aggregate([
      { $unwind: '$sessions' },
      { $match:  { 'sessions.end': { $exists: false } } },
      {
        $project: {
          _id: 0,
          userName:         1,
          userId:           1,
          tehsil:           1,
          subscriptionType: 1,
          ipAddress:        '$sessions.ipAddress',
          start:            '$sessions.start'
        }
      },
      { $sort: { start: -1 } }
    ]);
    res.json(list);
  } catch (err) {
    console.error('online-users error', err);
    res.status(500).json({ error: 'Unable to fetch online users' });
  }
});
// POST: Shift GeoJSON
app.post('/api/geojson/:tehsil/:mauza/shift', isAuthenticated, async (req, res) => {
  const { tehsil, mauza } = req.params;
  const { distance, direction } = req.body; // { distance: Number (feet), direction: 'North'|'South'|'East'|'West' }
  const meters = parseFloat(distance) * FEET_TO_METERS;

  let dx = 0, dy = 0;
  if (direction === 'East')  dx = meters;
  if (direction === 'West')  dx = -meters;
  if (direction === 'North') dy = meters;
  if (direction === 'South') dy = -meters;

  const doc = await GeoJson.findOne({ tehsil, mauza });
  if (!doc) return res.status(404).json({ message: 'GeoJSON not found' });

  // Set defaultBounds only if not already set
  if (!doc.defaultBounds) {
    const bounds = getGeoJsonBounds(doc.data.features);
    if (!bounds) return res.status(400).json({ message: 'No geometry found' });
    doc.defaultBounds = bounds;
  }

  // Shift
  doc.data.features.forEach(f => {
    f.geometry.coordinates = shiftCoordinates(f.geometry.coordinates, dx, dy);
  });
  await doc.save();
  res.json({ success: true, data: doc.data });
});

// POST: Reset GeoJSON to Default Bounds
app.post('/api/geojson/:tehsil/:mauza/reset', isAuthenticated, async (req, res) => {
  const { tehsil, mauza } = req.params;
  const doc = await GeoJson.findOne({ tehsil, mauza });
  if (!doc || !doc.defaultBounds) return res.status(400).json({ message: 'No default bounds set' });

  // Get current bounds
  const currentBounds = getGeoJsonBounds(doc.data.features);
  if (!currentBounds) return res.status(400).json({ message: 'No geometry found' });

  // Compute shift needed to realign SW corners
  const { dx, dy } = computeShift(currentBounds, doc.defaultBounds);

  // Shift back
  doc.data.features.forEach(f => {
    f.geometry.coordinates = shiftCoordinates(f.geometry.coordinates, dx, dy);
  });
  await doc.save();
  res.json({ success: true, data: doc.data });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
