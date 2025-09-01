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

app.use('/JSON Murabba',  express.static(GEO_ROOT));
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

  fee: { type: Number, default: 1000 },
  renewalHistory: { type: [renewalEntrySchema], default: [] },
  renewalCount: { type: Number, default: 0 },
  sessions: [sessionSchema]
});

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
    if (updateData.password && updateData.password.trim()) {
      const salt = await bcrypt.genSalt(10);
      updateData.password = await bcrypt.hash(updateData.password, salt);
    } else {
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

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
