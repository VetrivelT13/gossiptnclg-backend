// server.js - Complete Backend for GossipTNClg
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// ===== MODELS =====

// User Model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  college: { type: String, default: '' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  banned: { type: Boolean, default: false },
  bannedReason: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Post Model
const postSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  type: { type: String, enum: ['gossip', 'meme', 'confession'], default: 'gossip' },
  content: String,
  imageUrl: String,
  college: String,
  reactions: {
    like: { type: Number, default: 0 },
    laugh: { type: Number, default: 0 },
    dislike: { type: Number, default: 0 }
  },
  timestamp: { type: Date, default: Date.now },
  expiresAt: Date, // For confessions auto-delete
  reported: { type: Boolean, default: false },
  reportCount: { type: Number, default: 0 },
  reportReasons: [String]
});
const Post = mongoose.model('Post', postSchema);

// Event Model
const eventSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  title: { type: String, required: true },
  description: String,
  date: Date,
  imageUrl: String,
  approved: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now }
});
const Event = mongoose.model('Event', eventSchema);

// Poll Model
const pollSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  question: { type: String, required: true },
  options: [String],
  votes: [Number],
  voters: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // Track who voted
  expiresAt: Date,
  timestamp: { type: Date, default: Date.now }
});
const Poll = mongoose.model('Poll', pollSchema);

// ===== HELPER FUNCTIONS =====

// Generate Anonymous Username
const generateUsername = () => {
  const adjectives = ['Canteen', 'Bench', 'Library', 'Hostel', 'Campus', 'Exam', 'Bunking', 'Placement', 'Lab', 'Semester'];
  const nouns = ['Ninja', 'Warrior', 'Legend', 'Master', 'Hero', 'Pro', 'Wizard', 'King', 'Queen', 'Ghost'];
  const num = Math.floor(Math.random() * 1000);
  return `${adjectives[Math.floor(Math.random() * adjectives.length)]}${nouns[Math.floor(Math.random() * nouns.length)]}${num}`;
};

// Generate Obfuscated College Hint
const generateCollegeHint = () => {
  const hints = [
    'Top Engineering Hub 🎓',
    'Arts College Vibes 🎨',
    'Tech Campus 💻',
    'Medical Marvel 🏥',
    'Law School Elite ⚖️',
    'Management Institute 📊',
    'Science Paradise 🔬',
    'Commerce Corner 💼'
  ];
  return hints[Math.floor(Math.random() * hints.length)];
};

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Admin Middleware
const isAdmin = async (req, res, next) => {
  const user = await User.findById(req.user.userId);
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ===== ROUTES =====

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, college } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate unique username
    let username = generateUsername();
    while (await User.findOne({ username })) {
      username = generateUsername();
    }

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      username,
      college: college || ''
    });

    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        college: user.college,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Email not registered' });
    }

    // Check if banned
    if (user.banned) {
      return res.status(403).json({ error: `Your account has been banned. Reason: ${user.bannedReason || 'Violation of community guidelines'}` });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Incorrect password' });
    }

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        college: user.college,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST ROUTES
app.get('/api/posts', async (req, res) => {
  try {
    const { type, limit = 50 } = req.query;
    const query = type ? { type } : {};
    
    const posts = await Post.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));
    
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Bad word filter
const BAD_WORDS = ['rape','kill yourself','kys','die','suicide','slut','whore','bitch','prostitute','naked','nude','sex','porn','fuck','fucking','bastard','idiot','stupid girl','ugly','fat bitch','characterless','loose','sleeps around'];
const containsBadWords = (text) => {
  const lower = text.toLowerCase();
  return BAD_WORDS.some(w => lower.includes(w));
};

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { content, type, imageUrl } = req.body;
    const user = await User.findById(req.user.userId);

    // Block banned users
    if (user.banned) {
      return res.status(403).json({ error: 'Your account has been banned for violating community guidelines.' });
    }

    // Block harmful content
    if (containsBadWords(content)) {
      return res.status(400).json({ error: '🚫 Your post contains content that violates our community guidelines. Posts targeting or harassing individuals are not allowed.' });
    }

    const post = new Post({
      userId: user._id,
      username: user.username,
      content,
      type,
      imageUrl,
      college: user.college || generateCollegeHint(),
      expiresAt: type === 'confession' ? new Date(Date.now() + 48 * 60 * 60 * 1000) : null
    });

    await post.save();

    // Emit to all connected clients via Socket.io
    io.emit('new_post', post);

    res.status(201).json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/posts/:id/react', authenticateToken, async (req, res) => {
  try {
    const { type } = req.body; // 'like', 'laugh', 'dislike'
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    post.reactions[type] += 1;
    await post.save();

    // Emit reaction update
    io.emit('post_reaction', { postId: post._id, reactions: post.reactions });

    res.json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Only owner or admin can delete
    if (post.userId.toString() !== req.user.userId) {
      const user = await User.findById(req.user.userId);
      if (user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
      }
    }

    await Post.findByIdAndDelete(req.params.id);
    
    io.emit('post_deleted', req.params.id);
    
    res.json({ message: 'Post deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// EVENT ROUTES
app.get('/api/events', async (req, res) => {
  try {
    const events = await Event.find().sort({ timestamp: -1 });
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/events', authenticateToken, async (req, res) => {
  try {
    const { title, description, date, imageUrl } = req.body;
    const user = await User.findById(req.user.userId);

    const event = new Event({
      userId: user._id,
      username: user.username,
      title,
      description,
      date,
      imageUrl,
      approved: true  // Auto-approved — no admin permission needed
    });

    await event.save();
    
    io.emit('new_event', event);
    
    res.status(201).json(event);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/events/:id/approve', authenticateToken, isAdmin, async (req, res) => {
  try {
    const event = await Event.findByIdAndUpdate(
      req.params.id,
      { approved: true },
      { new: true }
    );
    
    io.emit('event_approved', event);
    
    res.json(event);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POLL ROUTES
app.get('/api/polls', async (req, res) => {
  try {
    const polls = await Poll.find().sort({ timestamp: -1 });
    res.json(polls);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/polls', authenticateToken, async (req, res) => {
  try {
    const { question, options } = req.body;
    const user = await User.findById(req.user.userId);

    const poll = new Poll({
      userId: user._id,
      username: user.username,
      question,
      options,
      votes: options.map(() => 0),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
    });

    await poll.save();
    
    io.emit('new_poll', poll);
    
    res.status(201).json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/polls/:id/vote', authenticateToken, async (req, res) => {
  try {
    const { optionIndex } = req.body;
    const poll = await Poll.findById(req.params.id);

    if (!poll) {
      return res.status(404).json({ error: 'Poll not found' });
    }

    // Check if user already voted
    if (poll.voters.includes(req.user.userId)) {
      return res.status(400).json({ error: 'Already voted' });
    }

    poll.votes[optionIndex] += 1;
    poll.voters.push(req.user.userId);
    await poll.save();

    io.emit('poll_update', poll);

    res.json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// TRENDING / HOT GOSSIP
app.get('/api/trending', async (req, res) => {
  try {
    const posts = await Post.find({ type: 'gossip' })
      .sort({ timestamp: -1 })
      .limit(50);

    // Calculate trending score
    const trending = posts.map(post => ({
      ...post.toObject(),
      score: post.reactions.like + (post.reactions.laugh * 2) - post.reactions.dislike
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);

    res.json(trending);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ADMIN ROUTES
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const stats = {
      totalUsers: await User.countDocuments(),
      totalPosts: await Post.countDocuments(),
      totalEvents: await Event.countDocuments(),
      pendingEvents: await Event.countDocuments({ approved: false }),
      reportedPosts: await Post.countDocuments({ reported: true })
    };
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// REPORT A POST
app.post('/api/posts/:id/report', authenticateToken, async (req, res) => {
  try {
    const { reason } = req.body;
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });

    post.reported = true;
    post.reportCount = (post.reportCount || 0) + 1;
    if (reason) post.reportReasons.push(reason);

    // Auto-hide if reported 3+ times
    if (post.reportCount >= 3) {
      post.autoHidden = true;
    }

    await post.save();
    io.emit('post_reported', { postId: post._id, reportCount: post.reportCount });
    res.json({ message: 'Post reported. Our team will review it.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET REPORTED POSTS (admin)
app.get('/api/admin/reported-posts', authenticateToken, isAdmin, async (req, res) => {
  try {
    const posts = await Post.find({ reported: true }).sort({ reportCount: -1, timestamp: -1 });
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// BAN USER (admin)
app.post('/api/admin/ban-user', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { userId, reason } = req.body;
    const user = await User.findByIdAndUpdate(
      userId,
      { banned: true, bannedReason: reason || 'Violation of community guidelines' },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Delete all their posts
    await Post.deleteMany({ userId: user._id });
    io.emit('user_banned', { userId: user._id });

    res.json({ message: `✅ ${user.username} has been banned and their posts removed.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// UNBAN USER (admin)
app.post('/api/admin/unban-user', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findByIdAndUpdate(userId, { banned: false, bannedReason: '' }, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: `✅ ${user.username} has been unbanned.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// CLEAR REPORT ON POST (admin reviewed and cleared)
app.put('/api/admin/posts/:id/clear-report', authenticateToken, isAdmin, async (req, res) => {
  try {
    const post = await Post.findByIdAndUpdate(
      req.params.id,
      { reported: false, reportCount: 0, reportReasons: [], autoHidden: false },
      { new: true }
    );
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ONE-TIME ADMIN SETUP (only works if no admin exists yet)
app.post('/api/admin/make-admin', async (req, res) => {
  try {
    const { email, secretKey } = req.body;
    if (secretKey !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: 'Wrong secret key' });
    }
    const existingAdmin = await User.findOne({ role: 'admin' });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin already exists', admin: existingAdmin.email });
    }
    const user = await User.findOneAndUpdate({ email }, { role: 'admin' }, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: `✅ ${user.username} is now admin!`, user: { email: user.email, username: user.username, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE EVENT (admin only)
app.delete('/api/events/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Event.findByIdAndDelete(req.params.id);
    io.emit('event_deleted', req.params.id);
    res.json({ message: 'Event deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE POST (admin only)
app.delete('/api/admin/posts/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Post.findByIdAndDelete(req.params.id);
    io.emit('post_deleted', req.params.id);
    res.json({ message: 'Post deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET ALL PENDING EVENTS (admin)
app.get('/api/admin/pending-events', authenticateToken, isAdmin, async (req, res) => {
  try {
    const events = await Event.find({ approved: false }).sort({ timestamp: -1 });
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== SOCKET.IO =====
let connectedUsers = 0;

io.on('connection', (socket) => {
  connectedUsers++;
  console.log('🔌 User connected:', socket.id, `| Online: ${connectedUsers}`);

  // Broadcast updated count to all clients
  io.emit('reader_count', connectedUsers);

  socket.on('disconnect', () => {
    connectedUsers = Math.max(0, connectedUsers - 1);
    console.log('❌ User disconnected:', socket.id, `| Online: ${connectedUsers}`);
    io.emit('reader_count', connectedUsers);
  });
});

// GET live reader count
app.get('/api/stats/live', (req, res) => {
  res.json({ count: connectedUsers });
});

// ===== CRON JOB - Delete expired confessions =====
setInterval(async () => {
  try {
    const result = await Post.deleteMany({
      type: 'confession',
      expiresAt: { $lt: new Date() }
    });
    if (result.deletedCount > 0) {
      console.log(`🗑️ Deleted ${result.deletedCount} expired confessions`);
    }
  } catch (error) {
    console.error('Error deleting confessions:', error);
  }
}, 60 * 60 * 1000); // Run every hour

// ===== START SERVER =====
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});