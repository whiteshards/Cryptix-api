
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many authentication attempts' },
  standardHeaders: true,
  legacyHeaders: false,
});

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const customerSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: /^[a-zA-Z0-9_]+$/
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  collection: 'customers'
});

customerSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

customerSchema.methods.comparePassword = async function(password) {
  return bcrypt.compare(password, this.password);
};

const Customer = mongoose.model('Customer', customerSchema);

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  });
};

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const customer = await Customer.findById(decoded.userId).select('-password');
    
    if (!customer) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.customer = customer;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const validateInput = (req, res, next) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  if (username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: 'Username must be 3-30 characters' });
  }
  
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
  }
  
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  
  next();
};

app.post('/register', authLimiter, validateInput, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const existingCustomer = await Customer.findOne({ username });
    if (existingCustomer) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    
    const customer = new Customer({ username, password });
    await customer.save();
    
    const token = generateToken(customer._id);
    
    res.status(201).json({
      success: true,
      token,
      customer: {
        id: customer._id,
        username: customer.username,
        createdAt: customer.createdAt
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/login', authLimiter, validateInput, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const customer = await Customer.findOne({ username });
    if (!customer) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isPasswordValid = await customer.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = generateToken(customer._id);
    
    res.json({
      success: true,
      token,
      customer: {
        id: customer._id,
        username: customer.username,
        createdAt: customer.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/profile', authenticateToken, (req, res) => {
  res.json({
    success: true,
    customer: {
      id: req.customer._id,
      username: req.customer.username,
      createdAt: req.customer.createdAt
    }
  });
});

app.get('/protected', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'This is a protected route',
    customer: req.customer.username
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((error, req, res, next) => {
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = { app, authenticateToken };
