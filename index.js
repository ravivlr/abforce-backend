const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const validator = require('validator');
const { sendEmail } = require('./emailService');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: [
    'https://glittery-halva-254a81.netlify.app', 
    'http://localhost:3000', // For local development
    'http://localhost:5500'  // For local development
  ],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parsing middleware
app.use(express.json());

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/abforce';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  console.log('Continuing with in-memory database for testing...');
});

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String,
    default: null
  },
  passwordResetToken: {
    type: String,
    default: null
  },
  passwordResetExpires: {
    type: Date,
    default: null
  },
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  accountLockedUntil: {
    type: Date,
    default: null
  },
  twoFactorSecret: {
    type: String,
    default: null
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: null
  },
  lastPasswordChange: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// In-memory database fallback for testing
let inMemoryUsers = [];
let userIdCounter = 1;

// Helper function to get user by ID or create one
const getUserById = (id) => {
  if (mongoose.connection.readyState === 1) {
    return User.findById(id);
  } else {
    return Promise.resolve(inMemoryUsers.find(u => u._id === id));
  }
};

// Helper function to find user by query
const findUser = (query) => {
  if (mongoose.connection.readyState === 1) {
    return User.findOne(query);
  } else {
    return Promise.resolve(inMemoryUsers.find(u => {
      if (query.$or) {
        return query.$or.some(condition => {
          const key = Object.keys(condition)[0];
          return u[key] === condition[key];
        });
      }
      // Handle special cases for date comparisons
      if (query.passwordResetExpires && query.passwordResetExpires.$gt) {
        return u.passwordResetToken === query.passwordResetToken && 
               u.passwordResetExpires && 
               new Date(u.passwordResetExpires) > query.passwordResetExpires.$gt;
      }
      return Object.keys(query).every(key => {
        if (key === 'passwordResetExpires') return true; // Skip this in the every check
        return u[key] === query[key];
      });
    }));
  }
};

// Helper function to save user
const saveUser = (userData) => {
  if (mongoose.connection.readyState === 1) {
    // For MongoDB, create a new User document or update existing one
    if (userData._id) {
      // Update existing user
      return User.findByIdAndUpdate(userData._id, userData, { new: true, upsert: true });
    } else {
      // Create new user
      const user = new User(userData);
      return user.save();
    }
  } else {
    const user = {
      _id: userData._id || `user_${userIdCounter++}`,
      username: userData.username,
      email: userData.email,
      password: userData.password,
      createdAt: new Date(),
      lastLogin: null,
      isEmailVerified: userData.isEmailVerified || false,
      emailVerificationToken: userData.emailVerificationToken || null,
      passwordResetToken: userData.passwordResetToken || null,
      passwordResetExpires: userData.passwordResetExpires || null,
      failedLoginAttempts: userData.failedLoginAttempts || 0,
      accountLockedUntil: userData.accountLockedUntil || null,
      twoFactorSecret: userData.twoFactorSecret || null,
      twoFactorEnabled: userData.twoFactorEnabled || false,
      lastPasswordChange: userData.lastPasswordChange || new Date()
    };
    
    // Check if user already exists and update, otherwise add new
    const existingIndex = inMemoryUsers.findIndex(u => u._id === user._id || u.email === user.email);
    if (existingIndex >= 0) {
      inMemoryUsers[existingIndex] = user;
    } else {
      inMemoryUsers.push(user);
    }
    
    console.log('Saved user to in-memory database:', { username: user.username, email: user.email, _id: user._id });
    console.log('Total users in memory:', inMemoryUsers.length);
    
    return Promise.resolve(user);
  }
};

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Utility functions
const validatePassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  const errors = [];
  if (password.length < minLength) errors.push(`Password must be at least ${minLength} characters long`);
  if (!hasUpperCase) errors.push('Password must contain at least one uppercase letter');
  if (!hasLowerCase) errors.push('Password must contain at least one lowercase letter');
  if (!hasNumbers) errors.push('Password must contain at least one number');
  if (!hasSpecialChar) errors.push('Password must contain at least one special character');
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

const generateToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

const isAccountLocked = (user) => {
  return user.accountLockedUntil && user.accountLockedUntil > Date.now();
};

const lockAccount = async (user) => {
  const lockTime = 15 * 60 * 1000; // 15 minutes
  user.accountLockedUntil = new Date(Date.now() + lockTime);
  user.failedLoginAttempts = 0;
  await saveUser(user);
};

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Health check
app.get('/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected';
  const userCount = mongoose.connection.readyState !== 1 ? inMemoryUsers.length : 0;
  
  res.json({
    status: 'OK',
    database: dbStatus,
    authentication: 'JWT',
    storage: dbStatus === 'Connected' ? 'MongoDB' : `In-Memory (${userCount} users)`,
    timestamp: new Date().toISOString()
  });
});

// Register endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, email, password, confirm_password } = req.body;

    // Input validation and sanitization
    if (!username || !email || !password || !confirm_password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Sanitize inputs
    const sanitizedUsername = validator.escape(username.trim());
    const sanitizedEmail = validator.normalizeEmail(email.trim());

    // Validate email format
    if (!validator.isEmail(sanitizedEmail)) {
      return res.status(400).json({ error: 'Please provide a valid email address' });
    }

    // Validate username format
    if (!validator.isAlphanumeric(sanitizedUsername)) {
      return res.status(400).json({ error: 'Username can only contain letters and numbers' });
    }

    if (password !== confirm_password) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    // Enhanced password validation
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: 'Password does not meet requirements',
        details: passwordValidation.errors
      });
    }

    // Check if user already exists
    const existingUser = await findUser({
      $or: [{ email: sanitizedEmail }, { username: sanitizedUsername }]
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User with this email or username already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generate email verification token
    const emailVerificationToken = generateToken();

    // Create user
    const userData = {
      username: sanitizedUsername,
      email: sanitizedEmail,
      password: hashedPassword,
      emailVerificationToken
    };

    const user = await saveUser(userData);

    // Send verification email
    const emailResult = await sendEmail(user.email, 'verification', {
      username: user.username,
      token: emailVerificationToken
    });

    // Generate JWT token (but require email verification for full access)
    const token = jwt.sign(
      { userId: user._id, username: user.username, emailVerified: false },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: emailResult.success 
        ? 'User registered successfully. Please check your email to verify your account.'
        : 'User registered successfully. Please check your email to verify your account. (Email sending failed, but you can still verify manually)',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
        createdAt: user.createdAt
      },
      api_token: token,
      requiresEmailVerification: true,
      emailSent: emailResult.success,
      verificationToken: emailVerificationToken // For testing purposes
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Sanitize input
    const sanitizedUsername = validator.escape(username.trim());

    // Find user
    console.log('Login attempt for:', sanitizedUsername);
    console.log('In-memory users:', inMemoryUsers.map(u => ({ 
      username: u.username, 
      email: u.email,
      _id: u._id
    })));
    
    const user = await findUser({
      $or: [{ email: sanitizedUsername }, { username: sanitizedUsername }]
    });

    console.log('Found user for login:', user);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (isAccountLocked(user)) {
      const lockTimeRemaining = Math.ceil((user.accountLockedUntil - Date.now()) / 60000);
      return res.status(423).json({ 
        error: 'Account is temporarily locked due to too many failed login attempts',
        lockTimeRemaining: `${lockTimeRemaining} minutes`
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      // Increment failed login attempts
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      
      // Lock account after 5 failed attempts
      if (user.failedLoginAttempts >= 5) {
        await lockAccount(user);
        return res.status(423).json({ 
          error: 'Account locked due to too many failed login attempts. Please try again in 15 minutes.'
        });
      }
      
      await saveUser(user);
      return res.status(401).json({ 
        error: 'Invalid credentials',
        remainingAttempts: 5 - user.failedLoginAttempts
      });
    }

    // Reset failed login attempts on successful login
    user.failedLoginAttempts = 0;
    user.accountLockedUntil = null;
    user.lastLogin = new Date();
    await saveUser(user);

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username, 
        emailVerified: user.isEmailVerified 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
        lastLogin: user.lastLogin
      },
      api_token: token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route - get user profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await getUserById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    // Remove password from response
    const { password, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Password reset request endpoint
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const sanitizedEmail = validator.normalizeEmail(email.trim());
    
    if (!validator.isEmail(sanitizedEmail)) {
      return res.status(400).json({ error: 'Please provide a valid email address' });
    }

    console.log('Looking for user with email:', sanitizedEmail);
    console.log('In-memory users:', inMemoryUsers.map(u => ({ 
      username: u.username, 
      email: u.email 
    })));
    
    const user = await findUser({ email: sanitizedEmail });
    
    console.log('Found user for forgot password:', user);
    
    if (!user) {
      // Don't reveal if email exists or not for security
      return res.json({ 
        message: 'If an account with that email exists, a password reset link has been sent.' 
      });
    }

    // Generate reset token
    const resetToken = generateToken();
    const resetExpires = new Date(Date.now() + 3600000); // 1 hour

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = resetExpires;
    await saveUser(user);

    // Send password reset email
    const emailResult = await sendEmail(user.email, 'passwordReset', {
      username: user.username,
      token: resetToken
    });

    res.json({
      message: emailResult.success 
        ? 'Password reset link has been sent to your email'
        : 'Password reset link has been sent to your email. (Email sending failed, but you can still reset manually)',
      resetToken: resetToken, // For testing purposes
      expiresIn: '1 hour',
      emailSent: emailResult.success
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Password reset confirmation endpoint
app.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    // Find user with valid reset token
    console.log('Looking for user with token:', token);
    console.log('Current time:', Date.now());
    console.log('In-memory users:', inMemoryUsers.map(u => ({ 
      username: u.username, 
      email: u.email, 
      passwordResetToken: u.passwordResetToken,
      passwordResetExpires: u.passwordResetExpires 
    })));
    
    const user = await findUser({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });

    console.log('Found user:', user);

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    // Validate new password
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: 'Password does not meet requirements',
        details: passwordValidation.errors
      });
    }

    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update user
    user.password = hashedPassword;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    user.lastPasswordChange = new Date();
    await saveUser(user);

    res.json({ message: 'Password has been reset successfully' });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Email verification endpoint
app.post('/verify-email', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Verification token is required' });
    }

    const user = await findUser({ emailVerificationToken: token });

    if (!user) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    await saveUser(user);

    res.json({ message: 'Email verified successfully' });

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password endpoint (for authenticated users)
app.post('/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }

    const user = await getUserById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Validate new password
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: 'Password does not meet requirements',
        details: passwordValidation.errors
      });
    }

    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    user.password = hashedPassword;
    user.lastPasswordChange = new Date();
    await saveUser(user);

    res.json({ message: 'Password changed successfully' });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout endpoint (client-side token removal)
app.post('/logout', (req, res) => {
  res.json({ message: 'Logout successful' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

