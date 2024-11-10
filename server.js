// Server
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure SendGrid API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// MongoDB connection using the URI from .env
const mongoUri = process.env.MONGO_URI;
mongoose.connect(mongoUri)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('MongoDB connection error:', error);
  });

// Session Management
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: mongoUri }),
  cookie: {
    secure: false, // Set to true if using HTTPS
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000 // 30 minutes session expiry
  }
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(helmet());

// Rate Limiting for Login Route
const loginLimiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again after 30 minutes.',
});

// Token Schema Definition
const tokenSchema = new mongoose.Schema({
  email: { type: String, required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 3600 }, // Token expires in 1 hour
});
const Token = mongoose.model('Token', tokenSchema);

// User Schema Definition
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  invalidLoginAttempts: { type: Number, default: 0 },
  accountLockedUntil: { type: Date },
  lastLoginTime: { type: Date },
});
const User = mongoose.model('User', userSchema);

// Generate Random String Function
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

// Hash Password Function
function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

// Password Validation Function
function isValidPassword(password) {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
  return passwordRegex.test(password);
}

// Middleware for Authentication
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ success: false, message: 'Unauthorized access.' });
  }
}

// Fetch user details route
app.get('/user-details', isAuthenticated, async (req, res) => {
  try {
    const email = req.session.email;
    if (!email) {
      return res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }

    // Fetch user details from the database
    const user = await User.findOne(
      { email: email }, // Change this according to your actual field name if different
      { email: 1, _id: 0 } // Return only the email field
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    // Return only necessary details
    res.json({
      success: true,
      user: {
        email: user.email // Return the user's email
      }
    });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ success: false, message: 'Error fetching user details.' });
  }
});

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  // Validate email input
  if (!email) {
    return res.status(400).send('Email is required');
  }

  try {
    let existingToken = await Token.findOne({ email });
    const resetToken = generateRandomString(32);

    if (existingToken) {
      existingToken.token = resetToken;
      await existingToken.save();
    } else {
      const newToken = new Token({ email, token: resetToken });
      await newToken.save();
    }

    // Send the email with the token
    const msg = {
      to: email,
      from: 'jessyanfa@gmail.com', // Replace with your verified sender email
      subject: 'Password Reset Request',
      text: `Your password reset token is: ${resetToken}`,
      html: `<p>Your password reset token is:</p><h3>${resetToken}</h3>`,
    };

    await sgMail.send(msg);
    res.status(200).send('Password reset email sent');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error finding or updating token');
  }
});

// Reset Password Endpoint
app.post('/send-password-reset', async (req, res) => {
  const { resetKey, newPassword } = req.body;

  try {
    const existingToken = await Token.findOne({ token: resetKey });
    if (!existingToken) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset key.' });
    }

    // Hash the new password
    const hashedPassword = hashPassword(newPassword);
    const user = await User.findOne({ email: existingToken.email });

    if (!user) {
      return res.status(400).json({ success: false, message: 'User not found.' });
    }

    // Update the user's password
    user.password = hashedPassword;
    await user.save();

    // Remove the token after successful reset
    await Token.deleteOne({ token: resetKey });

    res.json({ success: true, message: 'Your password has been successfully reset.' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ success: false, message: 'Password reset failed.' });
  }
});

// Sign Up Route
app.post('/signup', async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  try {
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered.' });
    }

    

    const hashedPassword = hashPassword(password);

    const newUser = new User({ firstName, lastName, email, password: hashedPassword });
    await newUser.save();

    res.json({ success: true, message: 'Account created successfully!' });
  } catch (error) {
    console.error('Error creating account:', error);
    res.status(500).json({ success: false, message: 'An internal server error occurred.' });
  }
});

// Complete Login Route
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    // Input validation
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }
    
    // Fetch user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }
    // Account lockout check
    if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
      const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
      return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });
    }
    // Password verification
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      // Handle failed attempts
      let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
      let updateFields = { invalidLoginAttempts: invalidAttempts };
      if (invalidAttempts >= 3) {
        // Lock account
        updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        updateFields.invalidLoginAttempts = 0;
        await User.updateOne({ _id: user._id }, { $set: updateFields });
        return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
      } else {
        await User.updateOne({ _id: user._id }, { $set: updateFields });
        return res.status(400).json({ success: false, message: 'Invalid email or password.' });
      }
    }

    // Successful login
    await User.updateOne(
      { _id: user._id },
      { $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
    );

    //set session data
    req.session.userId = user._id;
    req.session.email = user.email;
    req.session.role = user.role; // Assuming role is a field in User
    req.session.studentIDNumber = user.studentIDNumber; // Assuming studentIDNumber is a field in User

    //save session
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) return reject(err);
        resolve();
      });
    });
    
    res.json({ success: true, role: user.role, message: 'Login successful!' });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ success: false, message: 'Error during login.' });
  }
});

// Protected Route
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.sendFile(__dirname + '/public/dashboard.html');
});

// Logout Route
app.post('/logout', async (req, res) => {
  if (!req.session.userId) {
    return res.status(400).json({ success: false, message: 'No user is logged in.' });
  }
  try {
    req.session.destroy(err => {
      if (err) {
        console.error('Error destroying session:', err);
        return res.status(500).json({ success: false, message: 'Logout failed.' });
      }
      res.clearCookie('connect.sid');
      // Prevent caching
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.setHeader('Surrogate-Control', 'no-store');
      return res.json({ success: true, message: 'Logged out successfully.' });
    });
  } catch (error) {
    console.error('Error during logout:', error);
    return res.status(500).json({ success: false, message: 'Failed to log out.' });
  }
});

// Start the Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});