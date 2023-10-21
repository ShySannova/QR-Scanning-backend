const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors')
const app = express();
require('dotenv').config();


const PORT = process.env.PORT || 5000;
const mongoURI = process.env.MONGODB_URI;


// Use cors middleware
app.use(cors());

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Define a schema for the user collection
const userSchema = new mongoose.Schema({
  email: String,
  password: String, // You should hash and salt passwords
  savedResults: [
    {
      content: String,
      thumbnail: String,
      timestamp: Date, // Timestamp for saved results
    },
  ],
  timestamp: Date, // Timestamp for the user
});

// Create a model for the user collection
const User = mongoose.model('User', userSchema);

app.use(bodyParser.json());

const secretKey = 'yourSecretKey';

// Middleware for user authentication
const authenticateUser = async (req, res, next) => {
  // Get the token from the request headers
  const token = req.header('Authorization').replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    // Verify and decode the token
    const decoded = jwt.verify(token, secretKey);

    // Attach the user data to the request for future use
    const user = await User.findOne({ email: decoded.email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid token. User not found.' });
    }

    req.user = user;

    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token.' });
  }
};

// Register user
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ error: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({ email, password: hashedPassword, timestamp: new Date() });
  await user.save();

  res.status(201).json({ message: 'User created' });
});

// Login user and return a token
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ email }, secretKey, { expiresIn: '1h' });
  res.json({ token });
});

// Save a scanned QR code
app.post('/qrcodes', authenticateUser, async (req, res) => {
  const { user } = req;
  const { savedResult } = req.body; // Use req.body to get the savedResults array
  try {
    if (!user.savedResults) {
      user.savedResults = [];
    }

    // Loop through the savedResults array
      // Check if the content already exists in the user's saved results
      const existingResult = user.savedResults.find((result) => result.content === savedResult?.content);

      if (existingResult) {
        return res.status(400).json({ error: 'Result already saved' });
      }

      // Add the new result to the user's saved results with a timestamp
      user.savedResults.push({ ...savedResult, timestamp: new Date() });

    await user.save();

    res.json({ message: 'Result saved successfully' });
  } catch (error) {
    console.error('Failed to save result:', error);
    res.status(500).json({ error: 'Failed to save result' });
  }
});

// Retrieve saved QR codes
app.get('/qrcodes', authenticateUser, async (req, res) => {
  const { user } = req;

  try {
    if (user.savedResults) {
      res.json(user.savedResults);
    } else {
      res.json([]);
    }
  } catch (error) {
    console.error('Failed to retrieve QR codes:', error);
    res.status(500).json({ error: 'Failed to retrieve QR codes' });
  }
});

// Delete a saved QR code by ID
app.delete('/qrcodes/:id', authenticateUser, async (req, res) => {
  const { user } = req;
  const { id } = req.params;

  try {
    if (!user.savedResults) {
      return res.status(404).json({ error: 'Result not found' });
    }

    // Find and remove the result with the provided ID
    const index = user.savedResults.findIndex((result) => result._id.toString() === id);

    if (index === -1) {
      return res.status(404).json({ error: 'Result not found' });
    }

    user.savedResults.splice(index, 1);
    await user.save();

    res.json({ message: 'Result deleted successfully' });
  } catch (error) {
    console.error('Failed to delete result:', error);
    res.status(500).json({ error: 'Failed to delete result' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});
