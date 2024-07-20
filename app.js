// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = 'your_secret_key';


mongoose.connect('mongodb://localhost:27017/jwtauth');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

const corsOptions = {
  origin: 'http://localhost:5173', // Update this to the client URL
  credentials: true, // Allow credentials
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// Routes
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.find({username});
  console.log(user);
  if(user.length>0)
     { return res.status(400).send('User already exists');

     }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();
  res.status(201).send('User Registered');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ id: user._id, username }, SECRET_KEY, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, secure: false, sameSite: 'strict' }); // Secure should be true in production
    res.json({ message: 'Login successful' });
  } else {
    res.status(401).send('Invalid Credentials');
  }
});

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  console.log(token);
  if (!token) return res.sendStatus(404);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    console.log(user);
    req.user = user;
    next();
  });
};

app.get('/verify', authenticateToken, (req, res) => {
  const { id, username } = req.user;
  res.status(200).json({ id, username, message: 'Access' });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, secure: false, sameSite: 'strict' }); // Secure should be true in production
  res.status(200).json({ message: 'Logout successful' });

});



app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
