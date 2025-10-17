const express = require('express');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
require('dotenv').config();

// Import passport setup
require('./config/passport-setup');

// Import routes
const authRoutes = require('./routes/auth-routes');
const databaseRoutes = require('./routes/database-routes');
const queryRoutes = require('./routes/query-routes');

const app = express();

// Body parser middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set up view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Log HTTP requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Set up session middleware
app.use(
  session({
    secret: process.env.COOKIE_KEY,
    resave: true,
    saveUninitialized: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000 // 1 day in milliseconds
    }
  })
);

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

// Debug middleware to check authentication
app.use((req, res, next) => {
  console.log('Session:', req.session);
  console.log('User authenticated:', req.isAuthenticated());
  if (req.user) {
    console.log('User:', req.user.id);
  }
  next();
});

// Set up routes
app.use('/auth', authRoutes);
app.use('/database', databaseRoutes);
app.use('/query', queryRoutes);

// Middleware to check if user is logged in
const isLoggedIn = (req, res, next) => {
  if (req.user) {
    next();
  } else {
    console.log('Unauthorized access attempt to protected route');
    res.redirect('/auth/login');
  }
};

// Home route
app.get('/', (req, res) => {
  res.render('home', { user: req.user });
});

// Profile route (protected)
app.get('/profile', isLoggedIn, (req, res) => {
  console.log('Rendering profile for user:', req.user);
  res.render('profile', { user: req.user });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Application error:', err);
  res.status(500).send('Something went wrong!');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Google callback URL should be set to: http://localhost:${PORT}/auth/google/callback`);
});
