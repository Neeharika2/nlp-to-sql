const router = require('express').Router();
const passport = require('passport');

// Auth login
router.get('/login', (req, res) => {
  res.render('login');
});

// Auth logout
router.get('/logout', (req, res) => {
  req.logout(function(err) {
    if (err) { 
      console.error('Logout error:', err);
      return res.redirect('/');
    }
    res.redirect('/');
  });
});

// Auth with Google
router.get('/google', (req, res, next) => {
  console.log('Starting Google authentication...');
  passport.authenticate('google', {
    scope: ['profile', 'email']
  })(req, res, next);
});

// Callback route for Google to redirect to
router.get('/google/callback', 
  (req, res, next) => {
    console.log('Received callback from Google');
    next();
  },
  passport.authenticate('google', { 
    failureRedirect: '/auth/login',
    failureMessage: true
  }),
  (req, res) => {
    console.log('Authentication successful, redirecting to database config');
    console.log('User:', req.user);
    res.redirect('/database/config');
  }
);

// Debug route to check if authentication is working
router.get('/status', (req, res) => {
  res.json({
    authenticated: req.isAuthenticated(),
    user: req.user || 'Not logged in'
  });
});

module.exports = router;
