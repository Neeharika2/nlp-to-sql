const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();

// Serialize user into the session
passport.serializeUser((user, done) => {
  console.log('Serializing user:', user.id);
  done(null, user);
});

// Deserialize user from the session
passport.deserializeUser((user, done) => {
  console.log('Deserializing user:', user.id);
  done(null, user);
});

// Configure Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/callback',
      scope: ['profile', 'email']
    },
    (accessToken, refreshToken, profile, done) => {
      // Log profile information for debugging
      console.log('Google strategy callback executed');
      console.log('Profile:', profile);
      
      try {
        // Here you would typically find or create a user in your database
        // For this example, we'll just use the profile object
        const user = {
          id: profile.id,
          displayName: profile.displayName,
          email: profile.emails && profile.emails.length ? profile.emails[0].value : 'No email',
          photo: profile.photos && profile.photos.length ? profile.photos[0].value : null
        };
        
        console.log('Created user object:', user);
        return done(null, user);
      } catch (error) {
        console.error('Error in Google strategy callback:', error);
        return done(error, null);
      }
    }
  )
);
