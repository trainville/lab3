const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const userController = require("../controllers/userController");

require('dotenv').config();

const localLogin = new LocalStrategy(
  {
    usernameField: "email",
    passwordField: "password",
  },
  (email, password, done) => {
    const user = userController.getUserByEmailIdAndPassword(email, password);
    return user
      ? done(null, user)
      : done(null, false, {
          message: "Your login details are not valid. Please try again",
        });
  }
);

// set github strategy
const gitLogin = new GitHubStrategy(
  {
    clientID: process.env.GIT_APP_ID,
    clientSecret: process.env.GIT_APP_SECRET,
    callbackURL: process.env.GIT_APP_REDIRECT,
  },
    function(accessToken, refreshToken, profile, cb) {
      const user = userController.getUserByProfile(profile);
      cb(null,user);
    } 
  );

// set user to session
passport.serializeUser(function (user, done) {
  done(null, user.id);
});


passport.deserializeUser(function (id, done) {
  let user = userController.getUserById(id);
  if (user) {
    done(null, user);
  } else {
    done({ message: "User not found" }, null);
  }
});


module.exports = passport.use(localLogin),passport.use(gitLogin);
