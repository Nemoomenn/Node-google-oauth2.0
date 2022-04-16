const path = require("path");
const express = require("express");
const https = require("https");
const fs = require("fs");
const helmet = require("helmet");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
const cookieSession = require('cookie-session');

require("dotenv").config();

const PORT = 3000;
const app = express();

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log("Google Profile", profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save the session to the cookie
passport.serializeUser((user,done) => {
  done(null, user.id);
})

// Read the session from the cookie
passport.deserializeUser((obj, done) => {
  done(null, obj);
})

app.use(helmet());

app.use(cookieSession({
  name: 'session',
  maxAge: 24*60*60*1000,
  keys: ['secretkeyforsession', 'secretforrotation']
}))
app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req,res,next){
  console.log(req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;
  if(!isLoggedIn) return res.status(401).json({
    "message": "Unauthorized/Unauthenticated"
  });
  next();
}

app.get("/auth/google", passport.authenticate('google', {
  scope: ['email']
}));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    faliureRedirect: "/failure",
    successRedirect: "/",
    session: true,
  }),
  (req, res) => {
    console.log("Google Called Us Back!!!");
  }
);
app.get("/auth/logout", (req,res) => {
  req.logout();
  return res.redirect('/');
});

app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("Your personal secret valus is 23");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/failure", (req, res) => {
  return res.send("Failed to Log in...");
});


https
  .createServer(
    {
      key: fs.readFileSync("./key.pem"),
      cert: fs.readFileSync("./cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log("Listening on Port ", PORT);
  });
