require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require('cookie-parser')
const passport = require("passport");

const { Strategy, ExtractJwt } = require("passport-jwt");

const app = express();

app.use(passport.initialize());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser())

mongoose.connect("mongodb://localhost:27017/auth-example");

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = new mongoose.model("User", userSchema);

function extractToken(req) {
  let token = null

  if(req && req.cookies.auth) {
    token = req.cookies.auth
  }

  return token
}

let options = {
  jwtFromRequest: extractToken,
  secretOrKey: process.env.SECRET,
};

passport.use(
  new Strategy(options, (authToken, done) => {
    User.findOne({ _id: authToken.sub }, async (err, resp) => {
      if (err) {
        console.log(err.message);
      }

      if (resp) {
        return done(null, resp);
      } else {
        let newUser = new User.create({
          username: authToken.username,
          password: authToken.password,
        });

        await newUser.save();

        return done(null, newUser);
      }
    });
  })
);

function issueJwt(user) {
  let newToken = {
    sub: user._id,
    iat: Date.now(),
  };

  let signedJwt = jwt.sign(newToken, process.env.SECRET, { expiresIn: "1d" });

  return {
    token: signedJwt,
    expires: "1d",
  };
}

app.post("/login", async (req, res, next) => {
  let userObj = req.body;

  await User.findOne(userObj).then((user) => {
    if (!user) {
      res.cookie('auth', null)
      res.json({ success: false, msg: "no user exists" });
    } else if (userObj.password === user.password) {
      let userToken = issueJwt(user);

      res.cookie("auth", userToken.token)

      res.redirect('/dashboard');
    } else {
      res.cookie('auth', null)
      res.status(401).send("authorization denied");
    }
  });
});

app.get(
  "/dashboard",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.sendFile(__dirname + "/public/dashboard.html");
  }
);

app.listen(5000, () => {
  console.log("server is running");
});
