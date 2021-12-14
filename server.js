require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const passport = require("passport");

const { Strategy } = require("passport-jwt");

const app = express();

app.use(passport.initialize());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

mongoose.connect("mongodb://localhost:27017/auth-example");

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = new mongoose.model("User", userSchema);

//run ONCE to create user for subsequent queries
//their password is "password" we're putting it through 10 Salt Rounds
//Generally Salt Rounds should be hidden in .env
// bcrypt.hash("password", 10, async (err, hash) => {
//   let userDoc = {
//     username: "The Dude",
//     password: hash,
//   };

//   let user = new User(userDoc);

//   await user.save();

//   console.log("Let's bowl!");
// });

function extractToken(req) {
  let token = null;

  if (req && req.cookies.auth) {
    token = req.cookies.auth;
  }

  return token;
}

//secretOrKey is used by your JWTs for encryption. It should be stored in a .env file
let options = {
  jwtFromRequest: extractToken,
  secretOrKey: "supersecretString",
};

//passport strategy setup
passport.use(
  new Strategy(options, (authToken, done) => {
    //Auth token contains mongo ID as sub
    User.findOne({ _id: authToken.sub }, async (err, resp) => {
      //error handling
      if (err) {
        console.log(err.message);
      }
      // check for authorized users. Here if the user exists they are authorized
      if (resp) {
        return done(null, resp);
      } else {
        //otherwise we create a new user
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

//Issues signed JWTs; used on successful login
function issueJwt(user) {
  let newToken = {
    sub: user._id,
    iat: Date.now(),
  };

  //"supersecretString" is our JWT key, it should be the same value as the secretOrKey property in our passport options
  //this should also generally be coming from the .env file
  let signedJwt = jwt.sign(newToken, "supersecretString", { expiresIn: "1d" });

  return {
    token: signedJwt,
    expires: "1d",
  };
}

app.post("/login", async (req, res) => {
  let userObj = req.body;

  await User.findOne({username: userObj.username}).then(async (user) => {
    //grab our user from the database
    if (!user) {
      res.cookie("auth", null);
      res.json({ success: false, msg: "no user exists" });
    } else {
      //userObj is data from the client side form, user is our DB object
      let authorized = bcrypt.compare(userObj.password, user.password);

      if (authorized) {
        //if the passwords match, issue a JWT
        let userToken = issueJwt(user);
        //set the JWT as an "auth" cookie
        res.cookie("auth", userToken.token);
        //and redirect to the dashboard
        res.redirect("/dashboard");
      } else {
        res.cookie("auth", null);
        res.status(401).send("authorization denied");
      }
    }
  });
});

//using passport authentication so only logged in users can see the dashboard
app.get(
  "/dashboard",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.sendFile(__dirname + "/public/dashboard.html");
  }
);

app.listen(5000, () => {
  console.log("server is running on port 5000");
});
