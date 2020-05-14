//require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
var _ = require("lodash");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
//const md5 = require("md5");
//const bcrypt = require("bcryptjs");
//const salt = bcrypt.genSaltSync(10);
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
//const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: 'out little secret word',
    resave: false,
    saveUninitialized: false
  }));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

//forsession
mongoose.set('useNewUrlParser', true);
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);

//level2
//using dotenv & encryption
//const secret = process.env.SECRET;
//userSchema.plugin(encrypt, {secret: secret, encryptedFields: ["password"]});

//level3 -using md5 hashing
//const password = md5(req.body.password);

//level4 - Salting and hashing using bcrypt
//var salt = bcrypt.genSaltSync(10);
//bcrypt.hash(req.body.password, salt, function (err, hash)
// bcrypt.compare(password, foundUser.password, function (err, results)

//level5 - Cookies(session) using passport

//level6 - Third party oauth
//use passport-google-oauth20-create app in google developer console and follow the steps to get emailid,profile
//not implementing it.
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

//for level 1-2-3-4
/*app.post("/register", function (req, res) {
  bcrypt.hash(req.body.password, salt, function (err, hash) {
    const user = new User({
      email: req.body.username,
      password: hash,
    });
    user.save(function (err) {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });
});

app.post("/login", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;
  User.findOne({ email: username }, function (err, foundUser) {
    if (!err) {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function (err, results) {
          if (results === true) {
            res.render("secrets");
          }
        });
      }
    } else {
      console.log(err);
    }
  });
}); */

//for level - 5
//for session - passport
app.get("/secrets", function(req,res){
    User.find({"secret":{$ne: null}}, function(err, foundUsers){
      if(err){
        console.log(err);
      }
      else{
        if(foundUsers){
          res.render("secrets", {usersWithSecrets: foundUsers});
        }
      }
    });
});
app.post("/register", function(req,res){
    User.register({username: req.body.username}, req.body.password, function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets")
            });
        }
    });
});

app.post("/login", function(req,res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });

});

app.get("/logout", function(req,res){
    req.logOut();
    res.redirect("/");
});


app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});


app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err,foundUser){
    if(err){
      console.log(err);
    }
    else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});
