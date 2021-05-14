//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
// const InstagramStrategy = require('passport-instagram').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const app=express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret: 'this is my little secret',
  resave: false,
  saveUninitialized: true,
  // cookie: { secure: true }
}));
app.use(passport.initialize()); //start using passport for authentication
app.use(passport.session()); //use passport to deal with the session



//////////////building database/////////////////////
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false
});

mongoose.set('useCreateIndex', true);
const userSchema = new mongoose.Schema ({
  email: String,
  password :String,
  googleId:String,
  facebookId:String,
  githubId:String,
  secret:[String]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User",userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret:process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
// passport.use(new InstagramStrategy({
//     clientID: process.env.INSTAGRAM_CLIENT_ID,
//     clientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
//     callbackURL: "http://127.0.0.1:3000/auth/instagram/secrets"
//   },
//   function(accessToken, refreshToken, profile, done) {
//     User.findOrCreate({ instagramId: profile.id }, function (err, user) {
//       return done(err, user);
//     });
//   }
// ));
//////////handling routes/////////////
app.get("/", function(req, res){
  res.render("home");
});
app.get('/auth/google/',
  passport.authenticate('google', { scope: ["profile"] }),
);
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });
  app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
    });
    app.get('/auth/github',
      passport.authenticate('github'));

    app.get('/auth/github/secrets',
      passport.authenticate('github', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
      });
      app.get('/auth/instagram',
  passport.authenticate('instagram'));

app.get('/auth/instagram/secrets',
  passport.authenticate('instagram', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.get("/login", function(req, res){
  res.render("login");
});
app.get("/register", function(req, res){
  res.render("register");
});
app.get("/secrets", function(req, res){
  User.find({"secret":{$ne:null}},function(err , foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        res.render("secrets",{userswithSecrets :foundUser});
      }
    }
  });
});
app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");

  }
});
app.post("/submit",function(req,res){
  const submitted =req.body.secret;
  console.log(req.user.id);
  User.findById(req.user.id , function(err,foundUser){
    if(err){console.log(err);}
    else{
      if(foundUser){
        foundUser.secret=submitted;
        foundUser.save(function(){
          res.redirect("/secrets")
        });
      }
    }
  });
});
app.get("/logout", function(req, res){
  req.logout();
  res.redirect('/');
})

app.post("/register", function(req, res){
  User.register({username:req.body.username},req.body.password , function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});
app.post("/login", function(req, res){
  const user = new User ({
    username:req.body.username,
    password:req.body.password
  });
  req.login(user , function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  })
});


app.listen(3000, function() {
  console.log("Server started on port 3000.");
});

//app.post("/register", function(req, res){

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   // Store hash in your password DB.
  //   const newUser =  new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save(function(err){
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });
//});
//app.post("/login", function(req, res){
  // const username = req.body.username;
  // const password = req.body.password;
  // User.findOne({email: username}, function(err, foundUser){
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //           if(result === true){res.render("secrets");}
  //       });
  //
  //       }
  //     }
  //   })

//  });
