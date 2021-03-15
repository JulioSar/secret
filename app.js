//jshint esversion:6
require('dotenv').config();
const express= require ("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')
const FacebookStrategy = require('passport-facebook').Strategy;


const app = express();

app.use(express.static("public")); //Setting CSS
app.set("view engine", "ejs");//Setting views
app.use(bodyParser.urlencoded({extended:true}));//Body parser

//Using express session to initialize a session to encrypt password
app.use(session({
	secret: "Our little secret.",
	resave:false,
	saveUninitialized:false
}));

app.use(passport.initialize()); //Initializing passport
app.use(passport.session()); // Combining passport with session to encrypt passwords

mongoose.connect("mongodb://localhost:27017/userDB" , {useNewUrlParser:true, useUnifiedTopology:true, useCreateIndex:true }); //Setting DB

//DB Schema
const userSchema = new mongoose.Schema({
	email:String,
	password:String,
	googleId: String,
	facebookId:String,
	secret: String
});


//Adding pluggins to the schema in order to be able to use packages on it
userSchema.plugin(passportLocalMongoose); //Setting passport to local usage
userSchema.plugin(findOrCreate); //NPM package to create the findorcreate method. Otherwise we have to hard code it 

const User = new mongoose.model("user",userSchema); //Setting the table 

// The createStrategy is responsible to setup passport-local LocalStrategy with the correct options.
passport.use(User.createStrategy());

//Serialize the user and deseriale it in order to be able to encrypt it and un encrypt it 
passport.serializeUser(function(user, done) {
	done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
	User.findById(id, function(err, user) {
	  done(err, user);
	});
  });


//Setting google authentication
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID, //Client id on .env gotten from google
    clientSecret: process.env.CLIENT_SECRET, //Client key from google on .env
	callbackURL: "http://localhost:3000/auth/google/secrets", //Callback to go into google page 
	userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //added since google+ is out
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) { //finding or creating a google id depending if the user has already register or nor 
      return cb(err, user);
    });
  }
));


passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
	  console.log(profile);
	  
    User.findOrCreate({facebookId: profile.id}, function(err, user) {
      if (err) { return done(err); }
      done(null, user);
    });
  }
));



app.get("/",function(req,res){
	res.render("home");
	
});

//Button of google take us here and we are asking for the profile which include name and email and id
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/facebook', passport.authenticate('facebook'));


//Once it is authenticate redirect to secrets //This code and above was taken from passport website.
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect('/secrets');
  });

app.get('/auth/facebook/secrets',
	  passport.authenticate('facebook', { successRedirect: '/secrets',failureRedirect: '/login' }),
	  function(req, res){
		  res.redirect("/secrets");
	  }
);

app.get("/login",function(req,res){
	res.render("login");
	
});

app.get("/register",function(req,res){
	res.render("register");
	
});

app.get("/secrets",function(req, res){
	User.find({secret: {$ne: null}}, function (err,foundUsers) { //finding users secret on DB
		
			
		if (err){
			console.log(err);
			
		}else{
			if(foundUsers){
				res.render("secrets",{usersWithSecrets: foundUsers}); //Rendering on secret.ejs using ejs with userWithScecrets
			}
		}
	})

})

app.get("/submit",function(req, res){
	if (req.isAuthenticated()){		
		res.render("submit");
	}else{
		res.redirect("/login");
		console.log("not authenticated");
	}
})

app.get("/logout",function(req,res){
	req.logout();
	res.redirect("/");
})

//If there is a mistake on registration we will redirect again to register
app.post("/register", function (req,res){
	User.register({username:req.body.username}, req.body.password, function(err, user){
		if(err){
			console.log(err);
			res.redirect("/register");
			
		}else{
			//else if it is authenticated localy we will redirect to secrets
			passport.authenticate("local")(req,res,function(){
				res.redirect("/secrets");
			});
		}
	});


	
});

app.post("/login",function(req, res){

	const user = new User({
		username:req.body.username,
		password:req.body.password
	});

	req.login(user,function(err){
		if(err){
			console.log(err)
			res.redirect("/login");
		}else{
			//Same as register
			passport.authenticate("local")(req,res,function(){
				res.redirect("/secrets");
			});
		}
	})



});

app.post("/submit",function(req, res){
	const submittedSectred = req.body.secret; //from submit.ejs

	//Thanks to passport we can get the user ID to associate the secret to that user.
	User.findById(req.user.id,function(err,foundUser){
		if (err){
			console.log(err);
			
			
		}else{
			if(foundUser){
				foundUser.secret=submittedSectred;
				foundUser.save();
				res.redirect("/secrets");
			}
		}
	})


})



app.listen(3000, function(){
    console.log("Server started on port 3000");
})

