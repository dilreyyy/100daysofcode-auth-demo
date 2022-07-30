const express = require("express");
const encrypt = require("bcryptjs");

const db = require("../data/database");
const { ObjectId } = require("mongodb");

const router = express.Router();

router.get("/", function (req, res) {
  res.render("welcome");
});

//get SIGNUP ------------------------------------------------------
router.get("/signup", function (req, res) {
  let sessionSignupInfo = req.session.signupInfo;

  if ( !sessionSignupInfo ) { //check if signupinfo session is not create - means valid signup data
      sessionSignupInfo = {
        hasError: false,
        message: '',
        email: '',
        confirmEmail: '',
        password: ''
      }
  }

  req.session.signupInfo = null;
  res.render("signup", {inputData: sessionSignupInfo});
});

//get LOGIN ------------------------------------------------------
router.get("/login", function (req, res) {
  let sessionSignupInfo = req.session.signupInfo;

  if ( !sessionSignupInfo ) { //check if signupinfo session is not create - means valid signup data
      sessionSignupInfo = {
        hasError: false,
        message: '',
        email: '',
        password: ''
      }
  }
  req.session.signupInfo = null;
  res.render("login", {inputData: sessionSignupInfo});
});

//post SIGNUP ------------------------------------------------------
router.post("/signup", async function (req, res) {
  const userData = req.body;
  const email = userData.email;
  const confirmEmail = userData["confirm-email"];
  const password = userData.password;

  if (
    !email ||
    !confirmEmail ||
    !password ||
    password.trim().length < 6 ||
    email !== confirmEmail ||
    !email.includes("@")
  ) {
    // console.log("Invalid data");
    
    req.session.signupInfo = {
      hasError: true,
      message: 'Invalid data - please try again',
      email: email,
      confirmEmail: confirmEmail,
      password: password
    }

    req.session.save(function (){
      res.redirect("/signup");
    });
    return; //return so that code below does not execute
  }
  
  const emailExisting = await db
    .getDb()
    .collection("users")
    .findOne({ email: email });
  
  if (emailExisting) {
    console.log("Email exists - try another one");
    req.session.signupInfo = {
      hasError: true,
      message: 'Existing email - please use another email',
      email: email,
      confirmEmail: confirmEmail,
      password: password
    }
    req.session.save(function (){
      res.redirect('/signup');
    })
    return;
  }

  const encryptedPassword = await encrypt.hash(password, 12);

  const user = {
    email: email,
    password: encryptedPassword,
  };

  await db.getDb().collection("users").insertOne(user);
  res.redirect("/login");
});

//post LOGIN ------------------------------------------------------
router.post("/login", async function (req, res) {
  const userData = req.body;
  const email = userData.email;
  const password = userData.password;

  const emailFound = await db
    .getDb()
    .collection("users")
    .findOne({ email: email });

  if (!emailFound) {
    console.log("Email does not match in our database!");
    req.session.signupInfo = {
      hasError: true,
      message: 'Invalid credentials - please try again',
      email: email,
      password: password
    }
    req.session.save(function (){
      res.redirect("/login");
    });
    return 
  }

  const passwordFound = await encrypt.compare(password, emailFound.password);

  if (!passwordFound) {
    console.log("Password is incorrect!");
    req.session.signupInfo = {
      hasError: true,
      message: 'Invalid credentials - please try again',
      email: email,
      password: password
    }
    req.session.save(function (){
      res.redirect("/login");
    });
    return;
  }

  req.session.user = { id: emailFound._id, email: emailFound.email }
  req.session.isAuthenticated = true;
  req.session.save(function(){
    console.log("Success");
    res.redirect('/profile');
  });
});


//get ADMIN ------------------------------------------------------
router.get("/admin", async function (req, res) {

  if ( !req.session.isAuthenticated ) {
    return res.status(401).render('401');
  }

  const userType = await db.getDb().collection('users').findOne({_id: ObjectId(req.session.user.id)});

  if ( !userType || !userType.isAdmin ) {
    return res.status(403).render('403');
  }

  res.render("admin");
});

//get PROFILE ------------------------------------------------------
router.get("/profile", async function (req, res) {

  if ( !req.session.isAuthenticated ) {
    return res.status(401).render('401');
  }

  res.render("profile");
});

//post LOGOUT ------------------------------------------------------
router.post("/logout", function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect('/');
});

module.exports = router;
