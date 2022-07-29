const express = require("express");
const encrypt = require("bcryptjs");

const db = require("../data/database");

const router = express.Router();

router.get("/", function (req, res) {
  res.render("welcome");
});

router.get("/signup", function (req, res) {
  res.render("signup");
});

router.get("/login", function (req, res) {
  res.render("login");
});

router.post("/signup", async function (req, res) {
  const userData = req.body;
  const email = userData.email;
  const confirmEmail = userData["confirm-email"];
  const password = userData.password;
  // console.log(password.trim().length);
  if (
    !email ||
    !confirmEmail ||
    !password ||
    password.trim().length < 6 ||
    email !== confirmEmail ||
    !email.includes("@")
  ) {
    console.log("Invalid data");
    return res.redirect("/signup");
  }

  const emailExisting = await db
    .getDb()
    .collection("users")
    .findOne({ email: email });
  
  if (emailExisting) {
    console.log("Email exists - try another one");
    return res.redirect('/signup');
  }

  const encryptedPassword = await encrypt.hash(password, 12);

  const user = {
    email: email,
    password: encryptedPassword,
  };

  await db.getDb().collection("users").insertOne(user);
  res.redirect("/login");
});

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
    return res.redirect("/login");
  }
  const passwordFound = await encrypt.compare(password, emailFound.password);

  if (!passwordFound) {
    console.log("Password is incorrect!");
    return res.redirect("/login");
  }

  req.session.user = { id: emailFound._id, email: emailFound.email }
  req.session.isAuthenticated = true;
  req.session.save(function(){
    console.log("Success");
    res.redirect('/admin');
  });
});

router.get("/admin", function (req, res) {

  if ( !req.session.isAuthenticated ) {
    return res.status(401).render('401');
  }

  res.render("admin");
});

router.post("/logout", function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect('/');
});

module.exports = router;
