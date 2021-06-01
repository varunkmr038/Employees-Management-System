const express = require("express");
const router = express.Router();
const passport = require("passport");
const crypto = require("crypto");
const async = require("async");
const nodemailer = require("nodemailer");

const User = require("../models/usermodel");

//Get routes
router.get("/", (req, res) => {
  res.render("login", { title: "Login | Employee Database System" });
});

router.get("/signup", (req, res) => {
  res.render("signup", { title: "Signup" });
});

router.get("/logout", (req, res) => {
  req.logOut();
  req.flash("success_msg", "You have been logged out.");
  res.redirect("/");
});

router.get("/forgot", (req, res) => {
  res.render("forgot", { title: "Forgot Password" });
});

//POST routes
router.post(
  "/",
  passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/",
    failureFlash: "Invalid email or password. Try Again!!!",
  })
);

router.post("/signup", (req, res) => {
  let { name, email, password } = req.body;

  let userData = {
    name: name,
    email: email,
  };

  User.register(userData, password, (err, user) => {
    if (err) {
      req.flash("error_msg", "ERROR: " + err);
      res.redirect("/signup");
    }
    passport.authenticate("local")(req, res, () => {
      req.flash("success_msg", "Account created successfully");
      res.redirect("/");
    });
  });
});

// Routes to handle forgot password

router.post("/forgot", (req, res, next) => {
  let recoverPassword = "";

  async.waterfall([
    (done) => {
      crypto.randomBytes(30, (err, buf) => {
        let token = buf.toString("hex");
        done(err, token);
      });
    },

    (token, done) => {
      User.findOne({ email: req.body.email })
        .then((user) => {
          if (!user) {
            req.flash("failure_msg", "User does not exist with this email");
            return res.redirect("/forgot");
          }

          // if the user exists
          userPasswordToken = token;
          userPasswordExpires = Date.now() + 1800000; //30 mins

          user.save((err) => {
            done(err, token, user);
          });
        })
        .catch((err) => {
          req.flash("failure_msg", "Error : " + err.message);
          res.redirect("/forgot");
        });
    },

    (token, user) => {
      // create reusable transporter object using the default SMTP transport
      let smtpTransport = nodemailer.createTransport({
        service: "yahoo",
        port: 465,
        secure: false,
        auth: {
          user: process.env.EMAIL,
          pass: process.env.PASSWORD,
        },
      });

      let mailOptions = {
        to: user.email,
        from: `Varun Kumar ${process.env.EMAIL}`,
        subject: "Recovery email from Employee Database Website",
        text:
          "Please Click the following link to recover your password: \n \n" +
          "http://" +
          req.headers.host +
          "/reset/" +
          token +
          "\n\n" +
          "If you did not request this please ignore this email",
      };

      smtpTransport.sendMail(mailOptions, (err) => {
        req.flash(
          "success_msg",
          "Email Send with further instructions. Please Check that"
        );
        res.redirect("/forgot");
      });
    },
  ]);
});

module.exports = router;
