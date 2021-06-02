const express = require("express");
const router = express.Router();
const passport = require("passport");
const crypto = require("crypto");
const async = require("async");
const nodemailer = require("nodemailer");

const User = require("../models/usermodel");

// Checks if user is authenticated
function isAuthenticatedUser(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash("failure_msg", "Please Login first to access this page.");
  res.redirect("/");
}

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

router.get("/reset/:token", (req, res) => {
  User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  })
    .then((user) => {
      if (!user) {
        req.flash(
          "failure_msg",
          "Password Reset Token is invalid or has been expired"
        );
        return res.redirect("/forgot");
      }
      res.render("newpassword", {
        token: req.params.token,
        title: "New Password",
      });
    })
    .catch((err) => {
      req.flash("error", "ERROR" + err);
      res.redirect("/forgot");
    });
});

router.get("/changepassword", isAuthenticatedUser, (req, res) => {
  res.render("changepassword", { title: "Change Password" });
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
    passport.authenticate("local-signup")(req, res, () => {
      req.flash("success_msg", "Account created successfully");
      res.redirect("/");
    });
  });
});

router.post("/changepassword", (req, res) => {
  let { password, confirmpassword } = req.body;

  if (password != confirmpassword) {
    req.flash("failure_msg", `Passwords don't match ! Enter Again`);
    return res.redirect(`/changepassword`);
  }

  User.findOne({ email: req.user.email }).then((user) => {
    user.setPassword(password, (err) => {
      user.save((done) => {
        req.flash("success_msg", "Your Password has been changed");
        res.redirect("/home");
      });
    });
  });
});

// Routes to handle forgot password

router.post("/forgot", (req, res, next) => {
  async.waterfall([
    (done) => {
      crypto.randomBytes(20, (err, buf) => {
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
          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 1800000; //30 mins

          // save in database
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
        port: 587,
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

// change password
router.post("/reset/:token", (req, res) => {
  let { password, confirmpassword } = req.body;

  async.waterfall([
    (done) => {
      User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() },
      })
        .then((user) => {
          if (password != confirmpassword) {
            req.flash("failure_msg", `Passwords don't match ! Enter Again`);
            return res.redirect(`/reset/${req.params.token}`);
          }

          if (!user) {
            req.flash(
              "failure_msg",
              "Password Reset Token is invalid or has been expired"
            );
            return res.redirect("/forgot");
          }

          user.setPassword(req.body.password, (err) => {
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;

            user.save((err) => {
              done(err, user);
            });
          });
        })
        .catch((err) => {
          req.flash("error", "ERROR" + err);
          res.redirect("/forgot");
        });
    },
    (user) => {
      // create reusable transporter object using the default SMTP transport
      let smtpTransport = nodemailer.createTransport({
        service: "yahoo",
        port: 587,
        secure: false,
        auth: {
          user: process.env.EMAIL,
          pass: process.env.PASSWORD,
        },
      });

      let mailOptions = {
        to: user.email,
        from: `Varun Kumar ${process.env.EMAIL}`,
        subject: "Your Password is changed for Employee Database Website",
        text:
          "Hello, " +
          user.name +
          "\n\n" +
          "This is the confirmation that the password for your account on Employee Database Website has been changed",
      };

      smtpTransport.sendMail(mailOptions, (err) => {
        req.flash("success_msg", "Your Password has been changed");
        res.redirect("/");
      });
    },
    (err) => {
      res.redirect("/");
    },
  ]);
});

module.exports = router;
