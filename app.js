const express = require("express");
const app = express();
const port = process.env.PORT || 80;
const path = require("path");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const methodOverride = require("method-override");
const flash = require("connect-flash");
const session = require("express-session");
const bodyParser = require("body-parser");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const employeeRouter = require("./routes/employee");
const userRoutes = require("./routes/users");
const User = require("./models/usermodel");

dotenv.config({ path: "./config.env" });

//connecting to mongodb database
const db = process.env.DATABASE;
mongoose.connect(db, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});

// middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));
app.use(methodOverride("_method"));

//session
app.use(
  session({
    secret: "Employees Database System",
    resave: true,
    saveUninitialized: true,
  })
);

//flash
app.use(flash());

// passport middlewares
app.use(passport.initialize());
app.use(passport.session());
passport.use(
  new LocalStrategy({ usernameField: "email" }, User.authenticate())
);
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//setting messages variables globally
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.failure_msg = req.flash("failure_msg");
  res.locals.error = req.flash("error");
  res.locals.currentUser = req.user;
  next();
});

app.use(employeeRouter);
app.use(userRoutes);

app.listen(port, () => {
  console.log(`server started at port ${port}`);
});
