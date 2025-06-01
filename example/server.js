import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import csrfProtection from "../csrf.js";

const app = express();
const PORT = 3000;

app.set("view engine", "ejs");
app.set("views", "./views");

app.use(cookieParser("your-cookie-secret"));

app.use(
  session({
    // using memoryStore
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    },
  })
);

// form parsing
app.use(express.urlencoded({ extended: true }));

app.use(
  csrfProtection({
    secret: "csrfSecret32CharsLongForHMACUsage", // 32-char secret for HMAC
    cookie: {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production", // true in production
    },
    perSessionTokens: true,
  })
);


app.use((req, res, next) => {
  // ensure session is initialized
  if (!req.session.initialized) {
    req.session.initialized = true;
  }
  // make CSRF token available to the template
  res.locals.csrfToken = req.csrfToken();
  // save messages to locals for the template then clear them from the session
  res.locals.errorMessage = req.session.errorMessage;
  res.locals.successMessage = req.session.successMessage;
  delete req.session.errorMessage;
  delete req.session.successMessage;
  next();
});

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  if (username === "admin" && password === "password") {
    req.session.successMessage = "Login successful!";
    req.session.save(() => {
      res.redirect("/dashboard");
    });
  } else {
    req.session.errorMessage = "Invalid username or password.";
    req.session.save(() => {
      res.redirect("/login");
    });
  }
});

app.get("/dashboard", (req, res) => {
  res.render("dashboard");
});

app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    // handle CSRF errors
    console.log(`Possible CSRF attack from ${req.ip} on route ${req.url}`);
    req.session.errorMessage =
      "Invalid or expired form submission, please try again";
    req.session.save((saveErr) => {
      if (saveErr) {
        console.error("Session save error:", saveErr);
      }
      res.redirect("/login");
    });
  } else {
    // other errors
    req.session.errorMessage = "Something went wrong";
    req.session.save((saveErr) => {
      if (saveErr) {
        console.error("Session save error:", saveErr);
      }
      res.status(err.status || 500).redirect("/");
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
