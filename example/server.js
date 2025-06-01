import express from "express";
import session from "express-session";
import flash from "connect-flash";
import FileStore from "session-file-store";
import cookieParser from "cookie-parser";
import csrfProtection from "../csrf.js";

const app = express();
const PORT = 3000;

app.set("view engine", "ejs");
app.set("views", "./views");

const FileStoreSession = FileStore(session);

app.use(cookieParser("your-cookie-secret"));

// setup express-session middleware
app.use(
  session({
    store: new FileStoreSession({
      path: "./data/sessions",
      retries: 0,
    }),
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

// Configure connect-flash middleware
app.use(flash());

// Middleware to make flash messages available to all templates
app.use((req, res, next) => {
  if (req.method === "GET") {
    res.locals.messages = {
      error: req.flash("error"),
      success: req.flash("success"),
      info: req.flash("info"),
    };
  }
  next();
});

// Parse form data
app.use(express.urlencoded({ extended: true }));

// Setup CSRF protection after session and body parser
// We'll pass the secret and optionally configuration
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

// Middleware to make CSRF token available to all templates
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
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
    req.flash("success", "Login successful!");
    req.session.save(() => {
      res.redirect("/dashboard");
    });
  } else {
    req.flash("error", "Invalid username or password.");
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
    // Handle CSRF errors specifically
    // output error message with ip address
    console.log(`Possible CSRF attack from ${req.ip} on route ${req.url}`);
    req.flash("error", "Invalid or expired form submission, please try again");
    
    req.session.save((saveErr) => {
      if (saveErr) {
        console.error("Session save error:", saveErr);
      }
      res.redirect("/login");
    });
  } else {
    // Handle other errors
    req.flash("error", "Something went wrong");
    
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
