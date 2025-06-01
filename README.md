# small-csrf

A lightweight CSRF protection middleware for Express applications implementing OWASP's recommended Signed Double-Submit Cookie pattern.

## Introduction

`small-csrf` provides robust Cross-Site Request Forgery (CSRF) protection for your Node.js/Express applications. It implements the OWASP-recommended Signed Double-Submit Cookie pattern, which binds CSRF tokens to user sessions using [HMAC](https://en.wikipedia.org/wiki/HMAC) signatures for enhanced security.

Key features:

- Simple integration with Express and express-session
- Configurable token management
- Support for both per-session and per-request tokens
- Constant-time token comparison to prevent timing attacks
- Flexible configuration options for cookies and tokens

Whilst all implementation errors are my own, credit goes to OWASP and their [CSRF Cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) which lays out how they think this should be done. The only deliberate deviation from their advice is that I've implemented per-request token changes. If you want to stick to per-session (OWASP recommended), set `perSessionTokens: true` when setting up the csrfProtection middleware.

## Installation

```bash
npm install small-csrf
```

## Quick Start

Basic integration with Express and express-session:

```javascript
// npm install express express-session cookie-parser small-csrf
import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import csrfProtection from "small-csrf";

const app = express();

// Body parser middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Cookie parser middleware (required for csrf)
app.use(cookieParser());

// Session middleware (required for csrf)
app.use(
  session({
    secret: "your-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === "production" },
  })
);

// CSRF protection middleware
app.use(
  csrfProtection({
    secret: "at-least-32-characters-long-csrf-secret",
  })
);

// Example of rendering a form with CSRF token
app.get("/form", (req, res) => {
  res.send(`
    <form action="/submit" method="POST">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      <input type="text" name="data">
      <button type="submit">Submit</button>
    </form>
  `);
});

// Example of processing a form with CSRF protection
app.post("/submit", (req, res) => {
  // If the request reaches here, CSRF validation passed
  res.send("Form submitted successfully!");
});

// Example error handler for CSRF errors
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("Invalid CSRF token. Form submission failed.");
  }
  next(err);
});

app.listen(3000);
```

## How It Works

`small-csrf` implements the Signed Double-Submit Cookie pattern as recommended by OWASP:

1. A cryptographically strong random token is generated on GET requests
2. The token is:
   - Set as an HTTP-only cookie with appropriate security settings
   - Made available for inclusion in forms or AJAX requests via `req.csrfToken()`
3. When processing state-changing requests (POST, PUT, DELETE), the middleware:
   - Verifies that the token from the cookie matches the token submitted in the request
   - Uses an HMAC signature to bind the token to the user's session
   - Performs validation using constant-time comparison to prevent timing attacks

This approach effectively mitigates CSRF vulnerabilities applications.

## API Reference

### `csrfProtection(options)`

Creates and returns the CSRF middleware function.

#### Options

| Option             | Type    | Default                      | Description                                                         |
| ------------------ | ------- | ---------------------------- | ------------------------------------------------------------------- |
| `secret`           | String  | _required_                   | Secret key used for HMAC signature (must be at least 32 characters) |
| `cookie.key`       | String  | `"csrf_token"`               | Name of the cookie storing the CSRF token                           |
| `cookie.path`      | String  | `"/"`                        | Path for the CSRF cookie                                            |
| `cookie.httpOnly`  | Boolean | `true`                       | Whether the cookie is HTTP only                                     |
| `cookie.sameSite`  | String  | `"strict"`                   | SameSite policy for the cookie (`"strict"`, `"lax"`, or `"none"`)   |
| `cookie.secure`    | Boolean | `true`                       | Whether the cookie requires HTTPS                                   |
| `cookie.maxAge`    | Number  | `3600000`                    | Max age of the cookie in milliseconds (1 hour default)              |
| `ignoreMethods`    | Array   | `["GET", "HEAD", "OPTIONS"]` | HTTP methods that don't need CSRF validation                        |
| `csrfParam`        | String  | `"_csrf"`                    | Name of the parameter containing the CSRF token in requests         |
| `perSessionTokens` | Boolean | `false`                      | If true, generates one token per session instead of per request     |

### `req.csrfToken()`

Function added to the request object that returns the current CSRF token. Use this to include the token in your forms or AJAX requests.

## Security Considerations

For maximum security:

- Always use HTTPS in production environments
- Keep your CSRF secret different from your session secret
- Use a cryptographically strong secret (at least 32 characters)
- Consider enabling `perSessionTokens: true` if users need to submit multiple forms simultaneously
- Set appropriate `sameSite` and `secure` cookie options based on your application's requirements

## Examples

### AJAX Requests

When making AJAX requests, include the CSRF token in the header:

```javascript
// Client-side JavaScript
const csrfToken = document
  .querySelector('meta[name="csrf-token"]')
  .getAttribute("content");

fetch("/api/data", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken,
  },
  body: JSON.stringify({ data: "example" }),
});
```

Server-side template (example with EJS):

```html
<head>
  <meta name="csrf-token" content="<%= csrfToken() %>" />
</head>
```

### Single Page Applications (SPAs)

For SPAs, you can expose the CSRF token through an API endpoint:

```javascript
app.get("/api/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});
```

Then fetch the token when your SPA initializes.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT](LICENSE)
