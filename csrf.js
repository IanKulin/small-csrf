import crypto from "crypto";

/**
 * CSRF protection middleware implementing OWASP's Signed Double-Submit Cookie pattern
 * using HMAC to bind tokens to the user's session
 */
function csrfProtection(options = {}) {
  if (!options.secret || options.secret.length < 32) {
    throw new Error("CSRF secret must be at least 32 characters long");
  }
  const config = {
    secret: options.secret,
    cookie: {
      key: options.cookie?.key || "csrf_token",
      path: options.cookie?.path || "/",
      httpOnly: options.cookie?.httpOnly !== false,
      sameSite: options.cookie?.sameSite || "strict",
      secure: options.cookie?.secure !== false,
      maxAge: options.cookie?.maxAge || 3600000, // 1 hour in milliseconds, null would be a session cookie
    },
    ignoreMethods: options.ignoreMethods || ["GET", "HEAD", "OPTIONS"],
    value: options.value || defaultValue, // where to find the token
    csrfParam: options.csrfParam || "_csrf", // what name is used for the token
    perSessionTokens: options.perSessionTokens !== false,
  };
  // return the middleware function
  return function csrf(req, res, next) {
    if (config.ignoreMethods.includes(req.method)) {
      // for the methods we don't need to check, we provide the token in a cookie and
      // the function to access it so the library user can include it in their html
      const tokenData = generateToken(req, config);
      res.cookie(config.cookie.key, tokenData.token, tokenData.cookieOptions);
      req.csrfToken = () => tokenData.token;
      next();
      return;
    }
    // for the methods we are checking, do the check
    if (!verifyToken(req, config)) {
      const csrfError = new Error("Invalid CSRF token");
      csrfError.code = "EBADCSRFTOKEN"; // Custom error code
      csrfError.status = 403; // HTTP status code
      return next(csrfError);
    }
    // for the rare? situation where the library user is rendering another POST with
    // a form in it and the library users wants a new token, give them that ability
    req.csrfToken = () => generateToken(req, config);
    next();
  };
}

function generateToken(req, config) {
  if (!req.session) {
    throw new Error("Session middleware is required for CSRF protection");
  }
  const sessionID = req.session.id;
  let randomValue;
  if (config.perSessionTokens) {
    // per-session token: deterministic based on session ID, OWASP say this is fine, and
    // it allows the edge case of a user submitting forms from multiple tabs
    randomValue = crypto
      .createHmac("sha256", config.secret)
      .update(`csrf-session-${sessionID}`)
      .digest("hex");
  } else {
    // per-request token: random for each request
    randomValue = crypto.randomBytes(32).toString("hex");
  }
  const message = `${sessionID.length}!${sessionID}!${randomValue.length}!${randomValue}`;
  const hmac = crypto
    .createHmac("sha256", config.secret)
    .update(message)
    .digest("hex");
  const token = `${hmac}.${randomValue}`;
  const cookieOptions = {
    path: config.cookie.path,
    httpOnly: config.cookie.httpOnly,
    sameSite: config.cookie.sameSite,
    secure: config.cookie.secure,
    maxAge: config.cookie.maxAge,
  };
  return {
    token,
    cookieOptions,
  };
}

function verifyToken(req, config) {
  if (!req.session) {
    throw new Error("Session middleware is required for CSRF protection");
  }
  const cookieToken = req.cookies[config.cookie.key];
  if (!cookieToken) {
    return false;
  }

  const requestToken =
    (req.body && req.body[config.csrfParam]) ||
    req.headers["x-csrf-token"] ||
    req.headers["x-xsrf-token"];
  if (!requestToken) {
    return false;
  }
  const cookieParts = cookieToken.split(".");
  if (cookieParts.length !== 2) {
    return false;
  }
  const hmacFromCookie = cookieParts[0];
  const randomValue = cookieParts[1];
  // recreate the HMAC with the current session and random value
  const sessionID = req.session.id;
  const message = `${sessionID.length}!${sessionID}!${randomValue.length}!${randomValue}`;
  // generate the expected HMAC
  const expectedHmac = crypto
    .createHmac("sha256", config.secret)
    .update(message)
    .digest("hex");
  // compare them
  return (
    constantTimeEquals(hmacFromCookie, expectedHmac) &&
    constantTimeEquals(requestToken, cookieToken)
  );
}

function defaultValue(req) {
  return (
    (req.body && req.body._csrf) ||
    req.headers["x-csrf-token"] ||
    req.headers["x-xsrf-token"]
  );
}

function constantTimeEquals(a, b) {
  const MAX_TOKEN_LENGTH = 256;
  const strA = String(a || "");
  const strB = String(b || "");
  // result is an accumulator for all the errors
  let result = strA.length ^ strB.length;
  for (let i = 0; i < MAX_TOKEN_LENGTH; i++) {
    const charA = i < strA.length ? strA.charCodeAt(i) : 0;
    const charB = i < strB.length ? strB.charCodeAt(i) : 0;
    result |= charA ^ charB;
  }
  return result === 0;
}

export default csrfProtection;
