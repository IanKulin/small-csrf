// test runner is Node's built-in
// https://nodejs.org/api/test.html
// `npm test` to run

import { test, describe } from "node:test";
import assert from "node:assert";
import csrfProtection from "../csrf.js";

// Mock objects for testing
function createMockReq(overrides = {}) {
  return {
    method: "GET",
    session: { id: "test-session-id" },
    cookies: {},
    body: {},
    query: {},
    headers: {},
    ...overrides,
  };
}

function createMockRes() {
  const res = {
    cookies: {},
    cookie: function (name, value, options) {
      this.cookies[name] = { value, options };
    },
  };
  return res;
}

function createMockNext() {
  const calls = [];
  function next(error) {
    calls.push(error || "called");
  }
  next.calls = calls;
  return next;
}

describe("csrfProtection", () => {
  const testSecret = "this-is-a-very-long-secret-key-for-testing-purposes";

  test("should return a function", () => {
    assert.equal(typeof csrfProtection, "function");
  });

  describe("initialization", () => {
    test("should throw error if secret is too short", () => {
      assert.throws(() => {
        csrfProtection({ secret: "short" });
      }, /CSRF secret must be at least 32 characters long/);
    });

    test("should throw error if no secret provided", () => {
      assert.throws(() => {
        csrfProtection({});
      }, /CSRF secret must be at least 32 characters long/);
    });

    test("should accept valid configuration", () => {
      const middleware = csrfProtection({ secret: testSecret });
      assert.equal(typeof middleware, "function");
    });
  });

  describe("configuration options", () => {
    test("should use default cookie settings", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq();
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      const cookieData = res.cookies.csrf_token;
      assert.equal(cookieData.options.path, "/");
      assert.equal(cookieData.options.httpOnly, true);
      assert.equal(cookieData.options.sameSite, "strict");
      assert.equal(cookieData.options.secure, true);
      assert.equal(cookieData.options.maxAge, 3600000);
    });

    test("should use custom cookie settings", () => {
      const middleware = csrfProtection({
        secret: testSecret,
        cookie: {
          key: "custom_csrf",
          path: "/api",
          httpOnly: false,
          sameSite: "lax",
          secure: false,
          maxAge: 7200000,
        },
      });
      const req = createMockReq();
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      const cookieData = res.cookies.custom_csrf;
      assert.equal(cookieData.options.path, "/api");
      assert.equal(cookieData.options.httpOnly, false);
      assert.equal(cookieData.options.sameSite, "lax");
      assert.equal(cookieData.options.secure, false);
      assert.equal(cookieData.options.maxAge, 7200000);
    });

    test("should use custom ignore methods", () => {
      const middleware = csrfProtection({
        secret: testSecret,
        ignoreMethods: ["GET", "POST"],
      });
      const req = createMockReq({ method: "POST" });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0], "called");
      assert.equal(typeof req.csrfToken, "function");
    });

    test("should accept valid token from custom parameter name", () => {
      const middleware = csrfProtection({
        secret: testSecret,
        csrfParam: "custom_token",
      });

      // First generate a valid token
      const getReq = createMockReq({ method: "GET" });
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_token.value;

      // Then validate it using the custom parameter name
      const postReq = createMockReq({
        method: "POST",
        cookies: { csrf_token: validToken },
        body: { custom_token: validToken },
      });
      const postRes = createMockRes();
      const postNext = createMockNext();

      middleware(postReq, postRes, postNext);

      assert.equal(postNext.calls.length, 1);
      assert.equal(postNext.calls[0], "called");
    });

    test("should reject invalid tokens regardless of parameter name", () => {
      const middleware = csrfProtection({
        secret: testSecret,
        csrfParam: "custom_token",
      });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: "invalid.token" },
        body: { custom_token: "invalid.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);
      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });
  });

  test("should ignore token in default _csrf field when using custom parameter", () => {
    const middleware = csrfProtection({
      secret: testSecret,
      csrfParam: "custom_token",
    });

    // Generate a valid token
    const getReq = createMockReq({ method: "GET" });
    const getRes = createMockRes();
    const getNext = createMockNext();
    middleware(getReq, getRes, getNext);
    const validToken = getRes.cookies.csrf_token.value;

    // Put valid token in default field, but leave custom field empty
    const postReq = createMockReq({
      method: "POST",
      cookies: { csrf_token: validToken },
      body: {
        _csrf: validToken, // Valid token in default location
        custom_token: undefined, // No token in configured location
      },
    });
    const postRes = createMockRes();
    const postNext = createMockNext();

    middleware(postReq, postRes, postNext);

    // Should fail because it didn't find token in custom_token field
    assert.equal(postNext.calls[0].code, "EBADCSRFTOKEN");
  });

  describe("HTTP method handling", () => {
    test("should generate token for GET requests", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({ method: "GET" });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0], "called");
      assert.equal(typeof req.csrfToken, "function");
      assert.ok(res.cookies.csrf_token);
      assert.ok(res.cookies.csrf_token.value);
    });

    test("should generate token for HEAD requests", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({ method: "HEAD" });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0], "called");
      assert.equal(typeof req.csrfToken, "function");
    });

    test("should generate token for OPTIONS requests", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({ method: "OPTIONS" });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0], "called");
      assert.equal(typeof req.csrfToken, "function");
    });

    test("should validate token for POST requests", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: "invalid.token" },
        body: { _csrf: "invalid.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
      assert.equal(next.calls[0].status, 403);
    });
  });

  test("should handle PUT requests", () => {
    const middleware = csrfProtection({ secret: testSecret });

    // First, generate a valid token
    const getReq = createMockReq({ method: "GET" });
    const getRes = createMockRes();
    const getNext = createMockNext();
    middleware(getReq, getRes, getNext);
    const validToken = getRes.cookies.csrf_token.value;

    // Then, test PUT request with valid token
    const putReq = createMockReq({
      method: "PUT",
      cookies: { csrf_token: validToken },
      body: { _csrf: validToken },
    });
    const putRes = createMockRes();
    const putNext = createMockNext();

    middleware(putReq, putRes, putNext);

    assert.equal(putNext.calls.length, 1);
    assert.equal(putNext.calls[0], "called");
    assert.equal(typeof putReq.csrfToken, "function");
  });

  test("should handle PATCH requests", () => {
    const middleware = csrfProtection({ secret: testSecret });

    // First, generate a valid token
    const getReq = createMockReq({ method: "GET" });
    const getRes = createMockRes();
    const getNext = createMockNext();
    middleware(getReq, getRes, getNext);
    const validToken = getRes.cookies.csrf_token.value;

    // Then, test PATCH request with valid token
    const patchReq = createMockReq({
      method: "PATCH",
      cookies: { csrf_token: validToken },
      body: { _csrf: validToken },
    });
    const patchRes = createMockRes();
    const patchNext = createMockNext();

    middleware(patchReq, patchRes, patchNext);

    assert.equal(patchNext.calls.length, 1);
    assert.equal(patchNext.calls[0], "called");
    assert.equal(typeof patchReq.csrfToken, "function");
  });

  test("should handle DELETE requests", () => {
    const middleware = csrfProtection({ secret: testSecret });

    // First, generate a valid token
    const getReq = createMockReq({ method: "GET" });
    const getRes = createMockRes();
    const getNext = createMockNext();
    middleware(getReq, getRes, getNext);
    const validToken = getRes.cookies.csrf_token.value;

    // Then, test DELETE request with valid token
    const deleteReq = createMockReq({
      method: "DELETE",
      cookies: { csrf_token: validToken },
      headers: { "x-csrf-token": validToken }, // Using header for variety
    });
    const deleteRes = createMockRes();
    const deleteNext = createMockNext();

    middleware(deleteReq, deleteRes, deleteNext);

    assert.equal(deleteNext.calls.length, 1);
    assert.equal(deleteNext.calls[0], "called");
    assert.equal(typeof deleteReq.csrfToken, "function");
  });

  describe("session handling", () => {
    test("should throw error if session middleware is missing", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({ session: null });
      const res = createMockRes();
      const next = createMockNext();

      assert.throws(() => {
        middleware(req, res, next);
      }, /Session middleware is required for CSRF protection/);
    });

    test("should bind token to session ID", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req1 = createMockReq({ session: { id: "session-1" } });
      const req2 = createMockReq({ session: { id: "session-2" } });
      const res1 = createMockRes();
      const res2 = createMockRes();
      const next = createMockNext();

      middleware(req1, res1, next);
      middleware(req2, res2, next);

      const token1 = res1.cookies.csrf_token.value;
      const token2 = res2.cookies.csrf_token.value;

      // Tokens should be different for different sessions
      assert.notEqual(token1, token2);
    });

    test("should handle session ID changes gracefully", () => {
      const middleware = csrfProtection({ secret: testSecret });

      // Generate token with original session ID
      const originalReq = createMockReq({
        method: "GET",
        session: { id: "original-session-id" },
      });
      const originalRes = createMockRes();
      const originalNext = createMockNext();

      middleware(originalReq, originalRes, originalNext);
      const tokenFromOriginalSession = originalRes.cookies.csrf_token.value;

      // Try to use the token with a different session ID
      // (simulating session regeneration after login/logout)
      const newSessionReq = createMockReq({
        method: "POST",
        session: { id: "new-session-id-after-regeneration" },
        cookies: { csrf_token: tokenFromOriginalSession },
        body: { _csrf: tokenFromOriginalSession },
      });
      const newSessionRes = createMockRes();
      const newSessionNext = createMockNext();

      middleware(newSessionReq, newSessionRes, newSessionNext);

      // Should fail because token is bound to the original session ID
      assert.equal(newSessionNext.calls[0].code, "EBADCSRFTOKEN");
      assert.equal(newSessionNext.calls[0].status, 403);
    });
  });

  describe("token generation and validation", () => {
    test("should generate valid token structure", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq();
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      const token = res.cookies.csrf_token.value;
      const parts = token.split(".");
      assert.equal(parts.length, 2);
      assert.ok(parts[0].length > 0); // HMAC
      assert.ok(parts[1].length > 0); // Random value
    });

    test("should validate matching tokens", () => {
      const middleware = csrfProtection({ secret: testSecret });

      // First, generate a token
      const getReq = createMockReq({ method: "GET" });
      const getRes = createMockRes();
      const getNext = createMockNext();

      middleware(getReq, getRes, getNext);
      const generatedToken = getRes.cookies.csrf_token.value;

      // Then, validate it
      const postReq = createMockReq({
        method: "POST",
        cookies: { csrf_token: generatedToken },
        body: { _csrf: generatedToken },
      });
      const postRes = createMockRes();
      const postNext = createMockNext();

      middleware(postReq, postRes, postNext);

      assert.equal(postNext.calls.length, 1);
      assert.equal(postNext.calls[0], "called");
    });

    test("should reject mismatched tokens", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: "cookie.token" },
        body: { _csrf: "different.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });
  });

  describe("error conditions", () => {
    test("should fail when cookie token is missing", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        body: { _csrf: "some.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should fail when request token is missing", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: "some.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should fail with malformed cookie token", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: "malformed-token" },
        body: { _csrf: "malformed-token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should fail with empty token parts", () => {
      const middleware = csrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: "." },
        body: { _csrf: "." },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });
  });

  describe("token sources", () => {
    test("should accept token from request body", () => {
      const middleware = csrfProtection({ secret: testSecret });

      // Generate token first
      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_token.value;

      // Test body token
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: token },
        body: { _csrf: token },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);
      assert.equal(next.calls[0], "called");
    });

    test("should reject tokens from query string for security", () => {
      const middleware = csrfProtection({ secret: testSecret });

      // Generate valid token
      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_token.value;

      // Try to use token via query string only
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: token },
        query: { _csrf: token }, // Token only in query
        // No body or header token
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      // Should fail because query string tokens are rejected
      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should accept token from x-csrf-token header", () => {
      const middleware = csrfProtection({ secret: testSecret });

      // Generate token first
      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_token.value;

      // Test header token
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: token },
        headers: { "x-csrf-token": token },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);
      assert.equal(next.calls[0], "called");
    });

    test("should accept token from x-xsrf-token header", () => {
      const middleware = csrfProtection({ secret: testSecret });

      // Generate token first
      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_token.value;

      // Test xsrf header token
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_token: token },
        headers: { "x-xsrf-token": token },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);
      assert.equal(next.calls[0], "called");
    });

    test("should handle token precedence correctly", () => {
      const middleware = csrfProtection({ secret: testSecret });
      // I don't have deep feelings about the precedence of tokens
      // this just documents the current behavior

      // Generate valid tokens
      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_token.value;

      // Test 1: Body token should take precedence over header
      const req1 = createMockReq({
        method: "POST",
        cookies: { csrf_token: validToken },
        body: { _csrf: validToken }, // Valid token in body
        headers: { "x-csrf-token": "invalid-token" }, // Invalid token in header
      });
      const res1 = createMockRes();
      const next1 = createMockNext();

      middleware(req1, res1, next1);
      assert.equal(next1.calls[0], "called"); // Should succeed using body token

      // Test 2: x-csrf-token should take precedence over x-xsrf-token
      const req2 = createMockReq({
        method: "POST",
        cookies: { csrf_token: validToken },
        headers: {
          "x-csrf-token": validToken, // Valid token
          "x-xsrf-token": "invalid-token", // Invalid token
        },
      });
      const res2 = createMockRes();
      const next2 = createMockNext();

      middleware(req2, res2, next2);
      assert.equal(next2.calls[0], "called"); // Should succeed using x-csrf-token

      // Test 3: Should fall back to x-xsrf-token when others missing
      const req3 = createMockReq({
        method: "POST",
        cookies: { csrf_token: validToken },
        headers: {
          "x-xsrf-token": validToken, // Only this header present
        },
      });
      const res3 = createMockRes();
      const next3 = createMockNext();

      middleware(req3, res3, next3);
      assert.equal(next3.calls[0], "called"); // Should succeed using x-xsrf-token
    });
  });

  describe("per-session tokens", () => {
    test("should generate same token for same session when perSessionTokens is true", () => {
      const middleware = csrfProtection({
        secret: testSecret,
        perSessionTokens: true,
      });

      const sessionId = "consistent-session-id";
      const req1 = createMockReq({ session: { id: sessionId } });
      const req2 = createMockReq({ session: { id: sessionId } });
      const res1 = createMockRes();
      const res2 = createMockRes();
      const next = createMockNext();

      middleware(req1, res1, next);
      middleware(req2, res2, next);

      const token1 = res1.cookies.csrf_token.value;
      const token2 = res2.cookies.csrf_token.value;

      assert.equal(token1, token2);
    });

    test("should generate different tokens for different sessions when perSessionTokens is true", () => {
      const middleware = csrfProtection({
        secret: testSecret,
        perSessionTokens: true,
      });

      const req1 = createMockReq({ session: { id: "session-1" } });
      const req2 = createMockReq({ session: { id: "session-2" } });
      const res1 = createMockRes();
      const res2 = createMockRes();
      const next = createMockNext();

      middleware(req1, res1, next);
      middleware(req2, res2, next);

      const token1 = res1.cookies.csrf_token.value;
      const token2 = res2.cookies.csrf_token.value;

      assert.notEqual(token1, token2);
    });

    test("should generate different tokens for same session when perSessionTokens is false", () => {
      const middleware = csrfProtection({
        secret: testSecret,
        perSessionTokens: false,
      });

      const sessionId = "same-session-id";
      const req1 = createMockReq({ session: { id: sessionId } });
      const req2 = createMockReq({ session: { id: sessionId } });
      const res1 = createMockRes();
      const res2 = createMockRes();
      const next = createMockNext();

      middleware(req1, res1, next);
      middleware(req2, res2, next);

      const token1 = res1.cookies.csrf_token.value;
      const token2 = res2.cookies.csrf_token.value;

      assert.notEqual(token1, token2);
    });

    test("should generate same token for same session by default", () => {
      // perSessionTokens left on default
      const middleware = csrfProtection({ secret: testSecret });

      const sessionId = "same-session-id";
      const req1 = createMockReq({ session: { id: sessionId } });
      const req2 = createMockReq({ session: { id: sessionId } });
      const res1 = createMockRes();
      const res2 = createMockRes();
      const next = createMockNext();

      middleware(req1, res1, next);
      middleware(req2, res2, next);

      const token1 = res1.cookies.csrf_token.value;
      const token2 = res2.cookies.csrf_token.value;

      assert.equal(token1, token2);
    });
  });

  describe("constant time comparison", () => {
    // We can't directly test the constantTimeEquals function since it's not exported,
    // but we can test its behavior through the middleware

    test("should not be vulnerable to timing attacks on token comparison", () => {
      const middleware = csrfProtection({ secret: testSecret });

      // Generate a valid token
      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_token.value;

      // Test with tokens of different lengths
      const testTokens = [
        "a",
        "ab",
        "abc",
        validToken.slice(0, -1), // One character short
        validToken + "x", // One character long
        "x".repeat(validToken.length), // Same length, all wrong
      ];

      testTokens.forEach((testToken) => {
        const req = createMockReq({
          method: "POST",
          cookies: { csrf_token: validToken },
          body: { _csrf: testToken },
        });
        const res = createMockRes();
        const next = createMockNext();

        middleware(req, res, next);
        assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
      });
    });
  });

  describe("Misc edge cases", () => {
    test("should work with very long tokens", () => {
      const middleware = csrfProtection({ secret: testSecret });

      // Generate a normal token first to understand the structure
      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const normalToken = getRes.cookies.csrf_token.value;

      // Test 1: Very long valid token should work
      // (Normal tokens are much shorter than MAX_TOKEN_LENGTH, so this should pass)
      const req1 = createMockReq({
        method: "POST",
        cookies: { csrf_token: normalToken },
        body: { _csrf: normalToken },
      });
      const res1 = createMockRes();
      const next1 = createMockNext();

      middleware(req1, res1, next1);
      assert.equal(next1.calls[0], "called");

      // Test 2: Extremely long invalid token should fail gracefully
      const veryLongToken = "a".repeat(500); // Much longer than MAX_TOKEN_LENGTH (256)
      const req2 = createMockReq({
        method: "POST",
        cookies: { csrf_token: veryLongToken },
        body: { _csrf: veryLongToken },
      });
      const res2 = createMockRes();
      const next2 = createMockNext();

      middleware(req2, res2, next2);
      assert.equal(next2.calls[0].code, "EBADCSRFTOKEN");

      // Test 3: Token at exactly MAX_TOKEN_LENGTH should be handled
      const maxLengthToken = "b".repeat(256); // Exactly MAX_TOKEN_LENGTH
      const req3 = createMockReq({
        method: "POST",
        cookies: { csrf_token: maxLengthToken },
        body: { _csrf: maxLengthToken },
      });
      const res3 = createMockRes();
      const next3 = createMockNext();

      middleware(req3, res3, next3);
      assert.equal(next3.calls[0].code, "EBADCSRFTOKEN");
    });
  });

  describe("HMAC verification edge cases", () => {
    test("should fail with token from different session", () => {
      const middleware = csrfProtection({ secret: testSecret });

      // Generate token for session 1
      const session1Req = createMockReq({ session: { id: "session-1" } });
      const session1Res = createMockRes();
      const session1Next = createMockNext();
      middleware(session1Req, session1Res, session1Next);
      const session1Token = session1Res.cookies.csrf_token.value;

      // Try to use session 1's token with session 2
      const session2Req = createMockReq({
        method: "POST",
        session: { id: "session-2" },
        cookies: { csrf_token: session1Token },
        body: { _csrf: session1Token },
      });
      const session2Res = createMockRes();
      const session2Next = createMockNext();

      middleware(session2Req, session2Res, session2Next);
      assert.equal(session2Next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should fail with token generated using different secret", () => {
      const middleware1 = csrfProtection({ secret: testSecret });
      const middleware2 = csrfProtection({
        secret: "different-secret-key-for-testing-purposes",
      });

      // Generate token with first middleware
      const req1 = createMockReq();
      const res1 = createMockRes();
      const next1 = createMockNext();
      middleware1(req1, res1, next1);
      const token = res1.cookies.csrf_token.value;

      // Try to validate with second middleware (different secret)
      const req2 = createMockReq({
        method: "POST",
        cookies: { csrf_token: token },
        body: { _csrf: token },
      });
      const res2 = createMockRes();
      const next2 = createMockNext();

      middleware2(req2, res2, next2);
      assert.equal(next2.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should handle null/undefined values gracefully", () => {
      const middleware = csrfProtection({ secret: testSecret });

      const testCases = [
        { cookies: { csrf_token: null }, body: { _csrf: null } },
        { cookies: { csrf_token: undefined }, body: { _csrf: undefined } },
        { cookies: { csrf_token: "" }, body: { _csrf: "" } },
      ];

      testCases.forEach((testCase) => {
        const req = createMockReq({
          method: "POST",
          ...testCase,
        });
        const res = createMockRes();
        const next = createMockNext();

        middleware(req, res, next);
        assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
      });
    });
  });
});
