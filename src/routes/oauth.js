const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const { body, query, validationResult } = require("express-validator");
const config = require("../config");
const tokenService = require("../services/tokenService");
const { User, Role, Permission, OAuthClient, AuthorizationCode } = require("../models");

const router = express.Router();

// ============================================================
// .well-known/openid-configuration
// ============================================================
router.get("/.well-known/openid-configuration", (req, res) => {
  const issuer = config.jwt.issuer;
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email", "address", "phone", "offline_access"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    code_challenge_methods_supported: ["S256", "plain"],
    claims_supported: [
      "sub", "iss", "aud", "exp", "iat", "name", "given_name", "family_name",
      "email", "email_verified", "phone_number", "phone_number_verified",
      "address", "locale", "zoneinfo",
    ],
  });
});

// ============================================================
// JWKS
// ============================================================
router.get("/.well-known/jwks.json", (req, res) => {
  res.json(tokenService.getJWKS());
});

// ============================================================
// GET /oauth/authorize — show consent or redirect with code
// ============================================================
router.get("/oauth/authorize", [
  query("response_type").equals("code").withMessage("Only response_type=code supported"),
  query("client_id").notEmpty(),
  query("redirect_uri").isURL({ require_tld: false }),
  query("scope").optional(),
  query("state").optional(),
  query("code_challenge").optional(),
  query("code_challenge_method").optional().isIn(["S256", "plain"]),
  query("nonce").optional(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: "invalid_request", details: errors.array() });
  }

  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce } = req.query;

  // Validate client
  const client = await OAuthClient.findOne({ where: { client_id, active: true } });
  if (!client) {
    return res.status(400).json({ error: "invalid_client", error_description: "Client not found" });
  }

  // Validate redirect_uri
  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).json({ error: "invalid_request", error_description: "redirect_uri not registered" });
  }

  // If user not logged in, redirect to login page with return params
  if (!req.session || !req.session.userId) {
    const params = new URLSearchParams(req.query);
    return res.redirect(`${config.clientUrl}/login?${params.toString()}`);
  }

  // User is authenticated — issue authorization code
  const code = crypto.randomBytes(32).toString("hex");
  const scopes = scope || "openid profile email";

  await AuthorizationCode.create({
    code,
    client_id: client.id,
    user_id: req.session.userId,
    redirect_uri,
    scopes,
    code_challenge: code_challenge || null,
    code_challenge_method: code_challenge_method || null,
    nonce: nonce || null,
    expires_at: new Date(Date.now() + config.oauth.authCodeTTL * 1000),
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);

  res.redirect(redirectUrl.toString());
});

// ============================================================
// POST /oauth/token
// ============================================================
router.post("/oauth/token", express.urlencoded({ extended: false }), async (req, res) => {
  const { grant_type } = req.body;

  if (grant_type === "authorization_code") {
    return handleAuthCodeGrant(req, res);
  } else if (grant_type === "refresh_token") {
    return handleRefreshGrant(req, res);
  }

  return res.status(400).json({ error: "unsupported_grant_type" });
});

async function authenticateClient(req) {
  let clientId, clientSecret;

  // Try Basic auth first
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
    const colonIdx = decoded.indexOf(":");
    clientId = decoded.slice(0, colonIdx);
    clientSecret = decoded.slice(colonIdx + 1);
  } else {
    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  if (!clientId) return null;

  const client = await OAuthClient.findOne({ where: { client_id: clientId, active: true } });
  if (!client) return null;

  // Public clients don't require secret
  if (!client.is_confidential) return client;

  if (!clientSecret || !client.client_secret_hash) return null;
  const valid = await bcrypt.compare(clientSecret, client.client_secret_hash);
  return valid ? client : null;
}

async function handleAuthCodeGrant(req, res) {
  const { code, redirect_uri, code_verifier } = req.body;

  if (!code) {
    return res.status(400).json({ error: "invalid_request", error_description: "code is required" });
  }

  const client = await authenticateClient(req);
  if (!client) {
    return res.status(401).json({ error: "invalid_client" });
  }

  const authCode = await AuthorizationCode.findOne({
    where: { code, client_id: client.id, used: false },
  });

  if (!authCode || authCode.expires_at < new Date()) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Code expired or invalid" });
  }

  if (authCode.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
  }

  // PKCE verification
  if (authCode.code_challenge) {
    if (!code_verifier) {
      return res.status(400).json({ error: "invalid_grant", error_description: "code_verifier required" });
    }
    let computed;
    if (authCode.code_challenge_method === "S256") {
      computed = crypto.createHash("sha256").update(code_verifier).digest("base64url");
    } else {
      computed = code_verifier;
    }
    if (computed !== authCode.code_challenge) {
      return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
    }
  }

  // Mark code as used
  authCode.used = true;
  await authCode.save();

  // Load user
  const user = await User.findByPk(authCode.user_id, {
    include: [{ model: Role, as: "roles", include: [{ model: Permission, as: "permissions" }] }],
  });
  if (!user || !user.active) {
    return res.status(400).json({ error: "invalid_grant", error_description: "User inactive" });
  }

  const scopes = authCode.scopes.split(" ");
  const tokenPayload = buildTokenPayload(user, client.client_id, scopes);

  const accessToken = tokenService.signAccessToken(tokenPayload);
  const refreshToken = scopes.includes("offline_access")
    ? await tokenService.createRefreshToken(user.id, client.id, scopes)
    : undefined;

  const response = {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: config.jwt.accessTokenTTL,
  };

  if (refreshToken) response.refresh_token = refreshToken;

  // ID Token if openid scope
  if (scopes.includes("openid")) {
    const idPayload = buildIdTokenPayload(user, client.client_id, scopes, authCode.nonce);
    response.id_token = tokenService.signIdToken(idPayload);
  }

  res.json(response);
}

async function handleRefreshGrant(req, res) {
  const { refresh_token } = req.body;
  const client = await authenticateClient(req);
  if (!client) {
    return res.status(401).json({ error: "invalid_client" });
  }

  if (!refresh_token) {
    return res.status(400).json({ error: "invalid_request", error_description: "refresh_token required" });
  }

  const result = await tokenService.rotateRefreshToken(refresh_token, null, client.id);
  if (!result) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Refresh token invalid or expired" });
  }

  const user = await User.findByPk(result.scopes ? undefined : null);
  // Need to find user from old token — let's look up by the new token's user
  const crypto2 = require("crypto");
  const oldHash = crypto2.createHash("sha256").update(refresh_token).digest("hex");
  const { RefreshToken } = require("../models");
  const oldToken = await RefreshToken.findOne({ where: { token_hash: oldHash } });
  if (!oldToken) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  const userForToken = await User.findByPk(oldToken.user_id, {
    include: [{ model: Role, as: "roles" }],
  });
  if (!userForToken || !userForToken.active) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  const scopes = result.scopes ? result.scopes.split(" ") : ["openid", "profile", "email"];
  const tokenPayload = buildTokenPayload(userForToken, client.client_id, scopes);
  const accessToken = tokenService.signAccessToken(tokenPayload);

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: config.jwt.accessTokenTTL,
    refresh_token: result.token,
  });
}

// ============================================================
// POST /oauth/revoke
// ============================================================
router.post("/oauth/revoke", express.urlencoded({ extended: false }), async (req, res) => {
  const { token } = req.body;
  if (token) {
    await tokenService.revokeRefreshToken(token);
  }
  // Always return 200 per RFC 7009
  res.status(200).json({ status: "ok" });
});

// ============================================================
// GET /oauth/userinfo
// ============================================================
router.get("/oauth/userinfo", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "invalid_token" });
  }

  try {
    const decoded = tokenService.verifyToken(authHeader.slice(7));
    const user = await User.findByPk(decoded.sub, {
      include: [{ model: Role, as: "roles" }],
    });
    if (!user || !user.active) {
      return res.status(401).json({ error: "invalid_token" });
    }

    const scopes = (decoded.scope || "").split(" ");
    const claims = { sub: user.id };

    if (scopes.includes("profile")) {
      claims.name = [user.first_name, user.last_name].filter(Boolean).join(" ");
      claims.given_name = user.first_name;
      claims.family_name = user.last_name;
      claims.preferred_username = user.username;
      claims.picture = user.avatar_url
        ? (user.avatar_url.startsWith("http") ? user.avatar_url : `/api/files/${user.avatar_url}`)
        : null;
      claims.locale = user.locale;
      claims.zoneinfo = user.timezone;
      claims.updated_at = Math.floor(new Date(user.updatedAt).getTime() / 1000);
    }
    if (scopes.includes("email")) {
      claims.email = user.email;
      claims.email_verified = user.email_verified;
    }
    if (scopes.includes("phone")) {
      claims.phone_number = user.phone;
      claims.phone_number_verified = user.phone_verified;
    }

    res.json(claims);
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
});

// ============================================================
// POST /oauth/login — session-based login for authorize flow
// ============================================================
router.post("/oauth/login", [
  body("email").isEmail(),
  body("password").notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: "invalid_request", details: errors.array() });
  }

  const { email, password } = req.body;
  const user = await User.findOne({ where: { email, active: true } });
  if (!user) {
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: "invalid_credentials" });
  }

  // Set session
  req.session.userId = user.id;
  await user.update({ last_login_at: new Date() });

  res.json({ success: true, user: { id: user.id, email: user.email, username: user.username } });
});

// ============================================================
// POST /oauth/logout
// ============================================================
router.post("/oauth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ============================================================
// Helpers
// ============================================================
function buildTokenPayload(user, clientId, scopes) {
  const roles = user.roles ? user.roles.map((r) => r.name) : [];
  return {
    sub: user.id,
    aud: clientId,
    scope: scopes.join(" "),
    roles,
    email: user.email,
    username: user.username,
  };
}

function buildIdTokenPayload(user, clientId, scopes, nonce) {
  const payload = {
    sub: user.id,
    aud: clientId,
    auth_time: Math.floor(Date.now() / 1000),
  };
  if (nonce) payload.nonce = nonce;
  if (scopes.includes("email")) {
    payload.email = user.email;
    payload.email_verified = user.email_verified;
  }
  if (scopes.includes("profile")) {
    payload.name = [user.first_name, user.last_name].filter(Boolean).join(" ");
    payload.given_name = user.first_name;
    payload.family_name = user.last_name;
    payload.preferred_username = user.username;
    payload.locale = user.locale;
    payload.zoneinfo = user.timezone;
  }
  return payload;
}

module.exports = router;
