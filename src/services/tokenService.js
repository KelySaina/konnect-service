const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { loadKeys, getJWK } = require("../config/keys");
const config = require("../config");
const { RefreshToken } = require("../models");

let keys = null;
let jwk = null;

function init() {
  keys = loadKeys();
  jwk = getJWK(keys.publicKey);
}

function getJWKS() {
  if (!jwk) init();
  return { keys: [jwk] };
}

function getPublicKey() {
  if (!keys) init();
  return keys.publicKey;
}

function signAccessToken(payload) {
  if (!keys) init();
  return jwt.sign(payload, keys.privateKey, {
    algorithm: "RS256",
    expiresIn: config.jwt.accessTokenTTL,
    issuer: config.jwt.issuer,
    keyid: jwk.kid,
  });
}

function signIdToken(payload) {
  if (!keys) init();
  return jwt.sign(payload, keys.privateKey, {
    algorithm: "RS256",
    expiresIn: config.jwt.accessTokenTTL,
    issuer: config.jwt.issuer,
    keyid: jwk.kid,
  });
}

function verifyToken(token) {
  if (!keys) init();
  return jwt.verify(token, keys.publicKey, {
    algorithms: ["RS256"],
    issuer: config.jwt.issuer,
  });
}

async function createRefreshToken(userId, clientId = null, scopes = null) {
  const raw = crypto.randomBytes(48).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(raw).digest("hex");
  const family = crypto.randomBytes(16).toString("hex");

  await RefreshToken.create({
    token_hash: tokenHash,
    user_id: userId,
    client_id: clientId,
    scopes: scopes ? scopes.join(" ") : null,
    expires_at: new Date(Date.now() + config.jwt.refreshTokenTTL * 1000),
    family,
  });

  return raw;
}

async function rotateRefreshToken(oldRawToken, userId, clientId = null) {
  const oldHash = crypto.createHash("sha256").update(oldRawToken).digest("hex");
  const existing = await RefreshToken.findOne({ where: { token_hash: oldHash, revoked: false } });

  if (!existing || existing.expires_at < new Date()) {
    // Possible replay attack — revoke entire family
    if (existing) {
      await RefreshToken.update({ revoked: true }, { where: { family: existing.family } });
    }
    return null;
  }

  // Revoke old token
  existing.revoked = true;
  await existing.save();

  // Issue new one in same family
  const raw = crypto.randomBytes(48).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(raw).digest("hex");

  await RefreshToken.create({
    token_hash: tokenHash,
    user_id: userId,
    client_id: clientId,
    scopes: existing.scopes,
    expires_at: new Date(Date.now() + config.jwt.refreshTokenTTL * 1000),
    family: existing.family,
  });

  return { token: raw, scopes: existing.scopes };
}

async function revokeRefreshToken(rawToken) {
  const hash = crypto.createHash("sha256").update(rawToken).digest("hex");
  await RefreshToken.update({ revoked: true }, { where: { token_hash: hash } });
}

async function revokeAllUserTokens(userId) {
  await RefreshToken.update({ revoked: true }, { where: { user_id: userId, revoked: false } });
}

module.exports = {
  init,
  getJWKS,
  getPublicKey,
  signAccessToken,
  signIdToken,
  verifyToken,
  createRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  revokeAllUserTokens,
};
