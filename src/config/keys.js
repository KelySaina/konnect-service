const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const KEYS_DIR = path.join(__dirname, "../../keys");
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, "private.pem");
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, "public.pem");

function generateKeys() {
  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });

  console.log("RSA key pair generated in ./keys/");
  return { privateKey, publicKey };
}

function loadKeys() {
  if (!fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PUBLIC_KEY_PATH)) {
    console.log("No RSA keys found, generating...");
    return generateKeys();
  }

  return {
    privateKey: fs.readFileSync(PRIVATE_KEY_PATH, "utf8"),
    publicKey: fs.readFileSync(PUBLIC_KEY_PATH, "utf8"),
  };
}

// Derive JWK from public key for JWKS endpoint
function getJWK(publicKey) {
  const keyObject = crypto.createPublicKey(publicKey);
  const jwk = keyObject.export({ format: "jwk" });
  jwk.kid = crypto
    .createHash("sha256")
    .update(publicKey)
    .digest("hex")
    .slice(0, 16);
  jwk.use = "sig";
  jwk.alg = "RS256";
  return jwk;
}

// Auto-generate when run directly
if (require.main === module) {
  generateKeys();
}

module.exports = { loadKeys, getJWK, generateKeys };
