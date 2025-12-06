// secrets.js
// Shared logic for deriving the HMAC key from public.pem

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load the RSA public key from disk.
const publicKeyPem = fs.readFileSync(
  path.join(__dirname, 'config', 'public.pem'),
  'utf8'
);

// VULNERABILITY:
// Instead of using a private key for RS256 or a truly secret HMAC key,
// we derive the HS256 key directly from the public key file.
// Anyone who can read public.pem can compute the same HMAC key.
const HMAC_KEY = crypto.createHash('sha256').update(publicKeyPem).digest();

// Optional debug: you can keep this while testing locally.
// It will show up in node output when the module is first loaded.
console.log('[debug] HMAC_KEY length =', HMAC_KEY.length, 'bytes');

module.exports = {
  HMAC_KEY
};
