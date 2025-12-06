// updater.js
// Core logic for the vulnerable update mechanism.

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const config = require('./config/config-prod.json');

// We load an RSA public key from public.pem.
const publicKeyPem = fs.readFileSync(
  path.join(__dirname, 'config', 'public.pem'),
  'utf8'
);

// VULNERABILITY:
// Instead of using a private key for RS256 or a truly secret HMAC key,
// the server derives its HS256 key directly from the public key file.
// Anyone who can read public.pem (e.g. source code is public) can compute
// exactly the same HMAC key and forge valid tokens.
const hmacKey = crypto.createHash('sha256').update(publicKeyPem).digest();

/**
 * Verify the update token and obtain the manifest.
 *
 * Two modes:
 *  1) Inline manifest:
 *     payload = { manifest: { ... }, exp: ... }
 *     In this case we directly return payload.manifest.
 *
 *  2) Remote manifest URL:
 *     payload = { repoUrl: "http://...", exp: ... }
 *     In this case we fetch the manifest from repoUrl via HTTP(S).
 *
 * VULNERABILITY:
 *  - The code uses HS256 (HMAC with symmetric key).
 *  - The symmetric key is derived from a public file (public.pem),
 *    so it is not secret at all.
 */
async function verifyAndFetchManifest(updateToken) {
  try {
    const payload = jwt.verify(updateToken, hmacKey, {
      algorithms: ['HS256']
    });

    // Mode 1: inline manifest directly inside the token.
    if (payload.manifest && typeof payload.manifest === 'object') {
      return payload.manifest;
    }

    // Mode 2: fetch manifest from remote URL.
    const manifestUrl = payload.repoUrl;

    // Allow both http and https so the challenge can use localhost URLs.
    if (
      typeof manifestUrl !== 'string' ||
      (!manifestUrl.startsWith('http://') &&
        !manifestUrl.startsWith('https://'))
    ) {
      throw new Error('Invalid manifest URL');
    }

    const resp = await axios.get(manifestUrl, { timeout: 3000 });
    if (resp.status !== 200) {
      throw new Error('Cannot fetch manifest');
    }

    return resp.data;
  } catch (e) {
    console.error('verifyAndFetchManifest error:', e.message);
    throw new Error('Invalid update token');
  }
}

/**
 * Apply the manifest by loading and executing plugin files.
 *
 * Expected manifest structure:
 * {
 *   "version": 1,
 *   "plugins": [
 *     { "name": "hello", "entry": "hello.js" }
 *   ]
 * }
 *
 * VULNERABILITY:
 *  - Plugins are executed in a powerful vm context with access to require() and process.
 *  - Once integrity is broken, an attacker-controlled plugin can achieve arbitrary code execution.
 */
async function applyManifest(manifest) {
  const vm = require('vm');

  if (!manifest || typeof manifest !== 'object') {
    throw new Error('Invalid manifest format');
  }
  if (!Array.isArray(manifest.plugins)) {
    throw new Error('No plugins field');
  }

  for (const plugin of manifest.plugins) {
    const entry = plugin.entry;
    if (!entry || entry.includes('..') || entry.includes('/')) {
      // Very naive path validation.
      continue;
    }

    const pluginPath = path.join(__dirname, 'plugins', entry);
    if (!fs.existsSync(pluginPath)) {
      console.warn('Plugin file not found:', pluginPath);
      continue;
    }

    const code = fs.readFileSync(pluginPath, 'utf8');

    // Unsafe sandbox with high privileges.
    const sandbox = {
      console,
      require,
      module: {},
      exports: {},
      process,
      __dirname,
      __filename: pluginPath
    };

    vm.createContext(sandbox);
    vm.runInContext(code, sandbox, {
      filename: pluginPath,
      timeout: 1000
    });

    if (typeof sandbox.module.exports?.init === 'function') {
      sandbox.module.exports.init();
    }
  }
}

module.exports = {
  verifyAndFetchManifest,
  applyManifest
};
