// updater.js
// Core logic for the vulnerable update mechanism.

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const config = require('./config/config-prod.json');

// This is actually an RSA public key, but will be misused as a symmetric secret.
const publicKey = fs.readFileSync(
  path.join(__dirname, 'config', 'public.pem'),
  'utf8'
);

/**
 * Verify the update token and fetch the remote manifest JSON.
 *
 * Expected payload:
 * {
 *   "repoUrl": "http://127.0.0.1:5001/manifest.json",
 *   "exp": 1735660800
 * }
 *
 * VULNERABILITY:
 *  - The code uses HS256 (HMAC with symmetric key).
 *  - It incorrectly uses an RSA public key as the HMAC secret.
 *  - Since the public key is public, anyone can create a valid token.
 */
async function verifyAndFetchManifest(updateToken) {
  try {
    const payload = jwt.verify(updateToken, publicKey, {
      // Using a symmetric algorithm with a public key is a serious integrity failure.
      algorithms: ['HS256']
    });

    const manifestUrl = payload.repoUrl;

    // IMPORTANT: allow http for local testing & GitHub Actions
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
