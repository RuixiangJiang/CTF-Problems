// updater.js
// Core logic for the vulnerable update mechanism.

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { HMAC_KEY } = require('./secrets');

const config = require('./config/config-prod.json');

/**
 * Verify the update token and obtain the manifest.
 *
 * Two modes:
 *  1) Inline manifest:
 *     payload = { manifest: { ... }, exp: ... }
 *  2) Remote manifest URL:
 *     payload = { repoUrl: "http://...", exp: ... }
 */
async function verifyAndFetchManifest(updateToken) {
  try {
    // IMPORTANT: use the symmetric HMAC_KEY (Buffer), not the PEM string.
    console.log('[debug] verify using HS256, key length =', HMAC_KEY.length);
    const payload = jwt.verify(updateToken, HMAC_KEY, {
      algorithms: ['HS256']
    });

    // Mode 1: inline manifest directly inside the token.
    if (payload.manifest && typeof payload.manifest === 'object') {
      console.log('[debug] using inline manifest from token payload');
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

    console.log('[debug] fetching manifest from', manifestUrl);
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

    // Create a realistic CommonJS-like module object.
    const moduleObj = { exports: {} };

    // Unsafe sandbox with high privileges.
    const sandbox = {
      console,
      require,
      module: moduleObj,
      exports: moduleObj.exports,
      process,
      __dirname,
      __filename: pluginPath
    };

    vm.createContext(sandbox);
    vm.runInContext(code, sandbox, {
      filename: pluginPath,
      timeout: 1000
    });

    const exported = moduleObj.exports;

    if (typeof exported?.init === 'function') {
      exported.init();
    }
  }
}


module.exports = {
  verifyAndFetchManifest,
  applyManifest
};
