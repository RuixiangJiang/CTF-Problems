// test.js
// Minimal test runner for GitHub Actions. No external test framework is used.

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const TARGET_PORT = 4000;

async function main() {
  console.log('Starting server on port', TARGET_PORT);
  const server = require('./index'); // index.js exports the running server.

  try {
    // 1) Check home page.
    console.log('Checking home page...');
    const homeResp = await axios.get(`http://127.0.0.1:${TARGET_PORT}/`);
    if (homeResp.status !== 200) {
      throw new Error('Home page did not return 200 OK');
    }
    console.log('Home page OK');

    // 2) Check that missing updateToken is rejected.
    console.log('Checking update endpoint without token...');
    try {
      await axios.post(
        `http://127.0.0.1:${TARGET_PORT}/admin/update-plugins`,
        {}
      );
      throw new Error('Update endpoint unexpectedly accepted empty token');
    } catch (e) {
      if (!e.response || e.response.status !== 400) {
        throw new Error(
          'Update endpoint did not return 400 for missing token'
        );
      }
      console.log('Missing token correctly rejected');
    }

    // 3) Forge a token using HS256 with the public key as the secret.
    //    Here we put the manifest directly inside the token payload,
    //    so the server does not need to fetch anything over HTTP.
    console.log('Forging update token with inline manifest using public.pem as HS256 secret...');
    const publicKey = fs.readFileSync(
      path.join(__dirname, 'config', 'public.pem'),
      'utf8'
    );

    const manifest = {
      version: 1,
      plugins: [{ name: 'hello', entry: 'hello.js' }]
    };

    const payload = {
      manifest,
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    const token = jwt.sign(payload, publicKey, {
      algorithm: 'HS256'
    });

    console.log('Token forged, calling /admin/update-plugins ...');

    const updateResp = await axios.post(
      `http://127.0.0.1:${TARGET_PORT}/admin/update-plugins`,
      { updateToken: token }
    );

    if (!updateResp.data || updateResp.data.ok !== true) {
      throw new Error('Update endpoint did not return ok:true');
    }

    console.log('Update endpoint accepted forged token and applied manifest');
    console.log('All tests passed.');
    await cleanup(0, server);
  } catch (err) {
    console.error('TEST FAILED:', err);
    await cleanup(1, server);
  }
}

async function cleanup(code, server) {
  try {
    if (server) {
      server.close();
    }
  } catch (e) {
    console.error('Error while shutting down server:', e.message);
  } finally {
    process.exit(code);
  }
}

main();
