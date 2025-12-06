// index.js
// Main Express server for the challenge.

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const { verifyAndFetchManifest, applyManifest } = require('./updater');

const app = express();

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'views')));

// Simple home page.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

/**
 * Admin endpoint that triggers plugin updates.
 *
 * The idea is that in production this would only be called from CI/CD with a
 * "secure" token. In reality there is no authentication here; everything relies
 * on the integrity of the updateToken, which is incorrectly implemented.
 */
app.post('/admin/update-plugins', async (req, res) => {
  const updateToken = req.body.updateToken;
  if (!updateToken) {
    return res.status(400).json({ error: 'updateToken required' });
  }

  try {
    const manifest = await verifyAndFetchManifest(updateToken);
    await applyManifest(manifest);
    res.json({ ok: true, message: 'Plugins updated.' });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Simple API endpoint that plugins could hook.
app.get('/api/ping', (req, res) => {
  res.json({ msg: 'pong', from: 'core-server' });
});

// Start server only when this file is executed directly.
const PORT = process.env.PORT || 4000;
let server = null;

if (require.main === module) {
  server = app.listen(PORT, () => {
    console.log(`Signed but not Safe listening on http://0.0.0.0:${PORT}`);
  });
} else {
  // When required by test.js we also start the server.
  server = app.listen(PORT, () => {
    console.log(`Signed but not Safe listening on http://0.0.0.0:${PORT} (test mode)`);
  });
}

module.exports = server;
