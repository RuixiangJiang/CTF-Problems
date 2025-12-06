// scripts/app.js
// Static version of the "signed but not safe" challenge.
// All "verification" happens in the browser using Web Crypto.
// VULNERABILITY: HS256 key is derived from a public file (public.pem).

const tokenInput = document.getElementById("token-input");
const runBtn = document.getElementById("run-btn");
const statusEl = document.getElementById("status");
const logsEl = document.getElementById("logs");

let publicPem = null;
let hmacKey = null; // CryptoKey for HMAC-SHA256

// Obfuscated flag stored as hex chunks.
// This is just to avoid a trivial "flag{" string search.
const FLAG_PARTS = [
  "666c6167", // "flag"
  "7b", // "{"
  "7275697869616e67", // "ruixiang"
  "7d", // "}"
];

function hexToStr(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

function getFlag() {
  return FLAG_PARTS.map(hexToStr).join("");
}

function logLine(line) {
  const text = logsEl.textContent === "[no logs yet]"
    ? line
    : logsEl.textContent + "\n" + line;
  logsEl.textContent = text;
}

function setStatus(text, ok = false) {
  statusEl.textContent = text;
  statusEl.className = ok ? "ok" : "error";
}

/**
 * Load public.pem and derive the HS256 key from it.
 * This mirrors the insecure backend behavior.
 */
async function initKey() {
  if (hmacKey) return hmacKey;

  const resp = await fetch("public.pem");
  publicPem = await resp.text();

  const enc = new TextEncoder();
  // Derive a "secret" key from a public file (this is the bug).
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(publicPem));

  hmacKey = await crypto.subtle.importKey(
    "raw",
    digest,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return hmacKey;
}

/**
 * Base64URL helpers.
 */
function b64urlDecode(str) {
  // Pad and replace URL-safe chars.
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = str.length % 4;
  if (pad === 2) str += "==";
  else if (pad === 3) str += "=";
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function b64urlEncode(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  let b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/**
 * Verify HS256 JWT using the derived hmacKey.
 * Returns parsed payload object on success, or throws on failure.
 */
async function verifyTokenHS256(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  const [headerB64, payloadB64, sigB64] = parts;

  const headerBytes = b64urlDecode(headerB64);
  const payloadBytes = b64urlDecode(payloadB64);
  const headerJson = new TextDecoder().decode(headerBytes);
  const payloadJson = new TextDecoder().decode(payloadBytes);

  let header, payload;
  try {
    header = JSON.parse(headerJson);
    payload = JSON.parse(payloadJson);
  } catch {
    throw new Error("Invalid JSON in header or payload");
  }

  if (header.alg !== "HS256") {
    throw new Error("Unexpected alg: " + header.alg);
  }

  const key = await initKey();
  const dataToSign = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const expectedSig = await crypto.subtle.sign("HMAC", key, dataToSign);
  const expectedSigB64 = b64urlEncode(new Uint8Array(expectedSig));

  if (expectedSigB64 !== sigB64) {
    throw new Error("Signature mismatch");
  }

  // Check exp if present
  if (payload.exp && typeof payload.exp === "number") {
    const now = Math.floor(Date.now() / 1000);
    if (now > payload.exp) {
      throw new Error("Token expired");
    }
  }

  return payload;
}

/**
 * Simulated plugin loader (runs entirely in the browser).
 */
function applyManifest(manifest) {
  if (!manifest || typeof manifest !== "object") {
    throw new Error("Manifest not object");
  }
  if (!Array.isArray(manifest.plugins)) {
    throw new Error("Manifest.plugins must be array");
  }

  for (const plugin of manifest.plugins) {
    if (plugin.name === "evil") {
      logLine("[loader] Loading plugin: evil");
      runEvilPlugin();
    } else {
      logLine(`[loader] Skipping unknown plugin: ${plugin.name}`);
    }
  }
}

/**
 * Evil plugin implementation: just prints the flag.
 */
function runEvilPlugin() {
  try {
    const flag = getFlag();
    logLine(`[evil plugin] flag: ${flag}`);
  } catch (e) {
    logLine(`[evil plugin] failed to read flag: ${e.message}`);
  }
}

/**
 * Button handler: read token, verify, apply manifest, show logs.
 */
async function handleRun() {
  setStatus("");
  const token = tokenInput.value.trim();
  if (!token) {
    setStatus("Please paste a token first.");
    return;
  }

  try {
    const payload = await verifyTokenHS256(token);
    logLine("[core] token verified. Payload:");
    logLine(JSON.stringify(payload, null, 2));

    if (payload.manifest) {
      applyManifest(payload.manifest);
      setStatus("Token accepted, manifest applied.", true);
    } else {
      setStatus("Token is valid but no manifest found in payload.", false);
    }
  } catch (e) {
    console.error(e);
    setStatus("Token rejected: " + e.message);
  }
}

runBtn.addEventListener("click", () => {
  handleRun();
});

// Optional: focus textarea on load
tokenInput.focus();
