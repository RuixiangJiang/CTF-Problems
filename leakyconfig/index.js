const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const serveIndex = require("serve-index");
const fs = require("fs");
const YAML = require("yaml");

const app = express();
const PORT = process.env.PORT || 3000;

// ====== Configuration (intended secure part) ======
let ADMIN_USER = process.env.ADMIN_USER || "admin";
let ADMIN_PASS = process.env.ADMIN_PASS || "Very_Strong_Admin_Password_9fc1e2";
const FLAG = "flag{ruixiang}";

// Try to load backup config (simulating careless admin using it locally)
const backupConfigPath = path.join(__dirname, "backup", "config-prod.yaml.bak");
if (fs.existsSync(backupConfigPath)) {
  try {
    const file = fs.readFileSync(backupConfigPath, "utf8");
    const config = YAML.parse(file);
    if (config && config.admin && config.admin.username && config.admin.password) {
      ADMIN_USER = config.admin.username;
      ADMIN_PASS = config.admin.password;
      console.log("Loaded admin credentials from backup config.");
    }
  } catch (e) {
    console.error("Failed to parse backup config:", e);
  }
}

// ====== Middlewares ======
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Static files (login page)
app.use(express.static(path.join(__dirname, "public")));

// ❗ Misconfiguration: expose backup directory as static + directory listing
const backupDir = path.join(__dirname, "backup");
if (fs.existsSync(backupDir)) {
  app.use(
    "/backup",
    express.static(backupDir),
    serveIndex(backupDir, { icons: true })
  );
}

// ====== Auth helpers ======
function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.auth;
  if (token === "ok") {
    return next();
  }
  return res.status(401).send("Unauthorized. Please log in first.");
}

// ====== Routes ======

// GET / -> index.html via static

// POST /login: check credentials
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    res.cookie("auth", "ok", { httpOnly: true });
    return res.json({
      ok: true,
      message: "Login successful. Go to /admin to get the flag."
    });
  } else {
    return res
      .status(403)
      .json({ ok: false, message: "Invalid username or password." });
  }
});

// GET /admin: only for authenticated users
app.get("/admin", requireAuth, (req, res) => {
  res.send(`Welcome, admin.<br><br>Here is your flag: <b>${FLAG}</b>`);
});

// Fallback 404
app.use((req, res) => {
  res.status(404).send("Not found.");
});

app.listen(PORT, () => {
  console.log(`Leaky Config Pro listening on http://0.0.0.0:${PORT}`);
});
