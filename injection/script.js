const API_BASE = "https://chat.ruixiangj.top/injection";

async function handleLogin(event) {
  event.preventDefault();
  const resultDiv = document.getElementById("result");
  resultDiv.textContent = "Sending request...";

  const username = document.getElementById("username").value || "";
  const password = document.getElementById("password").value || "";

  try {
    const res = await fetch(`${API_BASE}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();

    if (!res.ok) {
      resultDiv.textContent = `Error: ${data.message || "Unknown error"}`;
      return;
    }

    if (data.flag) {
      resultDiv.textContent = `✅ ${data.message}\n\nFLAG: ${data.flag}`;
    } else {
      resultDiv.textContent = `ℹ️ ${data.message}`;
    }
  } catch (err) {
    console.error(err);
    resultDiv.textContent = "Network error. Check if backend is up.";
  }
}

document.getElementById("login-form").addEventListener("submit", handleLogin);
