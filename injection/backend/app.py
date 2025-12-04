import os
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

FLAG = os.getenv("FLAG", "flag{ruixiang}")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Create users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            flag TEXT
        );
        """)

    # Insert a normal user if not exist
    cur.execute("SELECT id FROM users WHERE username = 'user';")
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO users (username, password, is_admin) VALUES ('user', 'userpass', 0);"
        )

    # Insert admin user if not exist
    cur.execute("SELECT id FROM users WHERE username = 'admin';")
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO users (username, password, is_admin, flag) VALUES ('admin', 'supersecret_admin_password', 1, ?);",
            (FLAG, ),
        )

    conn.commit()
    conn.close()


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/login", methods=["POST"])
def login():
    """
    Intentionally vulnerable SQL login endpoint.
    The challenge is to log in as admin without knowing the password.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # 🚨 VULNERABLE: direct string interpolation into SQL
    query = f"""
        SELECT id, username, is_admin, flag
        FROM users
        WHERE username = '{username}' AND password = '{password}'
        LIMIT 1;
    """

    print("[DEBUG] Executing query:", query)

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(query)
        row = cur.fetchone()
    except Exception as e:
        conn.close()
        # Don't leak exact error to players, just return generic message
        return jsonify({"status": "error", "message": "Database error."}), 400

    conn.close()

    if row is None:
        return jsonify({
            "status": "fail",
            "message": "Invalid username or password."
        }), 401

    username_db = row["username"]
    is_admin = row["is_admin"]
    flag_value = row["flag"]

    if is_admin:
        # Admin login — expose flag
        return jsonify({
            "status": "ok",
            "message": f"Welcome, {username_db}! Here is your flag.",
            "flag": flag_value,
        })
    else:
        return jsonify({
            "status":
            "ok",
            "message":
            f"Welcome, {username_db}! But you are not admin.",
        })


if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
