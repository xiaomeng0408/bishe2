# -*- coding: utf-8 -*-
"""
社区聊天服务：Flask + SQLite（自动生成 community_chat.db，无需单独安装数据库）
与毕设演示页 hypertension_demo.html 配合：注册/登录时同步账号，聊天记录持久化。
"""
from __future__ import annotations

import os
import sqlite3
import secrets
import time
from datetime import datetime, timezone

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "community_chat.db")

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'elderly',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_chat_created ON chat_messages(created_at);
            """
        )
        conn.commit()

        cur = conn.execute("SELECT COUNT(*) AS c FROM users")
        if cur.fetchone()[0] == 0:
            now = _utc_now_iso()
            seeds = [
                ("test_user", "123456", "elderly"),
                ("new_user", "123456", "elderly"),
                ("doctor_li", "123456", "medical_staff"),
            ]
            for uname, pwd, role in seeds:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                    (uname, generate_password_hash(pwd), role, now),
                )
            conn.commit()
    finally:
        conn.close()


def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Token, X-Username"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.after_request
def after(resp):
    return _cors(resp)


@app.route("/api/chat/register", methods=["OPTIONS"])
@app.route("/api/chat/login", methods=["OPTIONS"])
@app.route("/api/chat/me", methods=["OPTIONS"])
@app.route("/api/chat/messages", methods=["OPTIONS"])
def chat_options():
    return _cors(jsonify({"ok": True}))


@app.route("/api/chat/register", methods=["POST"])
def chat_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    role = (data.get("role") or "elderly").strip()
    if role not in ("elderly", "community_staff"):
        role = "elderly"
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
            (username, generate_password_hash(password), role, _utc_now_iso()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "用户名已存在"}), 409
    return jsonify({"ok": True, "username": username, "role": role})


@app.route("/api/chat/login", methods=["POST"])
def chat_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "账号或密码错误"}), 401

    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO auth_tokens (token, user_id, created_at) VALUES (?,?,?)",
        (token, row["id"], time.time()),
    )
    db.commit()
    is_medical = row["role"] == "medical_staff"
    return jsonify(
        {
            "token": token,
            "username": row["username"],
            "role": row["role"],
            "is_medical": is_medical,
        }
    )


def _ensure_chat_user(db: sqlite3.Connection, username: str, role: str = "elderly"):
    username = (username or "").strip()
    if not username:
        return None

    row = db.execute(
        "SELECT id, username, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row:
        return row

    created_at = _utc_now_iso()
    db.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        (username, generate_password_hash(secrets.token_urlsafe(16)), role, created_at),
    )
    db.commit()
    return db.execute(
        "SELECT id, username, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def _user_from_token(db: sqlite3.Connection, auth_header: str | None, username: str | None = None):
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token:
            row = db.execute(
                """
                SELECT u.id, u.username, u.role
                FROM auth_tokens t
                JOIN users u ON u.id = t.user_id
                WHERE t.token = ?
                """,
                (token,),
            ).fetchone()
            if row:
                return row

    username = (username or "").strip()
    if username:
        return _ensure_chat_user(db, username)

    # 如果前端携带的是 Django JWT，而不是社区聊天服务自己的 token，
    # 允许通过用户名回退识别当前用户，避免误判为未登录。
    x_username = (request.headers.get("X-Username") or "").strip()
    if x_username:
        return _ensure_chat_user(db, x_username)

    return None


@app.route("/api/chat/me", methods=["GET"])
def chat_me():
    db = get_db()
    row = _user_from_token(db, request.headers.get("Authorization"), request.headers.get("X-Username"))
    if not row:
        return jsonify({"error": "未登录或令牌无效"}), 401
    return jsonify(
        {
            "username": row["username"],
            "role": row["role"],
            "is_medical": row["role"] == "medical_staff",
        }
    )


@app.route("/api/chat/messages", methods=["GET"])
def chat_list_messages():
    limit = request.args.get("limit", default="200")
    try:
        lim = max(1, min(500, int(limit)))
    except ValueError:
        lim = 200
    db = get_db()
    rows = db.execute(
        """
        SELECT id, username, role, content, created_at
        FROM chat_messages
        ORDER BY id ASC
        LIMIT ?
        """,
        (lim,),
    ).fetchall()

    out = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "username": r["username"],
                "role": r["role"],
                "is_medical": r["role"] == "medical_staff",
                "content": r["content"],
                "created_at": r["created_at"],
            }
        )
    return jsonify({"messages": out})


@app.route("/api/chat/messages", methods=["POST"])
def chat_post_message():
    db = get_db()
    data = request.get_json(silent=True) or {}
    row = _user_from_token(
        db,
        request.headers.get("Authorization"),
        request.headers.get("X-Username") or data.get("username"),
    )
    content = (data.get("content") or data.get("message") or "").strip()
    if not row:
        username = (data.get("username") or request.headers.get("X-Username") or "").strip()
        if username:
            row = db.execute(
                "SELECT id, username, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()
    if not row:
        return jsonify({"error": "请先登录后再发送消息"}), 401

    if not content:
        return jsonify({"error": "消息内容不能为空"}), 400
    if len(content) > 2000:
        return jsonify({"error": "消息过长（最多2000字）"}), 400

    created = _utc_now_iso()
    cur = db.execute(
        """
        INSERT INTO chat_messages (user_id, username, role, content, created_at)
        VALUES (?,?,?,?,?)
        """,
        (row["id"], row["username"], row["role"], content, created),
    )
    db.commit()
    mid = cur.lastrowid
    return jsonify(
        {
            "ok": True,
            "message": {
                "id": mid,
                "username": row["username"],
                "role": row["role"],
                "is_medical": row["role"] == "medical_staff",
                "content": content,
                "created_at": created,
            },
        }
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "community_chat"})


if __name__ == "__main__":
    init_db()
    print("社区聊天服务已启动：http://127.0.0.1:5000")
    print("SQLite 数据库文件：", DB_PATH)
    print("健康检查：GET http://127.0.0.1:5000/health")
    app.run(host="127.0.0.1", port=5000, debug=False)
