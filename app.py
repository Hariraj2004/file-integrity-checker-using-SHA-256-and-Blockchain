"""
File Integrity Checker — Flask Backend
SHA-256 + Simulated Blockchain with SQLite persistence
"""

import os, json, hashlib, time, sqlite3, threading
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g, session
from werkzeug.utils import secure_filename

# ─── CONFIG ──────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
IS_VERCEL   = os.environ.get("VERCEL", False)
UPLOAD_DIR  = "/tmp/uploads" if IS_VERCEL else os.path.join(BASE_DIR, "uploads")
STATIC_DIR  = os.path.join(BASE_DIR, "static")
DB_PATH     = "/tmp/integrity.db" if IS_VERCEL else os.path.join(BASE_DIR, "integrity.db")
MAX_MB      = 50
ALLOWED_EXT = None   # Accept any file type

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
app = Flask(__name__, static_folder=STATIC_DIR)
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key_change_me_in_prod")
app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
_db_lock = threading.Lock()

# ─── DATABASE ─────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE IF NOT EXISTS files (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT NOT NULL,
                original_name TEXT NOT NULL,
                size        INTEGER NOT NULL,
                sha256      TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'ok',
                registered  TEXT NOT NULL,
                last_check  TEXT,
                block_index INTEGER
            );

            CREATE TABLE IF NOT EXISTS blocks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER UNIQUE NOT NULL,
                timestamp   TEXT NOT NULL,
                data        TEXT NOT NULL,
                prev_hash   TEXT NOT NULL,
                block_hash  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                type        TEXT NOT NULL,
                message     TEXT NOT NULL,
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verify_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT NOT NULL,
                computed_hash TEXT NOT NULL,
                stored_hash   TEXT,
                result      TEXT NOT NULL,
                verified_at TEXT NOT NULL
            );
        """)
        db.commit()

        # Create genesis block if chain is empty
        cur = db.execute("SELECT COUNT(*) AS cnt FROM blocks")
        if cur.fetchone()["cnt"] == 0:
            genesis_data = "GENESIS_BLOCK:FILE_INTEGRITY_CHECKER:SHA256+BLOCKCHAIN"
            genesis_hash = sha256_string(f"0000000000000000:{genesis_data}:{int(time.time())}")
            db.execute("""
                INSERT INTO blocks (block_index, timestamp, data, prev_hash, block_hash)
                VALUES (0, ?, ?, ?, ?)
            """, (now_iso(), genesis_data,
                  "0000000000000000000000000000000000000000000000000000000000000000",
                  genesis_hash))
            db.commit()
        db.close()

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def now_display():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_string(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def add_block(db, data: str) -> dict:
    with _db_lock:
        row = db.execute("SELECT block_index, block_hash FROM blocks ORDER BY block_index DESC LIMIT 1").fetchone()
        prev_idx  = row["block_index"]
        prev_hash = row["block_hash"]
        new_idx   = prev_idx + 1
        ts        = now_iso()
        new_hash  = sha256_string(f"{prev_hash}:{data}:{ts}")
        db.execute("""
            INSERT INTO blocks (block_index, timestamp, data, prev_hash, block_hash)
            VALUES (?, ?, ?, ?, ?)
        """, (new_idx, ts, data, prev_hash, new_hash))
        db.commit()
        return {"index": new_idx, "hash": new_hash, "prevHash": prev_hash, "timestamp": ts, "data": data}

def add_alert(db, atype: str, message: str):
    db.execute("INSERT INTO alerts (type, message, created_at) VALUES (?, ?, ?)",
               (atype, message, now_display()))
    db.commit()

# ─── CORS (manual, no extra package) ──────────────────────────────────────────
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    return response

@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200

# ─── AUTHENTICATION ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    return jsonify({"logged_in": session.get("logged_in", False)})

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    pwd = data.get("password", "")
    if pwd == ADMIN_PASSWORD:
        session["logged_in"] = True
        return jsonify({"success": True, "message": "Logged in successfully"})
    return jsonify({"success": False, "error": "Invalid password"}), 401

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.pop("logged_in", None)
    return jsonify({"success": True, "message": "Logged out successfully"})

# ─── ROUTES: STATIC ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

# ─── ROUTES: FILES ────────────────────────────────────────────────────────────
@app.route("/api/files", methods=["GET"])
@login_required
def list_files():
    db = get_db()
    rows = db.execute("SELECT * FROM files ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/files/register", methods=["POST"])
@login_required
def register_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    db = get_db()
    original_name = str(f.filename)
    safe_name     = secure_filename(original_name)
    file_data     = f.read()
    file_hash     = str(sha256_bytes(file_data))
    file_size     = len(file_data)

    # Check if already registered
    existing = db.execute(
        "SELECT * FROM files WHERE original_name = ?", (original_name,)
    ).fetchone()

    if existing:
        existing = dict(existing)
        if existing["sha256"] == file_hash:
            # Same hash — re-verified OK
            db.execute("UPDATE files SET last_check=?, status='ok' WHERE original_name=?",
                       (now_display(), original_name))
            db.commit()
            add_alert(db, "ok", f'Re-verified: "{original_name}" — hash matches stored record.')
            return jsonify({
                "action": "reverified",
                "file": dict(db.execute(
                    "SELECT * FROM files WHERE original_name=?", (original_name,)
                ).fetchone())
            })
        else:
            # Hash changed — TAMPER!
            db.execute(
                "UPDATE files SET sha256=?, status='tampered', last_check=? WHERE original_name=?",
                (file_hash, now_display(), original_name)
            )
            db.commit()
            add_alert(db, "bad",
                f'TAMPER DETECTED: "{original_name}" — hash mismatch with stored record!')
            
            orig_name_str = str(original_name)
            file_hash_str = str(file_hash)
            block = add_block(db, f"TAMPER:{orig_name_str[:20]}:{file_hash_str[:12]}")
            return jsonify({
                "action": "tampered",
                "expected": existing["sha256"],
                "computed": file_hash,
                "block": block,
                "file": dict(db.execute(
                    "SELECT * FROM files WHERE original_name=?", (original_name,)
                ).fetchone())
            }), 200

    # New file — save and register
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(save_path, "wb") as out:
        out.write(file_data)

    orig_name_str = str(original_name)
    file_hash_str = str(file_hash)
    block = add_block(db, f"REG:{orig_name_str[:20]}:{file_hash_str[:12]}")
    db.execute("""
        INSERT INTO files (filename, original_name, size, sha256, status, registered, last_check, block_index)
        VALUES (?, ?, ?, ?, 'ok', ?, ?, ?)
    """, (safe_name, original_name, file_size, file_hash,
          now_display(), now_display(), block["index"]))
    db.commit()

    add_alert(db, "ok", f'Registered: "{original_name}" — SHA-256 anchored to block #{block["index"]}.')

    return jsonify({
        "action": "registered",
        "block": block,
        "file": dict(db.execute(
            "SELECT * FROM files WHERE original_name=?", (original_name,)
        ).fetchone())
    }), 201


@app.route("/api/files/<int:file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id):
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not row:
        return jsonify({"error": "File not found"}), 404
    row = dict(row)
    # Delete stored upload
    path = os.path.join(UPLOAD_DIR, row["filename"])
    if os.path.exists(path):
        os.remove(path)
    db.execute("DELETE FROM files WHERE id=?", (file_id,))
    db.commit()
    add_alert(db, "info", f'"{row["original_name"]}" removed from monitoring registry.')
    return jsonify({"deleted": True, "filename": row["original_name"]})


@app.route("/api/files/<int:file_id>/recheck", methods=["POST"])
@login_required
def recheck_file(file_id):
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not row:
        return jsonify({"error": "File not found"}), 404
    row = dict(row)
    saved_path = os.path.join(UPLOAD_DIR, row["filename"])
    if not os.path.exists(saved_path):
        return jsonify({"error": "Stored file missing from server"}), 404

    current_hash = sha256_file(saved_path)
    if current_hash == row["sha256"]:
        status = "ok"
        add_alert(db, "ok", f'Re-check OK: "{row["original_name"]}" — hash matches stored record.')
    else:
        status = "tampered"
        add_alert(db, "bad", f'Re-check ALERT: "{row["original_name"]}" — server-side hash changed!')

    db.execute("UPDATE files SET status=?, last_check=? WHERE id=?",
               (status, now_display(), file_id))
    db.commit()

    updated = dict(db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone())
    return jsonify({"status": status, "file": updated})


# ─── ROUTES: VERIFY ───────────────────────────────────────────────────────────
@app.route("/api/verify", methods=["POST"])
@login_required
def verify_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f         = request.files["file"]
    file_data = f.read()
    computed  = sha256_bytes(file_data)
    name      = f.filename
    db        = get_db()

    existing = db.execute(
        "SELECT * FROM files WHERE original_name=?", (name,)
    ).fetchone()

    if not existing:
        result = "not_registered"
        msg    = f'"{name}" has no stored record. Register it via File Monitor first.'
        db.execute("""INSERT INTO verify_log (filename, computed_hash, stored_hash, result, verified_at)
                      VALUES (?, ?, NULL, ?, ?)""",
                   (name, computed, result, now_display()))
        db.commit()
        return jsonify({"result": result, "computed": computed, "message": msg})

    existing = dict(existing)
    stored   = existing["sha256"]
    if computed == stored:
        result = "ok"
        msg    = f'"{name}" — integrity verified. Hash matches blockchain record.'
        add_alert(db, "ok", f'Verified: "{name}" — authentic, hash matches.')
    else:
        result = "tampered"
        msg    = f'"{name}" — TAMPER DETECTED! Hash does not match blockchain record.'
        add_alert(db, "bad", f'Verify ALERT: "{name}" — hash mismatch, file may have been modified!')
        db.execute("UPDATE files SET status='tampered', last_check=? WHERE original_name=?",
                   (now_display(), name))
        db.commit()

    db.execute("""INSERT INTO verify_log (filename, computed_hash, stored_hash, result, verified_at)
                  VALUES (?, ?, ?, ?, ?)""",
               (name, computed, stored, result, now_display()))
    db.commit()

    return jsonify({
        "result":   result,
        "computed": computed,
        "stored":   stored,
        "message":  msg,
        "file":     existing
    })


@app.route("/api/verify/hash", methods=["GET"])
def lookup_hash():
    h  = request.args.get("hash", "").strip().lower()
    db = get_db()
    if not h:
        return jsonify({"error": "hash param required"}), 400

    file_row  = db.execute("SELECT * FROM files WHERE sha256=?", (h,)).fetchone()
    block_row = db.execute(
        "SELECT * FROM blocks WHERE block_hash=? OR prev_hash=?", (h, h)
    ).fetchone()

    return jsonify({
        "hash":   h,
        "file":   dict(file_row) if file_row else None,
        "block":  dict(block_row) if block_row else None,
        "found":  bool(file_row or block_row)
    })


# ─── ROUTES: BLOCKCHAIN ───────────────────────────────────────────────────────
@app.route("/api/blockchain", methods=["GET"])
def get_blockchain():
    db   = get_db()
    rows = db.execute("SELECT * FROM blocks ORDER BY block_index").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/blockchain/validate", methods=["GET"])
def validate_chain():
    db     = get_db()
    blocks = db.execute("SELECT * FROM blocks ORDER BY block_index").fetchall()
    valid  = True
    broken_at = None

    for i in range(1, len(blocks)):
        blk  = dict(blocks[i])
        prev = dict(blocks[i - 1])
        expected_hash = sha256_string(f"{prev['block_hash']}:{blk['data']}:{blk['timestamp']}")
        if blk["prev_hash"] != prev["block_hash"]:
            valid = False
            broken_at = blk["block_index"]
            break

    return jsonify({
        "valid":      valid,
        "blocks":     len(blocks),
        "broken_at":  broken_at,
        "message":    "Chain is intact." if valid else f"Chain broken at block #{broken_at}!"
    })


# ─── ROUTES: ALERTS ───────────────────────────────────────────────────────────
@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    db   = get_db()
    rows = db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/alerts", methods=["DELETE"])
@login_required
def clear_alerts():
    db = get_db()
    db.execute("DELETE FROM alerts")
    db.commit()
    return jsonify({"cleared": True})


# ─── ROUTES: STATS ────────────────────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
def get_stats():
    db        = get_db()
    total     = db.execute("SELECT COUNT(*) AS c FROM files").fetchone()["c"]
    tampered  = db.execute("SELECT COUNT(*) AS c FROM files WHERE status='tampered'").fetchone()["c"]
    blocks    = db.execute("SELECT COUNT(*) AS c FROM blocks").fetchone()["c"]
    alerts    = db.execute("SELECT COUNT(*) AS c FROM alerts WHERE type='bad'").fetchone()["c"]
    return jsonify({
        "total_files":     total,
        "tampered_files":  tampered,
        "block_count":     blocks,
        "tamper_alerts":   alerts,
        "status":          "TAMPERED" if tampered else "ALL OK"
    })


# ─── ROUTES: VERIFY LOG ───────────────────────────────────────────────────────
@app.route("/api/verify/log", methods=["GET"])
def verify_log():
    db   = get_db()
    rows = db.execute("SELECT * FROM verify_log ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify([dict(r) for r in rows])


# ─── HEALTH ───────────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":    "online",
        "server":    "File Integrity Checker API",
        "version":   "1.0.0",
        "timestamp": now_display()
    })


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
# Ensure uploads directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Always initialize DB (needed for Vercel serverless cold starts)
init_db()

if __name__ == "__main__":
    print("\n" + "═" * 60)
    print("  FILE INTEGRITY CHECKER — Backend Server")
    print("  SHA-256 + Blockchain | Flask + SQLite")
    print("═" * 60)
    print(f"  API  →  http://localhost:5000/api")
    print(f"  UI   →  http://localhost:5000/")
    print(f"  DB   →  {DB_PATH}")
    print(f"  Uploads → {UPLOAD_DIR}")
    print("═" * 60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
