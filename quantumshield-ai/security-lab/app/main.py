"""
QuantumShield AI — Intentionally Vulnerable Security Lab Application
WARNING: This application is DELIBERATELY INSECURE for security testing demonstration.
         It contains ONLY fake data and ONLY runs in a controlled lab environment.
         NEVER deploy this in production or expose it to the internet.
"""
import os
import sqlite3
import jwt
import json
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# VULN: Overly permissive CORS
import tempfile

DB_PATH = os.environ.get("LAB_DB_PATH", os.path.join(tempfile.gettempdir(), "lab.db"))
SECRET_KEY = "weak-lab-secret-123"  # VULN: Weak JWT secret
ADMIN_SECRET = "admin-lab-secret"

# ─── Database Setup ──────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    cur = db.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        balance REAL DEFAULT 0.0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT DEFAULT 'pending',
        secret_notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        category TEXT
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS crypto_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_type TEXT,
        algorithm TEXT,
        key_size INTEGER,
        public_key TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    db.commit()

    # Seed data
    users = [
        ("alice", "alice@lab.local", generate_password_hash("Alice@123"), "user", 1500.00),
        ("bob", "bob@lab.local", generate_password_hash("Bob@456"), "user", 750.00),
        ("charlie", "charlie@lab.local", generate_password_hash("Charlie@789"), "user", 2000.00),
        ("admin", "admin@lab.local", generate_password_hash("Admin@lab2024"), "admin", 0.00),
    ]
    for u in users:
        try:
            cur.execute(
                "INSERT INTO users (username, email, password_hash, role, balance) VALUES (?,?,?,?,?)", u
            )
        except sqlite3.IntegrityError:
            pass

    orders_data = [
        (1, "Laptop Pro X1", 1299.99, "completed", "Alice's confidential order note"),
        (1, "Wireless Keyboard", 79.99, "shipped", "Alice's second order note"),
        (2, "USB-C Hub", 45.99, "pending", "Bob's private order note"),
        (3, "Monitor 4K", 599.99, "completed", "Charlie's order details"),
    ]
    for o in orders_data:
        try:
            cur.execute(
                "INSERT OR IGNORE INTO orders (user_id, product, amount, status, secret_notes) VALUES (?,?,?,?,?)", o
            )
        except Exception:
            pass

    products_data = [
        ("Laptop Pro X1", "High-performance laptop", 1299.99, "Electronics"),
        ("Wireless Keyboard", "Mechanical keyboard", 79.99, "Accessories"),
        ("USB-C Hub", "7-in-1 USB hub", 45.99, "Accessories"),
        ("Monitor 4K", "27-inch 4K display", 599.99, "Electronics"),
        ("Headphones", "Noise-cancelling", 199.99, "Audio"),
    ]
    for p in products_data:
        try:
            cur.execute("INSERT OR IGNORE INTO products (name, description, price, category) VALUES (?,?,?,?)", p)
        except Exception:
            pass

    # Crypto key metadata (demo only - these are NOT real private keys)
    crypto_data = [
        ("rsa", "RSA", 2048, "MIIBIjANBgkq...FAKE_PUBLIC_KEY_RSA_2048..."),
        ("ecc", "ECDSA-P256", 256, "MFkwEwYH...FAKE_PUBLIC_KEY_ECC_P256..."),
        ("rsa_weak", "RSA", 512, "MFwwDQYJ...FAKE_WEAK_RSA_512_KEY..."),  # VULN: Weak RSA
    ]
    for c in crypto_data:
        try:
            cur.execute("INSERT OR IGNORE INTO crypto_keys (key_type, algorithm, key_size, public_key) VALUES (?,?,?,?)", c)
        except Exception:
            pass

    db.commit()
    db.close()

# ─── Auth Helpers ────────────────────────────────────────────────────────────

def create_token(user_id: int, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow(),
    }
    # VULN: Uses HS256 with weak secret; no token revocation
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            # VULN: Also checks cookie (insecure)
            token = request.cookies.get("auth_token", "")
        if not token:
            return jsonify({"error": "Missing token"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.current_user_id = int(data["sub"])
            g.current_user_role = data.get("role", "user")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

# ─── Health ──────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "vulnerable-lab", "timestamp": datetime.utcnow().isoformat()})

# ─── IP Header Analysis (for spoofed-header detection testing) ───────────────

_request_log: list = []  # in-memory ring buffer — last 200 requests

@app.before_request
def _log_request_headers():
    """Log every request's IP-related headers for detection testing."""
    entry = {
        "ts": datetime.utcnow().isoformat(),
        "method": request.method,
        "path": request.path,
        "remote_addr": request.remote_addr,
        "x_forwarded_for": request.headers.get("X-Forwarded-For"),
        "x_real_ip": request.headers.get("X-Real-IP"),
        "true_client_ip": request.headers.get("True-Client-IP"),
        "cf_connecting_ip": request.headers.get("CF-Connecting-IP"),
        "x_originating_ip": request.headers.get("X-Originating-IP"),
        "user_agent": request.headers.get("User-Agent", "")[:120],
        "detected_spoof": False,
    }
    # Simple spoof detection: remote_addr is loopback but X-Forwarded-For is routable
    xff = entry["x_forwarded_for"] or ""
    if entry["remote_addr"] in ("127.0.0.1", "::1") and xff and not xff.startswith("127."):
        entry["detected_spoof"] = True
    _request_log.append(entry)
    if len(_request_log) > 200:
        _request_log.pop(0)

@app.route("/api/ip-log")
def ip_log():
    """Return the last N request IP logs — exposes whether spoofed headers were detected."""
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({
        "logs": list(reversed(_request_log[-limit:])),
        "total_requests": len(_request_log),
        "spoofed_count": sum(1 for r in _request_log if r["detected_spoof"]),
        "note": "VULN: This endpoint is unauthenticated — request logs exposed to anyone",
    })

@app.route("/api/ip-log/clear", methods=["POST"])
def clear_ip_log():
    _request_log.clear()
    return jsonify({"cleared": True})

# ─── Metadata Endpoints (for recon/tech discovery) ───────────────────────────

@app.route("/api/info")
def app_info():
    # VULN: Information disclosure
    return jsonify({
        "app": "VulnShop Lab",
        "version": "1.0.0",
        "framework": "Flask 3.0",
        "database": "SQLite",
        "debug": True,  # VULN: debug mode exposed
        "server": "Werkzeug/3.0",
        "python": "3.11",
    })

@app.route("/api/crypto/config")
def crypto_config():
    # VULN: Exposes cryptographic configuration
    db = get_db()
    keys = db.execute("SELECT id, key_type, algorithm, key_size, created_at FROM crypto_keys").fetchall()
    return jsonify({
        "tls": {
            "version": "TLSv1.2",
            "cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES256-GCM-SHA384"],
            "certificate": {"algorithm": "RSA", "key_size": 2048, "signature": "SHA256withRSA"},
        },
        "jwt": {"algorithm": "HS256", "secret_length": len(SECRET_KEY), "expiry_hours": 24},
        "keys": [dict(k) for k in keys],
        "session": {"mechanism": "JWT", "httponly": False, "secure": False, "samesite": None},
        "hashing": {"passwords": "bcrypt", "data": "SHA-1"},  # VULN: SHA-1 for data
    })

# ─── Auth Endpoints ───────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def login():
    # VULN: No rate limiting
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()
    # VULN: Username enumeration - different messages for unknown vs wrong password
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404  # VULN: reveals username existence

    if not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Incorrect password"}), 401  # VULN: different message

    token = create_token(user["id"], user["role"])
    # VULN: Token in response body AND cookie with no security flags
    resp = jsonify({
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"], "email": user["email"]},
        "message": "Login successful"
    })
    resp.set_cookie("auth_token", token, httponly=False, secure=False, samesite=None)  # VULN: insecure cookie
    return resp

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")
    role = data.get("role", "user")  # VULN: Mass assignment - user can set their own role

    if not username or not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
            (username, email, generate_password_hash(password), role)
        )
        db.commit()
        return jsonify({"message": "User created", "role": role}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409

@app.route("/api/auth/me")
@token_required
def me():
    db = get_db()
    user = db.execute("SELECT id, username, email, role, balance FROM users WHERE id=?", (g.current_user_id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(user))

# ─── Orders Endpoints (IDOR Vulnerable) ──────────────────────────────────────

@app.route("/api/orders", methods=["GET"])
@token_required
def get_my_orders():
    db = get_db()
    orders = db.execute(
        "SELECT * FROM orders WHERE user_id=?", (g.current_user_id,)
    ).fetchall()
    return jsonify([dict(o) for o in orders])

@app.route("/api/orders/<int:order_id>", methods=["GET"])
@token_required
def get_order(order_id):
    db = get_db()
    # VULN: IDOR - checks auth but NOT ownership. Any authenticated user can access any order.
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        return jsonify({"error": "Order not found"}), 404
    # Missing: if order["user_id"] != g.current_user_id: return 403
    return jsonify(dict(order))

@app.route("/api/orders/<int:order_id>", methods=["PUT"])
@token_required
def update_order(order_id):
    db = get_db()
    # VULN: IDOR on write - user can update any order
    data = request.get_json() or {}
    db.execute(
        "UPDATE orders SET status=? WHERE id=?",
        (data.get("status", "pending"), order_id)
    )
    db.commit()
    return jsonify({"message": "Order updated"})

# ─── Admin Endpoints (Missing AuthZ) ─────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
@token_required
def admin_users():
    # VULN: Checks auth (token required) but does NOT check admin role
    # Any authenticated user can access admin endpoints
    db = get_db()
    users = db.execute("SELECT id, username, email, role, balance, created_at FROM users").fetchall()
    return jsonify([dict(u) for u in users])

@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@token_required
def admin_delete_user(user_id):
    # VULN: Missing authorization check
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    return jsonify({"message": "User deleted"})

@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    # VULN: No auth required at all
    db = get_db()
    user_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    order_count = db.execute("SELECT COUNT(*) as c FROM orders").fetchone()["c"]
    return jsonify({"users": user_count, "orders": order_count, "server_time": datetime.utcnow().isoformat()})

# ─── Products Endpoint (SQL Injection) ───────────────────────────────────────

@app.route("/api/products", methods=["GET"])
def get_products():
    search = request.args.get("search", "")
    db = get_db()
    # VULN: SQL Injection - direct string interpolation
    try:
        query = f"SELECT * FROM products WHERE name LIKE '%{search}%' OR description LIKE '%{search}%'"
        products = db.execute(query).fetchall()
        return jsonify([dict(p) for p in products])
    except Exception as e:
        # VULN: Error disclosure
        return jsonify({"error": str(e), "query": query}), 500

# ─── Search Endpoint (XSS) ───────────────────────────────────────────────────

@app.route("/api/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    # VULN: Reflected XSS - echoes user input without sanitization
    return jsonify({
        "query": q,  # This is reflected without sanitization
        "results": [],
        "message": f"Search results for: {q}"
    })

@app.route("/search")
def search_html():
    q = request.args.get("q", "")
    # VULN: Reflected XSS in HTML response
    return f"""
    <html>
    <head><title>Search</title></head>
    <body>
    <h1>Search Results</h1>
    <p>Results for: {q}</p>
    <form method="GET"><input name="q" value="{q}"><button>Search</button></form>
    </body>
    </html>
    """

# ─── Messages Endpoint (Stored XSS / Injection) ──────────────────────────────

@app.route("/api/messages", methods=["POST"])
@token_required
def post_message():
    data = request.get_json() or {}
    content = data.get("content", "")
    # VULN: Stored XSS - content stored without sanitization
    db = get_db()
    db.execute("INSERT INTO messages (user_id, content) VALUES (?,?)", (g.current_user_id, content))
    db.commit()
    return jsonify({"message": "Posted", "content": content}), 201

@app.route("/api/messages", methods=["GET"])
def get_messages():
    db = get_db()
    msgs = db.execute("SELECT * FROM messages ORDER BY created_at DESC LIMIT 50").fetchall()
    return jsonify([dict(m) for m in msgs])

# ─── File Upload (Path Traversal / Type Bypass) ──────────────────────────────

UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/api/upload", methods=["POST"])
@token_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    file = request.files["file"]
    filename = file.filename  # VULN: No filename sanitization (path traversal risk)
    # VULN: No file type validation, no size limit
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)
    return jsonify({"message": "Uploaded", "filename": filename, "path": filepath})  # VULN: Exposes server path

@app.route("/api/download/<path:filename>")
@token_required
def download_file(filename):
    # VULN: Path traversal - no sanitization of filename
    # VULN: No ownership check - any user can download any file
    filepath = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "rb") as f:
            content = f.read()
        return content, 200
    return jsonify({"error": "File not found"}), 404

# ─── User Profile (IDOR + Mass Assignment) ───────────────────────────────────

@app.route("/api/users/<int:user_id>", methods=["GET"])
@token_required
def get_user_profile(user_id):
    db = get_db()
    # VULN: IDOR - any authenticated user can read any profile
    user = db.execute("SELECT id, username, email, role, balance, created_at FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(user))

@app.route("/api/users/<int:user_id>", methods=["PUT"])
@token_required
def update_user_profile(user_id):
    # VULN: No ownership check - can update any user
    # VULN: Mass assignment - can update sensitive fields like role, balance
    data = request.get_json() or {}
    db = get_db()
    allowed_fields = ["email", "role", "balance"]  # VULN: role and balance shouldn't be user-settable
    updates = {k: v for k, v in data.items() if k in allowed_fields}
    if updates:
        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [user_id]
        db.execute(f"UPDATE users SET {set_clause} WHERE id=?", values)
        db.commit()
    return jsonify({"message": "Profile updated", "updated_fields": list(updates.keys())})

# ─── Rate Limit Test Endpoint (Intentionally Unlimited) ──────────────────────

@app.route("/api/auth/password-reset", methods=["POST"])
def password_reset():
    # VULN: No rate limiting on password reset
    data = request.get_json() or {}
    email = data.get("email", "")
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    # VULN: Reveals whether email exists
    if not user:
        return jsonify({"error": "Email not found"}), 404
    return jsonify({"message": "Reset link sent to " + email})

# ─── Debug Endpoint (Information Disclosure) ─────────────────────────────────

@app.route("/api/debug")
def debug_info():
    # VULN: Debug endpoint exposed
    return jsonify({
        "env": dict(os.environ),  # VULN: Environment variables exposed
        "db_path": DB_PATH,
        "upload_dir": UPLOAD_DIR,
        "secret_key_hint": SECRET_KEY[:8] + "...",
    })

# ─── Cryptographic Metadata Endpoints ────────────────────────────────────────

@app.route("/api/crypto/rsa-demo")
def rsa_demo():
    """Returns metadata about RSA configuration (for quantum demo purposes)"""
    return jsonify({
        "algorithm": "RSA",
        "key_sizes_in_use": [2048, 512],
        "padding": "PKCS1v15",
        "signature_algorithm": "SHA256withRSA",
        "usage": ["key_exchange", "digital_signature"],
        "quantum_vulnerable": True,
        "demo_note": "RSA-2048 is computationally secure against classical attacks. Shor's algorithm on a sufficiently large quantum computer would break it.",
        "factoring_challenge": {
            "n_bits": 2048,
            "classical_best": "GNFS - sub-exponential",
            "quantum_shor": "Polynomial time (future CRQC required)"
        }
    })

@app.route("/api/crypto/ecc-demo")
def ecc_demo():
    """Returns metadata about ECC configuration"""
    return jsonify({
        "algorithm": "ECDSA",
        "curve": "P-256",
        "key_size_bits": 256,
        "usage": ["tls_auth", "jwt_signing"],
        "quantum_vulnerable": True,
        "demo_note": "ECDSA P-256 is secure against classical attacks. Shor's algorithm applied to the Elliptic Curve Discrete Log Problem (ECDLP) would break it.",
        "ecdlp_challenge": {
            "curve": "secp256r1 (P-256)",
            "classical_best": "BSGS / Pollard rho - exponential",
            "quantum_shor": "Polynomial time (future CRQC required)"
        }
    })

@app.route("/api/crypto/aes-demo")
def aes_demo():
    """Returns metadata about symmetric encryption configuration"""
    return jsonify({
        "algorithm": "AES",
        "mode": "GCM",
        "key_sizes_in_use": [128, 256],
        "usage": ["data_encryption", "session_encryption"],
        "quantum_vulnerable_to_grover": True,
        "demo_note": "AES-128 has ~2^64 quantum queries under Grover. AES-256 has ~2^128 quantum queries. AES-256 is generally considered quantum-safe.",
        "grover_analysis": {
            "aes_128": {"classical_security": 128, "quantum_security_bits": 64, "recommendation": "Migrate to AES-256"},
            "aes_256": {"classical_security": 256, "quantum_security_bits": 128, "recommendation": "Sufficient"}
        }
    })

# ─── JWT Weak Secret Demo ────────────────────────────────────────────────────

@app.route("/api/auth/verify-token", methods=["POST"])
def verify_token():
    """Verifies a JWT token - intentionally uses weak secret"""
    data = request.get_json() or {}
    token = data.get("token", "")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"valid": True, "payload": payload})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})

# ─── CORS Test Endpoint ───────────────────────────────────────────────────────

@app.route("/api/cors-test", methods=["GET", "OPTIONS"])
def cors_test():
    # VULN: Reflects Origin header with credentials allowed
    origin = request.headers.get("Origin", "*")
    resp = jsonify({"cors": "vulnerable", "reflected_origin": origin, "credentials": True})
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

# ─── Missing Security Headers ─────────────────────────────────────────────────

@app.after_request
def add_missing_security_headers(response):
    # VULN: Intentionally NOT adding security headers
    # Missing: X-Frame-Options, X-Content-Type-Options, CSP, HSTS, etc.
    response.headers["Server"] = "Werkzeug/3.0.3 Python/3.11"  # VULN: Server banner disclosure
    return response

# ─── Sitemap (for recon) ─────────────────────────────────────────────────────

@app.route("/api/sitemap")
def sitemap():
    """Intentionally exposes site structure for testing recon"""
    return jsonify({
        "endpoints": [
            {"path": "/health", "methods": ["GET"], "auth": False},
            {"path": "/api/info", "methods": ["GET"], "auth": False},
            {"path": "/api/auth/login", "methods": ["POST"], "auth": False},
            {"path": "/api/auth/register", "methods": ["POST"], "auth": False},
            {"path": "/api/auth/me", "methods": ["GET"], "auth": True},
            {"path": "/api/auth/password-reset", "methods": ["POST"], "auth": False},
            {"path": "/api/auth/verify-token", "methods": ["POST"], "auth": False},
            {"path": "/api/orders", "methods": ["GET"], "auth": True},
            {"path": "/api/orders/<id>", "methods": ["GET", "PUT"], "auth": True, "vuln": "IDOR"},
            {"path": "/api/admin/users", "methods": ["GET"], "auth": True, "vuln": "Missing AuthZ"},
            {"path": "/api/admin/users/<id>", "methods": ["DELETE"], "auth": True, "vuln": "Missing AuthZ"},
            {"path": "/api/admin/stats", "methods": ["GET"], "auth": False, "vuln": "Missing Auth"},
            {"path": "/api/products", "methods": ["GET"], "auth": False, "vuln": "SQL Injection"},
            {"path": "/api/search", "methods": ["GET"], "auth": False, "vuln": "XSS"},
            {"path": "/search", "methods": ["GET"], "auth": False, "vuln": "Reflected XSS"},
            {"path": "/api/messages", "methods": ["GET", "POST"], "auth": "POST only"},
            {"path": "/api/upload", "methods": ["POST"], "auth": True, "vuln": "Path Traversal"},
            {"path": "/api/download/<filename>", "methods": ["GET"], "auth": True, "vuln": "Path Traversal"},
            {"path": "/api/users/<id>", "methods": ["GET", "PUT"], "auth": True, "vuln": "IDOR+MassAssignment"},
            {"path": "/api/crypto/config", "methods": ["GET"], "auth": False, "vuln": "Info Disclosure"},
            {"path": "/api/crypto/rsa-demo", "methods": ["GET"], "auth": False},
            {"path": "/api/crypto/ecc-demo", "methods": ["GET"], "auth": False},
            {"path": "/api/crypto/aes-demo", "methods": ["GET"], "auth": False},
            {"path": "/api/debug", "methods": ["GET"], "auth": False, "vuln": "Info Disclosure"},
            {"path": "/api/cors-test", "methods": ["GET"], "auth": False, "vuln": "Insecure CORS"},
            {"path": "/api/sitemap", "methods": ["GET"], "auth": False},
        ]
    })

# ─── Known Vulnerabilities (for demo precision/recall metrics) ────────────────

@app.route("/api/known-vulnerabilities")
def known_vulnerabilities():
    """Returns list of known vulnerabilities for demo scoring"""
    return jsonify({
        "vulnerabilities": [
            {"id": "VULN-001", "type": "IDOR", "severity": "HIGH", "endpoint": "/api/orders/<id>"},
            {"id": "VULN-002", "type": "IDOR", "severity": "HIGH", "endpoint": "/api/users/<id>"},
            {"id": "VULN-003", "type": "MISSING_AUTHZ", "severity": "HIGH", "endpoint": "/api/admin/users"},
            {"id": "VULN-004", "type": "MISSING_AUTH", "severity": "HIGH", "endpoint": "/api/admin/stats"},
            {"id": "VULN-005", "type": "SQL_INJECTION", "severity": "CRITICAL", "endpoint": "/api/products"},
            {"id": "VULN-006", "type": "XSS", "severity": "MEDIUM", "endpoint": "/search"},
            {"id": "VULN-007", "type": "WEAK_CORS", "severity": "MEDIUM", "endpoint": "/*"},
            {"id": "VULN-008", "type": "MISSING_SECURITY_HEADERS", "severity": "LOW", "endpoint": "/*"},
            {"id": "VULN-009", "type": "INSECURE_COOKIE", "severity": "MEDIUM", "endpoint": "/api/auth/login"},
            {"id": "VULN-010", "type": "INFO_DISCLOSURE", "severity": "MEDIUM", "endpoint": "/api/debug"},
            {"id": "VULN-011", "type": "WEAK_CRYPTO", "severity": "HIGH", "endpoint": "/api/crypto/config"},
            {"id": "VULN-012", "type": "USERNAME_ENUMERATION", "severity": "LOW", "endpoint": "/api/auth/login"},
            {"id": "VULN-013", "type": "MASS_ASSIGNMENT", "severity": "HIGH", "endpoint": "/api/users/<id>"},
            {"id": "VULN-014", "type": "NO_RATE_LIMITING", "severity": "MEDIUM", "endpoint": "/api/auth/login"},
        ]
    })

# ─── App Init ────────────────────────────────────────────────────────────────

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
