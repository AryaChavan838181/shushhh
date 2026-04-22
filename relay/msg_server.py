"""
shushhh message server — .onion store-and-forward relay

Endpoints:
    POST /drop      — Store encrypted blob for a recipient
    GET  /fetch     — Retrieve pending messages for a recipient tag
    POST /ack       — Confirm delivery, hard-delete message

The server is cryptographically blind — it never holds session keys,
public keys, or usernames. All it sees are opaque ciphertext blobs and 
hashed routing tags.

Storage schema is deliberately disguised as analytics telemetry.
"""

import os
import time
import sqlite3
import uuid
from flask import Flask, request, jsonify, g

app = Flask(__name__)

# ============================================================
# Configuration
# ============================================================

DATABASE = os.environ.get("SHUSHHH_MSGDB", "telemetry.db")
TTL_SECONDS = 7 * 24 * 3600  # 7 days — messages auto-expire

# ============================================================
# Database
# ============================================================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)

    # Disguised as analytics telemetry — plausible deniability
    db.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_events (
            event_id          TEXT PRIMARY KEY,
            device_fingerprint TEXT NOT NULL,
            payload           BLOB NOT NULL,
            ts                INTEGER NOT NULL,
            ttl               INTEGER DEFAULT 604800
        )
    """)

    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_device_fp
        ON telemetry_events(device_fingerprint)
    """)

    db.commit()
    db.close()
    print("[+] Database initialized")

# ============================================================
# Helpers
# ============================================================

def cleanup_expired():
    """Remove messages older than TTL. Called periodically on fetch."""
    db = get_db()
    cutoff = int(time.time()) - TTL_SECONDS
    db.execute("DELETE FROM telemetry_events WHERE ts < ?", (cutoff,))
    db.commit()

# ============================================================
# Endpoints
# ============================================================

@app.route("/drop", methods=["POST"])
def drop():
    """
    Store an encrypted message blob for a recipient.
    Expects: { "tag": "hex_sha256_of_recipient_username", "blob": "encrypted_json" }
    """
    data = request.get_json(silent=True)
    if not data or "tag" not in data or "blob" not in data:
        return jsonify({"status": "error", "message": "missing fields"}), 400

    tag = data["tag"]
    blob = data["blob"]
    event_id = uuid.uuid4().hex
    timestamp = int(time.time())

    db = get_db()
    db.execute(
        "INSERT INTO telemetry_events (event_id, device_fingerprint, payload, ts) "
        "VALUES (?, ?, ?, ?)",
        (event_id, tag, blob, timestamp)
    )
    db.commit()

    return jsonify({"status": "ok", "event_id": event_id})

@app.route("/fetch", methods=["GET"])
def fetch():
    """
    Retrieve pending messages for a recipient tag.
    Expects query param: ?tag=hex_sha256_of_username
    Returns: { "status": "ok", "messages": [ { "event_id": "...", "blob": "..." }, ... ] }
    """
    tag = request.args.get("tag")
    if not tag:
        return jsonify({"status": "error", "message": "missing tag parameter"}), 400

    cleanup_expired()

    db = get_db()
    rows = db.execute(
        "SELECT event_id, payload FROM telemetry_events "
        "WHERE device_fingerprint = ? ORDER BY ts ASC",
        (tag,)
    ).fetchall()

    messages = [{"event_id": row["event_id"], "blob": row["payload"]} for row in rows]

    return jsonify({"status": "ok", "messages": messages})

@app.route("/ack", methods=["POST"])
def ack():
    """
    Confirm delivery — hard-delete a message from the server.
    Expects: { "event_id": "..." }
    """
    data = request.get_json(silent=True)
    if not data or "event_id" not in data:
        return jsonify({"status": "error", "message": "missing event_id"}), 400

    event_id = data["event_id"]

    db = get_db()
    cursor = db.execute(
        "DELETE FROM telemetry_events WHERE event_id = ?", (event_id,)
    )
    db.commit()

    if cursor.rowcount > 0:
        return jsonify({"status": "ok", "message": "deleted"})
    else:
        return jsonify({"status": "ok", "message": "not found"})

if __name__ == "__main__":
    print()
    print("=" * 50)
    print("  shushhh MESSAGE SERVER")
    print("  .onion store-and-forward relay")
    print("=" * 50)
    print()

    init_db()

    print("[+] Starting Msg Server on 127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
