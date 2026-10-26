from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import base64
import time
import sqlite3
import os

app = Flask(__name__)

DB_FILE = "totally_not_my_privateKeys.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()

    # Check if keys exist, if not, generate and insert expired and unexpired keys
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]
    if count == 0:
        # Insert expired key
        expired_priv = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        expired_pem = expired_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        expired_exp = int(time.time()) - 3600
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (expired_pem, expired_exp),
        )

        # Insert unexpired key
        valid_priv = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        valid_pem = valid_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        valid_exp = int(time.time()) + 3600
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)", (valid_pem, valid_exp)
        )

        conn.commit()
    conn.close()


init_db()


def int_to_base64(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


def public_jwk(kid, private_key):
    public_numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": str(kid),
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    now = int(time.time())
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Using parameterized query to prevent SQL injection
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (now,))
    rows = cursor.fetchall()
    conn.close()

    public_keys = []
    for row in rows:
        priv_key = serialization.load_pem_private_key(row["key"], password=None)
        public_keys.append(public_jwk(row["kid"], priv_key))

    return jsonify({"keys": public_keys}), 200


@app.route("/auth", methods=["POST"])
def auth():
    # Handle mock authentication payloads/requests gracefully
    request.get_json(silent=True)

    use_expired = "expired" in request.args
    now = int(time.time())

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Using parameterized queries to prevent SQL injection
    if use_expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (now,)
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (now,)
        )

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return jsonify({"error": "No matching key available"}), 500

    priv_key = serialization.load_pem_private_key(row["key"], password=None)
    kid = row["kid"]

    payload = {"sub": "test-user", "iat": now, "exp": now + 3600}

    token = jwt.encode(
        payload, priv_key, algorithm="RS256", headers={"kid": str(kid)}
    )

    return jsonify({"token": token}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
