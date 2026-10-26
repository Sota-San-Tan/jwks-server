import time
import sqlite3
import jwt
from cryptography.hazmat.primitives import serialization
from app import app, DB_FILE


def test_jwks_only_has_unexpired_keys():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()
    assert "keys" in data
    assert len(data["keys"]) >= 1

    now = int(time.time())
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT kid FROM keys WHERE exp <= ?", (now,))
    expired_rows = cursor.fetchall()
    conn.close()

    expired_kids = {str(row["kid"]) for row in expired_rows}
    for k in data["keys"]:
        assert k["kid"] not in expired_kids


def test_auth_returns_token():
    client = app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200

    data = response.get_json()
    assert "token" in data

    header = jwt.get_unverified_header(data["token"])
    assert "kid" in header


def test_auth_with_json_payload():
    client = app.test_client()
    response = client.post(
        "/auth", json={"username": "userABC", "password": "password123"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "token" in data


def test_auth_uses_unexpired_key():
    client = app.test_client()

    response = client.post("/auth")
    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)

    now = int(time.time())
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT kid FROM keys WHERE kid = ? AND exp > ?",
        (int(header["kid"]), now),
    )
    row = cursor.fetchone()
    conn.close()

    assert row is not None


def test_expired_parameter_uses_expired_key():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)

    now = int(time.time())
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT kid FROM keys WHERE kid = ? AND exp <= ?",
        (int(header["kid"]), now),
    )
    row = cursor.fetchone()
    conn.close()

    assert row is not None


def test_jwt_can_be_decoded_with_matching_key():
    client = app.test_client()

    response = client.post("/auth")
    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT key FROM keys WHERE kid = ?", (int(header["kid"]),))
    row = cursor.fetchone()
    conn.close()

    priv_key = serialization.load_pem_private_key(row["key"], password=None)

    payload = jwt.decode(
        token, priv_key.public_key(), algorithms=["RS256"]
    )

    assert payload["sub"] == "test-user"


def test_unknown_route_returns_404():
    client = app.test_client()

    response = client.get("/does-not-exist")

    assert response.status_code == 404
