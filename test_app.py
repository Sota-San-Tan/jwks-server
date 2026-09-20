import time
import jwt
from app import app, keys


def test_jwks_only_has_unexpired_keys():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()
    assert "keys" in data
    assert len(data["keys"]) == 1

    expired_key = next(key for key in keys if key["expires"] <= int(time.time()))
    assert data["keys"][0]["kid"] != expired_key["kid"]


def test_auth_returns_token():
    client = app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200

    data = response.get_json()
    assert "token" in data

    header = jwt.get_unverified_header(data["token"])
    assert "kid" in header


def test_auth_uses_unexpired_key():
    client = app.test_client()

    response = client.post("/auth")
    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)

    current_key = next(key for key in keys if key["expires"] > int(time.time()))
    assert header["kid"] == current_key["kid"]


def test_expired_parameter_uses_expired_key():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)

    expired_key = next(key for key in keys if key["expires"] <= int(time.time()))
    assert header["kid"] == expired_key["kid"]


def test_jwt_can_be_decoded_with_matching_key():
    client = app.test_client()

    response = client.post("/auth")
    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)

    current_key = next(
        key for key in keys
        if key["kid"] == header["kid"]
    )

    payload = jwt.decode(
        token,
        current_key["private"].public_key(),
        algorithms=["RS256"]
    )

    assert payload["sub"] == "test-user"


def test_unknown_route_returns_404():
    client = app.test_client()

    response = client.get("/does-not-exist")

    assert response.status_code == 404
