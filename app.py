from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import base64
import uuid
import time

app = Flask(__name__)

# Make two keys so one can be used as an expired key for testing.
def make_key(expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    if expired:
        expires = int(time.time()) - 3600
    else:
        expires = int(time.time()) + 3600

    return {
        "kid": str(uuid.uuid4()),
        "private": private_key,
        "expires": expires
    }


keys = [
    make_key(expired=False),
    make_key(expired=True)
]


def int_to_base64(value):
    # JWK uses base64url for RSA numbers.
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


def public_jwk(key):
    public_numbers = key["private"].public_key().public_numbers()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": key["kid"],
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e)
    }


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    now = int(time.time())

    public_keys = [
        public_jwk(key)
        for key in keys
        if key["expires"] > now
    ]

    return jsonify({"keys": public_keys}), 200


@app.route("/auth", methods=["POST"])
def auth():
    use_expired = "expired" in request.args

    if use_expired:
        key = next((key for key in keys if key["expires"] <= int(time.time())), None)
    else:
        key = next((key for key in keys if key["expires"] > int(time.time())), None)

    if key is None:
        return jsonify({"error": "No matching key available"}), 500

    payload = {
        "sub": "test-user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }

    token = jwt.encode(
        payload,
        key["private"],
        algorithm="RS256",
        headers={"kid": key["kid"]}
    )

    return jsonify({"token": token}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
