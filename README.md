# Basic JWKS Server

This project is a small JWKS server made with Python and Flask.

## What it does

- Creates RSA key pairs.
- Gives each key a unique `kid`.
- Gives keys expiration times.
- Provides a JWKS endpoint with only unexpired public keys.
- Provides a POST `/auth` endpoint that returns a JWT.
- Supports `/auth?expired=true` to create a JWT using the expired key.
- Includes tests and code coverage.

## Requirements

Python 3.10 or newer is recommended.

Install the packages with:

```text
pip install -r requirements.txt
```

## Run the server

```text
python app.py
```

The server runs on port 8080.

## Test the endpoints

Normal JWT:

```text
curl -X POST http://localhost:8080/auth
```

Expired JWT:

```text
curl -X POST "http://localhost:8080/auth?expired=true"
```

JWKS:

```text
curl http://localhost:8080/.well-known/jwks.json
```

## Run tests

```text
pytest
```

## Check coverage

```text
coverage run -m pytest
coverage report
```

The included tests cover the main key and endpoint behavior and are intended to meet the assignment's 80% coverage requirement.

## Notes

This is an educational project. The `/auth` endpoint does not perform real user authentication because the assignment says authentication is being mocked.
