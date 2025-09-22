# JWKS Server (FastAPI + Python)

A simple educational JWKS server that:

- Serves a JWKS at `/.well-known/jwks.json` containing only non-expired RSA public keys
- Issues JWTs at `/auth` (POST). When `?expired=true` is present, it returns a JWT signed with an expired key and with an expired `exp` claim
- Uses RS256 and includes `kid` in JWT headers

## Requirements

- Python 3.11+

## Setup

```bash
# From the project root
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

- JWKS: `GET http://localhost:8080/.well-known/jwks.json`
- Issue token: `POST http://localhost:8080/auth`
- Issue expired token: `POST http://localhost:8080/auth?expired=true`

## Example

```bash
# Get a token
TOKEN=$(curl -s -X POST http://localhost:8080/auth | jq -r .token)
echo $TOKEN

# Inspect header (should contain a kid)
python - <<'PY'
import jwt, os
hdr = jwt.get_unverified_header(os.environ['TOKEN'])
print(hdr)
PY

# Fetch JWKS
curl -s http://localhost:8080/.well-known/jwks.json | jq
```

## Test client and screenshot

Use the included test client to exercise the server and take a screenshot of the output.

```bash
# Terminal 1: run the server
uvicorn app.main:app --reload --port 8080

# Terminal 2: run the test client (BASE_URL defaults to http://localhost:8080)
python scripts/test_client.py
```

Save a screenshot of the Terminal 2 output to:

- `docs/screenshots/test_client.png`

Then commit it:

```bash
git add docs/screenshots/test_client.png
git commit -m "Add test client screenshot"
```

## Run tests

```bash
pytest -q --maxfail=1 --disable-warnings
```

## Notes

- Keys are generated in-memory on startup: one active key (valid ~1 hour) and one expired key (expired 1 hour ago). JWKS serves only the active, non-expired key. `/auth?expired=true` intentionally uses the expired key and sets an already-expired `exp` claim.
- This is for educational purposes only; do not use in production.
# project-1
