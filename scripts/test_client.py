from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import Dict, List

import jwt
import requests


def get_base_url() -> str:
	base_url = os.environ.get("BASE_URL", "http://localhost:8080").rstrip("/")
	return base_url


def fetch_jwks(base_url: str) -> Dict[str, List[dict]]:
	resp = requests.get(f"{base_url}/.well-known/jwks.json", timeout=10)
	resp.raise_for_status()
	return resp.json()


def request_token(base_url: str, expired: bool = False) -> str:
	resp = requests.post(f"{base_url}/auth", params={"expired": expired}, timeout=10)
	resp.raise_for_status()
	return resp.json()["token"]


def print_header(title: str) -> None:
	print("\n" + "=" * 80)
	print(title)
	print("=" * 80)


def main() -> int:
	base_url = get_base_url()
	print_header(f"JWKS Test Client → {base_url}")

	# 1) Fetch JWKS
	jwks = fetch_jwks(base_url)
	kids = [k.get("kid") for k in jwks.get("keys", [])]
	print(f"JWKS keys: {len(kids)} available")
	for i, kid in enumerate(kids, start=1):
		print(f"  {i}. kid={kid}")

	# 2) Request normal token
	print_header("Issuing normal token (/auth)")
	normal_token = request_token(base_url, expired=False)
	norm_hdr = jwt.get_unverified_header(normal_token)
	print(f"Header: kid={norm_hdr.get('kid')}, alg={norm_hdr.get('alg')}")

	# Verify signature using JWKS
	matching = [k for k in jwks.get("keys", []) if k.get("kid") == norm_hdr.get("kid")]
	if not matching:
		print("ERROR: normal token kid not found in JWKS")
		return 2
	public_key = jwt.algorithms.RSAAlgorithm.from_jwk(matching[0])
	claims = jwt.decode(normal_token, key=public_key, algorithms=["RS256"])
	print(f"Claims: sub={claims.get('sub')}, exp={claims.get('exp')} (valid)")

	# 3) Request expired token
	print_header("Issuing EXPIRED token (/auth?expired=true)")
	expired_token = request_token(base_url, expired=True)
	exp_hdr = jwt.get_unverified_header(expired_token)
	print(f"Header: kid={exp_hdr.get('kid')}, alg={exp_hdr.get('alg')}")

	# The expired token's kid should NOT be in JWKS
	in_jwks = exp_hdr.get("kid") in kids
	print(f"Expired token kid present in JWKS? {in_jwks}")

	# Decode without verification to inspect exp
	exp_claims = jwt.decode(expired_token, options={"verify_signature": False, "verify_exp": False})
	exp_time = datetime.fromtimestamp(exp_claims["exp"], tz=timezone.utc)
	print(f"Expired token exp: {exp_time.isoformat()} (now: {datetime.now(timezone.utc).isoformat()})")

	print("\nSUCCESS: test client ran end-to-end. Take a screenshot of this output.")
	return 0


if __name__ == "__main__":
	sys.exit(main())
