from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Dict, List

import jwt
import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from app.main import create_app


@pytest.fixture()
async def test_client() -> AsyncClient:
	app: FastAPI = create_app()
	async with AsyncClient(app=app, base_url="http://testserver") as client:
		yield client


@pytest.mark.anyio
async def test_jwks_serves_only_non_expired_keys(test_client: AsyncClient):
	res = await test_client.get("/.well-known/jwks.json")
	assert res.status_code == 200
	data: Dict[str, List[dict]] = res.json()
	assert "keys" in data
	# Exactly one active key should be present
	assert isinstance(data["keys"], list)
	assert len(data["keys"]) == 1
	jwk = data["keys"][0]
	assert jwk["kty"] == "RSA"
	assert jwk["alg"] == "RS256"
	assert "kid" in jwk


@pytest.mark.anyio
async def test_auth_issues_valid_token_with_kid(test_client: AsyncClient):
	# Get current JWKS to know the active kid
	jwks_res = await test_client.get("/.well-known/jwks.json")
	active_jwk = jwks_res.json()["keys"][0]
	active_kid = active_jwk["kid"]

	res = await test_client.post("/auth")
	assert res.status_code == 200
	token = res.json()["token"]

	headers = jwt.get_unverified_header(token)
	assert headers["kid"] == active_kid

	# Verify signature using the JWK from the server
	public_key = jwt.algorithms.RSAAlgorithm.from_jwk(active_jwk)
	claims = jwt.decode(token, key=public_key, algorithms=["RS256"])
	assert claims["sub"] == "demo-user"
	assert claims["exp"] > claims["iat"]


@pytest.mark.anyio
async def test_auth_expired_param_uses_expired_key_and_expired_exp(test_client: AsyncClient):
	# First, fetch JWKS and record all available kids
	jwks_res = await test_client.get("/.well-known/jwks.json")
	available_kids = {j["kid"] for j in jwks_res.json()["keys"]}

	res = await test_client.post("/auth", params={"expired": True})
	assert res.status_code == 200
	token = res.json()["token"]

	headers = jwt.get_unverified_header(token)
	expired_kid = headers["kid"]
	# The expired token's kid should not be present in served JWKS
	assert expired_kid not in available_kids

	# Decode without verifying signature to inspect expiration claim
	claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
	exp = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
	assert exp < datetime.now(tz=timezone.utc)
