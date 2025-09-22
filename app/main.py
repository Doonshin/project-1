from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from .keys import KeyStore


def create_app() -> FastAPI:
	app = FastAPI(title="JWKS Server", version="1.0.0")
	app.state.key_store = KeyStore()

	@app.get("/", tags=["meta"])
	def health() -> Dict[str, str]:
		return {"status": "ok"}

	@app.get("/.well-known/jwks.json", tags=["jwks"])
	def jwks() -> JSONResponse:
		store: KeyStore = app.state.key_store
		return JSONResponse(store.list_public_jwks())

	@app.post("/auth", tags=["auth"])
	def issue_token(expired: bool = Query(default=False, description="Issue JWT with expired key and expiry when true")) -> Dict[str, str]:
		store: KeyStore = app.state.key_store
		key = store.select_key(use_expired=expired)

		now = datetime.now(timezone.utc)
		if expired:
			exp = key.expires_at  # already in the past by construction
			# ensure the exp is strictly in the past
			if exp >= now:
				exp = now - timedelta(seconds=5)
		else:
			# Token should not outlive the key
			default_lifetime = timedelta(minutes=15)
			exp = min(now + default_lifetime, key.expires_at)

		payload: Dict[str, Any] = {
			"sub": "demo-user",
			"iat": int(now.timestamp()),
			"exp": int(exp.timestamp()),
		}

		try:
			token = jwt.encode(payload, key.private_pem(), algorithm="RS256", headers={"kid": key.kid})
		except Exception as exc:  # pragma: no cover - defensive
			raise HTTPException(status_code=500, detail=f"Failed to sign token: {exc}")

		return {"token": token}

	return app


app = create_app()


if __name__ == "__main__":
	import uvicorn

	uvicorn.run("app.main:app", host="0.0.0.0", port=8080, reload=True)
