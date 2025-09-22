from __future__ import annotations

import base64
import json
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE64URL_NO_PAD_ALPHABET = b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"


def _int_to_bytes(value: int) -> bytes:
	"""Convert a positive integer to big-endian bytes without leading zeros."""
	if value == 0:
		return b"\x00"
	length = (value.bit_length() + 7) // 8
	return value.to_bytes(length, "big")


def _b64url_encode(data: bytes) -> str:
	"""Base64url encode without padding, per JWK/JWT specs."""
	return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class RsaKeyRecord:
	"""Holds one RSA key pair and metadata.

	- kid: unique key id for JWKS discovery and JWT header use
	- expires_at: UTC time the key should be considered expired
	"""
	kid: str
	private_key: rsa.RSAPrivateKey
	public_key: rsa.RSAPublicKey
	expires_at: datetime

	def is_expired(self, now: Optional[datetime] = None) -> bool:
		now = now or datetime.now(timezone.utc)
		return now >= self.expires_at

	def to_public_jwk(self) -> Dict[str, str]:
		"""Return a minimal RS256 JWK for the public key."""
		numbers = self.public_key.public_numbers()
		e_b64 = _b64url_encode(_int_to_bytes(numbers.e))
		n_b64 = _b64url_encode(_int_to_bytes(numbers.n))
		return {
			"kty": "RSA",
			"kid": self.kid,
			"use": "sig",
			"alg": "RS256",
			"e": e_b64,
			"n": n_b64,
		}

	def private_pem(self) -> bytes:
		return self.private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption(),
		)


class KeyStore:
	"""In-memory key store with one active and one expired key for the assignment.

	This is intentionally simple: it creates one non-expired (active) key and one
	expired key on startup. The JWKS endpoint serves only non-expired keys. The
	/auth endpoint can issue tokens with either the active key or the expired key
	when `expired=true` is requested.
	"""

	def __init__(self, active_lifetime: timedelta = timedelta(hours=1)) -> None:
		self._lock = threading.RLock()
		self._active_lifetime = active_lifetime
		self._active_key: Optional[RsaKeyRecord] = None
		self._expired_key: Optional[RsaKeyRecord] = None
		self._initialize_keys()

	def _initialize_keys(self) -> None:
		with self._lock:
			now = datetime.now(timezone.utc)
			# Create an expired key that expired 1 hour ago
			expired_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
			expired_pub = expired_priv.public_key()
			expired_record = RsaKeyRecord(
				kid=str(uuid.uuid4()),
				private_key=expired_priv,
				public_key=expired_pub,
				expires_at=now - timedelta(hours=1),
			)

			# Create a fresh active key valid for the configured lifetime
			active_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
			active_pub = active_priv.public_key()
			active_record = RsaKeyRecord(
				kid=str(uuid.uuid4()),
				private_key=active_priv,
				public_key=active_pub,
				expires_at=now + self._active_lifetime,
			)

			self._expired_key = expired_record
			self._active_key = active_record

	def get_active_key(self) -> RsaKeyRecord:
		with self._lock:
			assert self._active_key is not None
			# If the active key has expired, rotate to a new one so the service keeps working
			if self._active_key.is_expired():
				self._expired_key = self._active_key
				new_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
				new_pub = new_priv.public_key()
				self._active_key = RsaKeyRecord(
					kid=str(uuid.uuid4()),
					private_key=new_priv,
					public_key=new_pub,
					expires_at=datetime.now(timezone.utc) + self._active_lifetime,
				)
			return self._active_key

	def get_expired_key(self) -> RsaKeyRecord:
		with self._lock:
			assert self._expired_key is not None
			return self._expired_key

	def list_public_jwks(self) -> Dict[str, List[Dict[str, str]]]:
		"""Return JWKS with only non-expired keys."""
		now = datetime.now(timezone.utc)
		keys: List[Dict[str, str]] = []
		with self._lock:
			if self._active_key and not self._active_key.is_expired(now):
				keys.append(self._active_key.to_public_jwk())
			# self._expired_key is not included intentionally
		return {"keys": keys}

	def select_key(self, use_expired: bool) -> RsaKeyRecord:
		return self.get_expired_key() if use_expired else self.get_active_key()
