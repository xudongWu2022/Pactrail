"""Signed, least-privilege payment capabilities for Pactrail agents.

Capabilities are HMAC-signed opaque bearer credentials. They are deliberately
not wallet credentials and contain no signing material.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


class CapabilityError(ValueError):
    pass


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def mint_capability(claims: dict[str, Any], secret: str) -> str:
    body = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signature = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"ptr1.{body}.{signature}"


def verify_capability(token: str, secret: str, *, now: int | None = None) -> dict[str, Any]:
    try:
        prefix, body, signature = token.split(".")
        expected = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
        if prefix != "ptr1" or not hmac.compare_digest(signature, expected):
            raise CapabilityError("invalid payment capability")
        claims = json.loads(_unb64(body))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CapabilityError("invalid payment capability") from exc
    if not isinstance(claims, dict) or int(claims.get("exp", 0)) <= int(now or time.time()):
        raise CapabilityError("payment capability is expired")
    return claims


@dataclass(frozen=True)
class PaymentIntent:
    request_id: str
    resource_id: str
    resource_url: str
    session_id: str
    agent_id: str
    budget_id: str
    expires_at: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PaymentIntent":
        return cls(**{key: value.get(key, "") for key in cls.__dataclass_fields__})
