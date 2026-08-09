"""Production boundary for an external x402 signer adapter.

Run this adapter in the wallet-controlled process, not in an Agent runtime.
The adapter fetches the canonical approval from its configured Pactrail Gateway,
checks the request body hash, and submits the payment signature directly to the
Gateway. The Agent never sees either the signer token or payment signature.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from typing import Any, Callable

from .client import PactrailError, SignerApprovalRequest


class PactrailSignerAdapter:
    def __init__(self, gateway_url: str, signer_id: str, signer_token: str):
        self.gateway_url = gateway_url.rstrip("/")
        self.signer_id = signer_id
        self.signer_token = signer_token

    def _request(self, path: str, *, body: bytes | None = None, headers: dict[str, str] | None = None):
        request = urllib.request.Request(
            self.gateway_url + path, data=body,
            headers={"authorization": f"Bearer {self.signer_token}", **(headers or {})},
            method="POST" if body is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response, response.read()
        except urllib.error.HTTPError as exc:
            raise PactrailError(f"signer adapter received {exc.code}: {exc.read().decode('utf-8', 'replace')}") from exc

    def sign_and_submit(self, approval: SignerApprovalRequest, payload: bytes,
                        sign_payment: Callable[[dict[str, Any]], str],
                        *, protocol_headers: dict[str, str] | None = None) -> tuple[dict, str]:
        """Claim a canonical approval, sign only it, and submit directly to Pactrail."""
        response, raw = self._request(f"/signer-approvals/{approval.approval_id}")
        claimed = json.loads(raw)
        if claimed.get("signer_id") != self.signer_id or claimed.get("request_id") != approval.request_id:
            raise PactrailError("signer approval is not bound to this signer or request")
        if claimed.get("body_sha256") != hashlib.sha256(payload).hexdigest():
            raise PactrailError("request body does not match the approved signer request")
        payment = sign_payment(claimed["requirements"])
        extras = {str(key).lower(): str(value) for key, value in (protocol_headers or {}).items()}
        forbidden = {"authorization", "payment-signature", "x-payment", "x-agent-id", "x-budget-id", "x-session-id", "x-request-id", "x-pactrail-signer-approval"}
        if forbidden.intersection(extras):
            raise PactrailError("signer protocol headers cannot override Pactrail approval bindings")
        headers = {
            "content-type": "application/json", "payment-signature": payment,
            "x-pactrail-signer-approval": approval.approval_id,
            "x-agent-id": claimed["agent_id"], "x-budget-id": claimed["budget_id"],
            "x-session-id": claimed["session_id"], "x-request-id": claimed["request_id"],
            **extras,
        }
        response, raw = self._request(f"/x402/{claimed['resource_id']}", body=payload, headers=headers)
        return json.loads(raw or b"{}"), response.headers.get("x-pactrail-request-id", claimed["request_id"])
