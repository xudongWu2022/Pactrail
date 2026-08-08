"""Stdlib-only Pactrail client. Wallet signing is delegated to the caller."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from spend_collector.capabilities import PaymentIntent


class PactrailError(RuntimeError):
    pass


@dataclass
class PactrailClient:
    gateway_url: str
    capability: str
    agent_id: str
    budget_id: str
    session_id: str

    def _request(self, path: str, *, body: dict | None = None, headers: dict[str, str] | None = None):
        all_headers = {"authorization": f"Capability {self.capability}", **(headers or {})}
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            all_headers.setdefault("content-type", "application/json")
        req = urllib.request.Request(self.gateway_url.rstrip("/") + path, data=data, headers=all_headers,
                                     method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return response, response.read()
        except urllib.error.HTTPError as exc:
            raise PactrailError(f"Pactrail returned {exc.code}: {exc.read().decode('utf-8', 'replace')}") from exc

    def create_payment_intent(self, resource_id: str) -> PaymentIntent:
        _, raw = self._request("/payment-intents", body={"resource_id": resource_id})
        return PaymentIntent.from_dict(json.loads(raw))

    def pay_x402(self, intent: PaymentIntent, payload: bytes, signer: Callable[[dict[str, Any]], str],
                 *, protocol_headers: dict[str, str] | None = None) -> tuple[dict, dict]:
        """Perform quote -> external signature -> retry. The SDK never sees a private key."""
        protocol_headers = {str(key).lower(): str(value) for key, value in (protocol_headers or {}).items()}
        protected = {"authorization", "content-type", "payment-signature", "x-agent-id", "x-budget-id", "x-session-id", "x-request-id"}
        conflict = protected.intersection(protocol_headers)
        if conflict:
            raise PactrailError(f"protocol headers cannot override Pactrail bindings: {', '.join(sorted(conflict))}")
        path = f"/x402/{intent.resource_id}"
        headers = {"content-type": "application/json", "x-agent-id": self.agent_id,
                   "x-budget-id": self.budget_id, "x-session-id": self.session_id,
                   "x-request-id": intent.request_id, **protocol_headers}
        req = urllib.request.Request(self.gateway_url.rstrip("/") + path, data=payload,
                                     headers={"authorization": f"Capability {self.capability}", **headers}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=30)
            raise PactrailError("x402 resource did not return a payment quote")
        except urllib.error.HTTPError as quote:
            if quote.code != 402:
                raise PactrailError(f"Pactrail returned {quote.code}: {quote.read().decode()}") from quote
            import base64
            requirements = json.loads(base64.b64decode(quote.headers["payment-required"]).decode())
        payment = signer(requirements)
        headers["payment-signature"] = payment
        req = urllib.request.Request(self.gateway_url.rstrip("/") + path, data=payload,
                                     headers={"authorization": f"Capability {self.capability}", **headers}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                receipt_id = response.headers.get("x-pactrail-request-id", intent.request_id)
                result = json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raise PactrailError(f"x402 payment failed: {exc.code} {exc.read().decode('utf-8', 'replace')}") from exc
        receipt_data: dict[str, Any] = {}
        for _ in range(10):
            _, raw = self._request(f"/x402/payments/{receipt_id}")
            receipt_data = json.loads(raw)
            if receipt_data.get("status") in {"delivered", "delivery_failed", "settlement_failed"}:
                break
            time.sleep(0.05)
        return result, receipt_data
