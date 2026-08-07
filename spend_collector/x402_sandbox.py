"""Local-only x402 facilitator and paid-resource simulator.

It deliberately accepts no wallet credentials and has no blockchain dependency.
Use it to exercise a gateway's verify -> settle -> protected-resource flow.
"""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


def make_x402_sandbox(host: str = "127.0.0.1", port: int = 8788) -> ThreadingHTTPServer:
    settlements: dict[str, dict] = {}

    class Sandbox(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _json(self, status: int, payload: dict) -> None:
            raw = json.dumps(payload, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _body(self) -> dict:
            raw = self.rfile.read(int(self.headers.get("content-length", "0") or 0))
            try:
                value = json.loads(raw or b"{}")
            except ValueError:
                value = {}
            return value if isinstance(value, dict) else {}

        @staticmethod
        def _payment(body: dict) -> dict:
            value = body.get("paymentPayload")
            return value if isinstance(value, dict) else {}

        def do_GET(self) -> None:
            if self.path == "/health":
                self._json(200, {"ok": True, "mode": "local-x402-sandbox"})
            elif self.path == "/supported":
                self._json(200, {"kinds": [{"x402Version": 2, "scheme": "exact", "network": "eip155:84532"}]})
            elif self.path.startswith("/paid/"):
                self._json(200, {"ok": True, "sandbox": True, "resource": self.path})
            else:
                self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            body = self._body()
            payment = self._payment(body)
            flags = payment.get("payload", {}) if isinstance(payment.get("payload"), dict) else {}
            if self.path == "/verify":
                if flags.get("force_invalid"):
                    self._json(200, {"isValid": False, "invalidReason": "sandbox_invalid_payment",
                                     "invalidMessage": "forced verification failure"})
                else:
                    self._json(200, {"isValid": True, "payer": "sandbox-payer"})
                return
            if self.path == "/settle":
                if flags.get("force_settlement_failure"):
                    self._json(200, {"success": False, "errorReason": "sandbox_settlement_failed",
                                     "errorMessage": "forced settlement failure"})
                    return
                fingerprint = hashlib.sha256(
                    json.dumps(payment, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                result = settlements.setdefault(fingerprint, {
                    "success": True, "payer": "sandbox-payer",
                    "transaction": "sandbox:" + fingerprint[:24],
                    "network": "eip155:8453",
                    "amount": str((body.get("paymentRequirements") or {}).get("amount", "0")),
                })
                self._json(200, result)
                return
            if self.path.startswith("/paid/"):
                self._json(200, {"ok": True, "sandbox": True, "resource": self.path, "received": body})
                return
            self._json(404, {"error": "not_found"})

    return ThreadingHTTPServer((host, port), Sandbox)


def x402_sandbox(host: str = "127.0.0.1", port: int = 8788) -> None:
    server = make_x402_sandbox(host, port)
    base = f"http://{host}:{server.server_port}"
    print(f"local x402 sandbox listening on {base}")
    print("facilitator_url=" + base)
    print("protected resource URL=" + base + "/paid/search")
    print("Set paymentPayload.payload.force_invalid or force_settlement_failure to exercise failures.")
    server.serve_forever()
