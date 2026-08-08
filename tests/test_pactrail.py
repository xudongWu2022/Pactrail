from __future__ import annotations

import json
import os
import tempfile
import threading
import urllib.error
import urllib.request
import unittest
from pathlib import Path

from spend_collector.__main__ import make_gateway_server
from spend_collector.capabilities import CapabilityError, mint_capability, verify_capability
from spend_collector.x402_sandbox import make_x402_sandbox
from pactrail import PactrailClient


class PactrailTest(unittest.TestCase):
    def test_capability_signature_and_expiry(self) -> None:
        token = mint_capability({"session_id": "ses:one", "exp": 200}, "secret")
        self.assertEqual(verify_capability(token, "secret", now=100)["session_id"], "ses:one")
        with self.assertRaises(CapabilityError):
            verify_capability(token + "x", "secret", now=100)
        with self.assertRaisesRegex(CapabilityError, "expired"):
            verify_capability(token, "secret", now=201)

    def test_session_capability_and_payment_intent_are_least_privilege(self) -> None:
        old_secret = os.environ.get("PACTRAIL_CAPABILITY_SECRET")
        os.environ["PACTRAIL_CAPABILITY_SECRET"] = "test-capability-secret"
        self.addCleanup(lambda: os.environ.__setitem__("PACTRAIL_CAPABILITY_SECRET", old_secret)
                        if old_secret is not None else os.environ.pop("PACTRAIL_CAPABILITY_SECRET", None))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "gateway_tokens": ["admin-token"], "budgets": {"team": 1.0},
                "x402_resources": {"research": {
                    "url": "http://127.0.0.1:9/unreachable", "amount": 0.1,
                    "asset": "0xUSDC", "pay_to": "0xmerchant", "network": "eip155:84532",
                    "facilitator_url": "http://127.0.0.1:9",
                }},
            }))
            server = make_gateway_server(root / "spend.db", policy, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda: (server.shutdown(), thread.join(1), server.server_close()))
            base = f"http://127.0.0.1:{server.server_port}"

            def post(path: str, body: dict, auth: str):
                req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST", headers={
                    "content-type": "application/json", "authorization": auth,
                })
                with urllib.request.urlopen(req, timeout=2) as response:
                    return response.status, json.load(response)

            status, session = post("/sessions", {"parent_task": "research", "budget_id": "team", "cap": 0.25,
                                                   "constraints": {"resource_ids": ["research"]}}, "Bearer admin-token")
            self.assertEqual(status, 201)
            with self.assertRaises(urllib.error.HTTPError) as error:
                post("/capabilities", {"session_id": session["session_id"], "agent_id": "research-bot",
                                        "resource_ids": ["other"]}, "Bearer admin-token")
            self.assertEqual(error.exception.code, 404)
            status, minted = post("/capabilities", {
                "session_id": session["session_id"], "agent_id": "research-bot", "resource_ids": ["research"],
                "networks": ["eip155:84532"], "assets": ["0xUSDC"], "schemes": ["exact"],
            }, "Bearer admin-token")
            self.assertEqual(status, 201)
            self.assertEqual(minted["claims"]["merchants"], ["0xmerchant"])
            self.assertEqual(minted["claims"]["networks"], ["eip155:84532"])
            self.assertEqual(minted["claims"]["assets"], ["0xUSDC"])
            self.assertEqual(minted["claims"]["schemes"], ["exact"])
            status, intent = post("/payment-intents", {"resource_id": "research"}, f"Capability {minted['capability']}")
            self.assertEqual(status, 201)
            self.assertEqual(intent["session_id"], session["session_id"])
            with self.assertRaises(urllib.error.HTTPError) as error:
                post("/payment-intents", {"resource_id": "not-approved"}, f"Capability {minted['capability']}")
            self.assertEqual(error.exception.code, 404)
            status, revoked = post(f"/sessions/{session['session_id']}/revoke", {}, "Bearer admin-token")
            self.assertEqual(status, 200)
            self.assertTrue(revoked["revoked"])
            with self.assertRaises(urllib.error.HTTPError) as error:
                post("/payment-intents", {"resource_id": "research"}, f"Capability {minted['capability']}")
            self.assertEqual(error.exception.code, 401)

    def test_sdk_runs_quote_sign_retry_and_receipt_with_external_signer_mock(self) -> None:
        old_secret = os.environ.get("PACTRAIL_CAPABILITY_SECRET")
        os.environ["PACTRAIL_CAPABILITY_SECRET"] = "test-capability-secret"
        self.addCleanup(lambda: os.environ.__setitem__("PACTRAIL_CAPABILITY_SECRET", old_secret)
                        if old_secret is not None else os.environ.pop("PACTRAIL_CAPABILITY_SECRET", None))
        sandbox = make_x402_sandbox(port=0)
        sandbox_thread = threading.Thread(target=sandbox.serve_forever, daemon=True)
        sandbox_thread.start()
        self.addCleanup(lambda: (sandbox.shutdown(), sandbox_thread.join(1), sandbox.server_close()))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "gateway_tokens": ["admin-token"], "budgets": {"team": 1.0},
                "x402_resources": {"research": {
                    "url": f"http://127.0.0.1:{sandbox.server_port}/paid/search",
                    "resource_url": "https://gateway.example/x402/research", "method": "POST", "amount": 0.1,
                    "asset": "0xUSDC", "pay_to": "0xmerchant", "network": "eip155:84532",
                    "facilitator_url": f"http://127.0.0.1:{sandbox.server_port}",
                }},
            }))
            server = make_gateway_server(root / "spend.db", policy, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda: (server.shutdown(), thread.join(1), server.server_close()))
            base = f"http://127.0.0.1:{server.server_port}"

            def admin(path: str, body: dict) -> dict:
                req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST", headers={
                    "content-type": "application/json", "authorization": "Bearer admin-token",
                })
                with urllib.request.urlopen(req, timeout=2) as response:
                    return json.load(response)

            session = admin("/sessions", {"parent_task": "sdk", "budget_id": "team", "cap": 0.25})
            minted = admin("/capabilities", {"session_id": session["session_id"], "agent_id": "research-bot",
                                               "resource_ids": ["research"]})
            client = PactrailClient(base, minted["capability"], "research-bot", "team", session["session_id"])
            intent = client.create_payment_intent("research")

            def external_signer(quote: dict) -> str:
                return json.dumps({"x402Version": 2, "accepted": quote["accepts"][0],
                                   "payload": {"authorization": "external"}, "resource": quote["resource"]})

            result, receipt = client.pay_x402(intent, b'{"query":"sdk"}', external_signer)
            self.assertTrue(result["ok"])
            self.assertEqual(receipt["status"], "delivered")
            self.assertEqual(receipt["request_id"], intent.request_id)
            self.assertEqual(receipt["session_id"], session["session_id"])
            self.assertEqual(receipt["agent_id"], "research-bot")
            self.assertEqual(receipt["budget_id"], "team")
            self.assertEqual(receipt["intent_status"], "delivered")

    def test_sdk_accounts_for_exact_upto_and_batch_settlement(self) -> None:
        old_secret = os.environ.get("PACTRAIL_CAPABILITY_SECRET")
        os.environ["PACTRAIL_CAPABILITY_SECRET"] = "test-capability-secret"
        self.addCleanup(lambda: os.environ.__setitem__("PACTRAIL_CAPABILITY_SECRET", old_secret)
                        if old_secret is not None else os.environ.pop("PACTRAIL_CAPABILITY_SECRET", None))
        sandbox = make_x402_sandbox(port=0)
        sandbox_thread = threading.Thread(target=sandbox.serve_forever, daemon=True)
        sandbox_thread.start()
        self.addCleanup(lambda: (sandbox.shutdown(), sandbox_thread.join(1), sandbox.server_close()))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def resource(scheme: str) -> dict:
                value = {
                    "url": f"http://127.0.0.1:{sandbox.server_port}/paid/search",
                    "resource_url": f"https://gateway.example/x402/{scheme}", "method": "POST", "amount": 0.1,
                    "asset": "0xUSDC", "pay_to": "0xmerchant", "network": "eip155:84532",
                    "scheme": scheme, "facilitator_url": f"http://127.0.0.1:{sandbox.server_port}",
                }
                if scheme in {"upto", "batch-settlement"}:
                    value["payment_policy"] = {"scheme": scheme, "authorization_limit_units": "100000"}
                if scheme == "batch-settlement":
                    value["payment_policy"]["batch_limit_units"] = "200000"
                    value["payment_policy"]["batch_id_header"] = "x-pactrail-batch-id"
                return value
            policy = root / "policy.json"
            policy.write_text(json.dumps({"gateway_tokens": ["admin-token"], "budgets": {"team": 1.0},
                                          "x402_resources": {kind: resource(kind) for kind in ("exact", "upto", "batch-settlement")}}))
            server = make_gateway_server(root / "spend.db", policy, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda: (server.shutdown(), thread.join(1), server.server_close()))
            base = f"http://127.0.0.1:{server.server_port}"

            def admin(path: str, body: dict) -> dict:
                request = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST", headers={
                    "content-type": "application/json", "authorization": "Bearer admin-token",
                })
                with urllib.request.urlopen(request, timeout=2) as response:
                    return json.load(response)

            session = admin("/sessions", {"parent_task": "schemes", "budget_id": "team", "cap": 0.5})
            minted = admin("/capabilities", {"session_id": session["session_id"], "agent_id": "research-bot",
                                               "resource_ids": ["exact", "upto", "batch-settlement"],
                                               "schemes": ["exact", "upto", "batch-settlement"]})
            client = PactrailClient(base, minted["capability"], "research-bot", "team", session["session_id"])

            def signer(quote: dict) -> str:
                return json.dumps({"x402Version": 2, "accepted": quote["accepts"][0],
                                   "payload": {"actual_usage_units": "18000"}, "resource": quote["resource"]})

            for scheme, expected in (("exact", "100000"), ("upto", "18000"), ("batch-settlement", "18000")):
                with self.subTest(scheme=scheme):
                    intent = client.create_payment_intent(scheme)
                    _, receipt = client.pay_x402(
                        intent, b'{"query":"scheme coverage"}', signer,
                        protocol_headers={"x-pactrail-batch-id": "batch:one"} if scheme == "batch-settlement" else None,
                    )
                    self.assertEqual(receipt["scheme"], scheme)
                    self.assertEqual(receipt["authorization_limit_units"], "100000")
                    self.assertEqual(receipt["usage_units"], expected)
                    self.assertEqual(receipt["settled_units"], expected)
            with self.assertRaisesRegex(Exception, "cannot override"):
                client.pay_x402(client.create_payment_intent("exact"), b"{}", signer,
                                protocol_headers={"authorization": "bad"})
