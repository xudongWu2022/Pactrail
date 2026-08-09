"""Copy-and-run Pactrail x402 demo. It transfers no funds and needs no wallet key.

Run from a source checkout with:
    python examples/run_pactrail_sandbox_demo.py

The mock signer exists only because the local facilitator is a deterministic
sandbox. In a real Base Sepolia run, replace it with an external CDP, hardware,
or browser signer; do not put a private key in the Agent process.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

# Make `python examples/run_pactrail_sandbox_demo.py` work from a source checkout
# without requiring an editable install first.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pactrail import PactrailClient
from pactrail_core.__main__ import make_gateway_server
from pactrail_core.x402_sandbox import make_x402_sandbox


def _post(url: str, body: dict, authorization: str) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"content-type": "application/json", "authorization": authorization},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def sandbox_signer(quote: dict) -> str:
    """A no-key stand-in for the local sandbox only."""
    return json.dumps({
        "x402Version": 2,
        "accepted": quote["accepts"][0],
        "payload": {"authorization": "sandbox-external-signer"},
        "resource": quote["resource"],
    })


def main() -> None:
    old_secret = os.environ.get("PACTRAIL_CAPABILITY_SECRET")
    os.environ["PACTRAIL_CAPABILITY_SECRET"] = "local-demo-capability-secret"
    sandbox = make_x402_sandbox(port=0)
    sandbox_thread = threading.Thread(target=sandbox.serve_forever, daemon=True)
    sandbox_thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="pactrail-demo-") as directory:
            root = Path(directory)
            policy = {
                "gateway_tokens": ["local-demo-admin"],
                "budgets": {"team-research": 1.0},
                "x402_resources": {
                    "sandbox-search": {
                        "url": f"http://127.0.0.1:{sandbox.server_port}/paid/search",
                        "resource_url": "https://pactrail.local/x402/sandbox-search",
                        "method": "POST", "amount": 0.1,
                        "asset": "0xUSDC", "pay_to": "0xmerchant",
                        "network": "eip155:84532",
                        "facilitator_url": f"http://127.0.0.1:{sandbox.server_port}",
                    }
                },
            }
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy))
            gateway = make_gateway_server(root / "spend.db", policy_path, port=0)
            gateway_thread = threading.Thread(target=gateway.serve_forever, daemon=True)
            gateway_thread.start()
            try:
                base = f"http://127.0.0.1:{gateway.server_port}"
                admin = "Bearer local-demo-admin"
                session = _post(base + "/sessions", {
                    "parent_task": "demo-research", "budget_id": "team-research", "cap": 0.25,
                    "constraints": {"resource_ids": ["sandbox-search"], "schemes": ["exact"]},
                }, admin)
                minted = _post(base + "/capabilities", {
                    "session_id": session["session_id"], "agent_id": "research-bot",
                    "resource_ids": ["sandbox-search"], "expires_in_seconds": 900,
                }, admin)
                agent = PactrailClient(base, minted["capability"], "research-bot", "team-research", session["session_id"])
                intent = agent.create_payment_intent("sandbox-search")
                result, receipt = agent.pay_x402(intent, b'{"query":"Pactrail demo"}', sandbox_signer)
                print(json.dumps({"intent": intent.__dict__, "merchant_result": result, "receipt": receipt}, indent=2))
            finally:
                gateway.shutdown()
                gateway_thread.join(2)
                gateway.server_close()
    finally:
        sandbox.shutdown()
        sandbox_thread.join(2)
        sandbox.server_close()
        if old_secret is None:
            os.environ.pop("PACTRAIL_CAPABILITY_SECRET", None)
        else:
            os.environ["PACTRAIL_CAPABILITY_SECRET"] = old_secret


if __name__ == "__main__":
    main()
