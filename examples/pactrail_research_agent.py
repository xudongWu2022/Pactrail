"""A generic Python Agent uses Pactrail, never a wallet private key.

Set PACTRAIL_CAPABILITY to a short-lived value minted by your gateway. Replace
external_signer with a CDP, browser, hardware-wallet, or other x402 signer.
"""
import json
import os

from pactrail import PactrailClient


def external_signer(payment_required: dict) -> str:
    # The SDK provides the exact V2 requirements. An external signer returns the
    # complete PAYMENT-SIGNATURE JSON string; Pactrail never receives a private key.
    raise RuntimeError("Connect your external x402 signer here; do not add a private key to this file.")


client = PactrailClient(
    gateway_url=os.environ.get("PACTRAIL_GATEWAY_URL", "http://127.0.0.1:8787"),
    capability=os.environ["PACTRAIL_CAPABILITY"],
    agent_id="research-bot",
    budget_id="team-research",
    session_id=os.environ["PACTRAIL_SESSION_ID"],
)
intent = client.create_payment_intent("sandbox-search")
print(json.dumps(intent.__dict__, indent=2))
print("Next: call client.pay_x402(intent, body, external_signer).")
