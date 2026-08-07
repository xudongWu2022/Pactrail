# CDP Server Wallet signer

Pactrail does not hold a private key. A CDP Server Wallet is the external x402
signer: Pactrail approves a payment intent, while CDP signs the x402 payload.

## Required local secrets

Set these only in a local shell or secret manager, never in a policy JSON or
the ledger:

```text
CDP_API_KEY_ID
CDP_API_KEY_SECRET
CDP_WALLET_SECRET
PACTRAIL_CDP_ACCOUNT_NAME=pactrail-x402-test
PACTRAIL_X402_NETWORK=eip155:84532
```

Use Base Sepolia (`eip155:84532`) first. Fund only the dedicated test account
with test USDC; do not reuse a general-purpose treasury wallet.

## Boundary

```text
Agent -> Pactrail policy approval -> CDP Server Wallet signs -> merchant/facilitator settles
```

The approval must bind agent, budget, merchant, `payTo`, asset, network, scheme,
amount and request ID. A signer must reject any request that does not match an
active Pactrail approval. The wallet secret must never be sent to the agent,
merchant, facilitator, SQLite database, artifacts, logs, or Git.

## SDKs

Install the CDP and x402 buyer dependencies in the external signer runtime, not
in the Pactrail Gateway process:

```bash
pip install cdp-sdk "x402[httpx]"
```

CDP's current x402 buyer guidance uses CDP Server Wallet as the signer, and the
x402 client handles the 402 -> signed retry path. Before enabling mainnet, test
the exact merchant flow on Base Sepolia and enforce a very small Pactrail budget.

## First real acceptance test

1. Start Pactrail with a test-only policy (one agent, one merchant, one `payTo`,
   one network, one asset, and a <= $0.10 budget).
2. Ask the merchant for its 402 quote without a payment payload.
3. Have Pactrail validate the quote and issue an approval.
4. Let CDP sign only that bound quote.
5. Retry once with `PAYMENT-SIGNATURE`; record the settlement response and
   reconcile the receipt in Pactrail.

Do not use a mainnet merchant until this flow succeeds with a dedicated test
wallet and the rejection paths are verified.
