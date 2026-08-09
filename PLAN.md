# Pactrail Working Plan

This file tracks the product direction. See [Product Map](docs/PRODUCT_MAP.md)
for where each existing capability belongs.

## Product position

**Pactrail is the x402 spend control plane for AI agents.** It lets an agent
request bounded payment capability without receiving a wallet key. Policy is
enforced before a signer is asked to authorize payment; receipts and imported
spend then remain available for audit.

## Shipped

- x402 gateway with merchant, `payTo`, asset, network, price, budget, and
  scheme policy checks.
- Spend Sessions and short-lived, revocable Payment Capabilities.
- Payment Intents, request-ID idempotency, budget reservations, and lifecycle
  records for `exact`, `upto`, and batch settlement.
- External signer approval binding: the agent has no signer credential and no
  generic `signTypedData` access.
- Sandbox, Bazaar discovery/filtering, facilitator capability preflight, Python
  SDK, and an explicit real-testnet integration path.
- Cross-rail ledger, imports, budget burn, and security signals as the
  supporting Spend Observability product.

## Now: make the product legible

1. Keep the Control Plane dashboard as the default experience: payment
   lifecycle, active sessions/holds, signer approvals, decisions, and receipts.
2. Keep cross-rail data in the secondary Spend Observability view; do not
   delete a proven importer or detector simply because it is not on the main
   workflow.
3. Use the Python research-agent example and sandbox as the copy-and-run
   developer entry point. Real Base Sepolia payment remains opt-in.
4. Collect feedback from agent developers using paid APIs. Validate whether the
   main pain is budget control, merchant trust, signer isolation, or audit.

## Next engineering milestones

1. Extract the HTTP gateway runtime from `pactrail_core.__main__` into a
   dedicated module while retaining the current CLI as a compatibility shell.
   This is a maintainability refactor, not a new protocol feature.
2. Make the wallet approval demo a reproducible example under `examples/` once
   its CDP configuration is safe to publish. It must contain no project secret,
   signer secret, or real wallet data.
3. Add real-testnet acceptance only behind explicit environment flags and keep
   sandbox as the default CI path.
4. Publish connector recipes for Prime Agent, LangGraph, and MCP after the
   generic Python path remains stable.

## Deliberately not doing

- Wallet custody, private-key storage, or an agent-held general signing key.
- Replacing the facilitator or operating the merchant service.
- Adding more payment schemes before a real developer needs them.
- Deleting observability assets that still provide audit value.
