# Five-Minute Technical Walkthrough

Use this as a tight product-and-engineering walkthrough. Do not start by listing
providers; start with the costly failure this repository makes observable.

## 0:00-0:30: The Problem

"An AI agent can spend through model APIs, paid tools, wallets, cloud accounts,
and cards. Those systems have separate logs and separate controls. This project
normalizes them into one ledger and gives the agent a pre-spend policy boundary."

Point to the top table in the README. The design choice worth stating: collection
is read-only, while the gateway is the only inline enforcement component.

## 0:30-1:30: Show A Working Product

```bash
python3 -m spend_collector demo-live --policy gateway.example.json
```

Open `http://127.0.0.1:8787/dashboard?token=dev-gateway-token`. Explain the
dashboard in this order: total spend across rails, budget burn, security signals,
then gateway audit decisions. The fixtures intentionally contain an anomalous
runaway loop and a new-key spike, so the view is never empty during a demo.

## 1:30-2:45: Show The Control Plane

```bash
curl -X POST http://127.0.0.1:8787/guard \
  -H "content-type: application/json" \
  -H "authorization: Bearer dev-gateway-token" \
  -d '{"agent":"research-bot","rail":"api_x402","provider":"x402","merchant":"0xtool","service":"/scrape","amount":1.5,"budget":"team-research"}'
```

Repeat with `"amount": 9` to show a deny. Mention that the gateway records a
decision and atomically reserves budget for allowed requests, so concurrent
requests cannot oversubscribe a cap. The provider key remains on the gateway;
the calling agent receives only a gateway token.

## 2:45-3:45: Show The Hard Payment Boundary

Open [`gateway.example.json`](../gateway.example.json) and the x402 section in
[`docs/OPERATIONS.md`](OPERATIONS.md). Explain the two protective properties:

- Payment data is checked against the configured resource URL, amount, `pay_to`,
  network, and asset. A signature intended for one resource cannot be replayed on
  another configured resource.
- Request IDs are idempotent; retrying a request reuses its recorded decision and
  cannot create another reservation.

Be precise: the repository records and releases gateway holds around a failed
forward. A full settlement-versus-delivery compensation lifecycle is intentionally
the next production-grade extension, not a claim already made.

## 3:45-4:40: Show How It Stays Correct

```bash
python3 -m spend_collector run-scenarios --path scenarios --out-dir artifacts
```

Open `artifacts/scenario-report.json`. These are JSON incident records, not a
presentation fixture: they run the real in-memory SQLite ledger, policy decision,
atomic reservation, and release logic. Highlight the duplicate-retry and
delivery-failure scenarios. This is the clearest evidence that payment behavior is
treated as an invariant rather than a happy-path demo.

## 4:40-5:00: Engineering Tradeoffs

- SQLite and the standard library make the project inspectable and easy to run;
  a production deployment can replace the store with a shared database.
- The canonical record is a FOCUS-shaped `SpendEvent`, which keeps adapters thin
  and makes every rail available to the same detectors and reports.
- Secrets, prompts, request bodies, and completions are deliberately excluded from
  the ledger. The audit trail is useful without becoming a second sensitive-data
  store.

Close with the next hard problem: reconciliation and compensation across intent,
gateway decision, provider/facilitator result, and final bill or chain settlement.
