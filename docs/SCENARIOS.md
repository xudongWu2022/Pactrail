# Incident Scenarios

`scenarios/` is a committed library of executable payment and gateway incident
records. Each JSON file runs against a new in-memory SQLite ledger, so it is safe
for CI and does not contact a provider, facilitator, wallet, or network.

Run all checked-in scenarios:

```bash
python3 -m pactrail run-scenarios --path scenarios --out-dir artifacts
```

The command writes `artifacts/scenario-report.json`. A non-zero exit means an
invariant failed; the report still includes the final ledger/gateway snapshot for
debugging.

## Scenario Shape

```json
{
  "id": "short-stable-name",
  "description": "What real incident or guarantee this records.",
  "policy": {"budgets": {"research": 10.0}},
  "steps": [
    {"action": "seed", "events": []},
    {
      "action": "guard",
      "request_id": "stable-id",
      "request": {"agent": "research-bot", "rail": "api_x402", "amount": 2.5, "budget": "research"},
      "expect": {"decision": "allow", "reservation_status": "active"}
    },
    {"action": "fault", "request_id": "stable-id", "kind": "upstream_timeout", "release_reservation": true}
  ],
  "expect": {
    "ledger": {"event_count": 0, "total": 0.0},
    "gateway": {"allow_count": 1, "reservations": {"released": {"count": 1}}},
    "requests": {"stable-id": {"decision": "allow", "reservation_status": "released"}}
  }
}
```

Supported actions:

- `seed`: ingest normalized `SpendEvent` rows. Reusing an `event_id` proves the
  ledger's idempotency behavior.
- `guard`: run the real policy decision plus atomic budget reservation. Reusing a
  `request_id` models a client retry and must not create a second decision/hold.
- `release`: release an active reservation after a completed forward.
- `fault`: retain a named failure in the report. Set `release_reservation: true`
  for a forward that did not produce observed spend.

Final `expect` values are partial snapshots: add only the fields that matter to
the incident. Floats use a small tolerance. Request expectations can include
`reason_contains` to make a denial explainable.

## What Belongs Here

Add a scenario for each bug or payment invariant that could cost money:

- a retry must never create a second hold or settlement row;
- a budget/velocity limit must deny before payment begins;
- a delivery failure must release an unused hold and remain visible;
- a reconciliation import must classify every intent as matched, pending, or a
  discrepancy once that lifecycle feature lands.

Keep scenarios deterministic: fixed IDs, fixed timestamps, and no secrets. The
current files are intentionally small executable examples, not synthetic load
tests. Testnet and facilitator integration remain a separate end-to-end layer.
