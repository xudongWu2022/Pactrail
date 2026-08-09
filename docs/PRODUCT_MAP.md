# Pactrail Product Map

Pactrail has one primary product and one supporting product. They share the
same ledger because a payment decision is more useful when it can be audited
afterward, but they should not compete for the headline.

## Primary: Payment Control Plane

This is the developer-facing reason to adopt Pactrail.

| Job | Existing capability | Entry point |
| --- | --- | --- |
| Give an agent bounded authority | Spend Sessions + Payment Capabilities | `POST /sessions`, `POST /capabilities` |
| Ask for a payment | Payment Intent | `POST /payment-intents` or `PactrailClient` |
| Negotiate x402 | Quote, 402 retry, facilitator routing | `/x402/<resource>` |
| Keep the wallet outside the agent | External signer approval binding | `PactrailSignerAdapter` |
| Prove what happened | Request-ID linked receipt and lifecycle record | `GET /x402/payments/<request_id>` |
| Discover safely | Bazaar filtering and reviewed resource adoption | `fetch-bazaar`, `filter-bazaar`, `adopt-bazaar` |

The Control Plane dashboard is the default at `/dashboard`. It should answer:
"What can this agent spend, what is currently waiting for a signature, and
what settled?"

## Supporting: Spend Observability

This is retained because it turns Pactrail from a policy check into an audit
surface across existing spending rails.

| Capability | Keep because |
| --- | --- |
| LLM, Stripe, USDC, and cloud ingestion | Existing teams can reconcile spend that did not originate from Pactrail yet. |
| SQLite ledger | Payment receipts, decisions, and imported events can be joined locally. |
| Budget burn and detectors | Useful post-payment security and FinOps evidence. |
| HTML report | Gives a zero-dependency self-hosted dashboard. |

It is a secondary dashboard view, not the project headline.

## CLI families

The command names remain backward compatible, but documentation and product
navigation use these families:

| Family | Commands |
| --- | --- |
| Start and test | `demo`, `demo-live`, `gateway`, `x402-sandbox`, `run-scenarios` |
| Control and policy | `guard`, `validate-policy`, `audit-config`, `freeze`, `unfreeze`, `release-reservation` |
| x402 discovery | `check-facilitator`, `fetch-bazaar`, `filter-bazaar`, `adopt-bazaar` |
| Observability | `pull*`, `report`, `simulate-spend` |

Do not delete an observability command merely because it is not in the default
demo. Keep it only if it has a documented data source and a corresponding
dashboard section; otherwise move it to an extension in a future major version.

## Deliberate boundaries

- Pactrail does not hold wallet private keys or persistent signing authority.
- Pactrail does not replace an x402 facilitator or merchant service.
- The wallet/demo application is a separate integration surface, not part of
  the Gateway runtime.
- Generated databases, reports, and local wallet demo worktrees are local
  artifacts; they are not product source code.
