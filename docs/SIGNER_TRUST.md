# Production signer trust boundary

This protocol prevents an Agent from using a general-purpose wallet signing
function. The Agent receives a Payment Capability; the signer adapter receives
a distinct secret from its own environment. Neither receives a wallet private
key from Pactrail.

```text
Agent -> Gateway: get 402 quote + create signer approval
Agent -> Signer adapter: approval_id + request body
Signer adapter -> Gateway: fetch canonical approval with its signer credential
Signer adapter -> Wallet: sign only the canonical quote
Signer adapter -> Gateway: submit payment signature directly
Gateway -> facilitator -> merchant: verify, settle, deliver
Gateway -> Agent: safe receipt / result
```

The Agent never receives the signer credential or the `payment-signature`.
The signer adapter never trusts an Agent-supplied amount, recipient, network or
quote. It re-fetches the canonical approval from its configured Gateway.

## Policy

Keep the signer credential outside JSON policy. Reference an environment
variable instead:

```json
{
  "capability_secret_env": "PACTRAIL_CAPABILITY_SECRET",
  "require_signer_approval": true,
  "signer_adapters": {
    "cdp-wallet-ui": {"auth_env": "PACTRAIL_CDP_SIGNER_TOKEN"}
  }
}
```

Run the signer adapter in a wallet-controlled process or service, separate from
the Agent runtime. In production, use HTTPS and an authenticated service-to-
service channel for that adapter. Do not put `PACTRAIL_CDP_SIGNER_TOKEN` in an
Agent environment, browser bundle, policy file, database, logs, or Git.

## Agent side

```python
intent = agent.create_payment_intent("research")
approval = agent.prepare_signer_approval(
    intent, b'{"query":"research"}', signer_id="cdp-wallet-ui"
)
# Send only approval.approval_id and the original body to the separate signer service.
```

## Signer side

```python
from pactrail import PactrailSignerAdapter

adapter = PactrailSignerAdapter(
    "https://pactrail.example",
    "cdp-wallet-ui",
    signer_token=os.environ["PACTRAIL_CDP_SIGNER_TOKEN"],
)

# sign_payment is implemented by the external wallet and receives only the
# canonical quote fetched from Pactrail, never arbitrary Agent typed data.
result, receipt_id = adapter.sign_and_submit(approval, body, sign_payment)
```

The Gateway rejects the submission when the signer token, approval ID, agent,
budget, session, resource, request body hash, quote, or expiry do not match.
Each approval is atomically consumed once before settlement.

This does not restrict the wallet owner from spending manually elsewhere. It
restricts the Agent: it cannot invoke a generic signing API or submit the
payment signature directly.
