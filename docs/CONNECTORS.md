# Pactrail Connector Blueprint

Any Agent runtime integrates by replacing its payment/tool function with the
Pactrail SDK: create a payment intent, send the signed x402 retry, retain the
receipt. The runtime never receives a management token or wallet private key.

## Prime Agent

Wrap `PactrailClient.create_payment_intent()` and `pay_x402()` in a project
skill. Give that skill only `PACTRAIL_CAPABILITY`, not an administrator token.

## LangGraph

Place the Pactrail call in a payment node. Persist `session_id`, intent ID and
receipt in graph state; route policy denials to a human-review or fallback node.

## MCP

Expose `create_payment_intent` and `get_receipt` as MCP tools. Keep signing in a
separate user-controlled wallet client, never inside the MCP server process.

## Scheme-specific calls

`PactrailClient.pay_x402()` keeps Pactrail's authorization, agent, budget,
session and request headers reserved. For a `batch-settlement` resource, pass
only the protocol batch identifier through its safe extension point:

```python
result, receipt = client.pay_x402(
    intent, body, external_signer,
    protocol_headers={"x-pactrail-batch-id": "batch:research-42"},
)
```

The gateway binds that batch ID to the Spend Session on first use and rejects
cross-session reuse. For `upto`, the external signer/facilitator reports actual
atomic usage; Pactrail records it separately from the authorized limit.
