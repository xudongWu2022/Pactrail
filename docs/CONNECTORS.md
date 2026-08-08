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
