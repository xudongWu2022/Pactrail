# Security

Pactrail is designed to be self-hosted by default. Provider keys
stay in the user's machine, server, VPC, or secret manager; the project does not
depend on a hosted control plane.

## Trust Model

- Run the gateway in your own environment.
- Store real provider keys in environment variables or a secret manager.
- Put only environment variable names in policy files, for example
  `api_key_env: "OPENAI_API_KEY"`.
- Give Agents short-lived Payment Capabilities, not provider keys, administrator
  credentials, or wallet access.
- Keep `SPEND_GATEWAY_TOKEN` with the administrator. It creates Sessions and
  Capabilities; it is never an Agent credential.
- The gateway does not send data to project-owned servers.
- Audit logs store metadata only: agent, rail, provider, amount, budget,
  decision, and reasons.
- Audit logs do not store prompts, request bodies, completions, responses,
  provider keys, gateway tokens, or x402 payment signatures.
- Configured `/x402/<resource-id>` routes settle already-signed payment payloads
  through your facilitator. Ledger rows store settlement metadata such as payer,
  transaction, amount, and resource, not the signed payment payload.

## Recommended Deployment

Use least-privilege credentials where providers support them:

- Restricted Stripe keys.
- Limited-scope LLM admin/read keys for cost pulls.
- Gateway-held provider keys for inline model/API calls.
- Limited wallet permissions or spend-limited wallets for payment rails.

For local sandbox development, Pactrail defaults to `deployment_mode:
"development"` and binds to loopback by default. This keeps the first-run path
small; do not expose that mode to the internet.

For production, declare `deployment_mode: "production"`. Pactrail then refuses
to start unless all of the following are present:

- A gateway administrator credential (`gateway_tokens` or
  `SPEND_GATEWAY_TOKEN`).
- A server-side `PACTRAIL_CAPABILITY_SECRET` (or configured equivalent).
- `require_signer_approval: true` and a configured wallet adapter credential.
- An HTTPS `public_base_url`, intended to sit behind your TLS reverse proxy.
- HTTPS merchant and facilitator URLs for every x402 resource.

The wallet adapter is not a second policy engine. It is the connection between
Pactrail's already-approved payment and the user's wallet. Small self-hosted
setups may run it inside their wallet UI; keep it separate from the Agent when
the wallet SDK needs isolation. Never put its credential in an Agent process or
browser bundle.

Pactrail never accepts credentials in dashboard query strings. Put an
authenticated dashboard behind your own same-origin admin UI or reverse proxy.

## Reporting Vulnerabilities

Open a private security advisory or contact the maintainer directly before
publishing vulnerabilities. Do not include real provider keys, wallet material,
prompts, customer data, or raw provider responses in reports.
