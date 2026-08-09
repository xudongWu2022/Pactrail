# CDP Wallet + Pactrail Capability Demo

This optional local demo connects the independent CDP non-custodial wallet UI
to Pactrail's least-privilege payment path. It uses the x402 sandbox by default;
no USDC moves unless you deliberately configure a real Base Sepolia resource.

## Trust boundary

There are three credentials with deliberately different homes:

| Credential | Holder | May do |
| --- | --- | --- |
| Gateway administrator token | trusted local operator / server | Create and revoke sessions; mint capabilities |
| Payment capability (`ptr1.…`) | the browser or Agent for a short time | Create/settle only its permitted payment intent |
| Wallet signing authority | CDP non-custodial wallet UI | Approve the exact EIP-712 x402 authorization |

Never place an administrator token, a capability secret, or a wallet key in a
`VITE_*` environment variable. A short-lived capability may be pasted into the
UI for a local demo; it is scoped and revocable, not a general management key.

## Start the sandbox gateway

Configure a local `PACTRAIL_CAPABILITY_SECRET` in the gateway process and keep
the administrator token there too. Then run the existing sandbox facilitator
and gateway with [`gateway.x402-sandbox.example.json`](../gateway.x402-sandbox.example.json).

Create a short session from a trusted terminal, replacing the placeholders:

```powershell
$headers = @{ Authorization = "Bearer <admin-token>"; "Content-Type" = "application/json" }
$session = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/sessions -Headers $headers -Body (@{
  parent_task = "cdp-wallet-demo"; budget_id = "team-research"; cap = 0.10
  constraints = @{ resource_ids = @("sandbox-search"); merchants = @("local-x402-sandbox"); networks = @("eip155:84532"); assets = @("0x036CbD53842c5426634e7929541eC2318f3dCF7e"); schemes = @("exact") }
} | ConvertTo-Json -Depth 5)

$capability = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/capabilities -Headers $headers -Body (@{
  session_id = $session.session_id; agent_id = "research-bot"; resource_ids = @("sandbox-search"); expires_in_seconds = 900
} | ConvertTo-Json)
$capability.capability
```

Copy the resulting `ptr1.…` value. It expires within 15 minutes and becomes
invalid immediately if the operator revokes `$session.session_id`.

## Use the independent wallet UI

The CDP sample app stays private to the operator. In its `.env`, set only the
gateway URL, then run its normal Vite development server. Paste the generated
capability into **Short-lived payment capability** and press **Create
constrained payment intent**.

The UI then does the following in order:

1. `POST /payment-intents` with `Authorization: Capability ptr1.…`.
2. Requests the resulting resource's x402 quote.
3. Lets CDP's non-custodial wallet sign EIP-712 typed data.
4. Retries the x402 request carrying the same capability and request ID.
5. Retrieves the safe receipt using the same capability.

The UI never sends a gateway admin credential to the browser and never reads a
wallet private key. See [Base Sepolia acceptance](BASE_SEPOLIA.md) when swapping
the sandbox resource for an explicitly enabled real testnet resource.
