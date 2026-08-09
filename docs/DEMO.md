# Three-Minute Demo Script

This is a reproducible walkthrough for a short product video. It uses only fixture
data, so it does not expose provider keys, wallet keys, prompts, or real spend.

1. Generate the safe static showcase (0:00-0:10), then start the live experience (0:10-0:30).

   ```bash
   python3 -m pactrail showcase
   ```

   Open `artifacts-showcase/report.html`. It contains clearly fictional,
   auditable examples of a completed payment, a signer approval waiting, and a
   policy denial. It never spends testnet or mainnet funds.

   ```bash
   python3 -m pactrail demo-live --policy gateway.example.json
   ```

   Open `http://127.0.0.1:8787/dashboard?token=dev-gateway-token`.

2. Start on the **Control plane** view (0:30-1:20). Explain the lifecycle:
   Agent payment intent → Pactrail policy decision → wallet/signer approval →
   x402 settlement → receipt. Point out active sessions, budget holds, signer
   approvals, and the payment lifecycle table.

3. Switch to **Spend observability** (1:20-2:00). Point out total spend, rail
   mix, budget burn, then the seeded spend spike, burn rate, spend per task,
   new-key spike, and new-merchant/provider signals.

4. Show pre-spend enforcement (2:00-2:35).

   ```bash
   curl -X POST http://127.0.0.1:8787/guard -H "content-type: application/json" -H "authorization: Bearer dev-gateway-token" -d '{"agent":"research-bot","rail":"api_x402","provider":"x402","merchant":"0xtool","service":"/scrape","amount":1.5,"budget":"team-research"}'
   ```

   Repeat with `"amount": 9` to show a deny. Refresh the dashboard to show the
   decision in the control-plane audit section.

5. Close with a provider integration (2:35-3:00). Set a provider key only in the
   gateway terminal, then run `python3 examples/openai_gateway.py`. Explain that the
   agent gets a scoped gateway token while the gateway records spend and applies the
   budget policy before forwarding.
