# Three-Minute Demo Script

This is a reproducible walkthrough for a short product video. It uses only fixture
data, so it does not expose provider keys, wallet keys, prompts, or real spend.

1. Start the live experience (0:00-0:30).

   ```bash
   python3 -m spend_collector demo-live --policy gateway.example.json
   ```

   Open `http://127.0.0.1:8787/dashboard?token=dev-gateway-token`.

2. Show the ledger view (0:30-1:20). Point out total spend, rail mix, budget burn,
   and the four fixture rails: LLM token, x402, USDC, and Stripe.

3. Show security signals (1:20-2:00). Scroll to the alerts and call out the seeded
   spend spike, budget burn, burn rate, spend per task, new-key spike, and
   new-merchant/provider cases.

4. Show pre-spend enforcement (2:00-2:35).

   ```bash
   curl -X POST http://127.0.0.1:8787/guard -H "content-type: application/json" -H "authorization: Bearer dev-gateway-token" -d '{"agent":"research-bot","rail":"api_x402","provider":"x402","merchant":"0xtool","service":"/scrape","amount":1.5,"budget":"team-research"}'
   ```

   Repeat with `"amount": 9` to show a deny. Refresh the dashboard to show the
   decision in the audit section.

5. Close with a provider integration (2:35-3:00). Set a provider key only in the
   gateway terminal, then run `python3 examples/openai_gateway.py`. Explain that the
   agent gets a scoped gateway token while the gateway records spend and applies the
   budget policy before forwarding.
