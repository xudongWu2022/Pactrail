# Real Base Sepolia Acceptance

This is an opt-in acceptance procedure. Do not use a mainnet asset or an
unbounded wallet for this demo.

1. Fund a non-custodial test wallet with Base Sepolia ETH and test USDC.
2. Set `PACTRAIL_CAPABILITY_SECRET` and the gateway's administrator credential
   only in the gateway environment. Configure an x402 resource with the real
   Base Sepolia USDC address, an approved `pay_to`, `network: eip155:84532`,
   and a facilitator that preflights the selected V2 scheme.
3. Mint a session with a cap at or below `$0.10`, then mint a capability that
   permits exactly that resource and scheme.
4. Use the separate CDP non-custodial UI or another external x402 signer to sign
   the quote produced by `PactrailClient`. Never put wallet keys in the Python
   SDK, policy file or Agent environment.
5. Verify the safe Pactrail receipt: it includes request, session, agent,
   budget, scheme, authorization, usage, settlement, and facilitator/chain
   transaction reference. For `upto`, verify that authorization, usage,
   settlement and release values agree before treating the run as accepted.

The normal test suite uses only the local sandbox. A real testnet transaction is
an operator-run acceptance check, not CI.
