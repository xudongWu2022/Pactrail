"""Anthropic Messages API request through the local spend gateway."""
from __future__ import annotations

import json
import os
import urllib.request


request = urllib.request.Request(
    "http://127.0.0.1:8787/anthropic/v1/messages",
    data=json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 128,
        "messages": [{"role": "user", "content": "Summarize this receipt."}],
    }).encode(),
    headers={
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
        "authorization": f"Bearer {os.environ['SPEND_GATEWAY_TOKEN']}",
        "x-agent-id": "research-bot",
        "x-budget-id": "team-research",
    },
    method="POST",
)
with urllib.request.urlopen(request) as response:
    print(response.read().decode())
