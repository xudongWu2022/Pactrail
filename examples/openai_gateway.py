"""OpenAI SDK-compatible HTTP request through the local spend gateway."""
from __future__ import annotations

import json
import os
import urllib.request


request = urllib.request.Request(
    "http://127.0.0.1:8787/openai/v1/chat/completions",
    data=json.dumps({
        "model": "gpt-4.1-mini",
        "messages": [{"role": "user", "content": "Summarize this receipt."}],
    }).encode(),
    headers={
        "content-type": "application/json",
        "authorization": f"Bearer {os.environ['SPEND_GATEWAY_TOKEN']}",
        "x-agent-id": "research-bot",
        "x-budget-id": "team-research",
    },
    method="POST",
)
with urllib.request.urlopen(request) as response:
    print(response.read().decode())
