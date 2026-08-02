"""Verify an x402 resource and print its public payment requirements safely."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


request = urllib.request.Request(
    "http://127.0.0.1:8787/x402/scraper-paid",
    headers={"x-agent-id": "research-bot", "x-budget-id": "team-research"},
)
try:
    urllib.request.urlopen(request)
except urllib.error.HTTPError as error:
    if error.code != 402:
        raise
    print(json.dumps(json.loads(error.headers["payment-required"]), indent=2))
