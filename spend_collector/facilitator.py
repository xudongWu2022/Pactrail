"""Small, dependency-free x402 facilitator adapter layer."""
from __future__ import annotations

import json
import os
import urllib.request


class FacilitatorError(ValueError):
    pass


def facilitator_headers(auth_env: str | None = None) -> dict[str, str]:
    """Read a pre-minted bearer credential from the environment, never policy."""
    token = os.environ.get(auth_env or "", "").strip() if auth_env else ""
    return {"authorization": f"Bearer {token}"} if token else {}


def fetch_supported(base_url: str, *, auth_env: str | None = None, timeout: float = 10) -> dict:
    url = base_url.rstrip("/") + "/supported"
    req = urllib.request.Request(url, headers=facilitator_headers(auth_env), method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        value = json.load(response)
    if not isinstance(value, dict) or not isinstance(value.get("kinds"), list):
        raise FacilitatorError("facilitator /supported response must contain kinds[]")
    return value


def supports(capabilities: dict, *, version: int, scheme: str, network: str) -> bool:
    for kind in capabilities.get("kinds", []):
        if not isinstance(kind, dict):
            continue
        if int(kind.get("x402Version", 0)) != int(version) or kind.get("scheme") != scheme:
            continue
        advertised = str(kind.get("network", ""))
        if advertised == network or advertised in {"*", network.split(":", 1)[0] + ":*"}:
            return True
    return False


def require_supported(base_url: str, *, version: int, scheme: str, network: str,
                      auth_env: str | None = None, timeout: float = 10) -> dict:
    capabilities = fetch_supported(base_url, auth_env=auth_env, timeout=timeout)
    if not supports(capabilities, version=version, scheme=scheme, network=network):
        raise FacilitatorError(
            f"facilitator does not support x402 v{version} {scheme} on {network}"
        )
    return capabilities
