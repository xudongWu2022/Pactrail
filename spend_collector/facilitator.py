"""Small, dependency-free x402 facilitator adapter layer."""
from __future__ import annotations

import json
import os
import subprocess
import urllib.request


class FacilitatorError(ValueError):
    pass


def facilitator_headers(auth_env: str | None = None) -> dict[str, str]:
    """Read a pre-minted bearer credential from the environment, never policy."""
    token = os.environ.get(auth_env or "", "").strip() if auth_env else ""
    return {"authorization": f"Bearer {token}"} if token else {}


def _cdp_cli(action: str, payload: dict | None = None, *, environment: str = "", timeout: float = 30) -> dict:
    """Use the operator's configured CDP CLI without exposing its API key to Pactrail."""
    command = ["cdp"]
    if environment:
        command.extend(["--env", environment])
    command.extend(["x402", action])
    if payload:
        for key in ("x402Version", "paymentPayload", "paymentRequirements"):
            if key in payload:
                command.append(f"{key}:={json.dumps(payload[key], separators=(',', ':'))}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FacilitatorError(f"CDP CLI {action} failed to start: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise FacilitatorError(f"CDP CLI x402 {action} failed: {detail}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise FacilitatorError(f"CDP CLI x402 {action} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise FacilitatorError(f"CDP CLI x402 {action} response must be an object")
    return value


def cdp_cli_x402(action: str, payload: dict, *, environment: str = "", timeout: float = 30) -> dict:
    if action not in {"verify", "settle"}:
        raise FacilitatorError(f"unsupported CDP CLI x402 action: {action}")
    return _cdp_cli(action, payload, environment=environment, timeout=timeout)


def fetch_supported(base_url: str, *, auth_env: str | None = None, mode: str = "http",
                    cdp_environment: str = "", timeout: float = 10) -> dict:
    if mode == "cdp-cli":
        value = _cdp_cli("supported", environment=cdp_environment, timeout=timeout)
        if not isinstance(value.get("kinds"), list):
            raise FacilitatorError("CDP CLI x402 supported response must contain kinds[]")
        return value
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
                      auth_env: str | None = None, mode: str = "http", cdp_environment: str = "",
                      timeout: float = 10) -> dict:
    capabilities = fetch_supported(base_url, auth_env=auth_env, mode=mode,
                                  cdp_environment=cdp_environment, timeout=timeout)
    if not supports(capabilities, version=version, scheme=scheme, network=network):
        raise FacilitatorError(
            f"facilitator does not support x402 v{version} {scheme} on {network}"
        )
    return capabilities
