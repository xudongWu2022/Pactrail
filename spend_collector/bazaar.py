"""Fail-closed local policy filtering for x402 Bazaar discovery results."""
from __future__ import annotations

import re
import json
import urllib.parse
import urllib.request


def candidates(payload) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("items", "resources", "data"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
    raise ValueError("Bazaar input must be an array or an object containing items/resources/data")


def _requirements(resource: dict) -> dict:
    value = resource.get("paymentRequirements") or resource.get("payment_requirements") or resource.get("accepts") or {}
    if isinstance(value, list):
        value = value[0] if value else {}
    return value if isinstance(value, dict) else {}


def _price_usd(resource: dict, requirements: dict) -> float | None:
    value = resource.get("priceUsd", resource.get("price_usd", resource.get("price", requirements.get("price"))))
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        match = re.fullmatch(r"\s*\$?([0-9]+(?:\.[0-9]+)?)\s*", value)
        if match:
            return float(match.group(1))
    return None


def filter_resources(payload, policy: dict) -> list[dict]:
    """Evaluate discovery candidates against an explicit allow policy.

    Unknown fields are denied only when that policy dimension is configured. This
    keeps discovery safe while still accepting different Bazaar response versions.
    """
    cfg = policy.get("bazaar_policy", policy)
    allowed_networks = set(map(str, cfg.get("allowed_networks", [])))
    allowed_schemes = set(map(str, cfg.get("allowed_schemes", [])))
    allowed_assets = {str(v).lower() for v in cfg.get("allowed_assets", [])}
    allowed_pay_to = {str(v).lower() for v in cfg.get("allowed_pay_to", [])}
    approved_merchants = {str(v).lower() for v in cfg.get("approved_merchants", [])}
    max_price = cfg.get("max_usd_price")
    out: list[dict] = []
    for item in candidates(payload):
        req = _requirements(item)
        network = str(req.get("network", item.get("network", "")))
        scheme = str(req.get("scheme", item.get("scheme", "")))
        asset = str(req.get("asset", item.get("asset", "")))
        pay_to = str(req.get("payTo", req.get("pay_to", item.get("payTo", item.get("pay_to", "")))))
        merchant = str(item.get("merchant", item.get("merchantId", item.get("provider", pay_to))))
        price = _price_usd(item, req)
        reasons: list[str] = []
        if allowed_networks and network not in allowed_networks:
            reasons.append(f"network {network or 'unknown'} is not allowed")
        if allowed_schemes and scheme not in allowed_schemes:
            reasons.append(f"scheme {scheme or 'unknown'} is not allowed")
        if allowed_assets and asset.lower() not in allowed_assets:
            reasons.append(f"asset {asset or 'unknown'} is not allowed")
        if allowed_pay_to and pay_to.lower() not in allowed_pay_to:
            reasons.append(f"payTo {pay_to or 'unknown'} is not allowlisted")
        if approved_merchants and merchant.lower() not in approved_merchants:
            reasons.append(f"merchant {merchant or 'unknown'} is not approved")
        if max_price is not None and (price is None or price > float(max_price)):
            detail = "unavailable" if price is None else f"${price:.6g}"
            reasons.append(f"price {detail} exceeds or cannot satisfy max_usd_price ${float(max_price):.6g}")
        out.append({
            "allowed": not reasons,
            "reasons": reasons or ["Bazaar policy checks passed"],
            "resource": item.get("resource", item.get("url", "")),
            "merchant": merchant,
            "network": network,
            "scheme": scheme,
            "asset": asset,
            "pay_to": pay_to,
            "price_usd": price,
        })
    return out


def fetch_resources(base_url: str = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources",
                    *, limit: int = 100, offset: int = 0, timeout: float = 15):
    query = urllib.parse.urlencode({"type": "http", "limit": limit, "offset": offset})
    with urllib.request.urlopen(base_url + "?" + query, timeout=timeout) as response:
        return json.load(response)


def approved_gateway_resources(payload, policy: dict) -> dict:
    """Create reviewable x402_resources config from only approved Bazaar results."""
    original = {str(item.get("resource", item.get("url", ""))): item for item in candidates(payload)}
    resources: dict[str, dict] = {}
    for row in filter_resources(payload, policy):
        if not row["allowed"]:
            continue
        item = original.get(str(row["resource"]), {})
        resource_id = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(row["resource"]).split("//")[-1]).strip("-")[:80]
        requirements = _requirements(item)
        resources[resource_id] = {
            "url": row["resource"], "method": str(item.get("method", "POST")).upper(),
            "amount": float(item.get("price", 0) or 0) if isinstance(item.get("price"), (int, float)) else 0,
            "scheme": row["scheme"], "asset": row["asset"], "pay_to": row["pay_to"],
            "network": row["network"], "merchant": row["merchant"],
            "service": str(item.get("description", resource_id)), "preflight_supported": True,
        }
        if "amount" in requirements:
            resources[resource_id]["amount_units"] = str(requirements["amount"])
    return resources
