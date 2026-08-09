"""Pactrail gateway, control-plane demo, and observability CLI."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone

from .adapters import from_llm_usage, from_stripe_events, from_usdc_transfers, from_x402_settlements
from .detectors import run_all
from .gateway import (
    GuardDecision,
    GuardRequest,
    PolicyError,
    audit_config as build_audit_config,
    cap_for_request,
    decide,
    inspect_content,
    record_forwarded_spend,
    record_target_spend,
    rate_cap_for_request,
    record_x402_settlement,
    require_valid_policy,
    validate_policy as validate_policy_data,
    worst_case_amount,
)
from .providers import llm_provider
from .report import render
from .scenarios import ScenarioError, render_report, run_scenarios
from .store import SpendStore
from .facilitator import FacilitatorError, cdp_cli_x402, require_supported
from .bazaar import approved_gateway_resources, fetch_resources, filter_resources
from .x402_sandbox import x402_sandbox
from .capabilities import CapabilityError, mint_capability, verify_capability

_ROOT = Path(__file__).resolve().parent.parent
_FIXTURES = _ROOT / "fixtures"
DEFAULT_MAX_REQUEST_BYTES = 10 * 1024 * 1024


class PayloadTooLarge(ValueError):
    pass


def _load_fixture(name: str):
    with open(_FIXTURES / name, encoding="utf-8") as f:
        return json.load(f)


def _load_json_file(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _load_config(path: str | Path | None) -> dict:
    if not path:
        return {}
    return _load_json_file(path)


def _load_wallet_map(path: str | Path | None = None, config: dict | None = None,
                     base_dir: str | Path | None = None) -> dict:
    data: dict = {}
    config = config or {}
    def resolve(value: str | Path) -> Path:
        p = Path(value)
        return p if p.is_absolute() or base_dir is None else Path(base_dir) / p
    if path:
        data = _load_json_file(resolve(path))
    elif config.get("wallet_map_file"):
        data = _load_json_file(resolve(config["wallet_map_file"]))
    elif isinstance(config.get("wallets"), dict):
        data = config["wallets"]
    elif isinstance(config.get("wallet_map"), dict):
        data = config["wallet_map"]
    if isinstance(data.get("wallets"), dict):
        data = data["wallets"]
    return {str(k).lower(): v for k, v in data.items()}


def _load_budgets(default: dict[str, float] | None = None) -> dict[str, float]:
    path = os.environ.get("SPEND_BUDGETS_FILE")
    if not path:
        return dict(default or {})
    data = _load_json_file(path)
    return {str(k): float(v) for k, v in data.items()}


def _budgets_from_config(config: dict, default: dict[str, float] | None = None) -> dict[str, float]:
    budgets = config.get("budgets")
    if isinstance(budgets, dict):
        return {str(k): float(v) for k, v in budgets.items()}
    return _load_budgets(default)


def _rail_config(config: dict, name: str) -> dict:
    rails = config.get("rails")
    if isinstance(rails, dict) and isinstance(rails.get(name), dict):
        return rails[name]
    if isinstance(config.get(name), dict):
        return config[name]
    return {}


def _enabled(cfg: dict, default: bool = True) -> bool:
    return bool(cfg.get("enabled", default))


def _load_id_list(path: str | Path | None = None, values: list[str] | None = None) -> list[str]:
    out = [str(v).strip() for v in (values or []) if str(v).strip()]
    if not path:
        return out
    p = Path(path)
    text = p.read_text(encoding="utf-8").strip()
    if not text:
        return out
    if p.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("generation_ids") or data.get("ids") or []
        out.extend(str(v).strip() for v in data if str(v).strip())
    else:
        out.extend(line.strip() for line in text.splitlines() if line.strip())
    return out


def _with_stream_usage(raw: bytes) -> bytes:
    """Streamed chat responses omit token usage, so streamed spend can't be priced.
    For a `stream: true` body, ask the provider to emit a final usage chunk
    (OpenAI-compatible: stream_options.include_usage). Non-stream bodies pass through.
    """
    try:
        data = json.loads(raw or b"{}")
    except (ValueError, TypeError):
        return raw
    if not isinstance(data, dict) or not data.get("stream"):
        return raw
    opts = dict(data["stream_options"]) if isinstance(data.get("stream_options"), dict) else {}
    if opts.get("include_usage"):
        return raw
    opts["include_usage"] = True
    data["stream_options"] = opts
    return json.dumps(data).encode()


def _usage_body_from_sse(tail: bytes) -> bytes | None:
    """Pull the final usage-bearing SSE chunk from a streamed response tail and return
    a synthetic non-stream body {id, model, usage} that record_forwarded_spend can
    price. Returns None if the stream carried no usage (nothing to record).
    """
    found = None
    for line in tail.decode("utf-8", "ignore").splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        chunk = line[len("data:"):].strip()
        if not chunk or chunk == "[DONE]":
            continue
        try:
            obj = json.loads(chunk)
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get("usage"):
            found = obj
    if found is None:
        return None
    return json.dumps({"id": found.get("id"), "model": found.get("model"),
                       "usage": found["usage"]}).encode()


def _is_event_stream(content_type: str) -> bool:
    """A forwarded response needs SSE usage-teeing only if it is a real event
    stream. Chunked transfer-encoding is just HTTP framing (OpenAI sends ordinary
    JSON chunked too) and must NOT trigger stream handling, or the response gets
    SSE-parsed, finds no usage, and the spend goes unrecorded.
    """
    return "text/event-stream" in (content_type or "").lower()


def _print_summary(store: SpendStore) -> None:
    print(f"\nTotal agent spend: ${store.total():.4f}   (one ledger, all rails)\n")
    print("By agent x rail:")
    for r in store.by("x_agent_id", "rail"):
        print(f"  {r['x_agent_id']:<13} {r['rail']:<10} ${r['spend']:.4f}  ({r['events']} events)")


def _alert_row(alert) -> dict:
    return {
        "kind": alert.kind,
        "subject": alert.subject,
        "detail": alert.detail,
        "severity": alert.severity,
        "value": alert.value,
    }


def _run_summary(store: SpendStore, alerts: list, budgets: dict[str, float]) -> dict:
    return {
        "total_spend": store.total(),
        "events": store.db.execute("SELECT COUNT(*) FROM spend_events").fetchone()[0],
        "agents": store.db.execute("SELECT COUNT(DISTINCT x_agent_id) FROM spend_events").fetchone()[0],
        "rails": [r["rail"] for r in store.by("rail")],
        "budgets": budgets,
        "alerts": {
            "total": len(alerts),
            "high": sum(1 for a in alerts if a.severity == "high"),
            "warn": sum(1 for a in alerts if a.severity == "warn"),
        },
    }


def _write_json_artifact(path: str | Path, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def _decode_x402_header(value: str) -> dict:
    import base64
    raw = (value or "").strip()
    if not raw:
        raise ValueError("missing payment payload")
    try:
        data = json.loads(raw)
    except ValueError:
        padded = raw + "=" * (-len(raw) % 4)
        data = json.loads(base64.b64decode(padded).decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("payment payload must be an object")
    return data


def _x402_amount_units(resource: dict) -> str:
    if resource.get("amount_units") is not None:
        return str(resource["amount_units"])
    decimals = int(resource.get("asset_decimals", 6))
    return str(int(round(float(resource["amount"]) * (10 ** decimals))))


def _x402_scheme(resource: dict) -> str:
    policy = resource.get("payment_policy") or {}
    return str(policy.get("scheme", resource.get("scheme", "exact")))


def _x402_authorization_units(resource: dict) -> str:
    """Amount the wallet may authorize. It is deliberately not always spend."""
    policy = resource.get("payment_policy") or {}
    if _x402_scheme(resource) in {"upto", "batch-settlement"}:
        return str(policy["authorization_limit_units"])
    return _x402_amount_units(resource)


def _x402_payment_requirements(resource: dict) -> dict:
    return {
        "scheme": _x402_scheme(resource),
        "network": str(resource.get("network", "eip155:8453")),
        "asset": str(resource["asset"]),
        "amount": _x402_authorization_units(resource),
        "payTo": str(resource["pay_to"]),
        "maxTimeoutSeconds": int(resource.get("max_timeout_seconds", 60)),
        "extra": {
            "name": str(resource.get("asset_name", "USDC")),
            "version": str(resource.get("asset_version", "2")),
        },
    }


def _x402_public_requirements(resource_id: str, resource: dict, requirements: dict) -> dict:
    return {
        "x402Version": int(resource.get("x402_version", 2)),
        # V2 requires a ResourceInfo object and an accepts array. Do not replace
        # these with a project-specific resource id: @x402/fetch validates this
        # exact wire shape before it asks a wallet to sign.
        "resource": {
            "url": str(resource.get("resource_url") or resource.get("url") or ""),
            "description": str(resource.get("description") or resource.get("service") or resource_id),
            "mimeType": str(resource.get("mime_type", "application/json")),
        },
        "accepts": [requirements],
    }


def _x402_payment_binding_errors(payment_payload: dict, requirements: dict, resource: dict) -> list[str]:
    accepted = payment_payload.get("accepted")
    if not isinstance(accepted, dict):
        return ["payment payload missing accepted requirements"]
    errors: list[str] = []
    for key in ("scheme", "network", "asset", "amount", "payTo"):
        if str(accepted.get(key, "")) != str(requirements.get(key, "")):
            errors.append(f"payment accepted.{key} does not match requirements")

    resource_payload = payment_payload.get("resource")
    if isinstance(resource_payload, dict):
        signed_url = str(resource_payload.get("url") or "")
        required_url = str(resource.get("resource_url") or resource.get("url") or "")
        if signed_url and required_url and signed_url != required_url:
            errors.append("payment resource.url does not match configured resource")
    else:
        errors.append("payment payload missing resource binding")
    return errors


def _x402_settlement_units(settle_result: dict, authorization_limit_units: str, scheme: str) -> str:
    """Read the actual charge reported by the facilitator and enforce scheme semantics."""
    extra = settle_result.get("extra") or {}
    raw = extra.get("chargedAmount", settle_result.get("amount", authorization_limit_units))
    try:
        settled = int(str(raw))
        authorized = int(str(authorization_limit_units))
    except (TypeError, ValueError) as exc:
        raise ValueError("facilitator returned a non-integer atomic settlement amount") from exc
    if settled < 0 or settled > authorized:
        raise ValueError("facilitator settlement exceeds the x402 authorization limit")
    if scheme == "exact" and settled != authorized:
        raise ValueError("exact x402 settlement must equal the authorized amount")
    return str(settled)


def _facilitator_request_json(url: str, payload: dict, resource: dict) -> dict:
    if resource.get("facilitator_mode") == "cdp-cli":
        action = urllib.parse.urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
        return cdp_cli_x402(action, payload, environment=str(resource.get("facilitator_cdp_env", "")),
                            timeout=float(resource.get("timeout", 30)))
    headers = {"content-type": "application/json"}
    auth_env = resource.get("facilitator_auth_env")
    if auth_env and os.environ.get(str(auth_env)):
        headers["authorization"] = f"Bearer {os.environ[str(auth_env)]}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=float(resource.get("timeout", 30))) as resp:
        data = json.load(resp)
    if not isinstance(data, dict):
        raise ValueError("facilitator response must be a JSON object")
    return data


def check_facilitator(args) -> dict:
    """Fail closed when a facilitator does not advertise a resource's payment kind."""
    try:
        capabilities = require_supported(
            args.url, version=args.version, scheme=args.scheme, network=args.network,
            auth_env=args.auth_env, timeout=args.timeout,
        )
    except (FacilitatorError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        raise SystemExit(1)
    result = {"ok": True, "url": args.url, "version": args.version,
              "scheme": args.scheme, "network": args.network,
              "extensions": capabilities.get("extensions", [])}
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def filter_bazaar_cmd(args) -> list[dict]:
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    policy = _load_policy(args.policy)
    results = filter_resources(payload, policy)
    output = {"allowed": sum(r["allowed"] for r in results), "denied": sum(not r["allowed"] for r in results),
              "resources": results}
    if args.out:
        _write_json_artifact(args.out, output)
    print(json.dumps(output, indent=2, sort_keys=True))
    return results


def fetch_bazaar_cmd(args) -> dict:
    payload = fetch_resources(args.url, limit=args.limit, offset=args.offset, timeout=args.timeout)
    _write_json_artifact(args.out, payload)
    print(f"Wrote {args.out}")
    return payload


def adopt_bazaar_cmd(args) -> dict:
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    resources = approved_gateway_resources(payload, _load_policy(args.policy))
    _write_json_artifact(args.out, {"x402_resources": resources})
    print(f"Wrote {len(resources)} approved x402 resource(s) to {args.out}")
    return resources


def _alert_payload(alerts: list, summary: dict) -> dict | None:
    """Slack-compatible / generic JSON for the high-severity alerts, or None."""
    high = [a for a in alerts if a.severity == "high"]
    if not high:
        return None
    lines = "\n".join(f"[{a.severity}] {a.kind} {a.subject}: {a.detail}" for a in high)
    return {"text": f"agent-spend: {len(high)} high alert(s)\n{lines}",
            "alerts": [_alert_row(a) for a in high], "summary": summary}


_ALERT_HOSTS = (  # webhook host substring -> platform envelope
    ("hooks.slack.com", "slack"),
    ("discord", "discord"),
    ("feishu", "feishu"), ("larksuite", "feishu"), ("larkoffice", "feishu"),
    ("office.com", "teams"),
)


def _alert_platform(url: str) -> str:
    """Notification platform for a webhook URL. SPEND_ALERT_FORMAT overrides; else
    auto-detect from the host; else a generic JSON POST.
    """
    override = os.environ.get("SPEND_ALERT_FORMAT", "").strip().lower()
    if override:
        return override
    host = urllib.parse.urlsplit(url).netloc.lower()
    for needle, platform in _ALERT_HOSTS:
        if needle in host:
            return platform
    return "generic"


def _format_alert(platform: str, text: str, structured: dict) -> dict:
    """Wrap the alert text in each platform's expected envelope."""
    if platform == "slack":
        return {"text": text}
    if platform == "discord":
        return {"content": text[:1900]}  # Discord caps content at 2000 chars
    if platform == "feishu":  # Feishu / Lark
        return {"msg_type": "text", "content": {"text": text}}
    if platform == "teams":
        return {"@type": "MessageCard", "@context": "http://schema.org/extensions",
                "title": "agent-spend alerts", "text": text}
    return structured  # generic: full {text, alerts, summary}


def _triage_alerts(alerts: list, summary: dict) -> str | None:
    """Opt-in AI triage: ask an LLM for the likely cause + one recommended action for
    the high-severity alerts. Enabled by SPEND_TRIAGE_MODEL; uses an OpenAI-compatible
    endpoint (SPEND_TRIAGE_BASE_URL, default OpenAI). For the default OpenAI URL it
    uses SPEND_TRIAGE_API_KEY or OPENAI_API_KEY. If the base URL points at a local
    gateway, it uses SPEND_TRIAGE_API_KEY or SPEND_GATEWAY_TOKEN instead. Sends only
    alert metadata; best-effort, None on any failure.
    """
    model = os.environ.get("SPEND_TRIAGE_MODEL")
    high = [a for a in alerts if a.severity == "high"]
    base = os.environ.get("SPEND_TRIAGE_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    host = (urllib.parse.urlsplit(base).hostname or "").lower()
    local_gateway = host in {"127.0.0.1", "localhost", "::1"}
    key = (
        os.environ.get("SPEND_TRIAGE_API_KEY")
        or (os.environ.get("SPEND_GATEWAY_TOKEN") if local_gateway else os.environ.get("OPENAI_API_KEY"))
    )
    if not model or not key or not high:
        return None
    facts = {"alerts": [_alert_row(a) for a in high],
             "total_spend": summary.get("total_spend"), "budgets": summary.get("budgets")}
    body = {
        "model": model, "max_tokens": 160, "temperature": 0,
        "messages": [
            {"role": "system", "content": "You are an agent-spend security analyst. Given "
             "anomaly alerts (metadata only), reply in 2-3 sentences: the most likely cause "
             "and one concrete recommended action. No preamble."},
            {"role": "user", "content": json.dumps(facts)},
        ],
    }
    req = urllib.request.Request(
        f"{base}/chat/completions", data=json.dumps(body).encode(),
        headers={"content-type": "application/json", "authorization": f"Bearer {key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        return (data["choices"][0]["message"]["content"] or "").strip() or None
    except (urllib.error.URLError, OSError, KeyError, ValueError, IndexError):
        return None


def _notify_alerts(alerts: list, summary: dict) -> bool:
    """POST high-severity alerts to SPEND_ALERT_WEBHOOK (opt-in). Formats for Slack,
    Discord, Feishu/Lark, Teams, or a generic JSON body (auto-detected from the URL,
    or SPEND_ALERT_FORMAT), and appends opt-in AI triage. Metadata only, never breaks a run.
    """
    url = os.environ.get("SPEND_ALERT_WEBHOOK")
    payload = _alert_payload(alerts, summary)
    if not url or payload is None:
        return False
    triage = _triage_alerts(alerts, summary)
    if triage:
        payload = {**payload, "text": f"{payload['text']}\n\n\U0001f50e {triage}", "triage": triage}
    body = _format_alert(_alert_platform(url), payload["text"], payload)
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"content-type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            return True
    except (urllib.error.URLError, OSError):
        return False


def _finish_run(store: SpendStore, budgets: dict[str, float], out_dir: str | Path = ".") -> None:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    _print_summary(store)
    alerts = run_all(store, budgets)
    print("\nAlerts:")
    if alerts:
        for a in alerts:
            print(f"  [{a.severity:<4}] {a.kind:<22} {a.subject:<13} {a.detail}")
    else:
        print("  none")

    report_path = out_path / "report.html"
    alerts_path = out_path / "alerts.json"
    summary_path = out_path / "run-summary.json"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(render(store, budgets, alerts))
    print(f"\nWrote {report_path}  (open in a browser)")
    summary = _run_summary(store, alerts, budgets)
    _write_json_artifact(alerts_path, [_alert_row(a) for a in alerts])
    _write_json_artifact(summary_path, summary)
    print(f"Wrote {alerts_path} and {summary_path}")
    if _notify_alerts(alerts, summary):
        print("Sent high-severity alerts to SPEND_ALERT_WEBHOOK")


def demo(out_dir: str | Path = ".", db_path: str | Path = "spend.db") -> None:
    """Run the product demo: LLM + x402 + USDC + Stripe -> ledger -> security signals."""
    llm = _load_fixture("llm_usage.json")
    x402 = _load_fixture("x402_settlements.json")
    usdc = _load_fixture("usdc_transfers.json")
    stripe = _load_fixture("stripe_events.json")
    budgets = _load_budgets(_load_fixture("budgets.json"))

    with SpendStore(db_path) as store:
        store.ingest(from_llm_usage(llm))
        store.ingest(from_x402_settlements(x402))
        store.ingest(from_usdc_transfers(usdc))
        store.ingest(from_stripe_events(stripe))
        _finish_run(store, budgets, out_dir)

        alerts = run_all(store, budgets)
        kinds = {a.kind for a in alerts}
        expected = {
            "spend_spike",
            "budget_burn",
            "budget_burn_rate",
            "spend_per_task",
            "new_key_spike",
            "new_merchant_provider",
        }
        assert 36.10 < store.total() < 36.12, store.total()
        assert expected <= kinds, kinds
        assert any(a.kind == "spend_spike" and a.subject == "research-bot" for a in alerts), alerts
        assert any(a.kind == "new_key_spike" and a.subject == "new-key-bot" for a in alerts), alerts
        assert any(a.kind == "new_merchant_provider" and a.subject == "support-bot" for a in alerts), alerts
    print("[self-check] cross-rail ledger + Phase-0 security demo -- OK")

    from .sources import decode_transfer_log
    log = {"topics": ["0x" + "d" * 64, "0x" + "0" * 24 + "11" * 20, "0x" + "0" * 24 + "22" * 20],
           "data": "0x" + format(2_500_000, "064x"), "transactionHash": "0xabc", "blockNumber": "0x10"}
    decoded = decode_transfer_log(log)
    assert decoded["to"] == "0x" + "22" * 20 and decoded["amount_raw"] == 2_500_000
    print("[self-check] x402 Transfer decoder -- OK")

    event = {"id": "evt_1", "created": 1781740800, "type": "payment_intent.succeeded",
             "data": {"object": {"id": "pi_1", "amount_received": 4200, "currency": "usd",
                                  "metadata": {"agent_id": "ops-bot", "budget_id": "team-ops"}}}}
    stripe_event = from_stripe_events([event])[0]
    assert stripe_event.billed_cost == 42.0 and stripe_event.rail == "card"
    print("[self-check] Stripe payment mapping -- OK")


def _seed_control_plane_showcase(store: SpendStore) -> None:
    """Create stable, fictional control-plane records for the live product demo.

    These rows are intentionally ledger-only: they explain the product without
    pretending a testnet payment occurred. Real receipts are still created by
    the gateway/facilitator path.
    """
    existing = store.db.execute(
        "SELECT 1 FROM payment_intents WHERE request_id = 'showcase:paid-search'"
    ).fetchone()
    if existing:
        return

    expiry = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    constraints = {
        "resource_ids": ["market-research-search", "financial-data-snapshot"],
        "merchants": ["atlas-research"],
        "networks": ["eip155:84532"],
        "assets": ["USDC"],
        "schemes": ["exact", "upto"],
    }
    paid_session = store.create_spend_session(
        parent_task="Prepare competitor research brief", budget_id="team-research",
        cap=2.00, expires_at=expiry, constraints=constraints,
    )
    pending_session = store.create_spend_session(
        parent_task="Refresh market data snapshot", budget_id="team-research",
        cap=1.00, expires_at=expiry, constraints=constraints,
    )

    paid_request = "showcase:paid-search"
    paid_guard = GuardRequest(
        x_agent_id="research-bot", rail="api_x402", amount=0.10,
        x_budget_id="team-research", provider_name="x402", service_name="/search",
        x_merchant_id="atlas-research", x_session_id=str(paid_session["session_id"]),
    )
    store.record_gateway_decision(
        request_id=paid_request, req=paid_guard, decision="allow",
        reasons=["budget remaining 1.90", "merchant atlas-research is approved", "Base Sepolia USDC allowed"],
        route_type="x402", route_id="market-research-search",
    )
    store.create_payment_intent(
        request_id=paid_request, session_id=str(paid_session["session_id"]),
        resource_id="market-research-search", agent_id="research-bot", budget_id="team-research",
    )
    approval = store.create_signer_approval(
        request_id=paid_request, signer_id="wallet-ui", quote_hash="a" * 64, body_hash="b" * 64,
        requirements={"scheme": "exact", "network": "eip155:84532", "asset": "USDC"}, expires_at=expiry,
    )
    store.claim_x402_payment(
        paid_request, "market-research-search", "showcase-payment-fingerprint-paid",
        scheme="exact", authorization_limit_units="100000",
    )
    store.account_x402_payment(paid_request, usage_units="75000", settled_units="75000")
    store.update_x402_payment(paid_request, "delivered", transaction_ref="facilitator:demo-settlement-7f2c")
    store.update_payment_intent(paid_request, "delivered")
    store.update_signer_approval(str(approval["approval_id"]), "delivered")

    pending_request = "showcase:pending-snapshot"
    pending_guard = GuardRequest(
        x_agent_id="research-bot", rail="api_x402", amount=0.30,
        x_budget_id="team-research", provider_name="x402", service_name="/snapshot",
        x_merchant_id="atlas-research", x_session_id=str(pending_session["session_id"]),
    )
    store.record_gateway_decision(
        request_id=pending_request, req=pending_guard, decision="allow",
        reasons=["budget reserved before signing", "merchant atlas-research is approved"],
        route_type="x402", route_id="financial-data-snapshot",
    )
    store.create_payment_intent(
        request_id=pending_request, session_id=str(pending_session["session_id"]),
        resource_id="financial-data-snapshot", agent_id="research-bot", budget_id="team-research",
    )
    store.create_signer_approval(
        request_id=pending_request, signer_id="wallet-ui", quote_hash="c" * 64, body_hash="d" * 64,
        requirements={"scheme": "upto", "network": "eip155:84532", "asset": "USDC"}, expires_at=expiry,
    )
    store.update_payment_intent(pending_request, "signer_approval_pending")

    blocked_guard = GuardRequest(
        x_agent_id="research-bot", rail="api_x402", amount=4.50,
        x_budget_id="team-research", provider_name="x402", service_name="/bulk-export",
        x_merchant_id="unknown-payto", x_session_id=str(pending_session["session_id"]),
    )
    store.record_gateway_decision(
        request_id="showcase:blocked-export", req=blocked_guard, decision="deny",
        reasons=["merchant unknown-payto is not approved", "amount 4.50 exceeds agent cap 1.00"],
        route_type="x402", route_id="unreviewed-bulk-export",
    )


def showcase(out_dir: str | Path = "artifacts-showcase", db_path: str | Path = "pactrail-showcase.db") -> None:
    """Generate a static, safe-to-share product showcase without a wallet or API key."""
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    demo(out_dir, db_path)
    budgets = _load_budgets(_load_fixture("budgets.json"))
    with SpendStore(db_path) as store:
        _seed_control_plane_showcase(store)
        report_path = Path(out_dir) / "report.html"
        report_path.write_text(render(store, budgets, run_all(store, budgets)), encoding="utf-8")
    print(f"[showcase] control-plane story written to {report_path}")


def demo_live(out_dir: str | Path = "artifacts-live", db_path: str | Path = "spend-demo.db",
              policy_path: str | Path | None = None, host: str = "127.0.0.1", port: int = 8787) -> None:
    """Seed the fixture ledger, then serve its auto-refreshing dashboard."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    demo(out_path, db_path)
    with SpendStore(db_path) as store:
        _seed_control_plane_showcase(store)
    print(f"\nLive demo dashboard: http://{host}:{port}/dashboard")
    gateway(db_path, policy_path, host, port)


def pull(db_path: str | Path = "spend.db", out_dir: str | Path = ".", days: int = 7,
         provider: str = "anthropic") -> None:
    """Pull real LLM cost data (read-only admin key). provider: anthropic | openai."""
    from .sources import (env_admin_key, env_openai_key, fetch_anthropic_cost_report,
                          fetch_openai_costs, from_llm_cost_rows)
    if provider == "openai":
        key = env_openai_key()
        if not key:
            print("Set OPENAI_ADMIN_KEY to pull OpenAI cost data:\n"
                  "  export OPENAI_ADMIN_KEY=sk-...\n"
                  "  python3 -m pactrail pull --provider openai")
            sys.exit(1)
        rows = fetch_openai_costs(key, days=days)
    else:
        key = env_admin_key()
        if not key:
            print("Set ANTHROPIC_ADMIN_KEY to pull real cost data:\n"
                  "  export ANTHROPIC_ADMIN_KEY=sk-ant-admin01-...\n"
                  "  python3 -m pactrail pull")
            sys.exit(1)
        rows = fetch_anthropic_cost_report(key, days=days)
    with SpendStore(str(db_path)) as store:
        n = store.ingest(from_llm_cost_rows(rows))
        print(f"ingested {n} {provider} cost rows -> {db_path}")
        _finish_run(store, _load_budgets(), out_dir)


def pull_openrouter(db_path: str | Path = "spend.db", out_dir: str | Path = ".",
                    generation_ids: list[str] | None = None,
                    generation_ids_file: str | Path | None = None) -> None:
    """Pull OpenRouter generation metadata by generation id."""
    from .sources import env_openrouter_key, fetch_openrouter_generations, from_openrouter_generation_rows
    key = env_openrouter_key()
    if not key:
        print("Set OPENROUTER_API_KEY to pull OpenRouter generation metadata:\n"
              "  export OPENROUTER_API_KEY=sk-or-...\n"
              "  python3 -m pactrail pull-openrouter --generation-id gen_...")
        sys.exit(1)
    ids = _load_id_list(generation_ids_file, generation_ids)
    if not ids:
        print("Pass at least one OpenRouter generation id:\n"
              "  python3 -m pactrail pull-openrouter --generation-id gen_...\n"
              "  python3 -m pactrail pull-openrouter --generation-ids-file generations.txt")
        sys.exit(1)
    with SpendStore(str(db_path)) as store:
        n = store.ingest(from_openrouter_generation_rows(fetch_openrouter_generations(key, ids)))
        print(f"ingested {n} OpenRouter generations -> {db_path}")
        _finish_run(store, _load_budgets(), out_dir)


def pull_aws(db_path: str | Path = "spend.db", out_dir: str | Path = ".", days: int = 7,
             tag_agent: str = "agent_id", tag_budget: str = "budget_id") -> None:
    """Pull AWS Cost Explorer spend grouped by agent/budget cost allocation tags."""
    from .sources import (
        env_aws_access_key_id, env_aws_secret_access_key, env_aws_session_token,
        fetch_aws_cost_and_usage, from_aws_cost_rows,
    )
    access_key = env_aws_access_key_id()
    secret_key = env_aws_secret_access_key()
    if not access_key or not secret_key:
        print("Set AWS read-only Cost Explorer credentials:\n"
              "  export AWS_ACCESS_KEY_ID=...\n"
              "  export AWS_SECRET_ACCESS_KEY=...\n"
              "  python3 -m pactrail pull-aws")
        sys.exit(1)
    with SpendStore(str(db_path)) as store:
        n = store.ingest(from_aws_cost_rows(fetch_aws_cost_and_usage(
            access_key,
            secret_key,
            session_token=env_aws_session_token(),
            days=days,
            tag_agent=tag_agent,
            tag_budget=tag_budget,
        )))
        print(f"ingested {n} AWS cost rows -> {db_path}")
        _finish_run(store, _load_budgets(), out_dir)


def pull_gcp_billing_file(db_path: str | Path = "spend.db", out_dir: str | Path = ".",
                          billing_export_file: str | Path | None = None,
                          label_agent: str = "agent_id",
                          label_budget: str = "budget_id") -> None:
    """Pull GCP Cloud Billing export rows from a JSON/NDJSON/CSV file."""
    from .sources import load_gcp_billing_export, from_gcp_billing_rows
    if not billing_export_file:
        print("Pass a GCP Billing Export file:\n"
              "  python3 -m pactrail pull-gcp-billing-file --billing-export-file gcp-billing.ndjson")
        sys.exit(1)
    with SpendStore(str(db_path)) as store:
        rows = load_gcp_billing_export(billing_export_file)
        n = store.ingest(from_gcp_billing_rows(rows, label_agent=label_agent, label_budget=label_budget))
        print(f"ingested {n} GCP billing rows -> {db_path}")
        _finish_run(store, _load_budgets(), out_dir)


def _azure_token_from_env_or_sp(env: dict | None = None) -> str | None:
    from .sources import fetch_azure_access_token
    env = env or os.environ
    token = env.get("AZURE_ACCESS_TOKEN")
    if token:
        return token
    tenant_id = env.get("AZURE_TENANT_ID")
    client_id = env.get("AZURE_CLIENT_ID")
    client_secret = env.get("AZURE_CLIENT_SECRET")
    if tenant_id and client_id and client_secret:
        return fetch_azure_access_token(tenant_id, client_id, client_secret)
    return None


def pull_azure(db_path: str | Path = "spend.db", out_dir: str | Path = ".", days: int = 7,
               scope: str | None = None, tag_agent: str = "agent_id",
               tag_budget: str = "budget_id") -> None:
    """Pull Azure Cost Management spend grouped by agent/budget tags."""
    from .sources import fetch_azure_cost_usage, from_azure_cost_rows
    scope = scope or os.environ.get("AZURE_COST_SCOPE")
    if not scope:
        print("Set an Azure Cost Management scope:\n"
              "  export AZURE_COST_SCOPE=/subscriptions/00000000-0000-0000-0000-000000000000\n"
              "  python3 -m pactrail pull-azure --scope \"$AZURE_COST_SCOPE\"")
        sys.exit(1)
    token = _azure_token_from_env_or_sp()
    if not token:
        print("Set Azure read-only Cost Management credentials:\n"
              "  export AZURE_ACCESS_TOKEN=$(az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv)\n"
              "  # or set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET for service principal auth\n"
              "  python3 -m pactrail pull-azure --scope \"$AZURE_COST_SCOPE\"")
        sys.exit(1)
    with SpendStore(str(db_path)) as store:
        n = store.ingest(from_azure_cost_rows(fetch_azure_cost_usage(
            token,
            scope,
            days=days,
            tag_agent=tag_agent,
            tag_budget=tag_budget,
        )))
        print(f"ingested {n} Azure cost rows -> {db_path}")
        _finish_run(store, _load_budgets(), out_dir)


def pull_x402(db_path: str | Path = "spend.db", out_dir: str | Path = ".",
              pay_to: str | None = None, lookback_blocks: int = 2000,
              wallet_map_path: str | Path | None = None) -> None:
    """Pull real x402 settlements (USDC into a merchant address on Base, read-only RPC)."""
    from .sources import env_pay_to, fetch_base_usdc_transfers
    pay_to = pay_to or env_pay_to()
    if not pay_to:
        print("Pass an x402 receiving address (Base USDC):\n"
              "  X402_PAY_TO=0x... python3 -m pactrail pull-x402\n"
              "  python3 -m pactrail pull-x402 --pay-to 0x...")
        sys.exit(1)
    with SpendStore(str(db_path)) as store:
        n = store.ingest(from_x402_settlements(
            fetch_base_usdc_transfers(pay_to, lookback_blocks=lookback_blocks),
            wallet_map=_load_wallet_map(wallet_map_path),
        ))
        print(f"ingested {n} x402 settlements -> {db_path}")
        _finish_run(store, _load_budgets(), out_dir)


def pull_usdc(db_path: str | Path = "spend.db", out_dir: str | Path = ".",
              pay_to: str | None = None, lookback_blocks: int = 2000,
              wallet_map_path: str | Path | None = None) -> None:
    """Pull direct USDC transfers into a wallet on Base (read-only public RPC)."""
    from .sources import env_usdc_pay_to, fetch_base_usdc_transfers
    pay_to = pay_to or env_usdc_pay_to()
    if not pay_to:
        print("Pass a USDC receiving address on Base:\n"
              "  USDC_PAY_TO=0x... python3 -m pactrail pull-usdc\n"
              "  python3 -m pactrail pull-usdc --pay-to 0x...")
        sys.exit(1)
    with SpendStore(str(db_path)) as store:
        n = store.ingest(from_usdc_transfers(
            fetch_base_usdc_transfers(pay_to, lookback_blocks=lookback_blocks),
            wallet_map=_load_wallet_map(wallet_map_path),
        ))
        print(f"ingested {n} USDC transfers -> {db_path}")
        _finish_run(store, _load_budgets(), out_dir)


def pull_stripe(db_path: str | Path = "spend.db", out_dir: str | Path = ".",
                days: int = 7, limit: int = 100) -> None:
    """Pull real card payments via the Stripe Events API (read-only, restricted key)."""
    from .sources import env_stripe_key, fetch_stripe_payment_intent_events
    key = env_stripe_key()
    if not key:
        print("Set STRIPE_SECRET_KEY (restricted read key) to pull card payments:\n"
              "  export STRIPE_SECRET_KEY=rk_live_...\n"
              "  python3 -m pactrail pull-stripe")
        sys.exit(1)
    with SpendStore(str(db_path)) as store:
        n = store.ingest(from_stripe_events(fetch_stripe_payment_intent_events(key, days=days, limit=limit)))
        print(f"ingested {n} Stripe payments -> {db_path}")
        _finish_run(store, _load_budgets(), out_dir)


def _configured_env(cfg: dict, default_name: str) -> str | None:
    name = cfg.get("api_key_env") or default_name
    return os.environ.get(str(name))


def pull_all(config_path: str | Path | None = None, db_path: str | Path | None = None,
             out_dir: str | Path | None = None) -> None:
    """Pull every configured rail into one ledger, then render once."""
    from .sources import (
        env_aws_access_key_id, env_aws_secret_access_key, env_aws_session_token,
        env_pay_to, env_usdc_pay_to, fetch_anthropic_cost_report,
        fetch_aws_cost_and_usage, fetch_azure_access_token, fetch_azure_cost_usage,
        fetch_base_usdc_transfers, fetch_openai_costs, fetch_openrouter_generations,
        fetch_stripe_payment_intent_events, from_aws_cost_rows, from_azure_cost_rows,
        from_gcp_billing_rows, from_llm_cost_rows, from_openrouter_generation_rows,
        load_gcp_billing_export,
    )
    config = _load_config(config_path)
    config_base = Path(config_path).resolve().parent if config_path else None
    db_path = db_path or config.get("db", "spend.db")
    out_dir = out_dir or config.get("out_dir", "artifacts")
    wallet_map = _load_wallet_map(config=config, base_dir=config_base)
    budgets = _budgets_from_config(config)

    with SpendStore(str(db_path)) as store:
        llm_cfg = _rail_config(config, "llm") or _rail_config(config, "llm_token")
        if _enabled(llm_cfg):
            provider = str(llm_cfg.get("provider", config.get("llm_provider", "anthropic")))
            days = int(llm_cfg.get("days", config.get("days", 7)))
            if provider == "openrouter":
                key = _configured_env(llm_cfg, "OPENROUTER_API_KEY")
                ids = _load_id_list(llm_cfg.get("generation_ids_file"), llm_cfg.get("generation_ids") or [])
                if key and ids:
                    n = store.ingest(from_openrouter_generation_rows(fetch_openrouter_generations(key, ids)))
                    print(f"ingested {n} OpenRouter generations -> {db_path}")
                elif not key:
                    print("skipped llm/openrouter: set OPENROUTER_API_KEY or rails.llm.api_key_env")
                else:
                    print("skipped llm/openrouter: set rails.llm.generation_ids or generation_ids_file")
            elif provider == "openai":
                key = _configured_env(llm_cfg, "OPENAI_ADMIN_KEY")
                if key:
                    n = store.ingest(from_llm_cost_rows(fetch_openai_costs(key, days=days)))
                    print(f"ingested {n} openai cost rows -> {db_path}")
                else:
                    print("skipped llm/openai: set OPENAI_ADMIN_KEY or rails.llm.api_key_env")
            else:
                key = _configured_env(llm_cfg, "ANTHROPIC_ADMIN_KEY")
                if key:
                    n = store.ingest(from_llm_cost_rows(fetch_anthropic_cost_report(key, days=days)))
                    print(f"ingested {n} anthropic cost rows -> {db_path}")
                else:
                    print("skipped llm/anthropic: set ANTHROPIC_ADMIN_KEY or rails.llm.api_key_env")

        openrouter_cfg = _rail_config(config, "openrouter")
        if _enabled(openrouter_cfg, default=False):
            key = _configured_env(openrouter_cfg, "OPENROUTER_API_KEY")
            ids = _load_id_list(
                openrouter_cfg.get("generation_ids_file"),
                openrouter_cfg.get("generation_ids") or [],
            )
            if key and ids:
                n = store.ingest(from_openrouter_generation_rows(fetch_openrouter_generations(key, ids)))
                print(f"ingested {n} OpenRouter generations -> {db_path}")
            elif not key:
                print("skipped openrouter: set OPENROUTER_API_KEY or rails.openrouter.api_key_env")
            else:
                print("skipped openrouter: set rails.openrouter.generation_ids or generation_ids_file")

        aws_cfg = _rail_config(config, "aws") or _rail_config(config, "cloud")
        if _enabled(aws_cfg, default=False):
            access_key = os.environ.get(str(aws_cfg.get("access_key_env", "AWS_ACCESS_KEY_ID")))
            secret_key = os.environ.get(str(aws_cfg.get("secret_key_env", "AWS_SECRET_ACCESS_KEY")))
            session_token = os.environ.get(str(aws_cfg.get("session_token_env", "AWS_SESSION_TOKEN")))
            if access_key and secret_key:
                n = store.ingest(from_aws_cost_rows(fetch_aws_cost_and_usage(
                    access_key,
                    secret_key,
                    session_token=session_token or env_aws_session_token(),
                    days=int(aws_cfg.get("days", config.get("days", 7))),
                    tag_agent=str(aws_cfg.get("tag_agent", "agent_id")),
                    tag_budget=str(aws_cfg.get("tag_budget", "budget_id")),
                )))
                print(f"ingested {n} AWS cost rows -> {db_path}")
            else:
                print("skipped aws: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or rails.aws *_env")

        gcp_cfg = _rail_config(config, "gcp")
        if _enabled(gcp_cfg, default=False):
            export_file = gcp_cfg.get("billing_export_file")
            if export_file:
                export_path = Path(export_file)
                if config_base is not None and not export_path.is_absolute():
                    export_path = config_base / export_path
                n = store.ingest(from_gcp_billing_rows(
                    load_gcp_billing_export(export_path),
                    label_agent=str(gcp_cfg.get("label_agent", "agent_id")),
                    label_budget=str(gcp_cfg.get("label_budget", "budget_id")),
                ))
                print(f"ingested {n} GCP billing rows -> {db_path}")
            else:
                print("skipped gcp: set rails.gcp.billing_export_file")

        azure_cfg = _rail_config(config, "azure")
        if _enabled(azure_cfg, default=False):
            scope = azure_cfg.get("scope") or os.environ.get("AZURE_COST_SCOPE")
            token = os.environ.get(str(azure_cfg.get("access_token_env", "AZURE_ACCESS_TOKEN")))
            if not token:
                tenant_id = os.environ.get(str(azure_cfg.get("tenant_id_env", "AZURE_TENANT_ID")))
                client_id = os.environ.get(str(azure_cfg.get("client_id_env", "AZURE_CLIENT_ID")))
                client_secret = os.environ.get(str(azure_cfg.get("client_secret_env", "AZURE_CLIENT_SECRET")))
                if tenant_id and client_id and client_secret:
                    token = fetch_azure_access_token(tenant_id, client_id, client_secret)
            if scope and token:
                n = store.ingest(from_azure_cost_rows(fetch_azure_cost_usage(
                    token,
                    str(scope),
                    days=int(azure_cfg.get("days", config.get("days", 7))),
                    tag_agent=str(azure_cfg.get("tag_agent", "agent_id")),
                    tag_budget=str(azure_cfg.get("tag_budget", "budget_id")),
                )))
                print(f"ingested {n} Azure cost rows -> {db_path}")
            elif not scope:
                print("skipped azure: set rails.azure.scope or AZURE_COST_SCOPE")
            else:
                print("skipped azure: set AZURE_ACCESS_TOKEN or service principal env vars")

        x402_cfg = _rail_config(config, "x402")
        if _enabled(x402_cfg):
            pay_to = x402_cfg.get("pay_to") or env_pay_to()
            if pay_to:
                rows = fetch_base_usdc_transfers(
                    str(pay_to),
                    lookback_blocks=int(x402_cfg.get("lookback_blocks", config.get("lookback_blocks", 2000))),
                )
                n = store.ingest(from_x402_settlements(rows, wallet_map=wallet_map))
                print(f"ingested {n} x402 settlements -> {db_path}")
            else:
                print("skipped x402: set rails.x402.pay_to or X402_PAY_TO")

        usdc_cfg = _rail_config(config, "usdc") or _rail_config(config, "stablecoin")
        if _enabled(usdc_cfg):
            pay_to = usdc_cfg.get("pay_to") or env_usdc_pay_to()
            if pay_to:
                rows = fetch_base_usdc_transfers(
                    str(pay_to),
                    lookback_blocks=int(usdc_cfg.get("lookback_blocks", config.get("lookback_blocks", 2000))),
                )
                n = store.ingest(from_usdc_transfers(rows, wallet_map=wallet_map))
                print(f"ingested {n} USDC transfers -> {db_path}")
            else:
                print("skipped usdc: set rails.usdc.pay_to, USDC_PAY_TO, or X402_PAY_TO")

        stripe_cfg = _rail_config(config, "stripe") or _rail_config(config, "card")
        if _enabled(stripe_cfg):
            key = _configured_env(stripe_cfg, "STRIPE_SECRET_KEY")
            if key:
                n = store.ingest(from_stripe_events(fetch_stripe_payment_intent_events(
                    key,
                    days=int(stripe_cfg.get("days", config.get("days", 7))),
                    limit=int(stripe_cfg.get("limit", 100)),
                )))
                print(f"ingested {n} Stripe payments -> {db_path}")
            else:
                print("skipped stripe: set STRIPE_SECRET_KEY or rails.stripe.api_key_env")

        _finish_run(store, budgets, out_dir)


def report(db_path: str | Path = "spend.db", out_dir: str | Path = ".") -> None:
    """Regenerate report.html from an existing SQLite ledger."""
    if not Path(db_path).exists():
        print(f"ledger not found: {db_path}")
        sys.exit(1)
    with SpendStore(str(db_path)) as store:
        if store.total() == 0:
            print(f"{db_path} is empty -- run a pull first (pull / pull-x402 / pull-usdc / pull-stripe).")
            sys.exit(1)
        print(f"loaded ledger {db_path}")
        _finish_run(store, _load_budgets(), out_dir)


def _load_policy(path: str | Path | None) -> dict:
    if not path:
        path = os.environ.get("SPEND_POLICY_FILE")
    if not path:
        return {}
    return _load_json_file(path)


def _request_id(value: str | None = None) -> str:
    return value or f"req:{uuid.uuid4().hex}"


def _decide_and_record(store: SpendStore, policy: dict, req: GuardRequest, *,
                       request_id: str | None = None, route_type: str = "guard",
                       route_id: str = "", session_cap: float | None = None) -> dict:
    request_id = _request_id(request_id)
    existing = store.gateway_decision_as_dict(request_id)
    if existing:
        return existing
    decision = decide(store, policy, req)
    ttl = int(policy.get("reservation_ttl_seconds", 900))
    cap = cap_for_request(policy, req)
    rate_cap = rate_cap_for_request(policy, req)
    store.reserve_and_record_gateway_decision(
        request_id=request_id,
        req=req,
        decision=decision.decision,
        reasons=decision.reasons,
        route_type=route_type,
        route_id=route_id,
        ttl_seconds=ttl,
        cap=cap,
        rate_cap=rate_cap,
        session_cap=session_cap,
    )
    return store.gateway_decision_as_dict(request_id) or decision.as_dict()


def _record_gateway_deny(store: SpendStore, req: GuardRequest, reasons: list[str], *,
                         request_id: str | None = None, route_type: str = "guard",
                         route_id: str = "") -> dict:
    request_id = _request_id(request_id)
    existing = store.gateway_decision_as_dict(request_id)
    if existing:
        return existing
    store.reserve_and_record_gateway_decision(
        request_id=request_id,
        req=req,
        decision="deny",
        reasons=reasons,
        route_type=route_type,
        route_id=route_id,
    )
    return store.gateway_decision_as_dict(request_id) or GuardDecision(
        "deny", reasons, asdict(req), request_id=request_id
    ).as_dict()


def guard(args) -> dict:
    policy = _load_policy(args.policy)
    require_valid_policy(policy, env_token=os.environ.get("SPEND_GATEWAY_TOKEN"))
    req = GuardRequest(
        x_agent_id=args.agent,
        rail=args.rail,
        amount=args.amount,
        x_budget_id=args.budget,
        provider_name=args.provider or "",
        service_name=args.service or "",
        x_merchant_id=args.merchant or "",
        x_session_id=args.session or "",
    )
    with SpendStore(args.db) as store:
        decision = _decide_and_record(store, policy, req, request_id=args.request_id)
    print(json.dumps(decision, indent=2, sort_keys=True))
    if not decision["allowed"] and args.enforce_exit_code:
        sys.exit(2)
    return decision


def simulate_spend(args) -> dict:
    """Run synthetic agent purchases through the local policy and ledger only.

    This command never contacts a provider, wallet, card network, or x402
    facilitator.  It is useful for exercising budgets and anomaly detection with
    the exact allow -> record-spend lifecycle used by the gateway.
    """
    if args.amount <= 0:
        raise ValueError("--amount must be greater than zero")
    if args.count < 1:
        raise ValueError("--count must be at least one")

    policy = _load_policy(args.policy)
    require_valid_policy(policy, env_token=os.environ.get("SPEND_GATEWAY_TOKEN"))
    provider = args.provider or {"llm_token": "openai", "api_x402": "x402",
                                 "stablecoin": "usdc", "card": "stripe"}.get(args.rail, "simulator")
    merchant = args.merchant or provider
    service = args.service or "simulated-purchase"
    decisions: list[dict] = []

    with SpendStore(args.db) as store:
        for index in range(args.count):
            req = GuardRequest(
                x_agent_id=args.agent,
                rail=args.rail,
                amount=args.amount,
                x_budget_id=args.budget,
                provider_name=provider,
                service_name=service,
                x_merchant_id=merchant,
                x_session_id=args.session or f"simulation-{uuid.uuid4().hex[:8]}",
            )
            request_id = f"sim:{uuid.uuid4().hex}"
            decision = _decide_and_record(store, policy, req, request_id=request_id,
                                          route_type="simulation", route_id="simulate-spend")
            decisions.append(decision)
            if decision["allowed"]:
                record_target_spend(store, {
                    "agent": args.agent, "rail": args.rail, "amount": args.amount,
                    "budget": args.budget, "provider": provider, "service": service,
                    "merchant": merchant, "session": req.x_session_id,
                }, request_id)

        _finish_run(store, {str(k): float(v) for k, v in (policy.get("budgets") or {}).items()}, args.out_dir)
        result = {
            "simulated": args.count,
            "recorded": sum(1 for decision in decisions if decision["allowed"]),
            "denied": sum(1 for decision in decisions if not decision["allowed"]),
            "total_spend": store.total(),
            "decisions": decisions,
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def _edit_frozen(policy_path: str, agents: list[str], budgets: list[str], *, remove: bool) -> dict:
    path = Path(policy_path)
    policy = _load_json_file(policy_path)
    for key, vals in (("frozen_agents", agents), ("frozen_budgets", budgets)):
        current = list(policy.get(key, []))
        for v in vals:
            if remove:
                current = [x for x in current if x != v]
            elif v not in current:
                current.append(v)
        policy[key] = current
    require_valid_policy(policy, env_token=os.environ.get("SPEND_GATEWAY_TOKEN"))
    tmp = path.with_name(f"{path.name}.tmp")
    bak = path.with_name(f"{path.name}.bak")
    if path.exists():
        bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)
    return policy


def freeze(args, *, remove: bool = False) -> dict:
    """Kill-switch: add (or with unfreeze, remove) agents/budgets from the policy's
    frozen lists. The running gateway reloads policy per request, so it takes effect
    immediately."""
    agents, budgets = list(args.agent or []), list(args.budget or [])
    if not agents and not budgets:
        print("freeze needs at least one --agent or --budget")
        sys.exit(1)
    policy = _edit_frozen(args.policy, agents, budgets, remove=remove)
    print(f"{'unfrozen' if remove else 'FROZEN'}: {', '.join(agents + budgets)}")
    print(f"frozen_agents={policy.get('frozen_agents', [])}  "
          f"frozen_budgets={policy.get('frozen_budgets', [])}")
    return policy


def unfreeze(args) -> dict:
    return freeze(args, remove=True)


def make_gateway_server(db_path: str | Path = "spend.db", policy_path: str | Path | None = None,
                        host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    startup_policy = _load_policy(policy_path)
    require_valid_policy(startup_policy, env_token=os.environ.get("SPEND_GATEWAY_TOKEN"))

    class Handler(BaseHTTPRequestHandler):
        def _cors_headers(self) -> dict[str, str]:
            """Allow the local Pactrail wallet demo to call its loopback gateway.

            This is deliberately restricted to localhost development origins. A
            deployed gateway should put its own authenticated UI behind the same
            origin or configure an explicit production allowlist.
            """
            origin = self.headers.get("origin", "")
            allowed = {"http://localhost:3000", "http://127.0.0.1:3000"}
            if origin in allowed:
                return {
                    "access-control-allow-origin": origin,
                    "vary": "Origin",
                    "access-control-allow-headers": (
                        "authorization, content-type, x-request-id, payment-signature, x-payment, "
                        "x-agent-id, x-budget-id, x-session-id, x-pactrail-signer-approval, access-control-expose-headers"
                    ),
                    "access-control-allow-methods": "GET, POST, OPTIONS",
                    "access-control-expose-headers": (
                        "payment-required, payment-response, x-payment-response, x-pactrail-request-id"
                    ),
                }
            return {}

        def _send(self, code: int, payload: dict, headers: dict | None = None) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode()
            self.send_response(code)
            sent_content_type = False
            response_headers = {**self._cors_headers(), **(headers or {})}
            for key, value in response_headers.items():
                if key.lower() == "content-type":
                    sent_content_type = True
                self.send_header(str(key), str(value))
            if not sent_content_type:
                self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_bytes(self, code: int, body: bytes, headers: dict[str, str]) -> None:
            self.send_response(code)
            for key, value in {**self._cors_headers(), **headers}.items():
                if key.lower() in {"connection", "content-length", "transfer-encoding"}:
                    continue
                self.send_header(key, value)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_upstream(self, resp, extra_headers: dict | None = None, on_body=None) -> bytes | None:
            headers = dict(resp.headers.items())
            content_type = headers.get("Content-Type", headers.get("content-type", ""))
            is_stream = _is_event_stream(content_type)
            self.send_response(resp.status)
            for key, value in headers.items():
                # The gateway owns CORS for its browser approval UI. Forwarding
                # an upstream Access-Control-* value as well would produce a
                # multi-value CORS header that browsers reject.
                if key.lower() in {"connection", "content-length", "transfer-encoding"} or key.lower().startswith("access-control-"):
                    continue
                self.send_header(key, value)
            for key, value in (extra_headers or {}).items():
                self.send_header(str(key), str(value))
            for key, value in self._cors_headers().items():
                self.send_header(str(key), str(value))
            if not is_stream:
                body = resp.read()
                if on_body is not None:
                    on_body(body)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return body
            self.end_headers()
            tail = bytearray()  # ponytail: keep last 64KB; the usage chunk is small and last
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                tail += chunk
                if len(tail) > 65536:
                    del tail[:-65536]
            raw = _usage_body_from_sse(bytes(tail))
            if on_body is not None:
                on_body(raw)
            return raw

        def _request_length(self, policy: dict) -> int:
            try:
                length = int(self.headers.get("content-length", "0") or 0)
            except ValueError as exc:
                raise ValueError("content-length must be an integer") from exc
            if length < 0:
                raise ValueError("content-length must not be negative")
            max_bytes = int(policy.get("max_request_bytes", DEFAULT_MAX_REQUEST_BYTES))
            if length > max_bytes:
                raise PayloadTooLarge(f"request body {length} bytes exceeds max_request_bytes {max_bytes}")
            return length

        def _read_json(self, policy: dict) -> dict:
            length = self._request_length(policy)
            self._raw_body = self.rfile.read(length)
            payload = json.loads(self._raw_body or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        def _read_raw(self, policy: dict) -> bytes:
            length = self._request_length(policy)
            self._raw_body = self.rfile.read(length)
            return self._raw_body

        def _target_body_bytes(self, payload: dict) -> bytes:
            body = payload.get("body", b"")
            if isinstance(body, (dict, list)):
                return json.dumps(body).encode()
            if isinstance(body, str):
                return body.encode()
            if body is None:
                return b""
            return body

        def _authorized(self, policy: dict, token: str = "") -> bool:
            tokens = policy.get("gateway_tokens")
            env_token = os.environ.get("SPEND_GATEWAY_TOKEN")
            if env_token:
                tokens = list(tokens or []) + [env_token]
            if not tokens:
                # Local development stays one-command friendly. Production is
                # fail-closed even if a bad policy somehow reached this point.
                return policy.get("deployment_mode", "development") != "production"
            auth = self.headers.get("authorization", "")
            bearer = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
            supplied = token or bearer or self.headers.get("x-gateway-token", "")
            supplied = str(supplied)
            return any(hmac.compare_digest(supplied, str(t)) for t in tokens)

        def _capability_secret(self, policy: dict) -> str:
            return os.environ.get(str(policy.get("capability_secret_env", "PACTRAIL_CAPABILITY_SECRET")), "")

        def _capability_claims(self, policy: dict) -> dict:
            secret = self._capability_secret(policy)
            auth = self.headers.get("authorization", "")
            token = auth.removeprefix("Capability ").strip() if auth.startswith("Capability ") else ""
            if not secret or not token:
                raise CapabilityError("missing payment capability")
            claims = verify_capability(token, secret)
            with SpendStore(str(db_path)) as store:
                session = store.spend_session(str(claims.get("session_id", "")))
            if session is None or session["status"] != "active" or session["expires_at"] <= datetime.now(timezone.utc).isoformat():
                raise CapabilityError("payment capability session is inactive or expired")
            return claims

        def _signer_identity(self, policy: dict) -> str | None:
            """Authenticate a separate signer adapter; agents never receive this token."""
            auth = self.headers.get("authorization", "")
            token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
            for signer_id, config in (policy.get("signer_adapters") or {}).items():
                expected = os.environ.get(str(config.get("auth_env", "")), "")
                if expected and token and hmac.compare_digest(token, expected):
                    return str(signer_id)
            return None

        @staticmethod
        def _claim_allows(claims: dict, resource_id: str, resource: dict, *, agent: str, budget: str) -> str | None:
            if claims.get("agent_id") != agent or claims.get("budget_id") != budget:
                return "capability is not valid for this agent or budget"
            if resource_id not in set(claims.get("resource_ids", [])):
                return "capability does not allow this resource"
            checks = {
                "merchants": str(resource.get("merchant") or resource.get("pay_to", "")),
                "networks": str(resource.get("network", "")),
                "assets": str(resource.get("asset", "")),
                "schemes": _x402_scheme(resource),
            }
            for key, actual in checks.items():
                allowed = claims.get(key, [])
                if allowed and actual not in allowed:
                    return f"capability does not allow {key[:-1]} {actual}"
            return None

        @staticmethod
        def _resource_capability_constraints(policy: dict, resource_ids: list[str]) -> tuple[dict[str, list[str]], str | None]:
            """Freeze every non-secret payment property into a minted capability."""
            values = {"merchants": set(), "networks": set(), "assets": set(), "schemes": set()}
            resources = policy.get("x402_resources", {})
            for resource_id in resource_ids:
                resource = resources.get(resource_id)
                if not isinstance(resource, dict):
                    return {}, resource_id
                values["merchants"].add(str(resource.get("merchant") or resource.get("pay_to", "")))
                values["networks"].add(str(resource.get("network", "")))
                values["assets"].add(str(resource.get("asset", "")))
                values["schemes"].add(_x402_scheme(resource))
            return {key: sorted(value for value in options if value) for key, options in values.items()}, None

        def _guard_request(self, payload: dict) -> GuardRequest:
            return GuardRequest(
                x_agent_id=str(payload["agent"]),
                rail=str(payload["rail"]),
                amount=float(payload["amount"]),
                x_budget_id=str(payload["budget"]),
                provider_name=str(payload.get("provider", "")),
                service_name=str(payload.get("service", "")),
                x_merchant_id=str(payload.get("merchant", "")),
                x_session_id=str(payload.get("session", "")),
            )

        def _request_id(self, payload: dict) -> str:
            return _request_id(self.headers.get("x-request-id") or payload.get("request_id"))

        def _guard_payload(self, payload: dict, *, route_type: str = "guard",
                           route_id: str = "") -> dict:
            req = self._guard_request(payload)
            with SpendStore(str(db_path)) as store:
                return _decide_and_record(
                    store,
                    _load_policy(policy_path),
                    req,
                    request_id=self._request_id(payload),
                    route_type=route_type,
                    route_id=route_id,
                )

        def _target_request(self, payload: dict, policy: dict) -> tuple[dict, dict]:
            target_id = str(payload["target"])
            target = policy.get("targets", {}).get(target_id)
            if not isinstance(target, dict):
                raise ValueError(f"target {target_id} is not configured")
            guard_payload = {
                "agent": payload["agent"],
                "rail": target["rail"],
                "amount": target["amount"],
                "budget": payload.get("budget", target.get("budget", "default")),
                "provider": target.get("provider", ""),
                "service": target.get("service", ""),
                "merchant": target.get("merchant", ""),
                "session": payload.get("session", ""),
            }
            return target, guard_payload

        def _x402_route(self, policy: dict) -> tuple[str, dict] | None:
            parsed = urllib.parse.urlsplit(self.path)
            parts = parsed.path.strip("/").split("/", 1)
            if len(parts) < 2 or parts[0] != "x402":
                return None
            resource_id = parts[1].split("/", 1)[0]
            resource = policy.get("x402_resources", {}).get(resource_id)
            if not isinstance(resource, dict):
                return None
            return resource_id, resource

        def _x402_guard_payload(self, resource_id: str, resource: dict) -> dict:
            agent = self.headers.get("x-agent-id") or resource.get("agent")
            if not agent:
                raise ValueError("x402 calls require X-Agent-ID or x402 resource agent")
            return {
                "agent": agent,
                "rail": "api_x402",
                "amount": float(_x402_authorization_units(resource)) / (10 ** int(resource.get("asset_decimals", 6))),
                "budget": self.headers.get("x-budget-id") or resource.get("budget", "default"),
                "provider": "x402",
                "service": resource.get("service", resource_id),
                "merchant": resource.get("merchant") or resource.get("pay_to", ""),
                "session": self.headers.get("x-session-id", ""),
                "asset": resource.get("asset_name", "USDC"),
                "asset_decimals": int(resource.get("asset_decimals", 6)),
                "network": resource.get("network", "eip155:8453"),
            }

        def _x402_headers(self, resource: dict) -> dict[str, str]:
            merged_headers = dict(resource.get("headers", {}))
            for header, env_name in resource.get("headers_env", {}).items():
                value = os.environ.get(str(env_name))
                if value:
                    merged_headers[str(header)] = value
            passthrough = {
                str(k): str(v)
                for k, v in self.headers.items()
                if k.lower() not in {
                    "host", "content-length", "connection", "authorization",
                    "payment-required", "payment-signature", "payment-response",
                    "x-payment", "x-payment-response", "x-agent-id", "x-budget-id",
                    "x-session-id", "x-gateway-token", "x-pactrail-signer-approval",
                }
            }
            passthrough.update({str(k): str(v) for k, v in merged_headers.items()})
            return passthrough

        def _send_x402_required(self, resource_id: str, resource: dict, requirements: dict,
                                status: int = 402, error: dict | None = None) -> None:
            payload = _x402_public_requirements(resource_id, resource, requirements)
            header_payload = dict(payload)
            if error:
                # The header must remain a schema-valid PaymentRequired V2.
                # Preserve machine-readable failure details in the JSON body.
                header_payload["error"] = str(error.get("message") or error.get("reason") or "payment failed")
                payload["error"] = error
            import base64
            encoded = base64.b64encode(
                json.dumps(header_payload, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            self._send(status, payload, headers={
                "content-type": "application/json",
                "payment-required": encoded,
            })

        def _forward_x402_resource(self, resource: dict, payment_response: dict, request_id: str) -> None:
            body = getattr(self, "_raw_body", b"")
            method = str(resource.get("method", self.command)).upper()
            data = None if method == "GET" else body
            req = urllib.request.Request(
                str(resource["url"]),
                data=data,
                headers=self._x402_headers(resource),
                method=method,
            )
            payment_header = json.dumps(payment_response, separators=(",", ":"))
            # A paid request must never silently carry its body or configured
            # merchant headers to a redirect destination.
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, request, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(req, timeout=float(resource.get("timeout", 30))) as resp:
                self._send_upstream(resp, extra_headers={
                    "payment-response": payment_header,
                    "x-payment-response": payment_header,
                    "x-pactrail-request-id": request_id,
                })

        def _merchant_x402_headers(self, resource: dict, *, include_payment: bool) -> dict[str, str]:
            """Use a narrow allowlist when proxying a standard x402 merchant.

            The merchant receives the original payment proof on the retry, but
            never Gateway credentials, browser cookies, or arbitrary proxy
            headers supplied by an Agent.
            """
            allowed = {"accept", "accept-language", "content-type", "idempotency-key"}
            headers = {
                str(key): str(value) for key, value in self.headers.items()
                if key.lower() in allowed
            }
            # Identify the gateway explicitly. Some public merchants block
            # Python's default User-Agent while accepting normal HTTP clients.
            # This value is gateway-owned, never inherited from the Agent.
            headers["user-agent"] = "Pactrail/0.1"
            for header, env_name in resource.get("headers_env", {}).items():
                value = os.environ.get(str(env_name))
                if value:
                    headers[str(header)] = value
            headers.update({str(key): str(value) for key, value in resource.get("headers", {}).items()})
            if include_payment:
                signature = self.headers.get("payment-signature", "")
                if not signature:
                    raise ValueError("standard x402 retry requires PAYMENT-SIGNATURE")
                headers["payment-signature"] = signature
            return headers

        def _merchant_x402_request(self, resource: dict, *, include_payment: bool) -> tuple[int, dict[str, str], bytes]:
            body = getattr(self, "_raw_body", b"")
            method = str(resource.get("method", self.command)).upper()
            request = urllib.request.Request(
                str(resource["url"]), data=None if method == "GET" else body,
                headers=self._merchant_x402_headers(resource, include_payment=include_payment), method=method,
            )
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, request, fp, code, msg, headers, newurl):
                    return None
            try:
                with urllib.request.build_opener(_NoRedirect).open(
                    request, timeout=float(resource.get("timeout", 30))
                ) as response:
                    return response.status, dict(response.headers.items()), response.read()
            except urllib.error.HTTPError as exc:
                return exc.code, dict(exc.headers.items()), exc.read()

        @staticmethod
        def _header(headers: dict[str, str], name: str) -> str:
            for key, value in headers.items():
                if key.lower() == name.lower():
                    return str(value)
            return ""

        def _validate_merchant_quote(self, resource_id: str, resource: dict, encoded: str) -> dict:
            quote = _decode_x402_header(encoded)
            expected = _x402_payment_requirements(resource)
            expected_url = str(resource.get("resource_url") or resource.get("url") or "")
            if int(quote.get("x402Version", 0)) != int(resource.get("x402_version", 2)):
                raise ValueError("merchant quote has an unsupported x402 version")
            quote_resource = quote.get("resource") or {}
            if not isinstance(quote_resource, dict) or str(quote_resource.get("url") or "") != expected_url:
                raise ValueError("merchant quote resource URL does not match the approved resource")
            accepts = quote.get("accepts")
            if not isinstance(accepts, list) or not any(
                isinstance(option, dict) and all(
                    str(option.get(key, "")) == str(expected.get(key, ""))
                    for key in ("scheme", "network", "asset", "amount", "payTo")
                ) for option in accepts
            ):
                raise ValueError(f"merchant quote does not match Pactrail policy for {resource_id}")
            return quote

        def _send_standard_merchant_response(self, status: int, headers: dict[str, str], body: bytes, *,
                                             request_id: str = "") -> None:
            """Return the merchant's x402 response without granting it Gateway-origin powers."""
            self.send_response(status)
            # Pactrail owns CORS on browser-facing responses, including the
            # merchant's initial 402 quote and final paid response.
            for key, value in self._cors_headers().items():
                self.send_header(key, value)
            for header in ("content-type", "cache-control", "payment-required", "payment-response"):
                value = self._header(headers, header)
                if value:
                    self.send_header(header, value)
            if request_id:
                self.send_header("x-pactrail-request-id", request_id)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle_standard_x402(self, policy: dict, resource_id: str, resource: dict) -> bool:
            """Proxy the standard x402 server handshake; Pactrail never settles for the merchant."""
            body = self._read_raw(policy)
            guard_payload = self._x402_guard_payload(resource_id, resource)
            approval_id = self.headers.get("x-pactrail-signer-approval", "").strip()
            signer_approval = None
            session_cap = None
            if approval_id:
                signer_id = self._signer_identity(policy)
                if not signer_id:
                    self._send(401, {"error": "invalid_wallet_adapter"})
                    return True
                with SpendStore(str(db_path)) as store:
                    signer_approval = store.consume_signer_approval(approval_id, signer_id=signer_id)
                    intent = store.payment_intent(str(signer_approval["request_id"])) if signer_approval else None
                    session = store.spend_session(str(intent["session_id"])) if intent else None
                if signer_approval is None or intent is None or session is None or session["status"] != "active":
                    self._send(403, {"error": "signer_approval_denied"})
                    return True
                if intent["resource_id"] != resource_id or signer_approval["body_hash"] != hashlib.sha256(body).hexdigest():
                    self._send(403, {"error": "signer_approval_binding_mismatch"})
                    return True
                for header, expected in (("x-agent-id", intent["agent_id"]), ("x-budget-id", intent["budget_id"]),
                                         ("x-session-id", intent["session_id"]), ("x-request-id", intent["request_id"])):
                    supplied = self.headers.get(header, "")
                    if supplied and supplied != expected:
                        self._send(403, {"error": "signer_approval_binding_mismatch", "detail": f"{header} does not match approval"})
                        return True
                guard_payload.update({"agent": intent["agent_id"], "budget": intent["budget_id"], "session": intent["session_id"]})
                session_cap = float(session["cap"])
            else:
                try:
                    claims = self._capability_claims(policy)
                except CapabilityError as exc:
                    self._send(401, {"error": "invalid_payment_capability", "detail": str(exc)})
                    return True
                capability_error = self._claim_allows(
                    claims, resource_id, resource, agent=str(guard_payload["agent"]), budget=str(guard_payload["budget"]),
                )
                if capability_error:
                    self._send(403, {"error": "payment_capability_denied", "detail": capability_error})
                    return True
                guard_payload["session"] = str(claims["session_id"])
                with SpendStore(str(db_path)) as store:
                    session = store.spend_session(str(claims["session_id"]))
                session_cap = float(session["cap"]) if session is not None else None

            if inspect_content(body, policy):
                self._send(403, {"error": "x402_content_denied"})
                return True
            payment_header = self.headers.get("payment-signature", "")
            if not payment_header:
                with SpendStore(str(db_path)) as store:
                    decision = decide(store, policy, self._guard_request(guard_payload)).as_dict()
                if not decision["allowed"]:
                    self._send(403, decision)
                    return True
                status, headers, response_body = self._merchant_x402_request(resource, include_payment=False)
                required = self._header(headers, "payment-required")
                if status != 402 or not required:
                    self._send(502, {"error": "merchant_did_not_return_standard_x402_quote"})
                    return True
                try:
                    self._validate_merchant_quote(resource_id, resource, required)
                except ValueError as exc:
                    self._send(502, {"error": "merchant_quote_rejected", "detail": str(exc)})
                    return True
                self._send_standard_merchant_response(status, headers, response_body)
                return True

            if policy.get("require_signer_approval") and signer_approval is None:
                self._send(403, {"error": "signer_approval_required"})
                return True
            requirements = _x402_payment_requirements(resource)
            payment_payload = _decode_x402_header(payment_header)
            binding_errors = _x402_payment_binding_errors(payment_payload, requirements, resource)
            if binding_errors:
                self._send(403, {"error": "payment_binding_mismatch", "detail": "; ".join(binding_errors)})
                return True
            request_id = _request_id(self.headers.get("x-request-id"))
            with SpendStore(str(db_path)) as store:
                decision = _decide_and_record(
                    store, policy, self._guard_request(guard_payload), request_id=request_id,
                    route_type="x402", route_id=resource_id, session_cap=session_cap,
                )
                if not decision["allowed"]:
                    self._send(403, decision)
                    return True
                fingerprint = hashlib.sha256(json.dumps(payment_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                previous = store.claim_x402_payment(
                    request_id, resource_id, fingerprint, scheme=str(requirements["scheme"]),
                    authorization_limit_units=str(requirements["amount"]),
                )
                if previous:
                    store.release_reservation(request_id)
                    self._send(409, {"error": "replayed_x402_payment", "previous_request_id": previous})
                    return True
                store.update_x402_payment(request_id, "submitted_to_merchant")
            status, headers, response_body = self._merchant_x402_request(resource, include_payment=True)
            receipt_header = self._header(headers, "payment-response")
            if not 200 <= status < 300 or not receipt_header:
                with SpendStore(str(db_path)) as store:
                    store.update_x402_payment(request_id, "merchant_delivery_unverified", detail=f"merchant HTTP {status}")
                self._send(502, {"error": "merchant_did_not_confirm_standard_settlement", "request_id": request_id})
                return True
            try:
                receipt = _decode_x402_header(receipt_header)
                settled_units = _x402_settlement_units(receipt, str(requirements["amount"]), str(requirements["scheme"]))
                with SpendStore(str(db_path)) as store:
                    store.account_x402_payment(request_id, usage_units=settled_units, settled_units=settled_units)
                    record_x402_settlement(store, guard_payload, request_id, requirements, {}, receipt)
                    store.update_x402_payment(request_id, "delivered", transaction_ref=str(receipt.get("transaction") or receipt.get("txHash") or ""))
                    if store.payment_intent(request_id):
                        store.update_payment_intent(request_id, "delivered")
                    if signer_approval is not None:
                        store.update_signer_approval(str(signer_approval["approval_id"]), "delivered")
            except ValueError as exc:
                with SpendStore(str(db_path)) as store:
                    store.update_x402_payment(request_id, "merchant_receipt_invalid", detail=str(exc))
                self._send(502, {"error": "invalid_merchant_payment_response", "request_id": request_id})
                return True
            self._send_standard_merchant_response(status, headers, response_body, request_id=request_id)
            return True

        def _handle_x402(self, policy: dict) -> bool:
            route = self._x402_route(policy)
            if not route:
                return False
            resource_id, resource = route
            if resource.get("x402_execution", "merchant") == "merchant":
                return self._handle_standard_x402(policy, resource_id, resource)
            body = self._read_raw(policy)
            guard_payload = self._x402_guard_payload(resource_id, resource)
            claims = None
            session_cap = None
            approval_id = self.headers.get("x-pactrail-signer-approval", "").strip()
            signer_approval = None
            if approval_id:
                signer_id = self._signer_identity(policy)
                if not signer_id:
                    self._send(401, {"error": "invalid_signer_adapter"})
                    return True
                with SpendStore(str(db_path)) as store:
                    signer_approval = store.consume_signer_approval(approval_id, signer_id=signer_id)
                    intent = store.payment_intent(str(signer_approval["request_id"])) if signer_approval else None
                    session = store.spend_session(str(intent["session_id"])) if intent else None
                if signer_approval is None or intent is None or session is None or session["status"] != "active":
                    self._send(403, {"error": "signer_approval_denied"})
                    return True
                if intent["resource_id"] != resource_id or signer_approval["body_hash"] != hashlib.sha256(body).hexdigest():
                    self._send(403, {"error": "signer_approval_binding_mismatch"})
                    return True
                for header, expected in (("x-agent-id", intent["agent_id"]), ("x-budget-id", intent["budget_id"]),
                                         ("x-session-id", intent["session_id"]), ("x-request-id", intent["request_id"])):
                    supplied = self.headers.get(header, "")
                    if supplied and supplied != expected:
                        self._send(403, {"error": "signer_approval_binding_mismatch", "detail": f"{header} does not match approval"})
                        return True
                guard_payload.update({"agent": intent["agent_id"], "budget": intent["budget_id"], "session": intent["session_id"]})
                session_cap = float(session["cap"])
            elif self._capability_secret(policy) or policy.get("deployment_mode", "development") == "production":
                try:
                    claims = self._capability_claims(policy)
                except CapabilityError as exc:
                    self._send(401, {"error": "invalid_payment_capability", "detail": str(exc)})
                    return True
                capability_error = self._claim_allows(
                    claims, resource_id, resource, agent=str(guard_payload["agent"]), budget=str(guard_payload["budget"]),
                )
                if capability_error:
                    self._send(403, {"error": "payment_capability_denied", "detail": capability_error})
                    return True
                guard_payload["session"] = str(claims["session_id"])
                with SpendStore(str(db_path)) as store:
                    session = store.spend_session(str(claims["session_id"]))
                session_cap = float(session["cap"]) if session is not None else None
            content_reasons = inspect_content(body, policy)
            if content_reasons:
                with SpendStore(str(db_path)) as store:
                    decision = _record_gateway_deny(
                        store,
                        self._guard_request(guard_payload),
                        content_reasons,
                        request_id=self.headers.get("x-request-id"),
                        route_type="x402",
                        route_id=resource_id,
                    )
                self._send(403, decision)
                return True
            requirements = _x402_payment_requirements(resource)
            if resource.get("preflight_supported"):
                try:
                    require_supported(
                        str(resource.get("facilitator_url", "")),
                        version=int(resource.get("x402_version", 2)),
                        scheme=str(requirements["scheme"]), network=str(requirements["network"]),
                        auth_env=resource.get("facilitator_auth_env"),
                        mode=str(resource.get("facilitator_mode", "http")),
                        cdp_environment=str(resource.get("facilitator_cdp_env", "")),
                        timeout=float(resource.get("timeout", 30)),
                    )
                except (FacilitatorError, OSError, ValueError) as exc:
                    self._send(503, {"error": "facilitator_unsupported", "detail": str(exc)})
                    return True
            payment_header = self.headers.get("payment-signature") or self.headers.get("x-payment")
            if not payment_header:
                with SpendStore(str(db_path)) as store:
                    decision = decide(store, policy, self._guard_request(guard_payload)).as_dict()
                if not decision["allowed"]:
                    self._send(403, decision)
                else:
                    self._send_x402_required(resource_id, resource, requirements)
                return True
            if policy.get("require_signer_approval") and signer_approval is None:
                self._send(403, {"error": "signer_approval_required"})
                return True

            request_id = _request_id(self.headers.get("x-request-id"))
            with SpendStore(str(db_path)) as store:
                if store.gateway_decision_by_request(request_id):
                    self._send(409, {
                        "error": "duplicate_x402_request_id",
                        "request_id": request_id,
                        "detail": "Use a fresh X-Request-ID and payment payload for each x402 settlement.",
                    })
                    return True
            with SpendStore(str(db_path)) as store:
                decision = _decide_and_record(
                    store,
                    policy,
                    self._guard_request(guard_payload),
                    request_id=request_id,
                    route_type="x402",
                    route_id=resource_id,
                    session_cap=session_cap,
                )
            if not decision["allowed"]:
                with SpendStore(str(db_path)) as store:
                    if store.payment_intent(request_id):
                        store.update_payment_intent(request_id, "denied")
                self._send(403, decision)
                return True
            with SpendStore(str(db_path)) as store:
                if store.payment_intent(request_id):
                    store.update_payment_intent(request_id, "executing")

            payment_payload = _decode_x402_header(payment_header)
            binding_errors = _x402_payment_binding_errors(payment_payload, requirements, resource)
            if binding_errors:
                with SpendStore(str(db_path)) as store:
                    store.release_reservation(request_id)
                self._send_x402_required(resource_id, resource, requirements, error={
                    "reason": "payment_binding_mismatch",
                    "message": "; ".join(binding_errors),
                })
                return True
            # A signature is single-use: retain only its digest, never the signed
            # payload, so it cannot be replayed under a fresh request id.
            payment_fingerprint = hashlib.sha256(
                json.dumps(payment_payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            scheme = str(requirements["scheme"])
            authorization_limit_units = str(requirements["amount"])
            payment_policy = resource.get("payment_policy") or {}
            batch_id = ""
            if scheme == "batch-settlement":
                batch_id = str(self.headers.get(str(payment_policy.get("batch_id_header", "")), "")).strip()
                if not batch_id:
                    with SpendStore(str(db_path)) as store:
                        store.release_reservation(request_id)
                    self._send(400, {"error": "missing_x402_batch_id", "request_id": request_id})
                    return True
            with SpendStore(str(db_path)) as store:
                previous_request = store.claim_x402_payment(
                    request_id, resource_id, payment_fingerprint, scheme=scheme,
                    authorization_limit_units=authorization_limit_units, batch_id=batch_id,
                )
                if previous_request:
                    store.release_reservation(request_id)
                    self._send(409, {
                        "error": "replayed_x402_payment",
                        "request_id": request_id,
                        "previous_request_id": previous_request,
                        "detail": "This payment signature was already submitted; sign a fresh payment.",
                    })
                    return True
                if batch_id:
                    try:
                        store.reserve_x402_batch(
                            batch_id=batch_id,
                            resource_id=resource_id,
                            authorization_limit_units=authorization_limit_units,
                            batch_limit_units=str(payment_policy["batch_limit_units"]),
                            session_id=str(guard_payload.get("session", "")),
                        )
                    except ValueError as exc:
                        store.release_reservation(request_id)
                        store.account_x402_payment(
                            request_id, usage_units="0", settled_units="0",
                        )
                        store.update_x402_payment(request_id, "batch_denied", detail=str(exc))
                        self._send(403, {"error": "x402_batch_limit_exceeded", "request_id": request_id,
                                         "detail": str(exc)})
                        return True
            facilitator = str(resource.get("facilitator_url", ""))
            if not facilitator:
                raise ValueError("x402 resource missing facilitator_url")
            version = int(resource.get("x402_version", payment_payload.get("x402Version", 2)))
            facilitator_payload = {
                "x402Version": version,
                "paymentPayload": payment_payload,
                "paymentRequirements": requirements,
            }
            try:
                verify_result = _facilitator_request_json(
                    facilitator.rstrip("/") + "/verify",
                    facilitator_payload,
                    resource,
                )
            except (FacilitatorError, OSError, ValueError) as exc:
                # A real facilitator can return an HTTP error (for example an
                # invalid self-payment) instead of a JSON {isValid:false}.
                # That is still a failed verification, never a spend.
                with SpendStore(str(db_path)) as store:
                    store.release_reservation(request_id)
                    store.account_x402_payment(request_id, usage_units="0", settled_units="0")
                    if batch_id:
                        store.account_x402_batch(batch_id=batch_id, authorization_limit_units=authorization_limit_units,
                                                 usage_units="0", settled_units="0")
                    store.update_x402_payment(request_id, "verification_failed", detail=str(exc))
                self._send_x402_required(resource_id, resource, requirements, error={
                    "reason": "facilitator_verification_failed",
                    "message": str(exc),
                })
                return True
            if not verify_result.get("isValid"):
                with SpendStore(str(db_path)) as store:
                    store.release_reservation(request_id)
                    store.account_x402_payment(request_id, usage_units="0", settled_units="0")
                    if batch_id:
                        store.account_x402_batch(batch_id=batch_id, authorization_limit_units=authorization_limit_units,
                                                 usage_units="0", settled_units="0")
                    store.update_x402_payment(request_id, "verification_failed",
                                              detail=str(verify_result.get("invalidReason", "invalid_payment")))
                self._send_x402_required(resource_id, resource, requirements, error={
                    "reason": verify_result.get("invalidReason", "invalid_payment"),
                    "message": verify_result.get("invalidMessage", "payment verification failed"),
                })
                return True

            with SpendStore(str(db_path)) as store:
                store.update_x402_payment(request_id, "verified")

            try:
                settle_result = _facilitator_request_json(
                    facilitator.rstrip("/") + "/settle",
                    facilitator_payload,
                    resource,
                )
            except (FacilitatorError, OSError, ValueError) as exc:
                with SpendStore(str(db_path)) as store:
                    store.release_reservation(request_id)
                    store.account_x402_payment(request_id, usage_units="0", settled_units="0")
                    if batch_id:
                        store.account_x402_batch(batch_id=batch_id, authorization_limit_units=authorization_limit_units,
                                                 usage_units="0", settled_units="0")
                    store.update_x402_payment(request_id, "settlement_failed", detail=str(exc))
                self._send_x402_required(resource_id, resource, requirements, error={
                    "reason": "facilitator_settlement_failed",
                    "message": str(exc),
                })
                return True
            if settle_result.get("success") is False:
                with SpendStore(str(db_path)) as store:
                    store.release_reservation(request_id)
                    store.account_x402_payment(request_id, usage_units="0", settled_units="0")
                    if batch_id:
                        store.account_x402_batch(batch_id=batch_id, authorization_limit_units=authorization_limit_units,
                                                 usage_units="0", settled_units="0")
                    store.update_x402_payment(request_id, "settlement_failed",
                                              detail=str(settle_result.get("errorReason", "settlement_failed")))
                self._send_x402_required(resource_id, resource, requirements, error={
                    "reason": settle_result.get("errorReason", "settlement_failed"),
                    "message": settle_result.get("errorMessage", "payment settlement failed"),
                })
                return True

            try:
                settled_units = _x402_settlement_units(settle_result, authorization_limit_units, scheme)
                with SpendStore(str(db_path)) as store:
                    store.account_x402_payment(
                        request_id, usage_units=settled_units, settled_units=settled_units,
                    )
                    if batch_id:
                        store.account_x402_batch(
                            batch_id=batch_id, authorization_limit_units=authorization_limit_units,
                            usage_units=settled_units, settled_units=settled_units,
                        )
                    record_x402_settlement(
                        store,
                        guard_payload,
                        request_id,
                        requirements,
                        verify_result,
                        settle_result,
                    )
                    store.update_x402_payment(
                        request_id, "settled",
                        transaction_ref=str(settle_result.get("transaction") or settle_result.get("txHash") or ""),
                    )
            except ValueError as exc:
                with SpendStore(str(db_path)) as store:
                    store.release_reservation(request_id)
                    store.account_x402_payment(request_id, usage_units="0", settled_units="0")
                    if batch_id:
                        store.account_x402_batch(batch_id=batch_id, authorization_limit_units=authorization_limit_units,
                                                 usage_units="0", settled_units="0")
                    store.update_x402_payment(request_id, "accounting_failed", detail=str(exc))
                self._send(502, {"error": "invalid_x402_settlement", "request_id": request_id,
                                 "detail": str(exc)})
                return True
            self._raw_body = body
            try:
                self._forward_x402_resource(resource, settle_result, request_id)
            except (urllib.error.URLError, OSError) as exc:
                with SpendStore(str(db_path)) as store:
                    store.update_x402_payment(request_id, "delivery_failed", detail=str(exc))
                raise
            with SpendStore(str(db_path)) as store:
                store.update_x402_payment(request_id, "delivered")
                if store.payment_intent(request_id):
                    store.update_payment_intent(request_id, "delivered")
                if signer_approval is not None:
                    store.update_signer_approval(str(signer_approval["approval_id"]), "delivered")
            return True

        def _forward(self, target: dict, payload: dict,
                     guard_payload: dict | None = None, request_id: str = "") -> None:
            merged_headers = dict(target.get("headers", {}))
            for header, env_name in target.get("headers_env", {}).items():
                value = os.environ.get(str(env_name))
                if value:
                    merged_headers[str(header)] = value
            merged_headers.update(payload.get("headers", {}) or {})
            headers = {
                str(k): str(v)
                for k, v in merged_headers.items()
                if str(k).lower() not in {"host", "content-length", "connection"}
            }
            body = payload.get("body", b"")
            if isinstance(body, (dict, list)):
                body = self._target_body_bytes(payload)
                headers.setdefault("content-type", "application/json")
            elif isinstance(body, str):
                body = self._target_body_bytes(payload)
            elif body is None:
                body = self._target_body_bytes(payload)
            method = str(target.get("method", "POST")).upper()
            req = urllib.request.Request(str(target["url"]), data=body, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=float(target.get("timeout", 30))) as resp:
                    self._send_upstream(resp)
                if guard_payload is not None:  # record flat per-call spend, release the hold
                    with SpendStore(str(db_path)) as store:
                        record_target_spend(store, guard_payload, request_id)
            except urllib.error.HTTPError as exc:
                self._send_bytes(exc.code, exc.read(), dict(exc.headers.items()))

        def _provider_route(self, policy: dict) -> tuple[str, dict, str] | None:
            parsed = urllib.parse.urlsplit(self.path)
            parts = parsed.path.strip("/").split("/", 1)
            if not parts or not parts[0]:
                return None
            provider_id = parts[0]
            provider = policy.get("providers", {}).get(provider_id)
            if not isinstance(provider, dict):
                return None
            known = llm_provider(provider_id)  # fill base_url/api_key_env from the catalog
            if known:
                provider = {**known, **provider}  # policy overrides catalog defaults
            suffix = "/" + parts[1] if len(parts) > 1 else "/"
            if parsed.query:
                suffix += "?" + parsed.query
            return provider_id, provider, suffix

        def _provider_guard_payload(self, provider_id: str, provider: dict,
                                    suffix: str, payload: dict) -> dict:
            service_key = provider.get("service_from_body")
            service = payload.get(service_key) if service_key else None
            agent = self.headers.get("x-agent-id") or provider.get("agent")
            budget = self.headers.get("x-budget-id") or provider.get("budget", "default")
            if not agent:
                raise ValueError("provider-compatible calls require X-Agent-ID or provider.agent")
            flat = float(provider.get("amount", provider.get("max_estimated_amount", 0)) or 0)
            worst = worst_case_amount(payload, provider)  # per-request LLM ceiling
            return {
                "agent": agent,
                "rail": provider.get("rail", "llm_token"),
                "amount": max(flat, worst) if worst is not None else flat,
                "budget": budget,
                "provider": provider.get("provider", provider_id),
                "service": service or provider.get("service", suffix),
                "merchant": provider.get("merchant", provider_id),
                "session": self.headers.get("x-session-id", ""),
            }

        def _provider_headers(self, provider: dict) -> dict[str, str]:
            headers = {
                str(k): str(v)
                for k, v in self.headers.items()
                if k.lower() not in {
                    "host", "content-length", "connection", "authorization",
                    "x-agent-id", "x-budget-id", "x-session-id", "x-gateway-token",
                }
            }
            provider_key = provider.get("api_key")
            if provider.get("api_key_env"):
                provider_key = os.environ.get(str(provider["api_key_env"]))
            if not provider_key:
                raise ValueError("provider API key is not configured")
            auth_header = str(provider.get("auth_header", "Authorization"))
            auth_prefix = str(provider.get("auth_prefix", "Bearer"))
            headers[auth_header] = f"{auth_prefix} {provider_key}".strip()
            return headers

        def _forward_provider(self, provider: dict, suffix: str,
                              guard_payload: dict | None = None, request_id: str = "") -> None:
            url = str(provider["base_url"]).rstrip("/") + suffix
            method = str(provider.get("method", "POST")).upper()
            body = _with_stream_usage(getattr(self, "_raw_body", b""))
            req = urllib.request.Request(
                url,
                data=body,
                headers=self._provider_headers(provider),
                method=method,
            )

            def close_hold(store: SpendStore, raw: bytes | None = None) -> None:
                if raw is not None and guard_payload is not None:
                    record_forwarded_spend(store, raw, provider, guard_payload)
                if request_id:
                    store.release_reservation(request_id)

            try:
                with urllib.request.urlopen(req, timeout=float(provider.get("timeout", 30))) as resp:
                    with SpendStore(str(db_path)) as store:
                        self._send_upstream(resp, on_body=lambda raw: close_hold(store, raw))
            except urllib.error.HTTPError as exc:
                if request_id:
                    with SpendStore(str(db_path)) as store:
                        store.release_reservation(request_id)
                self._send_bytes(exc.code, exc.read(), dict(exc.headers.items()))

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            for key, value in self._cors_headers().items():
                self.send_header(str(key), str(value))
            self.send_header("content-length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/health":
                self._send(200, {"ok": True})
                return
            if parsed.path.startswith("/signer-approvals/"):
                policy = _load_policy(policy_path)
                signer_id = self._signer_identity(policy)
                approval_id = parsed.path.rsplit("/", 1)[-1]
                if not signer_id:
                    self._send(401, {"error": "invalid_signer_adapter"})
                    return
                with SpendStore(str(db_path)) as store:
                    approval = store.signer_approval(approval_id)
                    intent = store.payment_intent(str(approval["request_id"])) if approval else None
                if approval is None or intent is None or approval["signer_id"] != signer_id or approval["status"] != "pending":
                    self._send(404, {"error": "signer_approval_not_found"})
                    return
                if approval["expires_at"] <= datetime.now(timezone.utc).isoformat():
                    self._send(410, {"error": "signer_approval_expired"})
                    return
                self._send(200, {
                    "approval_id": approval["approval_id"], "request_id": approval["request_id"],
                    "signer_id": approval["signer_id"], "resource_id": intent["resource_id"], "agent_id": intent["agent_id"],
                    "budget_id": intent["budget_id"], "session_id": intent["session_id"],
                    "body_sha256": approval["body_hash"], "quote_sha256": approval["quote_hash"],
                    "requirements": json.loads(approval["requirements_json"]), "expires_at": approval["expires_at"],
                })
                return
            if parsed.path in ("/", "/dashboard"):
                policy = _load_policy(policy_path)
                # Never accept credentials in a query string: URLs end up in
                # browser history, proxy logs and Referer headers.
                if not self._authorized(policy):
                    self._send(401, {"error": "unauthorized"})
                    return
                budgets = _load_budgets(policy.get("budgets") or {})
                with SpendStore(str(db_path)) as store:
                    html = render(store, budgets, run_all(store, budgets), refresh_seconds=30)
                self._send_bytes(200, html.encode("utf-8"), {"content-type": "text/html; charset=utf-8"})
                return
            if parsed.path.startswith("/x402/payments/"):
                policy = _load_policy(policy_path)
                request_id = parsed.path.rsplit("/", 1)[-1]
                with SpendStore(str(db_path)) as store:
                    payment = store.x402_payment(request_id)
                    intent = store.payment_intent(request_id)
                if not self._authorized(policy):
                    try:
                        claims = self._capability_claims(policy)
                    except CapabilityError as exc:
                        self._send(401, {"error": "unauthorized", "detail": str(exc)})
                        return
                    if intent is None or intent["session_id"] != claims.get("session_id"):
                        self._send(403, {"error": "payment_capability_denied"})
                        return
                if payment is None:
                    self._send(404, {"error": "x402_payment_not_found", "request_id": request_id})
                else:
                    receipt = {key: payment[key] for key in payment.keys() if key != "payment_fingerprint"}
                    # A receipt is useful to an Agent only if it can be joined
                    # directly to its task and constrained spending authority.
                    # Keep this limited to safe intent metadata, never claims or
                    # signatures.
                    if intent is not None:
                        receipt.update({
                            "session_id": intent["session_id"],
                            "agent_id": intent["agent_id"],
                            "budget_id": intent["budget_id"],
                            "intent_status": intent["status"],
                        })
                    self._send(200, receipt)
                return
            if parsed.path.startswith("/x402/batches/"):
                policy = _load_policy(policy_path)
                claims = None
                if not self._authorized(policy):
                    try:
                        claims = self._capability_claims(policy)
                    except CapabilityError as exc:
                        self._send(401, {"error": "unauthorized", "detail": str(exc)})
                        return
                batch_id = parsed.path.rsplit("/", 1)[-1]
                with SpendStore(str(db_path)) as store:
                    batch = store.x402_batch(batch_id)
                if batch is None:
                    self._send(404, {"error": "x402_batch_not_found", "batch_id": batch_id})
                elif claims is not None and batch["session_id"] != claims.get("session_id"):
                    self._send(403, {"error": "payment_capability_denied"})
                else:
                    self._send(200, {key: batch[key] for key in batch.keys()})
                return
            policy = _load_policy(policy_path)
            if self._handle_x402(policy):
                return
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            try:
                policy = _load_policy(policy_path)
                if self._handle_x402(policy):
                    return
                payload = self._read_json(policy)
                if self.path.startswith("/payment-intents/") and self.path.endswith("/signer-approvals"):
                    request_id = self.path.removeprefix("/payment-intents/").removesuffix("/signer-approvals").strip("/")
                    try:
                        claims = self._capability_claims(policy)
                    except CapabilityError as exc:
                        self._send(401, {"error": "invalid_payment_capability", "detail": str(exc)})
                        return
                    with SpendStore(str(db_path)) as store:
                        intent = store.payment_intent(request_id)
                    if intent is None or intent["session_id"] != claims.get("session_id") or intent["agent_id"] != claims.get("agent_id"):
                        self._send(403, {"error": "payment_capability_denied"})
                        return
                    resource = policy.get("x402_resources", {}).get(intent["resource_id"])
                    signer_id = str(payload.get("signer_id", ""))
                    if not isinstance(resource, dict) or signer_id not in (policy.get("signer_adapters") or {}):
                        self._send(404, {"error": "signer_or_resource_not_found"})
                        return
                    requirements = payload.get("requirements")
                    expected = _x402_public_requirements(str(intent["resource_id"]), resource, _x402_payment_requirements(resource))
                    if not isinstance(requirements, dict) or json.dumps(requirements, sort_keys=True, separators=(",", ":")) != json.dumps(expected, sort_keys=True, separators=(",", ":")):
                        self._send(403, {"error": "signer_approval_quote_mismatch"})
                        return
                    body_hash = str(payload.get("body_sha256", ""))
                    if len(body_hash) != 64 or any(char not in "0123456789abcdef" for char in body_hash.lower()):
                        self._send(400, {"error": "invalid_body_sha256"})
                        return
                    ttl = min(max(int(payload.get("expires_in_seconds", 300)), 1), 900)
                    with SpendStore(str(db_path)) as store:
                        session = store.spend_session(str(intent["session_id"]))
                        if session is None or session["status"] != "active":
                            self._send(403, {"error": "spend_session_inactive"})
                            return
                        expires_at = min(datetime.now(timezone.utc) + timedelta(seconds=ttl),
                                         datetime.fromisoformat(session["expires_at"]))
                        try:
                            approval = store.create_signer_approval(
                                request_id=request_id, signer_id=signer_id,
                                quote_hash=hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                                body_hash=body_hash, requirements=expected, expires_at=expires_at.isoformat(),
                            )
                        except Exception:
                            self._send(409, {"error": "signer_approval_already_exists"})
                            return
                        store.update_payment_intent(request_id, "signer_approval_pending")
                    self._send(201, {"approval_id": approval["approval_id"], "request_id": request_id,
                                     "signer_id": signer_id, "expires_at": approval["expires_at"]})
                    return
                if self.path == "/payment-intents":
                    try:
                        claims = self._capability_claims(policy)
                    except CapabilityError as exc:
                        self._send(401, {"error": "invalid_payment_capability", "detail": str(exc)})
                        return
                    resource_id = str(payload.get("resource_id", ""))
                    resource = policy.get("x402_resources", {}).get(resource_id)
                    if not isinstance(resource, dict):
                        self._send(404, {"error": "x402_resource_not_found", "resource_id": resource_id})
                        return
                    error = self._claim_allows(claims, resource_id, resource,
                                               agent=str(claims.get("agent_id", "")),
                                               budget=str(claims.get("budget_id", "")))
                    if error:
                        self._send(403, {"error": "payment_capability_denied", "detail": error})
                        return
                    request_id = _request_id()
                    with SpendStore(str(db_path)) as store:
                        intent = store.create_payment_intent(
                            request_id=request_id, session_id=str(claims["session_id"]), resource_id=resource_id,
                            agent_id=str(claims["agent_id"]), budget_id=str(claims["budget_id"]),
                        )
                    self._send(201, {**intent, "resource_url": f"/x402/{resource_id}"})
                    return
                if not self._authorized(policy):
                    self._send(401, {"error": "unauthorized"})
                    return
                if self.path == "/sessions":
                    cap = float(payload["cap"])
                    ttl = int(payload.get("expires_in_seconds", 3600))
                    if cap <= 0 or not 1 <= ttl <= 86400:
                        self._send(400, {"error": "invalid_session_cap_or_ttl"})
                        return
                    constraints = payload.get("constraints") or {}
                    if not isinstance(constraints, dict):
                        self._send(400, {"error": "invalid_session_constraints"})
                        return
                    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
                    with SpendStore(str(db_path)) as store:
                        session = store.create_spend_session(
                            parent_task=str(payload.get("parent_task", "")), budget_id=str(payload["budget_id"]),
                            cap=cap, expires_at=expires_at, constraints=constraints,
                        )
                    self._send(201, {key: session[key] for key in session.keys()})
                    return
                if self.path == "/capabilities":
                    secret = self._capability_secret(policy)
                    if not secret:
                        self._send(503, {"error": "capability_secret_not_configured"})
                        return
                    session_id = str(payload["session_id"])
                    with SpendStore(str(db_path)) as store:
                        session = store.spend_session(session_id)
                    if session is None or session["status"] != "active":
                        self._send(404, {"error": "spend_session_not_found", "session_id": session_id})
                        return
                    requested_budget = payload.get("budget_id")
                    if requested_budget is not None and str(requested_budget) != str(session["budget_id"]):
                        self._send(403, {"error": "payment_capability_budget_must_match_session"})
                        return
                    ttl = min(int(payload.get("expires_in_seconds", 900)), 3600)
                    session_constraints = json.loads(session["constraints_json"] or "{}")
                    resource_ids = list(payload.get("resource_ids") or session_constraints.get("resource_ids") or [])
                    if not resource_ids:
                        self._send(400, {"error": "payment_capability_requires_resource_ids"})
                        return
                    derived, missing_resource = self._resource_capability_constraints(policy, resource_ids)
                    if missing_resource:
                        self._send(404, {"error": "x402_resource_not_found", "resource_id": missing_resource})
                        return
                    requested = {"resource_ids": resource_ids}
                    for key, allowed_by_resource in derived.items():
                        explicit = list(payload.get(key) or [])
                        if explicit and not set(explicit).issubset(set(allowed_by_resource)):
                            self._send(400, {"error": "payment_capability_invalid_resource_constraint", "field": key})
                            return
                        # Default to properties derived from the selected resources.
                        requested[key] = explicit or allowed_by_resource
                    for key, values in requested.items():
                        allowed = session_constraints.get(key) or []
                        if allowed and not set(values).issubset(set(allowed)):
                            self._send(403, {"error": "payment_capability_exceeds_session", "field": key})
                            return
                    claims = {
                        "session_id": session_id, "agent_id": str(payload["agent_id"]),
                        "budget_id": str(session["budget_id"]),
                        **requested,
                        "exp": min(int(time.time()) + ttl, int(datetime.fromisoformat(session["expires_at"]).timestamp())),
                    }
                    self._send(201, {"capability": mint_capability(claims, secret), "claims": claims})
                    return
                if self.path.startswith("/sessions/") and self.path.endswith("/revoke"):
                    session_id = self.path.removeprefix("/sessions/").removesuffix("/revoke").strip("/")
                    with SpendStore(str(db_path)) as store:
                        revoked = store.revoke_spend_session(session_id)
                    self._send(200 if revoked else 404, {"session_id": session_id, "revoked": bool(revoked)})
                    return
                if self.path == "/reservations/release":
                    request_id = str(payload["request_id"])
                    with SpendStore(str(db_path)) as store:
                        released = store.release_reservation(request_id)
                    self._send(200, {"request_id": request_id, "released": released})
                    return
                if self.path.startswith("/x402/batches/") and self.path.endswith("/close"):
                    batch_id = self.path.removeprefix("/x402/batches/").removesuffix("/close").strip("/")
                    if not batch_id:
                        self._send(400, {"error": "missing_x402_batch_id"})
                        return
                    with SpendStore(str(db_path)) as store:
                        batch = store.x402_batch(batch_id)
                        if batch is None:
                            self._send(404, {"error": "x402_batch_not_found", "batch_id": batch_id})
                            return
                        if int(batch["reserved_units"]) != 0:
                            self._send(409, {"error": "x402_batch_has_active_authorizations", "batch_id": batch_id})
                            return
                        store.close_x402_batch(batch_id)
                        closed = store.x402_batch(batch_id)
                    self._send(200, {key: closed[key] for key in closed.keys()})
                    return
                if self.path == "/guard":
                    decision = self._guard_payload(payload)
                    self._send(200 if decision["allowed"] else 403, decision)
                    return
                if self.path == "/forward":
                    target, guard_payload = self._target_request(payload, policy)
                    if "request_id" in payload:
                        guard_payload["request_id"] = payload["request_id"]
                    content_reasons = inspect_content(self._target_body_bytes(payload), policy)
                    if content_reasons:
                        with SpendStore(str(db_path)) as store:
                            decision = _record_gateway_deny(
                                store,
                                self._guard_request(guard_payload),
                                content_reasons,
                                request_id=self._request_id(guard_payload),
                                route_type="target",
                                route_id=str(payload["target"]),
                            )
                        self._send(403, decision)
                        return
                    decision = self._guard_payload(guard_payload, route_type="target", route_id=str(payload["target"]))
                    if not decision["allowed"]:
                        self._send(403, decision)
                        return
                    self._forward(target, payload, guard_payload, decision.get("request_id", ""))
                    return
                provider_route = self._provider_route(policy)
                if provider_route:
                    provider_id, provider, suffix = provider_route
                    guard_payload = self._provider_guard_payload(provider_id, provider, suffix, payload)
                    content_reasons = inspect_content(getattr(self, "_raw_body", b""), policy)
                    if content_reasons:  # block on request content before policy/reservation
                        with SpendStore(str(db_path)) as store:
                            decision = _record_gateway_deny(
                                store,
                                self._guard_request(guard_payload),
                                content_reasons,
                                request_id=self._request_id(guard_payload),
                                route_type="provider",
                                route_id=provider_id,
                            )
                        self._send(403, decision)
                        return
                    decision = self._guard_payload(guard_payload, route_type="provider", route_id=provider_id)
                    if not decision["allowed"]:
                        self._send(403, decision)
                        return
                    self._forward_provider(provider, suffix, guard_payload, decision.get("request_id", ""))
                    return
                self._send(404, {"error": "not found"})
            except urllib.error.URLError as exc:
                self._send(502, {"error": str(exc)})
            except PayloadTooLarge as exc:
                self._send(413, {"error": "payload_too_large", "detail": str(exc)})
            except (KeyError, TypeError, ValueError) as exc:
                self._send(400, {"error": str(exc)})

        def log_message(self, fmt, *args):
            return

    return ThreadingHTTPServer((host, port), Handler)


def gateway(db_path: str | Path = "spend.db", policy_path: str | Path | None = None,
            host: str = "127.0.0.1", port: int = 8787) -> None:
    """Run a tiny local HTTP gateway with POST /guard and POST /forward."""
    server = make_gateway_server(db_path, policy_path, host, port)
    print(f"spend gateway listening on http://{host}:{port}")
    print("POST /guard for decisions; POST /forward to guard then proxy an allowlisted target")
    server.serve_forever()


def validate_policy_cmd(policy_path: str) -> None:
    policy = _load_policy(policy_path)
    try:
        require_valid_policy(policy, env_token=os.environ.get("SPEND_GATEWAY_TOKEN"))
    except PolicyError as exc:
        for error in str(exc).split("; "):
            print(f"error: {error}")
        sys.exit(1)
    print("policy OK")


def audit_config_cmd(policy_path: str, db_path: str = "spend.db", out_dir: str = "artifacts") -> None:
    policy = _load_policy(policy_path)
    report = build_audit_config(
        policy,
        db_path=db_path,
        out_dir=out_dir,
        env_token_configured=bool(os.environ.get("SPEND_GATEWAY_TOKEN")),
    )
    print(json.dumps(report, indent=2, sort_keys=True))


def release_reservation_cmd(db_path: str, request_id: str) -> None:
    with SpendStore(db_path) as store:
        released = store.release_reservation(request_id)
    print(json.dumps({"request_id": request_id, "released": released}, indent=2, sort_keys=True))


def run_scenarios_cmd(path: str | Path = "scenarios", out_dir: str | Path = "artifacts") -> dict:
    """Run executable incident records and write a machine-readable report."""
    try:
        results = run_scenarios(path)
    except ScenarioError as exc:
        print(f"scenario error: {exc}")
        sys.exit(1)
    report = render_report(results)
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report_path = destination / "scenario-report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"scenarios: {report['passed']} passed / {report['failed']} failed")
    print(f"wrote {report_path}")
    if report["failed"]:
        for result in report["scenarios"]:
            if not result["passed"]:
                print(f"FAIL {result['id']}: {result['error']}")
        sys.exit(1)
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pactrail",
        description="Pactrail Gateway and spend observability CLI.",
        epilog=(
            "Command families:\n"
            "  Start and test: showcase, demo, demo-live, gateway, x402-sandbox, run-scenarios\n"
            "  Control and policy: guard, validate-policy, audit-config, freeze, unfreeze\n"
            "  x402 discovery: check-facilitator, fetch-bazaar, filter-bazaar, adopt-bazaar\n"
            "  Observability: pull*, report, simulate-spend\n"
            "See docs/PRODUCT_MAP.md for the product map."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--out-dir", default=".", help="directory for report.html and JSON artifacts")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out-dir", default=argparse.SUPPRESS,
                        help="directory for report.html and JSON artifacts")
    sub = parser.add_subparsers(dest="cmd")

    demo_p = sub.add_parser("demo", parents=[common], help="run the fixture-backed product demo")
    demo_p.add_argument("--db", default="spend.db", help="SQLite ledger path")

    showcase_p = sub.add_parser("showcase", parents=[common],
                                help="write a safe, static Pactrail product showcase")
    showcase_p.add_argument("--db", default="pactrail-showcase.db", help="SQLite ledger path")
    showcase_p.set_defaults(out_dir="artifacts-showcase")

    demo_live_p = sub.add_parser("demo-live", parents=[common],
                                 help="seed fixture data and serve the live dashboard")
    demo_live_p.add_argument("--db", default="spend-demo.db", help="SQLite ledger path")
    demo_live_p.add_argument("--policy", help="gateway policy JSON; defaults to SPEND_POLICY_FILE")
    demo_live_p.add_argument("--host", default="127.0.0.1", help="bind host")
    demo_live_p.add_argument("--port", type=int, default=8787, help="bind port")

    pull_p = sub.add_parser("pull", parents=[common], help="pull LLM cost rows (Anthropic or OpenAI)")
    pull_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    pull_p.add_argument("--days", type=int, default=7, help="days of provider history to request")
    pull_p.add_argument("--provider", default="anthropic", choices=["anthropic", "openai"],
                        help="LLM cost provider")

    openrouter_p = sub.add_parser("pull-openrouter", parents=[common],
                                  help="pull OpenRouter generation metadata by id")
    openrouter_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    openrouter_p.add_argument("--generation-id", action="append", default=[],
                              help="OpenRouter generation id; may be repeated")
    openrouter_p.add_argument("--generation-ids-file",
                              help="text file or JSON file containing generation ids")

    aws_p = sub.add_parser("pull-aws", parents=[common],
                           help="pull AWS Cost Explorer spend grouped by tags")
    aws_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    aws_p.add_argument("--days", type=int, default=7, help="days of AWS cost history to request")
    aws_p.add_argument("--tag-agent", default="agent_id", help="AWS cost allocation tag for agent id")
    aws_p.add_argument("--tag-budget", default="budget_id", help="AWS cost allocation tag for budget id")

    gcp_p = sub.add_parser("pull-gcp-billing-file", parents=[common],
                           help="pull GCP Cloud Billing export rows from a file")
    gcp_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    gcp_p.add_argument("--billing-export-file", required=True,
                       help="BigQuery billing export rows as JSON, NDJSON, or CSV")
    gcp_p.add_argument("--label-agent", default="agent_id", help="GCP label for agent id")
    gcp_p.add_argument("--label-budget", default="budget_id", help="GCP label for budget id")

    azure_p = sub.add_parser("pull-azure", parents=[common],
                             help="pull Azure Cost Management spend grouped by tags")
    azure_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    azure_p.add_argument("--days", type=int, default=7, help="days of Azure cost history to request")
    azure_p.add_argument("--scope", help="Azure Cost Management scope; defaults to AZURE_COST_SCOPE")
    azure_p.add_argument("--tag-agent", default="agent_id", help="Azure tag for agent id")
    azure_p.add_argument("--tag-budget", default="budget_id", help="Azure tag for budget id")

    all_p = sub.add_parser("pull-all", parents=[common],
                           help="pull every configured rail from one JSON config")
    all_p.add_argument("--config", default="spend.config.json",
                       help="collector config path; defaults to spend.config.json")
    all_p.add_argument("--db", help="override SQLite ledger path from config")

    x402_p = sub.add_parser("pull-x402", parents=[common],
                            help="pull Base USDC settlements into an x402 address")
    x402_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    x402_p.add_argument("--pay-to", help="merchant receiving address; defaults to X402_PAY_TO")
    x402_p.add_argument("--lookback-blocks", type=int, default=2000, help="Base blocks to scan")
    x402_p.add_argument("--wallet-map", help="JSON wallet address -> agent/budget map")

    usdc_p = sub.add_parser("pull-usdc", parents=[common],
                            help="pull direct Base USDC transfers into an address")
    usdc_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    usdc_p.add_argument("--pay-to", help="receiving address; defaults to USDC_PAY_TO or X402_PAY_TO")
    usdc_p.add_argument("--lookback-blocks", type=int, default=2000, help="Base blocks to scan")
    usdc_p.add_argument("--wallet-map", help="JSON wallet address -> agent/budget map")

    stripe_p = sub.add_parser("pull-stripe", parents=[common],
                              help="pull Stripe succeeded PaymentIntent events")
    stripe_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    stripe_p.add_argument("--days", type=int, default=7, help="days of Stripe event history to request")
    stripe_p.add_argument("--limit", type=int, default=100, help="Stripe page size, 1-100")

    report_p = sub.add_parser("report", parents=[common],
                              help="regenerate dashboard from an existing ledger")
    report_p.add_argument("--db", default="spend.db", help="SQLite ledger path")

    guard_p = sub.add_parser("guard", help="pre-spend allow/deny decision")
    guard_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    guard_p.add_argument("--policy", help="gateway policy JSON; defaults to SPEND_POLICY_FILE")
    guard_p.add_argument("--agent", required=True, help="agent id asking to spend")
    guard_p.add_argument("--rail", required=True, help="rail, e.g. llm_token, api_x402, stablecoin, card")
    guard_p.add_argument("--amount", type=float, required=True, help="requested spend amount")
    guard_p.add_argument("--budget", required=True, help="budget id")
    guard_p.add_argument("--provider", help="provider, e.g. openai, x402, stripe")
    guard_p.add_argument("--service", help="model, endpoint, or merchant service")
    guard_p.add_argument("--merchant", help="merchant id/address")
    guard_p.add_argument("--session", help="task/session id")
    guard_p.add_argument("--request-id", help="idempotency key for audit/reservation")
    guard_p.add_argument("--enforce-exit-code", action="store_true",
                         help="exit 2 on deny so callers can block the spend")

    simulate_p = sub.add_parser("simulate-spend", parents=[common],
                                help="simulate agent purchases locally through policy and ledger")
    simulate_p.add_argument("--db", default="spend-sim.db", help="SQLite ledger path")
    simulate_p.add_argument("--policy", help="optional gateway policy JSON to enforce")
    simulate_p.add_argument("--agent", required=True, help="simulated agent id")
    simulate_p.add_argument("--budget", required=True, help="budget id charged by each purchase")
    simulate_p.add_argument("--amount", type=float, required=True, help="amount of each simulated purchase")
    simulate_p.add_argument("--count", type=int, default=1, help="number of purchase attempts")
    simulate_p.add_argument("--rail", default="api_x402", help="rail, e.g. llm_token, api_x402, stablecoin, card")
    simulate_p.add_argument("--provider", help="simulated provider name")
    simulate_p.add_argument("--merchant", help="simulated merchant id")
    simulate_p.add_argument("--service", help="simulated model, endpoint, or product")
    simulate_p.add_argument("--session", help="session id; a random one is used when omitted")

    gateway_p = sub.add_parser("gateway", help="run local HTTP pre-spend gateway")
    gateway_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    gateway_p.add_argument("--policy", help="gateway policy JSON; defaults to SPEND_POLICY_FILE")
    gateway_p.add_argument("--host", default="127.0.0.1", help="bind host")
    gateway_p.add_argument("--port", type=int, default=8787, help="bind port")

    sandbox_p = sub.add_parser("x402-sandbox", help="run a local x402 facilitator and paid-resource simulator")
    sandbox_p.add_argument("--host", default="127.0.0.1", help="bind host (keep loopback for local-only use)")
    sandbox_p.add_argument("--port", type=int, default=8788, help="bind port")

    facilitator_p = sub.add_parser("check-facilitator", help="verify a facilitator supports an x402 payment kind")
    facilitator_p.add_argument("--url", required=True, help="facilitator base URL")
    facilitator_p.add_argument("--network", required=True, help="CAIP-2 network id")
    facilitator_p.add_argument("--scheme", default="exact", help="x402 scheme")
    facilitator_p.add_argument("--version", type=int, default=2, help="x402 protocol version")
    facilitator_p.add_argument("--auth-env", help="environment variable holding a pre-minted Bearer JWT")
    facilitator_p.add_argument("--timeout", type=float, default=10, help="request timeout seconds")

    bazaar_p = sub.add_parser("filter-bazaar", help="locally filter x402 Bazaar discovery results with policy")
    bazaar_p.add_argument("--input", required=True, help="Bazaar discovery JSON (items/resources array)")
    bazaar_p.add_argument("--policy", required=True, help="policy JSON containing bazaar_policy")
    bazaar_p.add_argument("--out", help="optional JSON result path")

    fetch_bazaar_p = sub.add_parser("fetch-bazaar", help="download public x402 Bazaar HTTP resources")
    fetch_bazaar_p.add_argument("--out", default="bazaar-results.json", help="output JSON path")
    fetch_bazaar_p.add_argument("--url", default="https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources", help="Bazaar list endpoint")
    fetch_bazaar_p.add_argument("--limit", type=int, default=100, help="page size")
    fetch_bazaar_p.add_argument("--offset", type=int, default=0, help="page offset")
    fetch_bazaar_p.add_argument("--timeout", type=float, default=15, help="request timeout seconds")

    adopt_bazaar_p = sub.add_parser("adopt-bazaar", help="generate reviewable Gateway x402 resource config from approved Bazaar results")
    adopt_bazaar_p.add_argument("--input", required=True, help="Bazaar discovery JSON")
    adopt_bazaar_p.add_argument("--policy", required=True, help="policy JSON containing bazaar_policy")
    adopt_bazaar_p.add_argument("--out", default="bazaar-approved-resources.json", help="generated x402_resources JSON")

    validate_p = sub.add_parser("validate-policy", help="strictly validate gateway policy JSON")
    validate_p.add_argument("--policy", required=True, help="gateway policy JSON")

    audit_p = sub.add_parser("audit-config", help="show env vars, outbound hosts, and local files")
    audit_p.add_argument("--policy", required=True, help="gateway policy JSON")
    audit_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    audit_p.add_argument("--out-dir", default="artifacts", help="artifact directory")

    release_p = sub.add_parser("release-reservation", help="release an active gateway reservation")
    release_p.add_argument("--db", default="spend.db", help="SQLite ledger path")
    release_p.add_argument("--request-id", required=True, help="gateway request id")

    scenarios_p = sub.add_parser("run-scenarios", parents=[common],
                                 help="run JSON incident scenarios against an in-memory ledger")
    scenarios_p.add_argument("--path", default="scenarios", help="scenario JSON file or directory")
    scenarios_p.set_defaults(out_dir="artifacts")

    for name, verb in (("freeze", "freeze (deny all spend)"), ("unfreeze", "unfreeze")):
        fp = sub.add_parser(name, help=f"{verb} an agent/budget in the policy (kill-switch)")
        fp.add_argument("--policy", required=True, help="gateway policy JSON to edit")
        fp.add_argument("--agent", nargs="*", default=[], help="agent id(s)")
        fp.add_argument("--budget", nargs="*", default=[], help="budget id(s)")

    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    cmd = args.cmd or "demo"
    if cmd == "demo":
        demo(args.out_dir, args.db)
    elif cmd == "showcase":
        showcase(args.out_dir, args.db)
    elif cmd == "demo-live":
        demo_live(args.out_dir, args.db, args.policy, args.host, args.port)
    elif cmd == "pull":
        pull(args.db, args.out_dir, args.days, args.provider)
    elif cmd == "pull-openrouter":
        pull_openrouter(args.db, args.out_dir, args.generation_id, args.generation_ids_file)
    elif cmd == "pull-aws":
        pull_aws(args.db, args.out_dir, args.days, args.tag_agent, args.tag_budget)
    elif cmd == "pull-gcp-billing-file":
        pull_gcp_billing_file(
            args.db, args.out_dir, args.billing_export_file, args.label_agent, args.label_budget,
        )
    elif cmd == "pull-azure":
        pull_azure(args.db, args.out_dir, args.days, args.scope, args.tag_agent, args.tag_budget)
    elif cmd == "pull-all":
        pull_all(args.config, args.db, args.out_dir)
    elif cmd == "pull-x402":
        pull_x402(args.db, args.out_dir, args.pay_to, args.lookback_blocks, args.wallet_map)
    elif cmd == "pull-usdc":
        pull_usdc(args.db, args.out_dir, args.pay_to, args.lookback_blocks, args.wallet_map)
    elif cmd == "pull-stripe":
        pull_stripe(args.db, args.out_dir, args.days, args.limit)
    elif cmd == "report":
        report(args.db, args.out_dir)
    elif cmd == "guard":
        guard(args)
    elif cmd == "simulate-spend":
        simulate_spend(args)
    elif cmd == "gateway":
        gateway(args.db, args.policy, args.host, args.port)
    elif cmd == "x402-sandbox":
        x402_sandbox(args.host, args.port)
    elif cmd == "check-facilitator":
        check_facilitator(args)
    elif cmd == "filter-bazaar":
        filter_bazaar_cmd(args)
    elif cmd == "fetch-bazaar":
        fetch_bazaar_cmd(args)
    elif cmd == "adopt-bazaar":
        adopt_bazaar_cmd(args)
    elif cmd == "validate-policy":
        validate_policy_cmd(args.policy)
    elif cmd == "audit-config":
        audit_config_cmd(args.policy, args.db, args.out_dir)
    elif cmd == "release-reservation":
        release_reservation_cmd(args.db, args.request_id)
    elif cmd == "run-scenarios":
        run_scenarios_cmd(args.path, args.out_dir)
    elif cmd == "freeze":
        freeze(args)
    elif cmd == "unfreeze":
        unfreeze(args)


if __name__ == "__main__":
    main()
