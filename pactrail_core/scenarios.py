"""Executable incident scenarios for ledger and gateway invariants.

Scenarios deliberately use an in-memory ledger. They model the observable
sequence around a payment without touching a provider, wallet, or facilitator:
seed observed spend, make a pre-spend decision, replay a request, and model a
delivery fault that must release its budget hold. The resulting snapshot is
stable enough to commit as an engineering incident record.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .gateway import GuardRequest, cap_for_request, decide, rate_cap_for_request, validate_policy
from .schema import SpendEvent
from .store import SpendStore


class ScenarioError(ValueError):
    """A malformed scenario or an invariant that did not hold."""


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    description: str
    passed: bool
    snapshot: dict[str, Any]
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.scenario_id,
            "description": self.description,
            "passed": self.passed,
            "error": self.error,
            "snapshot": self.snapshot,
        }


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScenarioError(f"{label} must be an object")
    return value


def _request(value: Any) -> GuardRequest:
    data = _mapping(value, "request")
    required = ("agent", "rail", "amount", "budget")
    missing = [key for key in required if key not in data]
    if missing:
        raise ScenarioError(f"request missing: {', '.join(missing)}")
    try:
        return GuardRequest(
            x_agent_id=str(data["agent"]),
            rail=str(data["rail"]),
            amount=float(data["amount"]),
            x_budget_id=str(data["budget"]),
            provider_name=str(data.get("provider", "")),
            service_name=str(data.get("service", "")),
            x_merchant_id=str(data.get("merchant", "")),
            x_session_id=str(data.get("session", "")),
        )
    except (TypeError, ValueError) as exc:
        raise ScenarioError("request amount must be numeric") from exc


def _event(value: Any) -> SpendEvent:
    data = _mapping(value, "event")
    fields = set(SpendEvent.__dataclass_fields__)
    unknown = sorted(set(data) - fields)
    if unknown:
        raise ScenarioError(f"event has unknown fields: {', '.join(unknown)}")
    required = (
        "event_id", "event_time", "rail", "provider_name", "service_name",
        "billed_cost", "billing_currency", "consumed_quantity", "pricing_unit",
        "x_agent_id", "x_budget_id",
    )
    missing = [key for key in required if key not in data]
    if missing:
        raise ScenarioError(f"event missing: {', '.join(missing)}")
    try:
        return SpendEvent(**{key: data[key] for key in fields if key in data})
    except (TypeError, ValueError) as exc:
        raise ScenarioError(f"invalid event: {exc}") from exc


def _reservation_status(store: SpendStore, request_id: str) -> str:
    row = store.db.execute(
        "SELECT status FROM spend_reservations WHERE request_id = ?", (request_id,)
    ).fetchone()
    return str(row["status"]) if row else "none"


def _snapshot(store: SpendStore, faults: list[dict[str, str]]) -> dict[str, Any]:
    by_budget = {str(row["x_budget_id"]): float(row["spend"]) for row in store.by("x_budget_id")}
    by_rail = {str(row["rail"]): float(row["spend"]) for row in store.by("rail")}
    decisions = store.db.execute(
        "SELECT request_id, decision FROM gateway_decisions ORDER BY request_id"
    ).fetchall()
    reservations = store.db.execute(
        "SELECT status, COUNT(*) AS count, COALESCE(SUM(amount), 0) AS amount "
        "FROM spend_reservations GROUP BY status ORDER BY status"
    ).fetchall()
    return {
        "ledger": {
            "event_count": int(store.db.execute("SELECT COUNT(*) FROM spend_events").fetchone()[0]),
            "total": round(float(store.total()), 6),
            "by_budget": by_budget,
            "by_rail": by_rail,
        },
        "gateway": {
            "allow_count": sum(row["decision"] == "allow" for row in decisions),
            "deny_count": sum(row["decision"] == "deny" for row in decisions),
            "decision_count": len(decisions),
            "reservations": {
                str(row["status"]): {"count": int(row["count"]), "amount": round(float(row["amount"]), 6)}
                for row in reservations
            },
        },
        "faults": faults,
    }


def _assert_value(actual: Any, expected: Any, path: str) -> None:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise ScenarioError(f"{path} expected object, got {actual!r}")
        for key, value in expected.items():
            if key not in actual:
                raise ScenarioError(f"{path}.{key} missing")
            _assert_value(actual[key], value, f"{path}.{key}")
        return
    if isinstance(expected, float) or isinstance(actual, float):
        try:
            if abs(float(actual) - float(expected)) > 0.000001:
                raise ScenarioError(f"{path} expected {expected!r}, got {actual!r}")
            return
        except (TypeError, ValueError):
            pass
    if actual != expected:
        raise ScenarioError(f"{path} expected {expected!r}, got {actual!r}")


def _assert_request(store: SpendStore, request_id: str, expected: dict[str, Any]) -> None:
    decision = store.gateway_decision_as_dict(request_id)
    if not decision:
        raise ScenarioError(f"request {request_id} was not recorded")
    actual = {
        "decision": decision["decision"],
        "reservation_status": _reservation_status(store, request_id),
    }
    _assert_value(
        actual,
        {key: value for key, value in expected.items() if key != "reason_contains"},
        f"requests.{request_id}",
    )
    reason = expected.get("reason_contains")
    if reason and not any(str(reason) in item for item in decision["reasons"]):
        raise ScenarioError(f"requests.{request_id}.reasons missing {reason!r}")


def run_scenario(data: dict[str, Any]) -> ScenarioResult:
    """Run one scenario and return its snapshot; assertion failures are reported."""
    scenario_id = str(data.get("id", ""))
    description = str(data.get("description", ""))
    if not scenario_id:
        raise ScenarioError("scenario id is required")
    policy = _mapping(data.get("policy", {}), "policy")
    errors = validate_policy(policy)
    if errors:
        raise ScenarioError("invalid policy: " + "; ".join(errors))
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ScenarioError("steps must be a non-empty array")

    faults: list[dict[str, str]] = []
    with SpendStore() as store:
        try:
            for index, raw_step in enumerate(steps, start=1):
                step = _mapping(raw_step, f"steps[{index}]")
                action = str(step.get("action", ""))
                if action == "seed":
                    events = step.get("events")
                    if not isinstance(events, list):
                        raise ScenarioError(f"steps[{index}].events must be an array")
                    store.ingest(_event(event) for event in events)
                elif action == "guard":
                    request_id = str(step.get("request_id", ""))
                    if not request_id:
                        raise ScenarioError(f"steps[{index}].request_id is required")
                    existing = store.gateway_decision_as_dict(request_id)
                    if not existing:
                        req = _request(step.get("request"))
                        decision = decide(store, policy, req)
                        store.reserve_and_record_gateway_decision(
                            request_id=request_id,
                            req=req,
                            decision=decision.decision,
                            reasons=decision.reasons,
                            route_type=str(step.get("route_type", "guard")),
                            route_id=str(step.get("route_id", "")),
                            ttl_seconds=int(policy.get("reservation_ttl_seconds", 900)),
                            cap=cap_for_request(policy, req),
                            rate_cap=rate_cap_for_request(policy, req),
                        )
                    expected = step.get("expect")
                    if expected is not None:
                        _assert_request(store, request_id, _mapping(expected, f"steps[{index}].expect"))
                elif action == "release":
                    request_id = str(step.get("request_id", ""))
                    if not request_id:
                        raise ScenarioError(f"steps[{index}].request_id is required")
                    store.release_reservation(request_id)
                elif action == "fault":
                    request_id = str(step.get("request_id", ""))
                    kind = str(step.get("kind", ""))
                    if not request_id or not kind:
                        raise ScenarioError(f"steps[{index}] fault needs request_id and kind")
                    if step.get("release_reservation"):
                        store.release_reservation(request_id)
                    faults.append({"request_id": request_id, "kind": kind})
                else:
                    raise ScenarioError(f"steps[{index}].action is unknown: {action!r}")

            snapshot = _snapshot(store, faults)
            expected = _mapping(data.get("expect", {}), "expect")
            _assert_value(snapshot, {key: value for key, value in expected.items() if key != "requests"}, "snapshot")
            for request_id, request_expectation in _mapping(expected.get("requests", {}), "expect.requests").items():
                _assert_request(store, str(request_id), _mapping(request_expectation, f"expect.requests.{request_id}"))
            return ScenarioResult(scenario_id, description, True, snapshot)
        except ScenarioError as exc:
            return ScenarioResult(scenario_id, description, False, _snapshot(store, faults), str(exc))


def load_scenario(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"{source}: invalid JSON: {exc.msg}") from exc
    return _mapping(data, str(source))


def run_scenarios(path: str | Path) -> list[ScenarioResult]:
    source = Path(path)
    files = sorted(source.glob("*.json")) if source.is_dir() else [source]
    if not files:
        raise ScenarioError(f"no scenario JSON files found in {source}")
    results: list[ScenarioResult] = []
    for file in files:
        try:
            results.append(run_scenario(load_scenario(file)))
        except ScenarioError as exc:
            results.append(ScenarioResult(file.stem, "", False, {}, str(exc)))
    return results


def render_report(results: list[ScenarioResult]) -> dict[str, Any]:
    return {
        "passed": sum(result.passed for result in results),
        "failed": sum(not result.passed for result in results),
        "scenarios": [result.as_dict() for result in results],
    }
