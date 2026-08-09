"""Render a zero-dependency static HTML report from the ledger + alerts."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape

from .detectors import Alert
from .store import SpendStore

_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pactrail Control Plane</title>
<style>
:root{
  color-scheme:light;
  --bg:#f6f7f9;--panel:#ffffff;--ink:#111827;--muted:#667085;--line:#d9dee7;
  --green:#0f766e;--blue:#2563eb;--amber:#b45309;--red:#b91c1c;--soft:#eef2f7;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
.shell{max-width:1180px;margin:0 auto;padding:28px 20px 40px}
header{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:22px}
h1{margin:0;font-size:26px;letter-spacing:0;font-weight:760}
h2{margin:0 0 12px;font-size:15px;font-weight:720}
.sub{margin:6px 0 0;color:var(--muted)}
.badge{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);background:#fff;padding:7px 10px;border-radius:999px;color:#344054;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:999px;background:var(--green)}
.eyebrow{color:var(--green);font-weight:760;font-size:11px;letter-spacing:.12em;text-transform:uppercase;margin:0 0 7px}
.tabs{display:flex;gap:8px;border-bottom:1px solid var(--line);margin:0 0 18px}.tab{appearance:none;border:0;border-bottom:2px solid transparent;background:transparent;color:var(--muted);font:inherit;font-weight:700;padding:10px 2px;cursor:pointer;margin-right:18px}.tab.active{color:var(--green);border-bottom-color:var(--green)}
.view[hidden]{display:none}.section-intro{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin:0 0 14px}.section-intro h2{font-size:18px;margin:0}.section-intro .meta{max-width:620px}
.flow{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin-bottom:18px}.flow-step{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:13px;min-height:78px}.flow-step:not(:last-child):after{content:'→';position:absolute;right:-9px;top:26px;color:var(--muted);font-size:17px;z-index:1}.flow-step .label{margin-bottom:7px}.flow-step .value{font-size:17px;margin:0}.flow-step .meta{margin-top:4px}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;overflow-wrap:anywhere}.status{font-weight:720;text-transform:capitalize}.status.settled,.status.delivered{color:var(--green)}.status.denied,.status.verification_failed,.status.settlement_failed,.status.delivery_failed{color:var(--red)}.status.pending,.status.signer_approval_pending{color:var(--amber)}
.grid{display:grid;gap:14px}
.metrics{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:18px}
.metric{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:15px 16px;min-height:92px}
.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.value{font-size:28px;font-weight:760;margin-top:8px}
.value.small{font-size:22px}
.two{grid-template-columns:minmax(0,1fr) minmax(0,1fr);align-items:start;margin-bottom:18px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;min-width:0}
.row{display:grid;grid-template-columns:minmax(120px,1.2fr) minmax(140px,2fr) auto;gap:12px;align-items:center;padding:9px 0;border-top:1px solid #edf0f5}
.row:first-of-type{border-top:0}
.name{font-weight:650;overflow-wrap:anywhere}
.meta{color:var(--muted);font-size:12px}
.bar{height:9px;background:var(--soft);border-radius:999px;overflow:hidden}
.fill{height:100%;background:var(--blue);border-radius:999px}
.fill.warn{background:var(--amber)}
.fill.high{background:var(--red)}
.money{font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 8px;border-top:1px solid #edf0f5;text-align:left;vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;font-weight:680}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-flex;border-radius:999px;padding:3px 8px;font-size:12px;font-weight:680}
.pill.high{background:#fee2e2;color:var(--red)}
.pill.warn{background:#fef3c7;color:var(--amber)}
.pill.ok{background:#dcfce7;color:var(--green)}
.alerts{margin-bottom:18px}
.alert{display:grid;grid-template-columns:86px 150px minmax(0,1fr) auto;gap:12px;align-items:start;border-top:1px solid #edf0f5;padding:11px 0}
.alert:first-of-type{border-top:0}
.detail{overflow-wrap:anywhere}
.footer{color:var(--muted);font-size:12px;margin-top:18px}
@media (max-width:860px){
  header{display:block}.badge{margin-top:12px}.metrics,.two{grid-template-columns:1fr}
  .alert{grid-template-columns:1fr}.row{grid-template-columns:1fr}.money{text-align:left}.flow{grid-template-columns:1fr}.flow-step:not(:last-child):after{content:'↓';right:15px;top:auto;bottom:-16px}
  th:nth-child(4),td:nth-child(4){display:none}
}
</style>
</head>
<body><div class="shell">
"""

_TAIL = "</div></body></html>"


def _money(value: float) -> str:
    # Agent LLM spend is often sub-cent; plain ${:.2f} renders real costs as "$0.00".
    if 0 < abs(value) < 0.005:
        return "$" + f"{value:.6f}".rstrip("0").rstrip(".")
    return f"${value:,.2f}"


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}%"


def _bar_width(value: float | None, cap: float | None = None) -> float:
    if value is None:
        return 0.0
    if cap:
        return max(0.0, min(100.0, value / cap * 100))
    return max(0.0, min(100.0, value))


def _severity_class(severity: str) -> str:
    return "high" if severity == "high" else "warn" if severity == "warn" else "ok"


def _pretty_kind(kind: str) -> str:
    return kind.replace("_", " ")


def _event_rows(store: SpendStore, limit: int = 12) -> list:
    return store.db.execute(
        "SELECT event_time, x_agent_id, rail, provider_name, service_name, billed_cost, "
        "billing_currency, x_budget_id, x_receipt_ref, x_source_event "
        "FROM spend_events ORDER BY event_time DESC LIMIT ?",
        (limit,),
    ).fetchall()


def _top_alert(alerts: list[Alert]) -> str:
    if not alerts:
        return "No alerts"
    high = sum(1 for a in alerts if a.severity == "high")
    warn = sum(1 for a in alerts if a.severity == "warn")
    return f"{high} high / {warn} warn"


def _section_metrics(store: SpendStore, alerts: list[Alert]) -> str:
    total = store.total()
    events = store.db.execute("SELECT COUNT(*) FROM spend_events").fetchone()[0]
    agents = store.db.execute("SELECT COUNT(DISTINCT x_agent_id) FROM spend_events").fetchone()[0]
    rails = store.db.execute("SELECT COUNT(DISTINCT rail) FROM spend_events").fetchone()[0]
    return (
        "<section class='grid metrics'>"
        f"<div class='metric'><div class='label'>Total spend</div><div class='value'>{_money(total)}</div>"
        "<div class='meta'>Across all observed rails</div></div>"
        f"<div class='metric'><div class='label'>Alerts</div><div class='value small'>{escape(_top_alert(alerts))}</div>"
        "<div class='meta'>Phase-0 detection only</div></div>"
        f"<div class='metric'><div class='label'>Agents</div><div class='value'>{agents}</div>"
        f"<div class='meta'>{events} spend events</div></div>"
        f"<div class='metric'><div class='label'>Rails</div><div class='value'>{rails}</div>"
        "<div class='meta'>Token, API, card, stablecoin, cloud</div></div>"
        "</section>"
    )


def _section_rail_mix(store: SpendStore) -> str:
    total = store.total() or 1.0
    rows = store.by("rail")
    p = ["<section class='panel'><h2>Rail Mix</h2>"]
    if not rows:
        p.append("<div class='meta'>No spend events yet.</div>")
    for r in rows:
        pct = r["spend"] / total * 100
        p.append(
            "<div class='row'>"
            f"<div><div class='name'>{escape(r['rail'])}</div><div class='meta'>{r['events']} events</div></div>"
            f"<div class='bar'><div class='fill' style='width:{pct:.1f}%'></div></div>"
            f"<div class='money'>{_money(r['spend'])}</div>"
            "</div>"
        )
    p.append("</section>")
    return "".join(p)


def _section_budgets(store: SpendStore, caps: dict[str, float]) -> str:
    rows = store.budget_burn(caps)
    p = ["<section class='panel'><h2>Budget Burn</h2>"]
    if not rows:
        p.append("<div class='meta'>No budgets observed yet.</div>")
    for b in rows:
        cap = b["cap"]
        pct = b["pct"]
        klass = "high" if pct is not None and pct >= 100 else "warn" if pct is not None and pct >= 80 else ""
        cap_text = "uncapped" if cap is None else _money(cap)
        p.append(
            "<div class='row'>"
            f"<div><div class='name'>{escape(b['budget'])}</div><div class='meta'>cap {cap_text}</div></div>"
            f"<div class='bar'><div class='fill {klass}' style='width:{_bar_width(pct):.1f}%'></div></div>"
            f"<div class='money'>{_money(b['spent'])}<div class='meta'>{_pct(pct)}</div></div>"
            "</div>"
        )
    p.append("</section>")
    return "".join(p)


def _section_alerts(alerts: list[Alert]) -> str:
    p = ["<section class='panel alerts'><h2>Security Signals</h2>"]
    if not alerts:
        p.append("<span class='pill ok'>clear</span><div class='meta' style='margin-top:8px'>No alerts.</div>")
    else:
        ordered = sorted(alerts, key=lambda a: (0 if a.severity == "high" else 1, -a.value))
        for a in ordered:
            klass = _severity_class(a.severity)
            p.append(
                "<div class='alert'>"
                f"<div><span class='pill {klass}'>{escape(a.severity)}</span></div>"
                f"<div><div class='name'>{escape(_pretty_kind(a.kind))}</div><div class='meta'>{escape(a.subject)}</div></div>"
                f"<div class='detail'>{escape(a.detail)}</div>"
                f"<div class='money'>{a.value:.2f}</div>"
                "</div>"
            )
    p.append("</section>")
    return "".join(p)


def _section_gateway(store: SpendStore) -> str:
    allowed = store.db.execute(
        "SELECT COUNT(*) FROM gateway_decisions WHERE decision = 'allow'"
    ).fetchone()[0]
    blocked = store.db.execute(
        "SELECT COUNT(*) FROM gateway_decisions WHERE decision = 'deny'"
    ).fetchone()[0]
    active = store.db.execute(
        "SELECT COUNT(*) FROM spend_reservations WHERE status = 'active' AND expires_at > ?",
        (datetime.now(timezone.utc).isoformat(),),
    ).fetchone()[0]
    p = [
        "<section class='grid metrics'>",
        f"<div class='metric'><div class='label'>Gateway allowed</div><div class='value'>{allowed}</div>"
        "<div class='meta'>Pre-spend passes</div></div>",
        f"<div class='metric'><div class='label'>Gateway blocked</div><div class='value'>{blocked}</div>"
        "<div class='meta'>Denied before provider call</div></div>",
        f"<div class='metric'><div class='label'>Active holds</div><div class='value'>{active}</div>"
        "<div class='meta'>Reserved budget</div></div>",
        "<div class='metric'><div class='label'>Prompt storage</div><div class='value small'>off</div>"
        "<div class='meta'>Metadata-only audit</div></div>",
        "</section>",
        "<section class='grid two'>",
        "<section class='panel'><h2>Top Blocked Agents</h2><table><tr><th>Agent</th><th>Blocks</th></tr>",
    ]
    rows = store.db.execute(
        "SELECT x_agent_id, COUNT(*) AS blocks FROM gateway_decisions "
        "WHERE decision = 'deny' GROUP BY x_agent_id ORDER BY blocks DESC LIMIT 5"
    ).fetchall()
    if not rows:
        p.append("<tr><td colspan='2'>No gateway blocks yet.</td></tr>")
    for r in rows:
        p.append(f"<tr><td>{escape(r['x_agent_id'])}</td><td>{r['blocks']}</td></tr>")
    p.append("</table></section>")
    p.append("<section class='panel'><h2>Top Blocked Merchants</h2><table><tr><th>Merchant / Service</th><th>Blocks</th></tr>")
    rows = store.db.execute(
        "SELECT COALESCE(NULLIF(x_merchant_id, ''), service_name) AS merchant, COUNT(*) AS blocks "
        "FROM gateway_decisions WHERE decision = 'deny' "
        "GROUP BY merchant ORDER BY blocks DESC LIMIT 5"
    ).fetchall()
    if not rows:
        p.append("<tr><td colspan='2'>No blocked merchants yet.</td></tr>")
    for r in rows:
        p.append(f"<tr><td>{escape(r['merchant'] or 'unknown')}</td><td>{r['blocks']}</td></tr>")
    p.append("</table></section></section>")
    p.append("<section class='panel'><h2>Recent Gateway Decisions</h2><table><tr>"
             "<th>Time</th><th>Agent</th><th>Route</th><th>Decision</th><th>Reason</th></tr>")
    rows = store.db.execute(
        "SELECT created_at, x_agent_id, route_type, route_id, decision, reasons_json "
        "FROM gateway_decisions ORDER BY created_at DESC LIMIT 8"
    ).fetchall()
    if not rows:
        p.append("<tr><td colspan='5'>No gateway decisions yet.</td></tr>")
    for r in rows:
        reasons = ", ".join(json.loads(r["reasons_json"] or "[]"))
        klass = "ok" if r["decision"] == "allow" else "high"
        route = f"{r['route_type']}:{r['route_id']}" if r["route_id"] else r["route_type"]
        p.append(
            f"<tr><td>{escape(r['created_at'])}</td><td>{escape(r['x_agent_id'])}</td>"
            f"<td>{escape(route)}</td><td><span class='pill {klass}'>{escape(r['decision'])}</span></td>"
            f"<td>{escape(reasons)}</td></tr>"
        )
    p.append("</table></section>")
    return "".join(p)


def _status(value: object) -> str:
    """Render a status without trusting ledger text as HTML or CSS."""
    raw = str(value or "unknown")
    safe_class = "".join(char if char.isalnum() or char == "_" else "-" for char in raw.lower())
    return f"<span class='status {escape(safe_class)}'>{escape(raw.replace('_', ' '))}</span>"


def _control_metrics(store: SpendStore) -> str:
    now = datetime.now(timezone.utc).isoformat()
    active_sessions = store.db.execute(
        "SELECT COUNT(*) FROM spend_sessions WHERE status = 'active' AND expires_at > ?", (now,)
    ).fetchone()[0]
    active_holds = store.db.execute(
        "SELECT COUNT(*) FROM spend_reservations WHERE status = 'active' AND expires_at > ?", (now,)
    ).fetchone()[0]
    pending_approvals = store.db.execute(
        "SELECT COUNT(*) FROM signer_approvals WHERE status = 'pending' AND expires_at > ?", (now,)
    ).fetchone()[0]
    settled = store.db.execute(
        "SELECT COUNT(*) FROM x402_payments WHERE status IN ('settled', 'delivered')"
    ).fetchone()[0]
    return (
        "<section class='grid metrics'>"
        f"<div class='metric'><div class='label'>Active spend sessions</div><div class='value'>{active_sessions}</div>"
        "<div class='meta'>Task-scoped payment authority</div></div>"
        f"<div class='metric'><div class='label'>Active budget holds</div><div class='value'>{active_holds}</div>"
        "<div class='meta'>Reserved before settlement</div></div>"
        f"<div class='metric'><div class='label'>Signer approvals</div><div class='value'>{pending_approvals}</div>"
        "<div class='meta'>Pending one-time authorizations</div></div>"
        f"<div class='metric'><div class='label'>x402 settled</div><div class='value'>{settled}</div>"
        "<div class='meta'>Verified payment lifecycle records</div></div>"
        "</section>"
    )


def _section_payment_lifecycle(store: SpendStore) -> str:
    rows = store.db.execute(
        "SELECT i.request_id, i.session_id, i.resource_id, i.agent_id, i.status AS intent_status, "
        "p.scheme, p.authorization_limit_units, p.usage_units, p.settled_units, p.status AS payment_status, "
        "p.transaction_ref, a.status AS approval_status "
        "FROM payment_intents i "
        "LEFT JOIN x402_payments p ON p.request_id = i.request_id "
        "LEFT JOIN signer_approvals a ON a.request_id = i.request_id "
        "ORDER BY i.updated_at DESC LIMIT 12"
    ).fetchall()
    p = ["<section class='panel'><h2>Payment lifecycle</h2>"
         "<div class='meta'>Every row ties an agent request to its policy decision, signer approval, and settlement receipt.</div>"
         "<table><tr><th>Request</th><th>Agent / resource</th><th>Scheme</th><th>Authorization → settled</th><th>Lifecycle</th></tr>"]
    if not rows:
        p.append("<tr><td colspan='5'>No x402 payment intents yet. Start with the sandbox demo to create an auditable lifecycle.</td></tr>")
    for row in rows:
        amounts = " → ".join(escape(str(row[key] or "—")) for key in ("authorization_limit_units", "settled_units"))
        statuses = [_status(row["intent_status"])]
        if row["approval_status"]:
            statuses.append(_status(row["approval_status"]))
        if row["payment_status"]:
            statuses.append(_status(row["payment_status"]))
        p.append(
            "<tr>"
            f"<td><div class='mono'>{escape(row['request_id'])}</div><div class='meta'>{escape(row['session_id'])}</div></td>"
            f"<td><div class='name'>{escape(row['agent_id'])}</div><div class='meta'>{escape(row['resource_id'])}</div></td>"
            f"<td>{escape(str(row['scheme'] or 'awaiting quote'))}</td>"
            f"<td><div class='mono'>{amounts}</div><div class='meta'>protocol units</div></td>"
            f"<td>{'<br>'.join(statuses)}"
            f"<div class='meta mono'>{escape(str(row['transaction_ref'] or ''))}</div></td>"
            "</tr>"
        )
    p.append("</table></section>")
    return "".join(p)


def _section_sessions_and_approvals(store: SpendStore) -> str:
    now = datetime.now(timezone.utc).isoformat()
    sessions = store.db.execute(
        "SELECT session_id, parent_task, budget_id, cap, expires_at, status FROM spend_sessions "
        "ORDER BY updated_at DESC LIMIT 8"
    ).fetchall()
    approvals = store.db.execute(
        "SELECT approval_id, request_id, signer_id, status, expires_at FROM signer_approvals "
        "ORDER BY updated_at DESC LIMIT 8"
    ).fetchall()
    p = ["<section class='grid two'>",
         "<section class='panel'><h2>Spend sessions</h2><table><tr><th>Task / budget</th><th>Cap</th><th>Status</th></tr>"]
    if not sessions:
        p.append("<tr><td colspan='3'>No sessions yet.</td></tr>")
    for row in sessions:
        status = "expired" if row["status"] == "active" and row["expires_at"] <= now else row["status"]
        p.append(
            f"<tr><td><div class='mono'>{escape(row['parent_task'])}</div><div class='meta'>{escape(row['session_id'])} · {escape(row['budget_id'])}</div></td>"
            f"<td>{_money(float(row['cap']))}</td><td>{_status(status)}</td></tr>"
        )
    p.append("</table></section>")
    p.append("<section class='panel'><h2>Signer approvals</h2><table><tr><th>Signer / request</th><th>Expires</th><th>Status</th></tr>")
    if not approvals:
        p.append("<tr><td colspan='3'>No signer approvals yet. The wallet is never exposed to the agent.</td></tr>")
    for row in approvals:
        p.append(
            f"<tr><td><div class='name'>{escape(row['signer_id'])}</div><div class='meta mono'>{escape(row['request_id'])}</div></td>"
            f"<td class='mono'>{escape(row['expires_at'])}</td><td>{_status(row['status'])}</td></tr>"
        )
    p.append("</table></section></section>")
    return "".join(p)


def _section_agent_rail(store: SpendStore) -> str:
    p = ["<section class='panel'><h2>Agent x Rail</h2><table><tr>"
         "<th>Agent</th><th>Rail</th><th>Events</th><th class='num'>Spend</th></tr>"]
    rows = store.by("x_agent_id", "rail")
    if not rows:
        p.append("<tr><td colspan='4'>No spend events yet.</td></tr>")
    for r in rows:
        p.append(
            f"<tr><td>{escape(r['x_agent_id'])}</td><td>{escape(r['rail'])}</td>"
            f"<td>{r['events']}</td><td class='num'>{_money(r['spend'])}</td></tr>"
        )
    p.append("</table></section>")
    return "".join(p)


def _section_events(store: SpendStore) -> str:
    p = ["<section class='panel'><h2>Recent Ledger Events</h2><table><tr>"
         "<th>Time</th><th>Agent</th><th>Rail</th><th>Service</th><th>Evidence</th><th class='num'>Cost</th></tr>"]
    rows = _event_rows(store)
    if not rows:
        p.append("<tr><td colspan='6'>No spend events yet.</td></tr>")
    for r in rows:
        evidence = r["x_source_event"][-12:] if r["x_source_event"] else ""
        p.append(
            f"<tr><td>{escape(r['event_time'])}</td><td>{escape(r['x_agent_id'])}</td>"
            f"<td>{escape(r['rail'])}</td><td>{escape(r['provider_name'])} / {escape(r['service_name'])}</td>"
            f"<td>{escape(evidence)}</td>"
            f"<td class='num'>{_money(r['billed_cost'])} {escape(r['billing_currency'])}</td></tr>"
        )
    p.append("</table></section>")
    return "".join(p)


def render(store: SpendStore, caps: dict[str, float], alerts: list[Alert],
           refresh_seconds: int | None = None) -> str:
    head = _HEAD
    if refresh_seconds:  # live dashboard auto-refreshes; static snapshots do not
        head = head.replace(
            '<meta name="viewport"',
            f'<meta http-equiv="refresh" content="{int(refresh_seconds)}"><meta name="viewport"',
            1,
        )
    p = [head]
    p.append(
        "<header><div><p class='eyebrow'>Pactrail payment control plane</p><h1>Agent spend, constrained before it is signed.</h1>"
        "<p class='sub'>Control x402 payment authority, then retain a verifiable receipt and cross-rail audit trail.</p></div>"
        "<div class='badge'><span class='dot'></span>gateway online</div></header>"
    )
    p.append("<nav class='tabs' aria-label='Pactrail views'>"
             "<button class='tab active' type='button' data-view='control'>Control plane</button>"
             "<button class='tab' type='button' data-view='observability'>Spend observability</button></nav>")
    p.append("<main class='view' data-panel='control'>"
             "<div class='section-intro'><div><h2>Payment authority and execution</h2>"
             "<p class='meta'>The wallet key stays outside Pactrail. The gateway approves bounded intents, and an external signer can only sign a matching one-time approval.</p>"
             "</div></div>")
    p.append("<section class='flow' aria-label='Pactrail payment lifecycle'>"
             "<div class='flow-step'><div class='label'>1. Agent</div><div class='value'>Payment intent</div><div class='meta'>resource + task</div></div>"
             "<div class='flow-step'><div class='label'>2. Pactrail</div><div class='value'>Policy decision</div><div class='meta'>budget + merchant</div></div>"
             "<div class='flow-step'><div class='label'>3. Signer</div><div class='value'>One-time approval</div><div class='meta'>no key to agent</div></div>"
             "<div class='flow-step'><div class='label'>4. x402</div><div class='value'>Verify + settle</div><div class='meta'>facilitator</div></div>"
             "<div class='flow-step'><div class='label'>5. Receipt</div><div class='value'>Audit record</div><div class='meta'>intent → settlement</div></div></section>")
    p.append(_control_metrics(store))
    p.append(_section_payment_lifecycle(store))
    p.append(_section_sessions_and_approvals(store))
    p.append(_section_gateway(store))
    p.append("</main>")
    p.append("<main class='view' data-panel='observability' hidden>"
             "<div class='section-intro'><div><h2>Spend observability</h2>"
             "<p class='meta'>The original cross-rail ledger remains useful after the payment decision: it joins token, API, card, stablecoin, and cloud spend into one audit view.</p>"
             "</div></div>")
    p.append(_section_metrics(store, alerts))
    p.append("<section class='grid two'>")
    p.append(_section_rail_mix(store))
    p.append(_section_budgets(store, caps))
    p.append("</section>")
    p.append(_section_alerts(alerts))
    p.append("<section class='grid two'>")
    p.append(_section_agent_rail(store))
    p.append(_section_events(store))
    p.append("</section></main>")
    p.append("<p class='footer'>Pactrail enforces policy only when agents route payment through its gateway. "
             "Observability records metadata and receipts, never wallet keys or prompts.</p>")
    p.append("<script>document.querySelectorAll('[data-view]').forEach(function(button){button.addEventListener('click',function(){var view=button.dataset.view;document.querySelectorAll('[data-panel]').forEach(function(panel){panel.hidden=panel.dataset.panel!==view;});document.querySelectorAll('[data-view]').forEach(function(tab){tab.classList.toggle('active',tab===button);});});});</script>")
    p.append(_TAIL)
    return "".join(p)
