"""Append-only SQLite ledger + read-only summaries.

ponytail: SQLite (stdlib) is the thinnest store that works. Swap to DuckDB or
Postgres when you outgrow one file or need concurrent writers.
ponytail: total() sums mixed currencies 1:1 (USDC approx USD); add FX
normalization to a reporting currency before real use.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from .schema import COLUMNS, _NUMERIC, SpendEvent

_DDL = (
    "CREATE TABLE IF NOT EXISTS spend_events ("
    + ", ".join(f"{c} REAL" if c in _NUMERIC else f"{c} TEXT" for c in COLUMNS)
    + ", PRIMARY KEY (event_id))"
)


class SpendStore:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute(_DDL)
        self.db.execute(_GATEWAY_DECISIONS_DDL)
        self.db.execute(_SPEND_RESERVATIONS_DDL)
        self.db.execute(_X402_PAYMENTS_DDL)
        self.db.execute(_X402_BATCHES_DDL)
        self._migrate_columns()

    def _migrate_columns(self) -> None:
        existing = {row["name"] for row in self.db.execute("PRAGMA table_info(spend_events)")}
        for column in COLUMNS:
            if column not in existing:
                kind = "REAL" if column in _NUMERIC else "TEXT"
                default = "0" if column in _NUMERIC else "''"
                self.db.execute(f"ALTER TABLE spend_events ADD COLUMN {column} {kind} DEFAULT {default}")
        x402_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(x402_payments)")}
        for column in (
            "scheme TEXT DEFAULT 'exact'", "authorization_limit_units TEXT DEFAULT ''",
            "usage_units TEXT DEFAULT ''", "settled_units TEXT DEFAULT ''",
            "released_units TEXT DEFAULT ''", "batch_id TEXT DEFAULT ''",
        ):
            name = column.split()[0]
            if name not in x402_columns:
                self.db.execute(f"ALTER TABLE x402_payments ADD COLUMN {column}")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "SpendStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def ingest(self, events: Iterable[SpendEvent]) -> int:
        rows = [tuple(e.as_row()[c] for c in COLUMNS) for e in events]
        before = self.db.total_changes
        # INSERT OR IGNORE => idempotent on event_id (re-ingest never double-counts).
        self.db.executemany(
            f"INSERT OR IGNORE INTO spend_events ({', '.join(COLUMNS)}) "
            f"VALUES ({', '.join('?' for _ in COLUMNS)})",
            rows,
        )
        self.db.commit()
        return self.db.total_changes - before

    def total(self) -> float:
        return self.db.execute("SELECT COALESCE(SUM(billed_cost), 0) FROM spend_events").fetchone()[0]

    def by(self, *dims: str) -> list[sqlite3.Row]:
        cols = ", ".join(dims)
        return self.db.execute(
            f"SELECT {cols}, ROUND(SUM(billed_cost), 6) AS spend, COUNT(*) AS events "
            f"FROM spend_events GROUP BY {cols} ORDER BY spend DESC"
        ).fetchall()

    def budget_burn(self, caps: dict[str, float]) -> list[dict]:
        out = []
        for row in self.by("x_budget_id"):
            cap = caps.get(row["x_budget_id"])
            out.append({
                "budget": row["x_budget_id"],
                "spent": row["spend"],
                "cap": cap,
                "pct": round(100 * row["spend"] / cap, 1) if cap else None,
            })
        return out

    def active_reservations_total(self, budget: str, now: str | None = None) -> float:
        now = now or _now()
        row = self.db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS reserved FROM spend_reservations "
            "WHERE x_budget_id = ? AND status = 'active' AND expires_at > ?",
            (budget, now),
        ).fetchone()
        return float(row["reserved"] or 0)

    def gateway_decision_by_request(self, request_id: str):
        return self.db.execute(
            "SELECT * FROM gateway_decisions WHERE request_id = ?",
            (request_id,),
        ).fetchone()

    def gateway_decision_as_dict(self, request_id: str) -> dict | None:
        row = self.gateway_decision_by_request(request_id)
        if not row:
            return None
        request = {
            "x_agent_id": row["x_agent_id"],
            "rail": row["rail"],
            "amount": row["amount"],
            "x_budget_id": row["x_budget_id"],
            "provider_name": row["provider_name"],
            "service_name": row["service_name"],
            "x_merchant_id": row["x_merchant_id"],
            "x_session_id": "",
        }
        return {
            "decision": row["decision"],
            "allowed": row["decision"] == "allow",
            "reasons": json.loads(row["reasons_json"] or "[]"),
            "request": request,
            "request_id": row["request_id"],
            "reservation_id": row["reservation_id"] or "",
        }

    def release_reservation(self, request_id: str) -> int:
        before = self.db.total_changes
        self.db.execute(
            "UPDATE spend_reservations SET status = 'released' WHERE request_id = ? AND status = 'active'",
            (request_id,),
        )
        self.db.commit()
        return self.db.total_changes - before

    def record_gateway_decision(self, *, request_id: str, req, decision: str, reasons: list[str],
                                route_type: str = "guard", route_id: str = "",
                                reservation_id: str = "", now: str | None = None) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO gateway_decisions (decision_id, request_id, created_at, "
            "x_agent_id, rail, provider_name, service_name, x_merchant_id, amount, x_budget_id, "
            "decision, reasons_json, route_type, route_id, reservation_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"gwd:{request_id}",
                request_id,
                now or _now(),
                req.x_agent_id,
                req.rail,
                req.provider_name,
                req.service_name,
                req.x_merchant_id,
                req.amount,
                req.x_budget_id,
                decision,
                json.dumps(reasons, sort_keys=True),
                route_type,
                route_id,
                reservation_id,
            ),
        )
        self.db.commit()

    def claim_x402_payment(self, request_id: str, resource_id: str, payment_fingerprint: str, *,
                           scheme: str = "exact", authorization_limit_units: str = "",
                           batch_id: str = "") -> str | None:
        """Claim a signed x402 payload before verification/settlement.

        Returns the earlier request id when this exact signed payload was already
        claimed. The unique fingerprint makes the replay check safe across
        concurrent gateway workers without storing the payment payload itself.
        """
        now = _now()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT request_id FROM x402_payments WHERE payment_fingerprint = ?",
                (payment_fingerprint,),
            ).fetchone()
            if row:
                self.db.commit()
                return str(row["request_id"])
            self.db.execute(
                "INSERT INTO x402_payments (request_id, resource_id, payment_fingerprint, scheme, "
                "authorization_limit_units, batch_id, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'approved', ?, ?)",
                (request_id, resource_id, payment_fingerprint, scheme, authorization_limit_units, batch_id, now, now),
            )
            self.db.commit()
            return None
        except Exception:
            self.db.rollback()
            raise

    def update_x402_payment(self, request_id: str, status: str, *, transaction_ref: str = "",
                            detail: str = "") -> None:
        self.db.execute(
            "UPDATE x402_payments SET status = ?, transaction_ref = CASE WHEN ? = '' THEN transaction_ref ELSE ? END, "
            "detail = ?, updated_at = ? WHERE request_id = ?",
            (status, transaction_ref, transaction_ref, detail, _now(), request_id),
        )
        self.db.commit()

    def account_x402_payment(self, request_id: str, *, usage_units: str, settled_units: str) -> None:
        """Persist the final money facts without treating an authorization as spend."""
        row = self.x402_payment(request_id)
        if not row:
            raise ValueError(f"unknown x402 payment {request_id}")
        limit = int(row["authorization_limit_units"] or 0)
        usage = int(usage_units)
        settled = int(settled_units)
        if usage < 0 or settled < 0 or usage != settled:
            raise ValueError("x402 usage and settled amounts must be equal non-negative atomic units")
        if limit and settled > limit:
            raise ValueError(f"x402 settlement {settled} exceeds authorization limit {limit}")
        self.db.execute(
            "UPDATE x402_payments SET usage_units = ?, settled_units = ?, released_units = ?, updated_at = ? "
            "WHERE request_id = ?",
            (str(usage), str(settled), str(max(limit - settled, 0)), _now(), request_id),
        )
        self.db.commit()

    def reserve_x402_batch(self, *, batch_id: str, resource_id: str, authorization_limit_units: str,
                            batch_limit_units: str) -> None:
        """Atomically hold a batch slice so concurrent agent calls cannot exceed its cap."""
        authorization = int(authorization_limit_units)
        limit = int(batch_limit_units)
        if not batch_id or authorization <= 0 or limit <= 0:
            raise ValueError("batch id, authorization limit, and batch limit must be positive")
        now = _now()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT * FROM x402_batches WHERE batch_id = ?", (batch_id,)).fetchone()
            if row is None:
                self.db.execute(
                    "INSERT INTO x402_batches (batch_id, resource_id, status, authorization_limit_units, "
                    "reserved_units, usage_units, settled_units, created_at, updated_at) "
                    "VALUES (?, ?, 'open', ?, ?, '0', '0', ?, ?)",
                    (batch_id, resource_id, str(limit), str(authorization), now, now),
                )
            else:
                if row["resource_id"] != resource_id or row["status"] != "open":
                    raise ValueError("x402 batch is not open for this resource")
                if int(row["authorization_limit_units"]) != limit:
                    raise ValueError("x402 batch limit does not match the existing batch")
                if int(row["reserved_units"]) + authorization > limit:
                    raise ValueError("x402 batch authorization would exceed its cap")
                self.db.execute(
                    "UPDATE x402_batches SET reserved_units = ?, updated_at = ? WHERE batch_id = ?",
                    (str(int(row["reserved_units"]) + authorization), now, batch_id),
                )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def account_x402_batch(self, *, batch_id: str, authorization_limit_units: str,
                           usage_units: str, settled_units: str) -> None:
        """Replace a batch hold with actual usage, preserving the unused balance."""
        authorization, usage, settled = map(int, (authorization_limit_units, usage_units, settled_units))
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT * FROM x402_batches WHERE batch_id = ?", (batch_id,)).fetchone()
            if row is None or row["status"] != "open":
                raise ValueError("x402 batch is not open")
            if usage != settled or settled < 0 or settled > authorization:
                raise ValueError("invalid x402 batch settlement amount")
            reserved = int(row["reserved_units"]) - authorization
            if reserved < 0:
                raise ValueError("x402 batch reservation is inconsistent")
            self.db.execute(
                "UPDATE x402_batches SET reserved_units = ?, usage_units = ?, settled_units = ?, updated_at = ? "
                "WHERE batch_id = ?",
                (str(reserved), str(int(row["usage_units"]) + usage),
                 str(int(row["settled_units"]) + settled), _now(), batch_id),
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def close_x402_batch(self, batch_id: str) -> None:
        self.db.execute(
            "UPDATE x402_batches SET status = 'closed', updated_at = ? WHERE batch_id = ? AND status = 'open'",
            (_now(), batch_id),
        )
        self.db.commit()

    def x402_batch(self, batch_id: str):
        return self.db.execute("SELECT * FROM x402_batches WHERE batch_id = ?", (batch_id,)).fetchone()

    def x402_payment(self, request_id: str):
        return self.db.execute("SELECT * FROM x402_payments WHERE request_id = ?", (request_id,)).fetchone()

    def reserve_and_record_gateway_decision(self, *, request_id: str, req, decision: str,
                                            reasons: list[str], route_type: str = "guard",
                                            route_id: str = "", ttl_seconds: int = 900,
                                            cap: float | None = None,
                                            rate_cap: float | None = None) -> tuple[str, str]:
        """Atomically record a decision and, for allow, hold budget.

        Returns (decision, reservation_id). Duplicate request IDs return the
        existing decision without creating a second reservation.
        """
        now = _now()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.gateway_decision_by_request(request_id)
            if existing:
                self.db.commit()
                return existing["decision"], existing["reservation_id"] or ""

            final_decision = decision
            final_reasons = list(reasons)
            reservation_id = ""
            if decision == "allow":
                if cap is not None:
                    spent = self.db.execute(
                        "SELECT COALESCE(SUM(billed_cost), 0) AS spent FROM spend_events WHERE x_budget_id = ?",
                        (req.x_budget_id,),
                    ).fetchone()["spent"] or 0
                    reserved = self.active_reservations_total(req.x_budget_id, now)
                    if float(spent) + reserved + req.amount > float(cap):
                        final_decision = "deny"
                        final_reasons = [
                            f"budget {req.x_budget_id} would exceed cap "
                            f"{float(spent) + reserved + req.amount:.2f}/{float(cap):.2f}"
                        ]
                    else:
                        reservation_id = f"res:{uuid.uuid4().hex}"
                else:
                    reservation_id = f"res:{uuid.uuid4().hex}"
                if reservation_id and rate_cap is not None:
                    # Atomic velocity re-check: recent spend + active holds in the last
                    # hour. Makes the hourly cap race-safe like the budget cap, so a
                    # concurrent burst can't slip past it.
                    window = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                    recent = self.db.execute(
                        "SELECT COALESCE(SUM(billed_cost), 0) AS spent FROM spend_events "
                        "WHERE x_budget_id = ? AND event_time > ?",
                        (req.x_budget_id, window),
                    ).fetchone()["spent"] or 0
                    reserved_now = self.active_reservations_total(req.x_budget_id, now)
                    if float(recent) + reserved_now + req.amount > float(rate_cap):
                        final_decision = "deny"
                        final_reasons = [
                            f"budget {req.x_budget_id} hourly rate "
                            f"{float(recent) + reserved_now + req.amount:.2f}/{float(rate_cap):.2f} exceeded"
                        ]
                        reservation_id = ""
                if reservation_id:
                    expires_at = (
                        datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
                    ).isoformat()
                    self.db.execute(
                        "INSERT INTO spend_reservations (reservation_id, request_id, created_at, "
                        "expires_at, x_agent_id, x_budget_id, amount, status) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, 'active')",
                        (
                            reservation_id,
                            request_id,
                            now,
                            expires_at,
                            req.x_agent_id,
                            req.x_budget_id,
                            req.amount,
                        ),
                    )

            self.db.execute(
                "INSERT INTO gateway_decisions (decision_id, request_id, created_at, "
                "x_agent_id, rail, provider_name, service_name, x_merchant_id, amount, x_budget_id, "
                "decision, reasons_json, route_type, route_id, reservation_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"gwd:{request_id}",
                    request_id,
                    now,
                    req.x_agent_id,
                    req.rail,
                    req.provider_name,
                    req.service_name,
                    req.x_merchant_id,
                    req.amount,
                    req.x_budget_id,
                    final_decision,
                    json.dumps(final_reasons, sort_keys=True),
                    route_type,
                    route_id,
                    reservation_id,
                ),
            )
            self.db.commit()
            return final_decision, reservation_id
        except Exception:
            self.db.rollback()
            raise


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_GATEWAY_DECISIONS_DDL = (
    "CREATE TABLE IF NOT EXISTS gateway_decisions ("
    "decision_id TEXT PRIMARY KEY, request_id TEXT UNIQUE, created_at TEXT, "
    "x_agent_id TEXT, rail TEXT, provider_name TEXT, service_name TEXT, "
    "x_merchant_id TEXT, amount REAL, x_budget_id TEXT, decision TEXT, "
    "reasons_json TEXT, route_type TEXT, route_id TEXT, reservation_id TEXT)"
)

_SPEND_RESERVATIONS_DDL = (
    "CREATE TABLE IF NOT EXISTS spend_reservations ("
    "reservation_id TEXT PRIMARY KEY, request_id TEXT UNIQUE, created_at TEXT, "
    "expires_at TEXT, x_agent_id TEXT, x_budget_id TEXT, amount REAL, status TEXT)"
)

_X402_PAYMENTS_DDL = (
    "CREATE TABLE IF NOT EXISTS x402_payments ("
    "request_id TEXT PRIMARY KEY, resource_id TEXT, payment_fingerprint TEXT UNIQUE, "
    "scheme TEXT DEFAULT 'exact', authorization_limit_units TEXT DEFAULT '', usage_units TEXT DEFAULT '', "
    "settled_units TEXT DEFAULT '', released_units TEXT DEFAULT '', batch_id TEXT DEFAULT '', "
    "status TEXT, transaction_ref TEXT DEFAULT '', detail TEXT DEFAULT '', created_at TEXT, updated_at TEXT)"
)

_X402_BATCHES_DDL = (
    "CREATE TABLE IF NOT EXISTS x402_batches ("
    "batch_id TEXT PRIMARY KEY, resource_id TEXT, status TEXT, authorization_limit_units TEXT, "
    "reserved_units TEXT, usage_units TEXT, settled_units TEXT, created_at TEXT, updated_at TEXT)"
)
