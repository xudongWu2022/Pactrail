from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from pactrail_core.__main__ import main
from pactrail_core.scenarios import run_scenario, run_scenarios


ROOT = Path(__file__).resolve().parent.parent


class ScenarioTest(unittest.TestCase):
    def test_checked_in_incident_scenarios_pass(self) -> None:
        results = run_scenarios(ROOT / "scenarios")
        self.assertEqual(len(results), 4)
        self.assertTrue(all(result.passed for result in results), results)

    def test_failed_invariant_keeps_a_debug_snapshot(self) -> None:
        result = run_scenario({
            "id": "broken-budget-expectation",
            "policy": {"budgets": {"team": 1.0}},
            "steps": [{
                "action": "guard",
                "request_id": "req-1",
                "request": {"agent": "bot", "rail": "llm_token", "amount": 2, "budget": "team"},
            }],
            "expect": {"gateway": {"allow_count": 1}},
        })
        self.assertFalse(result.passed)
        self.assertIn("allow_count", result.error)
        self.assertEqual(result.snapshot["gateway"]["deny_count"], 1)

    def test_unknown_event_field_fails_instead_of_being_ignored(self) -> None:
        result = run_scenario({
            "id": "misspelled-event-field",
            "policy": {},
            "steps": [{"action": "seed", "events": [{"event_id": "bad", "typo": True}]}],
            "expect": {},
        })
        self.assertFalse(result.passed)
        self.assertIn("unknown fields", result.error)

    def test_cli_writes_a_machine_readable_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                main(["run-scenarios", "--path", str(ROOT / "scenarios"), "--out-dir", tmp])
            report_path = Path(tmp) / "scenario-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["passed"], 4)
            self.assertEqual(report["failed"], 0)


if __name__ == "__main__":
    unittest.main()
