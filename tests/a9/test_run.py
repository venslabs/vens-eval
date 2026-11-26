import contextlib
import datetime
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.a9.upstream import (
    ANTHROPIC_USAGE,
    OPENAI_USAGE,
    FakeUpstream,
    Reply,
    anthropic_error,
    anthropic_message,
    openai_completion,
)
from vkpi.a9 import run

HERE = Path(__file__).resolve().parent
FAKE_VENS = HERE / "fake_vens.py"
REAL_GRID = HERE.parents[1] / "vkpi" / "a9" / "prices" / "2026-11-26.json"
TEST_GRID = {
    "date": "2026-11-26",
    "currency": "USD",
    "unit": "per million tokens",
    "models": {
        "claude-sonnet-4-6": {
            "provider": "anthropic",
            "source": "https://example.invalid/anthropic",
            "service_tier": "standard",
            "inference_geo": "global",
            "prices": {"input": 3, "cache_write_5m": 3.75, "cache_write_1h": 6, "cache_read": 0.3, "output": 15},
        },
        "gpt-5.4-mini": {
            "provider": "openai",
            "source": "https://example.invalid/openai",
            "service_tier": "default",
            "prices": {"input": 0.75, "cache_read": 0.075, "output": 4.5},
        },
    },
}
RUN_FIELDS = {
    "format", "provider", "vens_sha256", "prices", "default_upstreams", "n", "exit_code", "complete",
    "launched_ns", "vex_written_ns", "seconds", "seconds_to_exit", "calls", "attempts", "statuses",
    "request_bytes", "response_bytes", "models", "tokens", "usd", "usd_per_cve", "usd_not_measured",
}
ONE_ANTHROPIC_CALL_USD = (2095 * 3 + 503 * 15) / 1e6


@contextlib.contextmanager
def working_directory(path):
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class RunTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.vex = self.root / "out.cdx.json"
        self.log = self.root / "calls.jsonl"
        self.grid = self.root / "prices.json"
        self.grid.write_text(json.dumps(TEST_GRID))
        self.report = self.root / "report.json"
        self.report.write_text("{}")

    def tearDown(self):
        self.dir.cleanup()

    def spec(self, upstream, provider="anthropic", **changes):
        fields = {
            "vens": FAKE_VENS,
            "provider": provider,
            "n": 5,
            "report": self.report,
            "vex": self.vex,
            "prices": self.grid,
            "log": self.log,
            "vens_args": ("--config-file", "config.yaml"),
            "upstreams": {provider: upstream.url},
            **changes,
        }
        return run.Spec(**fields)

    def env(self, **extra):
        return {"PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.defpath}", **extra}

    def test_complete_run(self):
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up:
            result = run.run(self.spec(up), self.env(FAKE_VENS_CALLS="2"))

        self.assertEqual(set(result), RUN_FIELDS)
        self.assertEqual(result["format"], "vens-kpi/a9-run/1")
        self.assertTrue(result["complete"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["vex_written_ns"], self.vex.stat().st_mtime_ns)
        self.assertEqual(result["seconds"], (result["vex_written_ns"] - result["launched_ns"]) / 1e9)
        self.assertGreater(result["seconds"], 0)
        self.assertLessEqual(result["seconds"], result["seconds_to_exit"])
        self.assertEqual((result["calls"], result["attempts"]), (2, 2))
        self.assertEqual(result["statuses"], {"200": 2})
        self.assertEqual(result["tokens"], {
            "cache_read": 0, "cache_write_1h": 0, "cache_write_5m": 0, "input": 2 * 2095, "output": 2 * 503,
        })
        self.assertAlmostEqual(result["usd"], 2 * ONE_ANTHROPIC_CALL_USD)
        self.assertAlmostEqual(result["usd_per_cve"], 2 * ONE_ANTHROPIC_CALL_USD / 5)
        self.assertEqual(result["usd_not_measured"], {})
        self.assertEqual(result["models"]["claude-sonnet-4-6"]["service_tiers"], ["standard"])
        self.assertEqual(result["n"], 5)
        self.assertFalse(result["default_upstreams"])
        self.assertEqual(result["vens_sha256"], hashlib.sha256(FAKE_VENS.read_bytes()).hexdigest())
        self.assertEqual(result["prices"], {
            "date": "2026-11-26", "sha256": hashlib.sha256(self.grid.read_bytes()).hexdigest(),
        })
        self.assertEqual(len(self.log.read_text().splitlines()), 2)

    def test_openai_run_prices_cached_input_apart(self):
        with FakeUpstream([Reply(200, openai_completion(OPENAI_USAGE))]) as up:
            result = run.run(self.spec(up, provider="openai"), self.env())
        self.assertEqual(result["tokens"], {"cache_read": 1920, "input": 86, "output": 300})
        self.assertAlmostEqual(result["usd"], (86 * 0.75 + 1920 * 0.075 + 300 * 4.5) / 1e6)
        self.assertEqual(result["models"]["gpt-5.4-mini"]["served"], ["gpt-5.4-mini-2026-03-17"])

    def test_aborted_run_keeps_its_cost_and_has_no_time(self):
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up:
            result = run.run(self.spec(up), self.env(FAKE_VENS_EXIT="3"))
        self.assertFalse(result["complete"])
        self.assertEqual(result["exit_code"], 3)
        self.assertIsNone(result["vex_written_ns"])
        self.assertIsNone(result["seconds"])
        self.assertGreater(result["seconds_to_exit"], 0)
        self.assertAlmostEqual(result["usd"], ONE_ANTHROPIC_CALL_USD)

    def test_error_responses_are_attempts_without_usage(self):
        replies = [Reply(429, anthropic_error("rate_limit_error")), Reply(200, anthropic_message(ANTHROPIC_USAGE))]
        with FakeUpstream(replies) as up:
            result = run.run(self.spec(up), self.env(FAKE_VENS_CALLS="2"))
        self.assertEqual(result["statuses"], {"200": 1, "429": 1})
        self.assertAlmostEqual(result["usd"], ONE_ANTHROPIC_CALL_USD)
        self.assertEqual(result["usd_not_measured"], {})

    def test_success_without_usage_is_not_measured(self):
        body = {key: value for key, value in anthropic_message(ANTHROPIC_USAGE).items() if key != "usage"}
        replies = [Reply(200, anthropic_message(ANTHROPIC_USAGE)), Reply(200, body)]
        with FakeUpstream(replies) as up:
            result = run.run(self.spec(up), self.env(FAKE_VENS_CALLS="2"))
        self.assertIsNone(result["usd"])
        self.assertIsNone(result["usd_per_cve"])
        self.assertIsNone(result["models"]["claude-sonnet-4-6"]["usd"])
        self.assertEqual(result["usd_not_measured"], {"claude-sonnet-4-6: 200 response without usable usage": 1})
        self.assertEqual(result["tokens"]["input"], 2095)

    def test_model_outside_the_grid_is_not_measured(self):
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up:
            result = run.run(self.spec(up), self.env(ANTHROPIC_MODEL="claude-opus-5"))
        self.assertIsNone(result["usd"])
        self.assertEqual(result["usd_not_measured"], {"claude-opus-5: not in the price grid": 1})

    def test_refusals(self):
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up:
            cases = {
                "llm flag": self.spec(up, vens_args=("--llm=openai",)),
                "no CVEs": self.spec(up, n=0),
                "not executable": self.spec(up, vens=self.grid),
            }
            for name, spec in cases.items():
                with self.subTest(name), self.assertRaises(ValueError):
                    run.run(spec, self.env())
            for existing in (self.vex, self.log):
                existing.write_text("{}")
                with self.subTest(existing.name), self.assertRaises(ValueError):
                    run.run(self.spec(up), self.env())
                existing.unlink()
        self.assertEqual(up.requests, [])

    def test_a_relative_binary_runs_the_file_it_hashed(self):
        here, decoys = self.root / "here", self.root / "decoys"
        here.mkdir()
        decoys.mkdir()
        shutil.copy2(FAKE_VENS, here / "vens")
        (decoys / "vens").write_text("#!/bin/sh\nexit 97\n")
        (decoys / "vens").chmod(0o755)
        env = self.env()
        env["PATH"] = f"{decoys}{os.pathsep}{env['PATH']}"
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up, working_directory(here):
            result = run.run(self.spec(up, vens=Path("./vens")), env)
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["complete"])
        self.assertEqual(result["vens_sha256"], hashlib.sha256(FAKE_VENS.read_bytes()).hexdigest())

    def test_main_writes_the_run_json(self):
        out = self.root / "run.json"
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up:
            argv = [
                "--vens", str(FAKE_VENS), "--provider", "anthropic", "--n", "5",
                "--input", str(self.report), "--vex", str(self.vex), "--prices", str(self.grid),
                "--log", str(self.log), "--out", str(out), "--upstream", f"anthropic={up.url}",
                "--", "--config-file", "config.yaml",
            ]
            with mock.patch.dict(os.environ, self.env()), mock.patch("sys.stderr", new_callable=io.StringIO) as err:
                self.assertEqual(run.main(argv), 0)
                self.assertEqual(run.main(argv), 2)
        self.assertIn("run.json already exists", err.getvalue())
        result = json.loads(out.read_text())
        self.assertTrue(result["complete"])
        self.assertEqual(result["attempts"], 1)

    def test_a_tier_off_the_grid_through_the_proxy(self):
        with FakeUpstream([Reply(200, openai_completion(OPENAI_USAGE, tier="priority"))]) as up:
            result = run.run(self.spec(up, provider="openai"), self.env())
        self.assertIsNone(result["usd"])
        self.assertEqual(result["usd_not_measured"], {"gpt-5.4-mini: served at tier priority, grid is default": 1})

    def test_main_never_repeats_a_credential_from_an_upstream(self):
        secret = "sk-test-SECRET-IN-URL"
        argv = [
            "--vens", str(FAKE_VENS), "--provider", "openai", "--n", "5",
            "--input", str(self.report), "--vex", str(self.vex), "--prices", str(self.grid),
            "--log", str(self.log), "--out", str(self.root / "run.json"),
            "--upstream", f"openai=https://user:{secret}@gateway.invalid:99999",
        ]
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(run.main(argv), 2)
        self.assertIn("vkpi.a9.run:", err.getvalue())
        self.assertNotIn(secret, err.getvalue())
        self.assertFalse(self.log.exists())


class SummarizeTest(unittest.TestCase):
    def record(self, **changes):
        return {
            "provider": "anthropic", "endpoint": "/v1/messages", "model": "claude-sonnet-4-6", "attempt": 1,
            "status": 200, "request_bytes": 100, "response_bytes": 50, "start_ns": 1, "end_ns": 2,
            "model_served": "claude-sonnet-4-6", "service_tier": "standard", "usage": ANTHROPIC_USAGE,
            "error": None, "forwarded": True, **changes,
        }

    def openai_record(self, **changes):
        return self.record(**{
            "provider": "openai", "endpoint": "/v1/chat/completions", "model": "gpt-5.4-mini",
            "model_served": "gpt-5.4-mini-2026-03-17", "service_tier": "default", "usage": OPENAI_USAGE, **changes,
        })

    def test_calls_are_first_attempts(self):
        records = [self.record(status=500, usage=None), self.record(attempt=2), self.record()]
        summary = run.summarize(records, TEST_GRID, 1)
        self.assertEqual((summary["calls"], summary["attempts"]), (2, 3))
        self.assertEqual(summary["statuses"], {"200": 2, "500": 1})
        self.assertEqual((summary["request_bytes"], summary["response_bytes"]), (300, 150))

    def test_unknown_attempts_leave_calls_unknown(self):
        self.assertIsNone(run.summarize([self.record(attempt=None)], TEST_GRID, 1)["calls"])

    def test_requests_without_an_answer(self):
        sent = self.record(status=None, usage=None, service_tier=None, error="upstream ConnectionResetError")
        summary = run.summarize([sent, self.record()], TEST_GRID, 1)
        self.assertEqual(summary["statuses"], {"200": 1, "none": 1})
        self.assertIsNone(summary["usd"])
        self.assertIsNone(summary["models"]["claude-sonnet-4-6"]["usd"])
        self.assertEqual(summary["usd_not_measured"], {"claude-sonnet-4-6: request sent, no answer": 1})

    def test_requests_stopped_before_the_provider_cost_nothing(self):
        stopped = [
            self.record(status=None, usage=None, service_tier=None, forwarded=False, error=error)
            for error in ("request without Content-Length", "client ConnectionResetError",
                          "upstream connect ConnectionRefusedError")
        ]
        summary = run.summarize([*stopped, self.record()], TEST_GRID, 1)
        self.assertEqual(summary["statuses"], {"200": 1, "none": 3})
        self.assertAlmostEqual(summary["usd"], ONE_ANTHROPIC_CALL_USD)
        self.assertEqual(summary["usd_not_measured"], {})

    def test_responses_served_off_the_grid_are_not_measured(self):
        us_only = {**ANTHROPIC_USAGE, "inference_geo": "us"}
        priority = {**ANTHROPIC_USAGE, "service_tier": "priority"}
        cases = {
            "openai priority": (self.openai_record(service_tier="priority"),
                                "gpt-5.4-mini: served at tier priority, grid is default"),
            "openai flex": (self.openai_record(service_tier="flex"),
                            "gpt-5.4-mini: served at tier flex, grid is default"),
            "openai tier unreported": (self.openai_record(service_tier=None),
                                       "gpt-5.4-mini: served at tier unreported, grid is default"),
            "anthropic priority": (self.record(service_tier="priority", usage=priority),
                                   "claude-sonnet-4-6: served at tier priority, grid is standard"),
            "anthropic us-only": (self.record(usage=us_only),
                                  "claude-sonnet-4-6: served at inference_geo us, grid is global"),
        }
        for name, (record, gap) in cases.items():
            with self.subTest(name):
                summary = run.summarize([record], TEST_GRID, 1)
                self.assertIsNone(summary["usd"])
                self.assertEqual(summary["usd_not_measured"], {gap: 1})
                self.assertTrue(summary["tokens"])

    def test_responses_served_on_the_grid_are_priced(self):
        no_geo = {key: value for key, value in ANTHROPIC_USAGE.items() if key != "inference_geo"}
        summary = run.summarize([self.record(), self.record(usage=no_geo), self.openai_record()], TEST_GRID, 1)
        self.assertEqual(summary["usd_not_measured"], {})
        self.assertAlmostEqual(summary["usd"], 2 * ONE_ANTHROPIC_CALL_USD + (86 * 0.75 + 1920 * 0.075 + 300 * 4.5) / 1e6)

    def test_request_outside_the_routes_is_not_measured(self):
        records = [self.record(provider=None, status=None, usage=None, error="unknown route"), self.record()]
        summary = run.summarize(records, TEST_GRID, 1)
        self.assertIsNone(summary["usd"])
        self.assertEqual(summary["usd_not_measured"], {"request outside the provider routes": 1})

    def test_missing_price_for_a_used_category(self):
        grid = json.loads(json.dumps(TEST_GRID))
        grid["models"]["claude-sonnet-4-6"]["prices"]["output"] = None
        summary = run.summarize([self.record()], grid, 1)
        self.assertIsNone(summary["usd"])
        self.assertEqual(summary["usd_not_measured"], {"claude-sonnet-4-6: no output price in the grid": 1})

    def test_no_calls_cost_nothing(self):
        summary = run.summarize([], TEST_GRID, 3)
        self.assertEqual((summary["usd"], summary["usd_per_cve"], summary["calls"]), (0.0, 0.0, 0))


QUOTED_COLUMNS = {
    "Base input tokens": "input",
    "5m cache writes": "cache_write_5m",
    "1h cache writes": "cache_write_1h",
    "Cache hits and refreshes": "cache_read",
    "Output tokens": "output",
    "Input": "input",
    "Cached input": "cache_read",
    "Output": "output",
}


def cells(row):
    return [cell.strip() for cell in row.strip().strip("|").split("|")][1:]


class GridTest(unittest.TestCase):
    def test_real_grid_matches_its_quotes(self):
        grid = run.load_grid(REAL_GRID)
        self.assertEqual(grid["date"], REAL_GRID.stem)
        self.assertEqual(set(grid["models"]), {"claude-sonnet-4-6", "gpt-5.4-mini"})
        for name, model in grid["models"].items():
            with self.subTest(name):
                datetime.date.fromisoformat(model["read_on"])
                quoted = {
                    QUOTED_COLUMNS[column]: float(value.split("/")[0].strip().lstrip("$"))
                    for column, value in zip(cells(model["columns"]), cells(model["quote"]))
                }
                self.assertEqual(quoted, model["prices"])

    def test_bad_grids_are_refused(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        model = TEST_GRID["models"]["gpt-5.4-mini"]
        untiered = {key: value for key, value in model.items() if key != "service_tier"}
        for name, grid in {
            "no date": {**TEST_GRID, "date": None},
            "no source": {**TEST_GRID, "models": {"m": {**model, "source": "http://example.invalid"}}},
            "no service tier": {**TEST_GRID, "models": {"m": untiered}},
            "geo not text": {**TEST_GRID, "models": {"m": {**model, "inference_geo": 1}}},
            "text price": {**TEST_GRID, "models": {"m": {**model, "prices": {"input": "0.75"}}}},
            "unknown category": {**TEST_GRID, "models": {"m": {**model, "prices": {"reasoning": 1}}}},
        }.items():
            path = Path(tmp.name) / f"{name}.json"
            path.write_text(json.dumps(grid))
            with self.subTest(name), self.assertRaises(ValueError):
                run.load_grid(path)


if __name__ == "__main__":
    unittest.main()
