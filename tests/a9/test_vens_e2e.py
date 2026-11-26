import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from tests.a9.upstream import (
    ANTHROPIC_USAGE,
    OPENAI_USAGE,
    FakeUpstream,
    Reply,
    anthropic_error,
    anthropic_message,
    openai_completion,
    openai_error,
    schema_answers,
)
from vkpi.a9 import run, usage

FIXTURES = Path(__file__).resolve().parent / "fixtures"
GRID = Path(__file__).resolve().parents[2] / "vkpi" / "a9" / "prices" / "2026-11-26.json"
FIXTURE_CVE = "CVE-2024-1234"
FAKE_KEY = "vkpi-fake-key"
SBOM_SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
BINARIES = {"v0.6.0": "VKPI_VENS_V060", "v0.7.0": "VKPI_VENS_V070"}

# A 500 the SDK retries at once, a success vens reads but cannot use, then a
# 400 that ends the run: every step of a call shows in the log.
CASES = {
    "anthropic": {
        "endpoint": "/v1/messages",
        "model": "claude-sonnet-4-6",
        "env": {"ANTHROPIC_API_KEY": FAKE_KEY, "ANTHROPIC_MODEL": "claude-sonnet-4-6"},
        "usage": ANTHROPIC_USAGE,
        "replies": [
            Reply(500, anthropic_error("api_error"), {"retry-after-ms": "10"}),
            Reply(200, anthropic_message(ANTHROPIC_USAGE), gzip=True),
            Reply(400, anthropic_error()),
        ],
    },
    "openai": {
        "endpoint": "/v1/chat/completions",
        "model": "gpt-5.4-mini",
        "env": {"OPENAI_API_KEY": FAKE_KEY, "OPENAI_MODEL": "gpt-5.4-mini"},
        "usage": OPENAI_USAGE,
        "replies": [
            Reply(500, openai_error("server_error"), {"retry-after-ms": "10"}),
            Reply(200, openai_completion(OPENAI_USAGE), gzip=True),
            Reply(400, openai_error()),
        ],
    },
}


@contextlib.contextmanager
def stderr_to(path):
    # vens writes its log to the inherited stderr: keep it for the failure message.
    saved = os.dup(2)
    with open(path, "wb") as sink:
        os.dup2(sink.fileno(), 2)
        try:
            yield
        finally:
            os.dup2(saved, 2)
            os.close(saved)


class VensThroughProxyTest(unittest.TestCase):
    def binary(self, version):
        variable = BINARIES[version]
        if os.environ.get(variable):
            return Path(os.environ[variable])
        if os.environ.get("VKPI_E2E_REQUIRED"):
            self.fail(f"{variable} is not set")
        self.skipTest(f"set {variable} to a vens {version} binary")

    def vens_run(self, vens, provider, replies):
        with tempfile.TemporaryDirectory() as tmp, FakeUpstream(replies) as upstream:
            root = Path(tmp)
            spec = run.Spec(
                vens=vens,
                provider=provider,
                n=1,
                report=FIXTURES / "report.trivy.json",
                vex=root / "out.cdx.json",
                prices=GRID,
                log=root / "calls.jsonl",
                vens_args=("--config-file", str(FIXTURES / "config.yaml"), "--sbom-serial-number", SBOM_SERIAL),
                upstreams={provider: upstream.url},
            )
            with stderr_to(root / "vens.log"):
                result = run.run(spec, {"PATH": os.defpath, "HOME": tmp, **CASES[provider]["env"]})
            seen = {
                "result": result,
                "log": spec.log.read_text(),
                "vens_log": (root / "vens.log").read_text(errors="replace"),
                "vex": json.loads(spec.vex.read_text()) if spec.vex.exists() else None,
            }
        return seen, upstream

    def test_both_versions_reach_the_provider_only_through_the_proxy(self):
        for version in BINARIES:
            for provider, case in CASES.items():
                with self.subTest(version=version, provider=provider):
                    seen, upstream = self.vens_run(self.binary(version), provider, case["replies"])
                    self.check_calls(seen, upstream, provider, case)

    def test_both_versions_complete_a_run_on_valid_answers(self):
        for version in BINARIES:
            for provider in CASES:
                with self.subTest(version=version, provider=provider):
                    seen, upstream = self.vens_run(self.binary(version), provider, schema_answers(provider, FIXTURE_CVE))
                    result = seen["result"]
                    self.assertTrue(result["complete"], seen["vens_log"])
                    self.assertEqual(result["exit_code"], 0)
                    self.assertLessEqual(result["launched_ns"], result["vex_written_ns"])
                    self.assertGreater(result["seconds"], 0)
                    self.assertLessEqual(result["seconds"], result["seconds_to_exit"])
                    self.assertEqual(result["usd_not_measured"], {})
                    self.assertEqual(result["calls"], len(upstream.requests))
                    self.assertEqual(result["attempts"], len(upstream.requests))
                    self.assertIn(FIXTURE_CVE, [vuln["id"] for vuln in seen["vex"]["vulnerabilities"]])

    def check_calls(self, seen, upstream, provider, case):
        result, log_text = seen["result"], seen["log"]
        records = [json.loads(line) for line in log_text.splitlines()]
        self.assertGreaterEqual(len(upstream.requests), 3, seen["vens_log"])
        self.assertEqual(len(records), len(upstream.requests), seen["vens_log"])
        for record, request, sent in zip(records, upstream.requests, upstream.sent):
            self.assertEqual(request["path"], case["endpoint"])
            self.assertEqual(record["provider"], provider)
            self.assertEqual(record["endpoint"], case["endpoint"])
            self.assertEqual(record["model"], case["model"])
            self.assertEqual(record["attempt"], int(request["headers"]["x-stainless-retry-count"]) + 1)
            self.assertEqual(record["request_bytes"], len(request["body"]))
            self.assertEqual(record["response_bytes"], len(sent))
            self.assertIsNone(record["error"])
            self.assertTrue(record["forwarded"])
            self.assertLessEqual(result["launched_ns"], record["start_ns"])
            self.assertLessEqual(record["start_ns"], record["end_ns"])
            headers = request["headers"]
            self.assertIn(FAKE_KEY, headers.get("x-api-key", "") + headers.get("authorization", ""))

        self.assertEqual([(r["attempt"], r["status"]) for r in records[:3]], [(1, 500), (2, 200), (1, 400)])
        self.assertEqual(records[1]["usage"], case["usage"])
        for private in (FAKE_KEY, FIXTURE_CVE, "a9-plumbing", "buffer overflow"):
            self.assertNotIn(private, log_text)

        self.assertEqual(result["attempts"], len(records))
        self.assertEqual(result["calls"], sum(r["attempt"] == 1 for r in records))
        self.assertEqual(result["tokens"], usage.tokens(provider, case["usage"]))
        self.assertIsNotNone(result["usd"])
        self.assertEqual(result["complete"], result["exit_code"] == 0 and seen["vex"] is not None)
        self.assertEqual(result["seconds"] is None, not result["complete"])


if __name__ == "__main__":
    unittest.main()
