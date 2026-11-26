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
)
from vkpi.a9 import run, usage

FIXTURES = Path(__file__).resolve().parent / "fixtures"
GRID = Path(__file__).resolve().parents[2] / "vkpi" / "a9" / "prices" / "2026-11-26.json"
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
    def test_both_versions_reach_the_provider_only_through_the_proxy(self):
        for version, variable in BINARIES.items():
            for provider, case in CASES.items():
                with self.subTest(version=version, provider=provider):
                    binary = os.environ.get(variable)
                    if not binary:
                        if os.environ.get("VKPI_E2E_REQUIRED"):
                            self.fail(f"{variable} is not set")
                        self.skipTest(f"set {variable} to a vens {version} binary")
                    self.check(Path(binary), provider, case)

    def check(self, vens, provider, case):
        with tempfile.TemporaryDirectory() as tmp, FakeUpstream(case["replies"]) as up:
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
                upstreams={provider: up.url},
            )
            with stderr_to(root / "vens.log"):
                result = run.run(spec, {"PATH": os.defpath, "HOME": tmp, **case["env"]})
            vens_log = (root / "vens.log").read_text(errors="replace")
            log_text = spec.log.read_text()
            records = [json.loads(line) for line in log_text.splitlines()]
            vex_exists = spec.vex.exists()

        self.assertGreaterEqual(len(up.requests), 3, vens_log)
        self.assertEqual(len(records), len(up.requests), vens_log)
        for record, seen, sent in zip(records, up.requests, up.sent):
            self.assertEqual(seen["path"], case["endpoint"])
            self.assertEqual(record["provider"], provider)
            self.assertEqual(record["endpoint"], case["endpoint"])
            self.assertEqual(record["model"], case["model"])
            self.assertEqual(record["attempt"], int(seen["headers"]["x-stainless-retry-count"]) + 1)
            self.assertEqual(record["request_bytes"], len(seen["body"]))
            self.assertEqual(record["response_bytes"], len(sent))
            self.assertIsNone(record["error"])
            self.assertLessEqual(result["launched_ns"], record["start_ns"])
            self.assertLessEqual(record["start_ns"], record["end_ns"])
            self.assertIn(FAKE_KEY, seen["headers"].get("x-api-key", "") + seen["headers"].get("authorization", ""))

        self.assertEqual([(r["attempt"], r["status"]) for r in records[:3]], [(1, 500), (2, 200), (1, 400)])
        self.assertEqual(records[1]["usage"], case["usage"])
        for private in (FAKE_KEY, "CVE-2024-1234", "a9-plumbing", "buffer overflow"):
            self.assertNotIn(private, log_text)

        self.assertEqual(result["attempts"], len(records))
        self.assertEqual(result["calls"], sum(r["attempt"] == 1 for r in records))
        self.assertEqual(result["tokens"], usage.tokens(provider, case["usage"]))
        self.assertIsNotNone(result["usd"])
        self.assertEqual(result["complete"], result["exit_code"] == 0 and vex_exists)
        self.assertEqual(result["seconds"] is None, not result["complete"])


if __name__ == "__main__":
    unittest.main()
