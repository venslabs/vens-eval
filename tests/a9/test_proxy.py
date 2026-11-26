import gzip
import http.client
import io
import json
import socket
import tempfile
import time
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
from vkpi.a9 import proxy

KEY = "sk-test-SECRET-KEY"
CONTEXT = "CONTEXT-MARKER internet-facing payment API"
LOG_FIELDS = {
    "attempt", "end_ns", "endpoint", "error", "model", "model_served", "provider",
    "request_bytes", "response_bytes", "service_tier", "start_ns", "status", "usage",
}
ANTHROPIC_HEADERS = {
    "x-api-key": KEY,
    "anthropic-version": "2023-06-01",
    "Content-Type": "application/json",
    "X-Stainless-Retry-Count": "0",
}


def anthropic_body(model="claude-sonnet-4-6"):
    return json.dumps({"model": model, "max_tokens": 16384, "system": CONTEXT, "messages": []}).encode()


def post(server, path, body, headers, conn=None):
    own = conn is None
    conn = conn or http.client.HTTPConnection(*server.server_address[:2], timeout=10)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, {name.lower(): value for name, value in resp.getheaders()}, resp.read()
    finally:
        if own:
            conn.close()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ProxyTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = Path(self.dir.name) / "calls.jsonl"

    def tearDown(self):
        self.dir.cleanup()

    def records(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_forwards_an_anthropic_call_and_logs_one_line(self):
        body = anthropic_body()
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server:
            status, _, data = post(server, "/anthropic/v1/messages", body, ANTHROPIC_HEADERS)

        self.assertEqual(status, 200)
        self.assertEqual(data, up.sent[0])
        [seen] = up.requests
        self.assertEqual(seen["path"], "/v1/messages")
        self.assertEqual(seen["body"], body)
        self.assertEqual(seen["headers"]["x-api-key"], KEY)
        self.assertEqual(seen["headers"]["anthropic-version"], "2023-06-01")

        [record] = self.records()
        self.assertEqual(set(record), LOG_FIELDS)
        self.assertEqual(record["provider"], "anthropic")
        self.assertEqual(record["endpoint"], "/v1/messages")
        self.assertEqual(record["model"], "claude-sonnet-4-6")
        self.assertEqual(record["model_served"], "claude-sonnet-4-6")
        self.assertEqual(record["attempt"], 1)
        self.assertEqual(record["status"], 200)
        self.assertEqual(record["request_bytes"], len(body))
        self.assertEqual(record["response_bytes"], len(data))
        self.assertEqual(record["usage"], ANTHROPIC_USAGE)
        self.assertEqual(record["service_tier"], "standard")
        self.assertIsNone(record["error"])

    def test_never_logs_keys_or_bodies(self):
        headers = {**ANTHROPIC_HEADERS, "Authorization": f"Bearer {KEY}"}
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE, text=CONTEXT))]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server:
            post(server, "/anthropic/v1/messages", anthropic_body(), headers)
        text = self.log.read_text()
        for secret in ("SECRET-KEY", "CONTEXT-MARKER", "Bearer", "x-api-key"):
            self.assertNotIn(secret, text)

    def test_openai_route_keeps_the_query_out_of_the_log(self):
        body = json.dumps({"model": "gpt-5.4-mini", "messages": []}).encode()
        headers = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json", "X-Stainless-Retry-Count": "0"}
        with FakeUpstream([Reply(200, openai_completion(OPENAI_USAGE))]) as up, \
                proxy.running(self.log, {"openai": up.url}) as server:
            status, _, _ = post(server, "/openai/v1/chat/completions?trace=1", body, headers)

        self.assertEqual(status, 200)
        self.assertEqual(up.requests[0]["path"], "/v1/chat/completions?trace=1")
        self.assertEqual(up.requests[0]["headers"]["authorization"], f"Bearer {KEY}")
        [record] = self.records()
        self.assertEqual(record["provider"], "openai")
        self.assertEqual(record["endpoint"], "/v1/chat/completions")
        self.assertEqual(record["model"], "gpt-5.4-mini")
        self.assertEqual(record["model_served"], "gpt-5.4-mini-2026-03-17")
        self.assertEqual(record["service_tier"], "default")
        self.assertEqual(record["usage"], OPENAI_USAGE)

    def test_statuses_and_attempts_of_a_retried_call(self):
        replies = [
            Reply(429, anthropic_error("rate_limit_error"), {"retry-after": "1"}),
            Reply(529, anthropic_error("overloaded_error"), {"x-should-retry": "true"}),
            Reply(200, anthropic_message(ANTHROPIC_USAGE)),
        ]
        with FakeUpstream(replies) as up, proxy.running(self.log, {"anthropic": up.url}) as server:
            conn = http.client.HTTPConnection(*server.server_address[:2], timeout=10)
            answers = [
                post(server, "/anthropic/v1/messages", anthropic_body(),
                     {**ANTHROPIC_HEADERS, "X-Stainless-Retry-Count": str(retry)}, conn)
                for retry in range(3)
            ]
            conn.close()

        self.assertEqual([status for status, _, _ in answers], [429, 529, 200])
        self.assertEqual(answers[0][1]["retry-after"], "1")
        self.assertEqual(answers[1][1]["x-should-retry"], "true")
        self.assertEqual([data for _, _, data in answers], up.sent)
        records = self.records()
        self.assertEqual([r["attempt"] for r in records], [1, 2, 3])
        self.assertEqual([r["status"] for r in records], [429, 529, 200])
        self.assertEqual([r["usage"] for r in records], [None, None, ANTHROPIC_USAGE])

    def test_attempt_is_unknown_without_the_sdk_header(self):
        headers = {key: value for key, value in ANTHROPIC_HEADERS.items() if key != "X-Stainless-Retry-Count"}
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server:
            post(server, "/anthropic/v1/messages", anthropic_body(), headers)
        self.assertIsNone(self.records()[0]["attempt"])

    def test_timestamps_bracket_the_upstream_wait(self):
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE), delay=0.25)]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server:
            before = time.time_ns()
            post(server, "/anthropic/v1/messages", anthropic_body(), ANTHROPIC_HEADERS)
            after = time.time_ns()
        [record] = self.records()
        self.assertLessEqual(before, record["start_ns"])
        self.assertLessEqual(record["end_ns"], after)
        self.assertGreaterEqual(record["end_ns"] - record["start_ns"], 250_000_000)

    def test_gzip_body_reaches_the_client_unchanged_and_usage_is_read(self):
        headers = {**ANTHROPIC_HEADERS, "Accept-Encoding": "gzip"}
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE), gzip=True)]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server:
            _, response_headers, data = post(server, "/anthropic/v1/messages", anthropic_body(), headers)
        self.assertEqual(response_headers["content-encoding"], "gzip")
        self.assertEqual(data, up.sent[0])
        self.assertEqual(json.loads(gzip.decompress(data))["usage"], ANTHROPIC_USAGE)
        [record] = self.records()
        self.assertEqual(record["usage"], ANTHROPIC_USAGE)
        self.assertEqual(record["response_bytes"], len(data))

    def test_upstream_connection_is_reused(self):
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server:
            for _ in range(2):
                post(server, "/anthropic/v1/messages", anthropic_body(), ANTHROPIC_HEADERS)
        self.assertEqual(up.requests[0]["client_port"], up.requests[1]["client_port"])

    def test_connection_fields_stay_on_their_hop(self):
        headers = {
            **ANTHROPIC_HEADERS,
            "Connection": "keep-alive, X-Hop",
            "X-Hop": "1",
            "Keep-Alive": "timeout=5",
            "Proxy-Authorization": "Basic Zm9vOmJhcg==",
        }
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server:
            post(server, "/anthropic/v1/messages", anthropic_body(), headers)
        seen = up.requests[0]["headers"]
        for name in ("x-hop", "keep-alive", "proxy-authorization"):
            self.assertNotIn(name, seen)
        self.assertEqual(seen["host"], up.url.removeprefix("http://"))

    def test_unknown_route(self):
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server:
            status, _, _ = post(server, "/googleai/v1beta/models", b"{}", {"Content-Type": "application/json"})
        self.assertEqual(status, 404)
        self.assertEqual(up.requests, [])
        [record] = self.records()
        self.assertIsNone(record["provider"])
        self.assertIsNone(record["status"])
        self.assertEqual(record["error"], "unknown route")

    def test_unreachable_upstream(self):
        upstream = f"http://127.0.0.1:{free_port()}"
        with proxy.running(self.log, {"anthropic": upstream}) as server:
            status, _, _ = post(server, "/anthropic/v1/messages", anthropic_body(), ANTHROPIC_HEADERS)
        self.assertEqual(status, 502)
        [record] = self.records()
        self.assertIsNone(record["status"])
        self.assertEqual(record["error"], "upstream ConnectionRefusedError")
        self.assertIsNone(record["usage"])

    def test_request_without_content_length_is_refused(self):
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE))]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server, \
                socket.create_connection(server.server_address[:2]) as client:
            client.sendall(b"POST /anthropic/v1/messages HTTP/1.1\r\nHost: proxy\r\n\r\n")
            status_line = client.makefile("rb").readline()
        self.assertTrue(status_line.startswith(b"HTTP/1.1 411 "), status_line)
        self.assertEqual(up.requests, [])
        [record] = self.records()
        self.assertEqual((record["provider"], record["status"]), ("anthropic", None))
        self.assertEqual(record["error"], "request without Content-Length")

    def test_a_call_the_client_gave_up_on_keeps_its_usage(self):
        request = (
            b"POST /anthropic/v1/messages HTTP/1.1\r\nHost: proxy\r\nContent-Type: application/json\r\n"
            b"X-Stainless-Retry-Count: 0\r\nContent-Length: %d\r\n\r\n" % len(anthropic_body())
        ) + anthropic_body()
        with FakeUpstream([Reply(200, anthropic_message(ANTHROPIC_USAGE), delay=0.2)]) as up, \
                proxy.running(self.log, {"anthropic": up.url}) as server, \
                socket.create_connection(server.server_address[:2]) as client:
            client.sendall(request)
            time.sleep(0.05)
        [record] = self.records()
        self.assertEqual(record["status"], 200)
        self.assertEqual(record["usage"], ANTHROPIC_USAGE)


class HelpersTest(unittest.TestCase):
    def test_base_url_env(self):
        self.assertEqual(proxy.base_url_env("http://127.0.0.1:8787"), {
            "OPENAI_BASE_URL": "http://127.0.0.1:8787/openai/v1/",
            "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787/anthropic/",
        })

    def test_parse_upstreams(self):
        self.assertEqual(proxy.parse_upstreams(["openai=http://127.0.0.1:9"]), {"openai": "http://127.0.0.1:9"})
        for bad in (["googleai=http://127.0.0.1:9"], ["openai=127.0.0.1:9"], ["anthropic"], ["openai=http://"]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                proxy.parse_upstreams(bad)

    def test_cli_refuses_a_bad_upstream_before_listening(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            log = Path(tmp) / "calls.jsonl"
            self.assertEqual(proxy.main(["--log", str(log), "--upstream", "openai=ftp://127.0.0.1"]), 2)
            self.assertFalse(log.exists())
        self.assertIn("vkpi.a9.proxy:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
