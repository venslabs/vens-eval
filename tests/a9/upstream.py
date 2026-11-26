from __future__ import annotations

import gzip
import json
import socketserver
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass(frozen=True)
class Reply:
    status: int
    body: dict
    headers: dict = field(default_factory=dict)
    delay: float = 0.0
    gzip: bool = False
    # Read the request, then close the connection without answering.
    drop: bool = False


# Answers the i-th request with replies[i], the last reply repeating, or with
# replies(request) when given a function.
class FakeUpstream(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, replies: list[Reply] | Callable[[dict], Reply]):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.replies = replies
        self.requests: list[dict] = []
        self.sent: list[bytes] = []
        self._lock = threading.Lock()

    def server_bind(self) -> None:
        # Skips HTTPServer's DNS lookup of its own name, slow on some hosts.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"

    def take(self, request: dict) -> Reply:
        with self._lock:
            self.requests.append(request)
            if callable(self.replies):
                return self.replies(request)
            return self.replies[min(len(self.requests), len(self.replies)) - 1]

    def __enter__(self):
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.shutdown()
        self.server_close()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: FakeUpstream

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        reply = self.server.take({
            "path": self.path,
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "body": body,
            "client_port": self.client_address[1],
        })
        time.sleep(reply.delay)
        if reply.drop:
            self.close_connection = True
            return
        data = json.dumps(reply.body).encode()
        headers = {"Content-Type": "application/json", **reply.headers}
        if reply.gzip and "gzip" in self.headers.get("Accept-Encoding", ""):
            data = gzip.compress(data)
            headers["Content-Encoding"] = "gzip"
        with self.server._lock:
            self.server.sent.append(data)
        self.send_response(reply.status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        pass


# Answers every call with the smallest reply its own response schema accepts.
def schema_answers(provider: str, text: str) -> Callable[[dict], Reply]:
    def answer(request: dict) -> Reply:
        body = json.loads(request["body"])
        if provider == "openai":
            content = json.dumps(instance(body["response_format"]["json_schema"]["schema"], text))
            return Reply(200, openai_completion(OPENAI_USAGE, content), gzip=True)
        content = json.dumps(instance(body["output_config"]["format"]["schema"], text))
        return Reply(200, anthropic_message(ANTHROPIC_USAGE, content), gzip=True)

    return answer


def instance(schema: dict, text: str) -> object:
    # Every property, one array item, the first value of an enum (so the ids
    # vens enumerates), and text for any other string.
    if "enum" in schema:
        return schema["enum"][0]
    kind = schema.get("type")
    if kind == "object":
        return {name: instance(sub, text) for name, sub in schema.get("properties", {}).items()}
    if kind == "array":
        return [instance(schema["items"], text) for _ in range(max(1, schema.get("minItems", 1)))]
    if kind == "string":
        return text
    if kind in ("number", "integer"):
        return schema.get("minimum", 5)
    if kind == "boolean":
        return False
    raise ValueError(f"no instance for schema type {kind!r}")


def openai_completion(usage: dict, content: str = "{}", tier: str = "default") -> dict:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1764000000,
        "model": "gpt-5.4-mini-2026-03-17",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content, "refusal": None},
            "finish_reason": "stop",
            "logprobs": None,
        }],
        "usage": usage,
        "service_tier": tier,
    }


def anthropic_message(usage: dict, text: str = "{}") -> dict:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-6",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": usage,
    }


def openai_error(kind: str = "invalid_request_error") -> dict:
    return {"error": {"message": "fake upstream", "type": kind, "param": None, "code": None}}


def anthropic_error(kind: str = "invalid_request_error") -> dict:
    return {"type": "error", "error": {"type": kind, "message": "fake upstream"}}


OPENAI_USAGE = {
    "prompt_tokens": 2006,
    "completion_tokens": 300,
    "total_tokens": 2306,
    "prompt_tokens_details": {"cached_tokens": 1920, "audio_tokens": 0},
    "completion_tokens_details": {
        "reasoning_tokens": 128,
        "audio_tokens": 0,
        "accepted_prediction_tokens": 0,
        "rejected_prediction_tokens": 0,
    },
}

ANTHROPIC_USAGE = {
    "input_tokens": 2095,
    "output_tokens": 503,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0,
    "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0},
    "inference_geo": "global",
    "service_tier": "standard",
}
