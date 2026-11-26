from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import socket
import socketserver
import ssl
import sys
import threading
import time
from collections.abc import Iterator
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import NamedTuple, TextIO
from urllib.parse import urlsplit

from vkpi.a9 import usage

HOST = "127.0.0.1"
UPSTREAMS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}

# Longer than the 10-minute attempt timeout the Anthropic SDK sets on a
# non-streaming call, so the proxy never cuts an attempt the client still waits for.
UPSTREAM_TIMEOUT = 900.0

# An upstream connection idle for longer is closed rather than reused: the
# provider may have dropped it, and a call sent on it would fail.
MAX_IDLE = 30.0

# Connection-specific fields (RFC 9110, 7.6.1) stay on their hop; Host and
# Content-Length are set again for the next one.
_HOP_FIELDS = frozenset({
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
    "host", "content-length", "expect",
})


class _Upstream(NamedTuple):
    scheme: str
    host: str
    port: int | None
    path: str


def _upstream(url: str) -> _Upstream:
    # An upstream URL can carry credentials, so no error repeats it.
    invalid = ValueError("an upstream must be an http or https URL with a host and a valid port")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise invalid from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise invalid
    return _Upstream(parts.scheme, parts.hostname, port, parts.path.rstrip("/"))


def base_url_env(proxy_url: str) -> dict[str, str]:
    return {
        "OPENAI_BASE_URL": f"{proxy_url}/openai/v1/",
        "ANTHROPIC_BASE_URL": f"{proxy_url}/anthropic/",
    }


def parse_upstreams(pairs: list[str]) -> dict[str, str]:
    upstreams = {}
    for pair in pairs:
        provider, _, url = pair.partition("=")
        if provider not in UPSTREAMS:
            raise ValueError(f"--upstream takes PROVIDER=URL, with PROVIDER one of {', '.join(sorted(UPSTREAMS))}")
        _upstream(url)
        upstreams[provider] = url
    return upstreams


@contextlib.contextmanager
def running(log_path: Path, upstreams: dict[str, str] | None = None, port: int = 0) -> Iterator[Proxy]:
    with open(log_path, "a", encoding="utf-8") as log:
        server = Proxy(log, upstreams, port)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class Proxy(ThreadingHTTPServer):
    # server_close() then waits for the calls still in flight, so a run that
    # stops early keeps the cost of the calls it had started.
    daemon_threads = False

    def __init__(self, log: TextIO, upstreams: dict[str, str] | None = None, port: int = 0):
        self.upstreams = {name: _upstream(url) for name, url in {**UPSTREAMS, **(upstreams or {})}.items()}
        self.pool = _Pool(UPSTREAM_TIMEOUT)
        self._log = log
        self._log_lock = threading.Lock()
        super().__init__((HOST, port), _Handler)

    def server_bind(self) -> None:
        # HTTPServer would look its own name up in DNS here, which can take
        # seconds and is never used.
        socketserver.TCPServer.server_bind(self)
        self.server_name = HOST
        self.server_port = self.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.server_port}"

    def record(self, entry: dict) -> None:
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        with self._log_lock:
            self._log.write(line + "\n")
            self._log.flush()

    def server_close(self) -> None:
        super().server_close()
        self.pool.close()


class _Pool:
    def __init__(self, timeout: float):
        self._timeout = timeout
        self._tls = ssl.create_default_context()
        self._idle: dict[_Upstream, list[tuple[http.client.HTTPConnection, float]]] = {}
        self._lock = threading.Lock()

    def get(self, upstream: _Upstream) -> http.client.HTTPConnection:
        with self._lock:
            idle = self._idle.get(upstream, [])
            while idle:
                conn, since = idle.pop()
                if time.monotonic() - since < MAX_IDLE:
                    return conn
                conn.close()
        if upstream.scheme == "https":
            return http.client.HTTPSConnection(upstream.host, upstream.port, timeout=self._timeout, context=self._tls)
        return http.client.HTTPConnection(upstream.host, upstream.port, timeout=self._timeout)

    def put(self, upstream: _Upstream, conn: http.client.HTTPConnection) -> None:
        with self._lock:
            self._idle.setdefault(upstream, []).append((conn, time.monotonic()))

    def close(self) -> None:
        with self._lock:
            for idle in self._idle.values():
                for conn, _ in idle:
                    conn.close()
            self._idle.clear()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: Proxy

    def do_POST(self) -> None:
        entry = {
            "provider": None,
            "endpoint": None,
            "model": None,
            "attempt": _attempt(self.headers.get("X-Stainless-Retry-Count")),
            "status": None,
            "request_bytes": 0,
            "response_bytes": 0,
            "start_ns": time.time_ns(),
            "end_ns": None,
            "model_served": None,
            "service_tier": None,
            "usage": None,
            "error": None,
            "forwarded": False,
        }
        try:
            self._forward(entry)
        finally:
            if entry["end_ns"] is None:
                entry["end_ns"] = time.time_ns()
            self.server.record(entry)

    def handle(self) -> None:
        try:
            super().handle()
        except ConnectionError:
            # The client left between two requests: every request it sent is already logged.
            pass

    def log_message(self, format: str, *args: object) -> None:
        # The JSONL log is the record; the default access log would repeat it on stderr.
        pass

    def _forward(self, entry: dict) -> None:
        provider, _, rest = self.path.lstrip("/").partition("/")
        requested = urlsplit("/" + rest)
        entry["endpoint"] = requested.path
        if provider in self.server.upstreams:
            entry["provider"] = provider
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length < 0:
            self._fail(entry, 411, "request without Content-Length")
            return
        try:
            body = self.rfile.read(length)
        except OSError as err:
            entry["error"] = f"client {type(err).__name__}"
            self.close_connection = True
            return
        entry["request_bytes"] = len(body)
        if entry["provider"] is None:
            self._fail(entry, 404, "unknown route")
            return
        entry["model"] = usage.requested_model(body)

        upstream = self.server.upstreams[provider]
        path = upstream.path + requested.path + (f"?{requested.query}" if requested.query else "")
        conn = self.server.pool.get(upstream)
        try:
            if conn.sock is None:
                conn.connect()
        except OSError as err:
            conn.close()
            self._fail(entry, 504 if isinstance(err, socket.timeout) else 502, f"upstream connect {type(err).__name__}")
            return
        # From here the provider may receive the request, and bill it.
        entry["forwarded"] = True
        try:
            conn.request("POST", path, body=body, headers=_forwarded(self.headers))
            resp = conn.getresponse()
            data = resp.read()
        except (OSError, http.client.HTTPException) as err:
            conn.close()
            self._fail(entry, 504 if isinstance(err, socket.timeout) else 502, f"upstream {type(err).__name__}")
            return
        if resp.will_close:
            conn.close()
        else:
            self.server.pool.put(upstream, conn)

        entry["status"] = resp.status
        entry["response_bytes"] = len(data)
        self._reply(entry, resp, data)
        entry.update(usage.parse_response(provider, data, resp.getheader("Content-Encoding")))

    def _reply(self, entry: dict, resp: http.client.HTTPResponse, data: bytes) -> None:
        try:
            self.send_response_only(resp.status, resp.reason)
            for name, value in resp.getheaders():
                if name.lower() not in _HOP_FIELDS:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError as err:
            entry["error"] = f"client {type(err).__name__}"
            self.close_connection = True
        entry["end_ns"] = time.time_ns()

    def _fail(self, entry: dict, status: int, reason: str) -> None:
        entry["error"] = reason
        body = json.dumps({"error": {"message": f"vens-kpi a9 proxy: {reason}"}}).encode()
        self.close_connection = True
        try:
            self.send_response_only(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass


def _attempt(header: str | None) -> int | None:
    # Both Go SDKs number each attempt of a call in this header, from 0.
    if header is None or not (header.isascii() and header.isdigit()):
        return None
    return int(header) + 1


def _forwarded(headers: Message) -> dict[str, str]:
    listed = {token.strip().lower() for token in (headers.get("Connection") or "").split(",")}
    forwarded: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in _HOP_FIELDS or name.lower() in listed:
            continue
        # A repeated field goes out once, its values joined (RFC 9110, 5.3).
        forwarded[name] = f"{forwarded[name]}, {value}" if name in forwarded else value
    return forwarded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m vkpi.a9.proxy",
        description="Forward vens's provider calls and log one JSON line per request.",
    )
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--upstream", action="append", default=[], metavar="PROVIDER=URL")
    args = parser.parse_args(argv)
    try:
        upstreams = parse_upstreams(args.upstream)
        with running(args.log, upstreams, args.port) as server:
            for name, value in base_url_env(server.url).items():
                print(f"{name}={value}", file=sys.stderr)
            threading.Event().wait()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError) as err:
        print(f"vkpi.a9.proxy: {err}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
