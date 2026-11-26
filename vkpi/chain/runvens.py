"""One `vens generate` laid out as an attempt folder: attempt.json written before vens starts and completed when it
ends, vens's whole log, the debug folder and the VEX. The scenario runner's layout; the tests and the Java run use it
on vens's mock.

vens is started by a guard (GUARD), a small process that leads a session of its own, so that no terminal signal
reaches vens and the guard's whole group can be killed at once. The guard's stdin is a control pipe whose write end
only this process holds, from the guard's start: its first line is vens's environment, and its end, whether this
process closes it or dies, SIGKILL included, makes the guard kill its group, the PGID it saved, whatever of vens
or what vens started is left. macOS has no parent-death signal: the pipe stands in for one. Every guard not yet
reaped is in a registry that kill_live() kills, which this module runs at exit and the runner on any stop.
"""
import atexit
import base64
import contextlib
import datetime
import hashlib
import json
import os
import re
import select
import signal
import subprocess
import sys
import threading
import time

SERIAL = "urn:uuid:00000000-0000-0000-0000-000000000001"
MARKER = "schema_version: 2\n"
TIMEOUT, STOPPED = "timeout", "the runner was stopped"
GUARD_LOST = "the guard ended before reporting vens's exit status"
POLL = 0.2
# seconds vens's stderr may stay open once its group is killed
DRAIN = 5.0
GUARD = """import json, os, signal, subprocess, sys, threading
pgid, line = os.getpgid(0), b""
while not line.endswith(b"\\n"):
    chunk = os.read(0, 65536)
    if not chunk:
        os._exit(0)
    line += chunk
try:
    vens = subprocess.Popen(sys.argv[1:], env=json.loads(line), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
except OSError as e:
    os.write(1, ("error %s\\n" % e).encode())
else:
    threading.Thread(target=lambda: os.write(1, b"exit %d\\n" % vens.wait()), daemon=True).start()
while os.read(0, 65536):
    pass
os.killpg(pgid, signal.SIGKILL)
"""

_LIVE, _LOCK = set(), threading.Lock()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def add_marker(src, dst):
    """A copy of a schema-1 config with the schema-2 marker as its first line, every other byte kept; a config
    that declares its schema already is copied as it is."""
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    declared = any(line.startswith("schema_version:") for line in text.splitlines())
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(text if declared else MARKER + text)
    return dst


def write_json(path, doc):
    """Written whole through a file of its own, so a kill mid-write leaves the file as it was."""
    tmp = f"{path}.{os.getpid()}-{threading.get_ident()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    os.replace(tmp, path)


def secret_pattern(key):
    """What the log and the archive are cleaned of for one API key: the key; its base64, standard and URL-safe, at
    each of the three byte alignments it can take inside a longer encoded text; and its first 8 and last 4
    characters around what an SDK shows of a key it masks (sk-...XXXX). None for no key."""
    if not key:
        return None
    raw, forms = key.encode(), {key.encode()}
    for pad in range(3):
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            coded = encode(b"\0" * pad + raw)
            # the characters that encode the key's bytes alone
            part = coded[(pad * 8 + 5) // 6:((pad + len(raw)) * 8) // 6]
            if len(part) >= 8:
                forms.add(part)
    alternatives = [re.escape(f) for f in sorted(forms, key=len, reverse=True)]
    if len(raw) >= 12:
        alternatives.append(re.escape(raw[:8]) + rb"[^\s\"']{0,%d}" % len(raw) + re.escape(raw[-4:]))
    return re.compile(b"|".join(alternatives))


def scrub(folder, pattern):
    """The files under folder that held a form of the key, each rewritten with *** in its place."""
    found = []
    for d, _, names in os.walk(folder):
        for n in names:
            path = os.path.join(d, n)
            with open(path, "rb") as fh:
                data = fh.read()
            clean = pattern.sub(b"***", data)
            if clean != data:
                tmp = f"{path}.{os.getpid()}-{threading.get_ident()}.tmp"
                with open(tmp, "wb") as fh:
                    fh.write(clean)
                os.replace(tmp, path)
                found.append(os.path.relpath(path, folder))
    return sorted(found)


def _killpg(pgid):
    with contextlib.suppress(OSError):
        os.killpg(pgid, signal.SIGKILL)


def kill_live():
    """Kills the group of every guard this process started and has not reaped."""
    with _LOCK:
        groups = sorted(_LIVE)
    for pgid in groups:
        _killpg(pgid)


atexit.register(kill_live)


def _guard(cmd, cwd, control):
    """GUARD over cmd, its stdin the read end of the control pipe; its stderr is vens's."""
    return subprocess.Popen([sys.executable, "-S", "-c", GUARD, *cmd], cwd=cwd, env={}, stdin=control,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)


def _copy(src, dst, pattern, done):
    """vens's stderr into its log as it comes, each form of the key cut out of each line before it is written; the
    pipe is read to its end even when a write fails, so that vens never blocks on it."""
    whole = True
    for line in iter(src.readline, b""):
        if whole:
            try:
                dst.write(pattern.sub(b"***", line) if pattern else line)
                dst.flush()
            except OSError:
                whole = False
    done.append(whole)


def _drain(src, dst, pattern, done):
    copier = threading.Thread(target=_copy, args=(src, dst, pattern, done), daemon=True)
    copier.start()
    return copier


def _report(guard, deadline, stop):
    """The guard's one line, b"exit N" or b"error ...", or (None, why): the deadline passed, stop was set, or the
    guard ended without a line."""
    out, fd = b"", guard.stdout.fileno()
    while not out.endswith(b"\n"):
        left = deadline - time.monotonic()
        if left <= 0:
            return None, TIMEOUT
        if stop is not None and stop.is_set():
            return None, STOPPED
        if select.select([fd], [], [], min(POLL, left))[0]:
            chunk = os.read(fd, 4096)
            if not chunk:
                return None, GUARD_LOST
            out += chunk
    return out.strip(), None


def _drained(copier, done):
    """Whether vens's stderr reached its log whole, the copier given DRAIN seconds once the group is killed: a
    process that left the group can hold the pipe open."""
    copier.join(DRAIN)
    return not copier.is_alive() and done == [True]


def run(cmd, folder, rec, *, env, cwd=None, timeout=600, key=None, stop=None):
    """Runs cmd, a vens command, into folder, which must not exist, and returns the attempt record completed.

    rec is written to folder/attempt.json before vens starts, then completed on the runner's clock: generate's
    start and end, its exit status, or, when the runner killed it, none and interrupted saying why (timed_out for the
    timeout); log_complete, whether vens's stderr reached folder/vens.log whole. env is vens's whole environment;
    key, the API key in it, is cut out of the log in each of its forms (secret_pattern). vens's stdout is dropped: it
    writes nothing there. A vens that does not start leaves setup_error and no start, and an OSError is raised; any
    error once the guard has started kills its group, is recorded and is raised."""
    os.makedirs(folder)
    path = os.path.join(folder, "attempt.json")
    gen = {"started_at": None, "ended_at": None, "exit_status": None, "timed_out": False, "interrupted": None,
           "log_complete": None}
    rec = {**rec, "generate": gen}
    write_json(path, rec)
    pattern = secret_pattern(key)
    control, control_w = os.pipe()
    try:
        with open(os.path.join(folder, "vens.log"), "wb") as log:
            started = utc()
            write_json(path, {**rec, "generate": {**gen, "started_at": started}})
            try:
                guard = _guard(cmd, cwd, control)
            except OSError as e:
                write_json(path, {**rec, "setup_error": f"the guard did not start: {e}"})
                raise
            os.close(control)
            control = None
            with _LOCK:
                _LIVE.add(guard.pid)
            try:
                os.write(control_w, json.dumps(env).encode() + b"\n")
                done = []
                copier = _drain(guard.stderr, log, pattern, done)
                line, why = _report(guard, time.monotonic() + timeout, stop)
                ended = utc()
                os.close(control_w)
                control_w = None
                # the guard kills its group once its control pipe closes; this kill, before it is reaped, is the same
                _killpg(guard.pid)
                guard.wait()
                whole = _drained(copier, done)
            except BaseException as e:
                _killpg(guard.pid)
                guard.wait()
                with contextlib.suppress(Exception):
                    write_json(path, {**rec, "generate": {**gen, "started_at": started, "ended_at": utc(),
                                                          "interrupted": f"the runner failed: {e!r}"}})
                raise
            finally:
                with _LOCK:
                    _LIVE.discard(guard.pid)
                guard.stdout.close()
    finally:
        for fd in (control, control_w):
            if fd is not None:
                os.close(fd)
    if line is not None and line.startswith(b"error "):
        error = line[len(b"error "):].decode(errors="replace")
        write_json(path, {**rec, "setup_error": f"vens did not start: {error}"})
        raise OSError(f"vens did not start: {error}")
    status = int(line.split()[1]) if line is not None else None
    rec = {**rec, "generate": {**gen, "started_at": started, "ended_at": ended, "exit_status": status,
                               "timed_out": why == TIMEOUT, "interrupted": why, "log_complete": whole}}
    write_json(path, rec)
    return rec


def generate(binary, config, report, folder, *, record=None, batch=1, llm="mock", env_extra=None, strict=False,
             timeout=600):
    """Runs vens generate into folder, which must not exist, and returns the attempt record it wrote. Only PATH,
    HOME and env_extra reach vens: no API key does."""
    rec = {"record": 1, "runner": "scenarios", **(record or {}), "provider": llm,
           "model": (record or {}).get("model", llm), "llm_batch_size": batch,
           "vens_binary_sha256": sha256(binary), "config": config, "report": report}
    cmd = [binary, "generate", "--llm", llm, "--config-file", config, "--llm-batch-size", str(batch),
           "--sbom-serial-number", SERIAL, "--attest", "--debug-dir", os.path.join(folder, "calls"), report,
           os.path.join(folder, "vex.cdx.json")]
    if strict:
        cmd.insert(2, "--strict")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), **(env_extra or {})}
    return run(cmd, folder, rec, env=env, timeout=timeout)
