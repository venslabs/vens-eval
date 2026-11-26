import base64
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from chain import attempt, campaign, read, runvens
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Variables Python sets in its own environment at startup, not given by the runner.
PYTHON_ADDS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}

# A runner that runs one vens through chain.runvens and is SIGKILLed once HOOK, one of runvens's steps, has returned
# and the pid file WAIT, if any, is there. ROOT, HOOK, WAIT, PIDS, CMD and FOLDER are set above this body.
PARENT = r'''
import os, signal, sys, time
sys.path.insert(0, ROOT)
from chain import runvens
real = getattr(runvens, HOOK)

def hooked(*args, **kw):
    out = real(*args, **kw)
    if HOOK == "_guard":
        open(os.path.join(PIDS, "guard"), "w").write(str(out.pid))
    end = time.time() + 5
    while WAIT and not os.path.exists(os.path.join(PIDS, WAIT)) and time.time() < end:
        time.sleep(0.02)
    os.kill(os.getpid(), signal.SIGKILL)

setattr(runvens, HOOK, hooked)
runvens.run(CMD, FOLDER, {}, env={"PATH": os.environ.get("PATH", "")}, timeout=60)
'''

# The vens that PARENT runs: it writes its pid, then sleeps, or leaves a child of its group running and exits 0.
SLEEPER = r'''
import os, subprocess, sys, time
mode, pids = sys.argv[1], sys.argv[2]
open(os.path.join(pids, "vens"), "w").write(str(os.getpid()))
if mode == "straggler":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    open(os.path.join(pids, "straggler"), "w").write(str(child.pid))
    sys.exit(0)
time.sleep(60)
'''


def forms(key):
    """The key as a log or a file could hold it: itself, its base64 alone, inside a longer encoded text at another
    byte alignment, and masked the way an SDK shows it."""
    return [key, base64.b64encode(key.encode()).decode(), "Basic " + base64.b64encode(b"u:" + key.encode()).decode(),
            key[:8] + "…" + key[-4:]]


def gone(pid, wait=5.0):
    end = time.time() + wait
    while time.time() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = os.path.realpath(tmp.name)
        self.out = os.path.join(self.dir, "campaign")

    def record(self, rel):
        with open(os.path.join(self.out, rel, "attempt.json")) as fh:
            return json.load(fh)

    def rewrite(self, rel, **fields):
        runvens.write_json(os.path.join(self.out, rel, "attempt.json"), {**self.record(rel), **fields})


class TestRunvens(Base):
    def test_an_error_between_the_start_and_the_end_kills_vens(self):
        folder, pidfile = os.path.join(self.dir, "a"), os.path.join(self.dir, "pid")
        cmd = [sys.executable, "-c", f"import os, time; open({pidfile!r}, 'w').write(str(os.getpid())); "
                                     f"time.sleep(60)"]

        def failing_drain(*args):
            end = time.time() + 10
            while time.time() < end and not os.path.exists(pidfile):
                time.sleep(0.05)
            raise RuntimeError("no thread for the log")

        with mock.patch.object(runvens, "_drain", failing_drain):
            with self.assertRaisesRegex(RuntimeError, "no thread for the log"):
                runvens.run(cmd, folder, {}, env={}, timeout=60)
        with open(pidfile) as fh:
            self.assertTrue(gone(int(fh.read())))
        self.assertEqual(runvens._LIVE, set())
        gen = self.record(folder)["generate"]
        self.assertEqual((gen["exit_status"], gen["interrupted"]),
                         (None, "the runner failed: RuntimeError('no thread for the log')"))

    def test_a_launch_that_fails_is_read_as_such(self):
        folder = os.path.join(self.dir, "a")
        with self.assertRaisesRegex(OSError, "vens did not start: "):
            runvens.run([os.path.join(self.dir, "no-vens")], folder, {"runner": "scenarios", "arm": "after"}, env={})
        rec = self.record(folder)
        self.assertEqual(rec["generate"]["started_at"], None)
        self.assertTrue(rec["setup_error"].startswith("vens did not start: "))
        for started in (None, "2026-11-20T10:00:00.000000Z"):
            self.rewrite(folder, generate={**rec["generate"], "started_at": started})
            got = attempt.read_attempt(folder)
            self.assertEqual((got["outcome"], got["failure"]["cause"], got["failure"]["cause_source"]),
                             ("failed", rec["setup_error"], "attempt.json"), started)

    def test_vens_gets_exactly_its_environment(self):
        folder, out = os.path.join(self.dir, "a"), os.path.join(self.dir, "env.json")
        cmd = [sys.executable, "-S", "-c", f"import json, os; json.dump(dict(os.environ), open({out!r}, 'w'))"]
        rec = runvens.run(cmd, folder, {}, env={"PATH": "/usr/bin", "A_KEY": "sk-x"})
        self.assertEqual(rec["generate"]["exit_status"], 0)
        with open(out) as fh:
            self.assertEqual(set(json.load(fh)) - PYTHON_ADDS, {"PATH", "A_KEY"})

    def kill_the_runner_at(self, hook, mode, wait=None):
        """PARENT run on SLEEPER, SIGKILLed after hook: the pid files it leaves."""
        pids = os.path.join(self.dir, "pids")
        os.makedirs(pids)
        sleeper = s.write(os.path.join(self.dir, "sleeper.py"), SLEEPER)
        header = (f"ROOT, HOOK, WAIT, PIDS = {ROOT!r}, {hook!r}, {wait!r}, {pids!r}\n"
                  f"CMD, FOLDER = {[sys.executable, sleeper, mode, pids]!r}, {os.path.join(self.dir, 'a')!r}\n")
        parent = s.write(os.path.join(self.dir, "parent.py"), header + PARENT)
        done = subprocess.run([sys.executable, parent], timeout=60)
        self.assertEqual(done.returncode, -signal.SIGKILL)
        return {n: int(open(os.path.join(pids, n)).read()) for n in os.listdir(pids)}

    def test_a_runner_killed_once_the_guard_runs_leaves_nothing(self):
        pids = self.kill_the_runner_at("_guard", "sleep")
        self.assertTrue(gone(pids["guard"]))
        if "vens" in pids:
            self.assertTrue(gone(pids["vens"]))

    def test_a_runner_killed_while_vens_runs_leaves_nothing(self):
        pids = self.kill_the_runner_at("_drain", "sleep", wait="vens")
        self.assertTrue(gone(pids["vens"]))

    def test_a_runner_killed_after_vens_ended_leaves_no_child_of_it(self):
        pids = self.kill_the_runner_at("_report", "straggler")
        self.assertTrue(gone(pids["straggler"]))
        self.assertTrue(gone(pids["vens"]))


class TestKeys(Base):
    def test_the_key_forms_cut_out(self):
        key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123"
        text = "\n".join(forms(key) + ["Basic " + base64.b64encode(b"ab" + key.encode()).decode(),
                                       base64.urlsafe_b64encode(b"\xff" + key.encode()).decode(), "sk-proj-***0123"])
        clean = runvens.secret_pattern(key).sub(b"***", text.encode()).decode()
        self.assertEqual([line for line in clean.splitlines() if "***" not in line], [])
        self.assertNotIn("abcdefghij", clean)
        self.assertIsNone(runvens.secret_pattern(""))


if __name__ == "__main__":
    unittest.main()
