"""A run's debug folder (`vens generate --debug-dir`): its calls, what each asked, and which were planned.

A call is three files, `batch-NNNNN.system.prompt`, `.human.prompt` and `.response`, numbered in call order; a call
vens wrote no reply for, a failed or a truncated one, keeps its prompts alone.
"""
import collections
import glob
import hashlib
import json
import os
import re
from dataclasses import dataclass

from chain.errors import Refused

PLANNED, ADJUSTMENT = "planned", "adjustment"
AGAIN_OMISSION, AGAIN_UNREADABLE, HALF = "again_omission", "again_unreadable", "half"
RECOVERY = (AGAIN_OMISSION, AGAIN_UNREADABLE, HALF)
KINDS = (PLANNED, ADJUSTMENT) + RECOVERY

_NAME = re.compile(r"batch-(\d+)\.system\.prompt")


@dataclass(frozen=True)
class Call:
    number: int
    system: bytes
    human: bytes
    response: object  # bytes, or None when vens wrote no reply

    def text(self, part):
        raw = getattr(self, part)
        return None if raw is None else raw.decode("utf-8", errors="replace")


def _read(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


def run_folders(calls_dir):
    return sorted(glob.glob(os.path.join(calls_dir, "run-*")))


def load(run_dir):
    """The run folder's calls in order; Refused when a file of it does not read (a folder in a file's place)."""
    try:
        numbers = sorted(int(m.group(1)) for m in map(_NAME.fullmatch, os.listdir(run_dir)) if m)
        out = []
        for n in numbers:
            base = os.path.join(run_dir, f"batch-{n:05d}")
            out.append(Call(n, _read(base + ".system.prompt"), _read(base + ".human.prompt"),
                            _read(base + ".response")))
    except OSError as e:
        raise Refused(f"{run_dir}: a call that does not read: {e}") from e
    return out


@dataclass(frozen=True)
class Asked:
    kind: str  # question, adjustment, batch (main's one call per batch) or unknown
    question: object  # the after's question sentence, None otherwise
    ids: tuple  # the after: the CVE ids in prompt order; main: one key per row entry


def asked(call, arm):
    """What a call asked, read from its human prompt (pkg/contract/render.go at 310-step3; main's JSON rows)."""
    text = call.text("human")
    if text is None:
        return Asked("unknown", None, ())
    try:
        if arm == "before":
            rows = json.loads(text)
            if isinstance(rows, list):
                return Asked("batch", None, tuple(json.dumps(r, sort_keys=True) for r in rows))
            return Asked("unknown", None, ())
        lines = text.split("\n")
        if lines[0] == "FLAGGED VULNERABILITY":
            return Asked("adjustment", None, (json.loads(lines[1])["vulnId"],))
        if lines[0] == "VULNERABILITIES":
            ids = tuple(e["vulnId"] for e in json.loads(lines[1]))
            return Asked("question", lines[lines.index("QUESTION") + 1], ids)
    except (ValueError, KeyError, TypeError, IndexError):
        pass
    return Asked("unknown", None, ())


def _reject(constant):
    raise ValueError(constant)


def unreadable(reply):
    """Whether the after reads a reply as unreadable (pkg/generator/ask.go readEntries at 310-step3): no JSON
    object, its answers no array, or an answer that is no JSON object."""
    # Go keeps numbers as raw text here; converting them would refuse an integer Go reads.
    try:
        top = json.loads(reply.decode("utf-8", errors="replace"), parse_constant=_reject,
                         parse_int=lambda _: 0, parse_float=lambda _: 0.0)
    except (ValueError, RecursionError):
        return True
    if not isinstance(top, dict):
        return True
    if "answers" not in top:
        return False
    items = top["answers"]
    return not isinstance(items, list) or any(not isinstance(x, dict) for x in items)


class _Mismatch(Exception):
    pass


def _ordered_subset(sub, full):
    wanted = set(sub)
    return bool(sub) and wanted <= set(full) and tuple(x for x in full if x in wanted) == tuple(sub)


def _classify_after(calls):
    """Mirrors ask.go at 310-step3: per batch and question one call, split in half while the provider truncates
    it, then one ask-again over the CVEs still without an answer, itself split if truncated; then the
    adjustments."""
    asks = [asked(c, "after") for c in calls]
    kinds, n = [None] * len(calls), len(calls)

    def matches(i, question, ids):
        return i < n and asks[i].kind == "question" and asks[i].question == question and asks[i].ids == ids

    def splitting(i, question, ids, role, unread):
        if i >= n:
            return i
        if not matches(i, question, ids):
            raise _Mismatch(i)
        kinds[i] = role
        if calls[i].response is None:
            half = (len(ids) + 1) // 2
            if len(ids) > 1 and matches(i + 1, question, ids[:half]):
                j = splitting(i + 1, question, ids[:half], HALF, unread)
                return splitting(j, question, ids[half:], HALF, unread)
            return i + 1
        if unreadable(calls[i].response):
            unread.append(i)
        return i + 1

    i = 0
    while i < n:
        a = asks[i]
        if a.kind == "adjustment":
            kinds[i] = ADJUSTMENT
            i += 1
            continue
        if a.kind != "question":
            raise _Mismatch(i)
        unread = []
        j = splitting(i, a.question, a.ids, PLANNED, unread)
        if j < n and asks[j].kind == "question" and asks[j].question == a.question and _ordered_subset(asks[j].ids,
                                                                                                         a.ids):
            j = splitting(j, a.question, asks[j].ids, AGAIN_UNREADABLE if unread else AGAIN_OMISSION, [])
        i = j
    return kinds


def _classify_before(calls):
    """main at 43ab10b: one call per batch of rows, its rows the batch's not yet scored; an ask-again over the
    rows its reply skipped, right after it; a truncated call's rows asked again in smaller batches. (kinds, problem):
    a call whose human prompt does not read leaves it and every call after it unclassified, since what it asked
    decides how the next calls read; it is never taken for a planned call."""
    asks = [asked(c, "before") for c in calls]
    stop = next((i for i, a in enumerate(asks) if a.kind != "batch"), len(calls))
    rows = [collections.Counter(a.ids) for a in asks[:stop]]
    kinds, stack = [], []
    for i, call in enumerate(calls[:stop]):
        here = rows[i]
        answered_before = i > 0 and kinds[-1] in (PLANNED, HALF) and calls[i - 1].response is not None
        if here and answered_before and here <= rows[i - 1]:
            kind = AGAIN_OMISSION
        else:
            while stack and not here <= stack[-1]:
                stack = stack[:-1]
            if stack and here:
                kind = HALF
                stack = stack[:-1] + [stack[-1] - here]
            else:
                kind = PLANNED
        if call.response is None and sum(here.values()) > 1 and i + 1 < len(calls):
            stack = stack + [here]
        kinds.append(kind)
    if stop == len(calls):
        return kinds, None
    return kinds + [None] * (len(calls) - stop), (f"call {calls[stop].number}'s human prompt does not read: it and "
                                                  f"the calls after it are not classified")


def classify(calls, arm):
    """(kind of each call, problem or None). A sequence that does not follow vens's order of calls leaves the
    calls from the first one out of order unclassified (None) and says where."""
    if arm not in ("before", "after"):
        return [None] * len(calls), "arm unknown: the calls are not classified"
    if arm == "before":
        return _classify_before(calls)
    try:
        return _classify_after(calls), None
    except _Mismatch as m:
        i = m.args[0]
        kinds = _classify_after_prefix(calls, i)
        return kinds, f"call {calls[i].number} does not follow 310-step3's order of calls"


def _classify_after_prefix(calls, stop):
    try:
        prefix = _classify_after(calls[:stop])
    except _Mismatch:
        prefix = [None] * stop
    return prefix + [None] * (len(calls) - stop)


def archive_check(run_dirs, calls, evidence, provider, model):
    """baseline.yml's archive check, restated: one run folder, every call with its human prompt and reply, the
    sha256 of system + blank line + human equal in order to the attested prompt_hash list, every call attested
    from the dispatched provider and model. (passed, reason)."""
    if len(run_dirs) != 1:
        return False, f"{len(run_dirs)} run folders under calls/"
    if any(c.human is None or c.response is None for c in calls):
        return False, "a call without its human prompt or reply"
    got = [hashlib.sha256((c.system or b"") + b"\n\n" + c.human).hexdigest() for c in calls]
    if got != [e.get("prompt_hash") for e in evidence]:
        return False, f"{len(got)} archived calls against {len(evidence)} attested, or a prompt hash differs"
    attested = sorted({(e.get("provider"), e.get("model")) for e in evidence})
    if provider is not None and attested != [(provider, model)]:
        return False, f"attested {attested}, dispatched {provider}/{model}"
    return True, ""
