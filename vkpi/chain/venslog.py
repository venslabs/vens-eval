"""vens's log, the stderr of `vens generate`, as Go's slog text handler writes it, in both arms.

Read from it: the run summary ("Scoring run finished"), the error that stopped a run, and the warnings that mark an
ask-again, an unreadable reply, a split and a rated CVE.
"""
import re

SUMMARY = "Scoring run finished"
SCORED = "Scored vulnerability"
UNREADABLE = "Unreadable reply; the vulnerabilities it leaves without an answer count as left out"
ASK_AGAIN = (
    "No readable answer for vulnerabilities; asking again for those alone",  # 310-step3
    "Model skipped vulnerabilities; asking again for those alone",  # main
)
SPLIT = (
    "LLM truncated the call; asking each half on its own",  # 310-step3
    "LLM truncated the batch; retrying with smaller batches",  # main
)
OMISSION, UNREADABLE_KIND = "omission", "unreadable"

_PAIR = re.compile(r'\s*([^\s=]+)=("(?:[^"\\]|\\.)*"|\S*)')
_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"',
            "'": "'"}
_WIDTH = {"x": 2, "u": 4, "U": 8}


def _unquote(quoted):
    """A string as Go's strconv.Quote writes it, its quotes included."""
    body, out, i = quoted[1:-1], [], 0
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 == len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
        elif nxt in _WIDTH:
            width = _WIDTH[nxt]
            out.append(chr(int(body[i + 2:i + 2 + width], 16)))
            i += 2 + width
        elif nxt in "01234567":
            out.append(chr(int(body[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(nxt)
            i += 2
    return "".join(out)


def fields(line):
    """{key: value} of one log line, slog groups kept as dotted keys; {} for a line slog did not write."""
    out, pos, line = {}, 0, line.rstrip("\r\n")
    while pos < len(line):
        if not line[pos:].strip():
            break
        m = _PAIR.match(line, pos)
        if not m:
            return {}
        value = m.group(2)
        out[m.group(1)] = _unquote(value) if value.startswith('"') else value
        pos = m.end()
    return out if "level" in out and "msg" in out else {}


def records(text):
    return [f for f in map(fields, text.splitlines()) if f]


def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return records(fh.read())


def _number(value):
    try:
        return int(value)
    except ValueError:
        return value


def summary(recs):
    """The last run summary as {rows, cves, llm_calls, asked_again, splits, failed, calls, counters, defects}, or
    None: a run that stops before scoring logs none. main logs no calls, counters or defects; they stay empty."""
    found = [r for r in recs if r["msg"] == SUMMARY]
    if not found:
        return None
    out = {"calls": {}, "counters": {}, "defects": {}}
    for key, value in found[-1].items():
        if key in ("time", "level", "msg"):
            continue
        group, _, name = key.partition(".")
        if name and group in out:
            out[group] = {**out[group], name: _number(value)}
        elif key == "failed":
            out["failed"] = value == "true"
        else:
            out[key] = _number(value)
    return out


def cause(recs):
    """The error that stopped the run: the `error` of vens's last `msg=Error` line, else the last ERROR line's."""
    errors = [r for r in recs if r["level"] == "ERROR"]
    final = [r for r in errors if r["msg"] == "Error" and "error" in r]
    if final:
        return final[-1]["error"]
    if errors:
        last = errors[-1]
        return last["msg"] + (": " + last["error"] if "error" in last else "")
    return None


def ask_agains(recs):
    """Each ask-again in log order, (question, kind): `unreadable` when an unreadable reply to its question was
    logged in the same batch before it, `omission` otherwise. A batch ends when its CVEs are rated. main logs no
    question and has no unreadable kind: a reply it cannot parse stops its run."""
    out, pending = [], frozenset()
    for r in recs:
        msg = r["msg"]
        if msg == UNREADABLE:
            pending = pending | {r.get("question")}
        elif msg in ASK_AGAIN:
            question = r.get("question")
            out.append((question, UNREADABLE_KIND if question in pending else OMISSION))
            pending = pending - {question}
        elif msg == SCORED:
            pending = frozenset()
    return out


def splits(recs):
    return sum(1 for r in recs if r["msg"] in SPLIT)


def unreadable_replies(recs):
    return sum(1 for r in recs if r["msg"] == UNREADABLE)
