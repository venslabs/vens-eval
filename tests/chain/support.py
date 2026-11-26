"""Shared helpers: the environment the optional tests need, and synthetic folders as vens and baseline.yml leave them.

    VB_VENS_AFTER, VB_VENS_BEFORE   vens binaries built from 310-step3 b7c0435 and main 43ab10b
    VB_DEMO                         a vens-demo tree at 7ab1570 (runs/2026-09-23/scan/scan.json, contexts/)
    VB_QUICKSTART                   vens's examples/quickstart at b7c0435
    VB_JAR, VB_JDK                  the calculator's 1.0.1 JAR and a JDK bin folder (JAVA_HOME/bin otherwise)
    VB_0B_MEASUREMENTS              a folder holding 0B's archives, 0b-phase1 and 0b-phase2
    VB_0B_READ0B                    0B's frozen reader, read0b.py, to compare with
"""
import hashlib
import json
import os

AFTER_SHA = "b7c0435835447027b04d54d4e6befaaee6b0626b"
BEFORE_SHA = "43ab10bf980d42b77157e003a27921805a546770"
MODEL = "gpt-5.4-mini-2026-03-17"
VECTOR = "SL:9/M:1/O:7/S:9/ED:9/EE:5/A:9/ID:9/LC:9/LI:9/LAV:7/LAC:9/FD:1/RD:4/NC:2/PV:9"
SCORE, SEVERITY = 61.625, "critical"
SYSTEM = "You are a security expert.\n\nDEPLOYMENT\nProject: svc\n"
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def env(name):
    value = os.environ.get(name)
    return value if value and os.path.exists(value) else None


def need(test, *names):
    missing = [n for n in names if env(n) is None]
    if missing:
        test.skipTest(f"set {', '.join(missing)} to run this test (see tests/support.py)")
    return [env(n) for n in names]


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode, **({} if mode == "wb" else {"encoding": "utf-8"})) as fh:
        fh.write(content if isinstance(content, (bytes, str)) else json.dumps(content, indent=1))
    return path


def after_human(question, ids):
    entries = [{"vulnId": i, "title": "t", "description": "d", "severity": "LOW", "packages": []} for i in ids]
    return f"VULNERABILITIES\n{json.dumps(entries)}\n\nQUESTION\n{question}\n\nANSWERS\n- a: A\n- cannot_tell: C"


def adjust_human(vid):
    return f"FLAGGED VULNERABILITY\n{json.dumps({'vulnId': vid, 'title': 't'})}\n\nQUESTIONS\nopportunity: ..."


def before_human(rows):
    return json.dumps([{"vulnId": v, "pkgId": "", "pkgName": p, "installedVersion": "1", "title": "t",
                        "description": "d", "severity": "LOW"} for v, p in rows])


def reply(ids, skip=()):
    return json.dumps({"answers": [{"vulnId": i, "reasoning": "r", "answer": "a"} for i in ids if i not in skip]})


def write_calls(run_dir, calls):
    """calls: [(system, human, response or None)], numbered from 1."""
    os.makedirs(run_dir, exist_ok=True)
    for n, (system, human, response) in enumerate(calls, 1):
        base = os.path.join(run_dir, f"batch-{n:05d}")
        write(base + ".system.prompt", system)
        write(base + ".human.prompt", human)
        if response is not None:
            write(base + ".response", response)
    return run_dir


def line(level, msg, **attrs):
    quote = lambda v: json.dumps(v) if isinstance(v, str) and (not v or any(c in v for c in ' ="')) else str(v)
    parts = [f"time=2026-11-20T10:00:00.000Z level={level} msg={quote(msg)}"]
    parts += [f"{k.replace('__', '.')}={quote(v) if not isinstance(v, bool) else str(v).lower()}"
              for k, v in attrs.items()]
    return " ".join(parts)


def summary_line(**attrs):
    return line("INFO", "Scoring run finished", **attrs)


def again_line(question, ids):
    return line("WARN", "No readable answer for vulnerabilities; asking again for those alone", question=question,
                unanswered=len(ids), of=len(ids), vulns=",".join(ids))


def unreadable_line(question):
    return line("WARN", "Unreadable reply; the vulnerabilities it leaves without an answer count as left out",
                question=question, error="the reply is not JSON", reply="oops")


def split_line(question, n):
    return line("WARN", "LLM truncated the call; asking each half on its own", question=question, **{"from": n},
                to=(n + 1) // 2)


def scored_line(vid):
    return line("INFO", "Scored vulnerability", vuln=vid, score=SCORE, severity=SEVERITY, vector=VECTOR)


def error_line(message):
    return line("ERROR", "Error", error=message)


def vex(ratings):
    """A VEX: [(vulnId, vector, severity, score)], a None vector for a CVE listed without a rating."""
    vulns = []
    for vid, vector, severity, score in ratings:
        rs = [] if vector is None else [{"method": "OWASP", "vector": vector, "severity": severity, "score": score}]
        vulns.append({"id": vid, "ratings": rs})
    return {"bomFormat": "CycloneDX", "vulnerabilities": vulns}


def attestation(calls, provider, model):
    """An attestation whose evidence matches calls, [(system, human, response)], from provider and model."""
    item = lambda name, value: {"name": name, "contents": {"attachment": {"content": value}}}
    ev = [{"data": [item("provider", provider), item("model", model),
                    item("prompt_hash", hashlib.sha256((s + "\n\n" + h).encode()).hexdigest())]}
          for s, h, _ in calls]
    return {"declarations": {"evidence": ev}}


def answers_doc(rated, unrated=(), counters=None, defects=None):
    """answers.json: rated, [(vulnId, vector)]; unrated, [(vulnId, [factors answered])]."""
    names = VECTOR_FACTORS
    vulns = [{"vulnId": vid, "adjustment": "not_asked",
              "factors": [{"factor": f, "answer": "a", "reading": "answered", "level": int(v.split(":")[1]),
                           "source": "answer"} for f, v in zip(names, vector.split("/"))]} for vid, vector in rated]
    vulns += [{"vulnId": vid, "unrated": True, "adjustment": "not_asked",
               "factors": [{"factor": f, "answer": "a", "reading": "answered"} for f in factors]}
              for vid, factors in unrated]
    return {"vulnerabilities": vulns, "counters": counters or {}, "defects": defects or {}}


VECTOR_FACTORS = ("SL", "M", "O", "S", "ED", "EE", "A", "ID", "LC", "LI", "LAV", "LAC", "FD", "RD", "NC", "PV")


def after_calls(vid, questions=("M", "O")):
    return [(SYSTEM, after_human(f"Question {q}?", [vid]), reply([vid])) for q in questions]


def before_calls(vid, packages=("p1", "p2")):
    """main's calls at batch 1, one per row: here one CVE in two packages."""
    return [(SYSTEM, before_human([(vid, p)]), json.dumps({"results": []})) for p in packages]


def baseline_folder(root, run_id, context, replicate, attempt, *, record, model=MODEL, provider="openai",
                    commit=AFTER_SHA, vid="CVE-2099-0001", calls=None, log=None, provenance=True, vex_file=True,
                    answers=True, arm="after"):
    """A baseline.yml artefact as the workflow with the attempt record would upload it; record holds the
    attempt.json fields past what was dispatched (generate, enrich, archive_check, provenance), None for a
    download made before the record."""
    folder = os.path.join(root, str(run_id), f"baseline-{model}-{context}-r{replicate}-a{attempt}")
    calls = (before_calls(vid) if arm == "before" else after_calls(vid)) if calls is None else calls
    write_calls(os.path.join(folder, "calls", "run-1"), calls)
    write(os.path.join(folder, f"vex-{context}.attestation.cdx.json"), attestation(calls, provider, model))
    if vex_file:
        write(os.path.join(folder, f"vex-{context}.cdx.json"), vex([(vid, VECTOR, SEVERITY, SCORE)]))
    if answers and arm == "after":
        write(os.path.join(folder, "calls", "run-1", "answers.json"), answers_doc([(vid, VECTOR)]))
    dispatched = {"provider": provider, "model": model, "llm_batch_size": 1, "vens_ref": commit,
                  "vens_sha": commit, "run_id": run_id, "run_attempt": attempt}
    if provenance:
        write(os.path.join(folder, "provenance.json"),
              {**dispatched, "archived_scan": "runs/2026-09-23/scan/scan.json", "context": f"contexts/{context}.yaml",
               "replicate": replicate, "calls": "calls/run-*/batch-NNNNN.{system.prompt,human.prompt,response}"})
    if record is not None:
        write(os.path.join(folder, "attempt.json"),
              {"record": 1, "runner": "baseline.yml", "arm": arm, **dispatched, "job": f"{context} · run {replicate}",
               "context": context, "replicate": replicate, **record})
    if log is not None:
        write(os.path.join(folder, f"vens-{context}.log"), "\n".join(log) + "\n")
    return folder


COMPLETE_RECORD = {"generate": {"started_at": "2026-11-20T10:00:00Z", "ended_at": "2026-11-20T10:01:00Z",
                                "exit_status": 0},
                   "enrich": {"started_at": "2026-11-20T10:01:00Z", "ended_at": "2026-11-20T10:01:01Z",
                              "exit_status": 0},
                   "archive_check": "success", "provenance": True}
