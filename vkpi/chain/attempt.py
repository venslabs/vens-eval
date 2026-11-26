"""One attempt's folder, complete or failed: what was run, how it ended and what it left.

Two runners leave such a folder. vens-demo's baseline.yml uploads one artefact per attempt,
baseline-<model>-<context>-r<replicate>-a<attempt>/, with the VEX, the enriched report, provenance.json, the
attestation and calls/, and, once its Score step writes them, attempt.json and vens's log, vens-<context>.log. The
scenario runner (ctx_runner.py) writes attempt.json, vens.log, calls/, the VEX and its attestation for each attempt
of each scenario run, in its campaign's folder (chain/campaign.py).

attempt.json, the attempt record, is written before `vens generate` runs and completed as the steps end:

    {"record": 1, "runner": "baseline.yml" | "scenarios", "arm": "before" | "after",
     "provider", "model", "llm_batch_size", "vens_ref", "vens_sha", "vens_binary_sha256",
     "run_id", "run_attempt", "job", "context", "replicate", "archived_scan", "config",      baseline.yml
     "campaign", "scenario", "report", "config", "replicate", "attempt", "freeze_sha256",    the scenario runner
     "retry_cap", "timeout_seconds", "parallelism", "key_env", "mock_env", "command",
     "record_check": {"passed", "cause"}, "retry_cap_reached", "redacted",
     "setup_error",
     "generate": {"started_at", "ended_at", "exit_status", "timed_out", "interrupted", "log_complete"},
     "enrich": {"started_at", "ended_at", "exit_status"},                                    baseline.yml
     "archive_check": "success" | "failure" | "skipped" | "cancelled",                       baseline.yml
     "provenance": true | false}                                                             baseline.yml

A field not yet written is absent or null. Times are UTC, ISO 8601, on the runner's clock. setup_error says why
`vens generate` never started (baseline.yml: a missing key, a bad batch size; the scenario runner: vens that does not
start); log_complete, whether vens's log, the key cut out of it, was written whole, which baseline.yml's archive check
requires. The scenario runner records a vens it killed with no exit status, interrupted saying why ("timeout", with
timed_out, "the runner was stopped", or the runner's own failure), and retry_cap_reached on a failed attempt that was
the last the retry cap allows. The reader tells four outcomes apart: a scoring that did not complete; a scoring that
completed and a later step that failed (baseline.yml's log capture, vens enrich, archive check or provenance.json; the
scenario runner's record check, record_gaps); a scoring interrupted, its start recorded and no exit status; a
complete attempt. What a folder does not say stays an explicit unknown.
"""
import os
import re

from chain import answers as answersmod
from chain import dispatch
from chain import calls as callmod
from chain import cdx, cost, recovery, venslog
from chain.errors import Refused, load_object

COMPLETE, FAILED = "complete", "failed"
SCORING, LATER_STEP, INTERRUPTED = "scoring", "later_step", "interrupted"
CONTEXTS = ("internet-facing", "internal", "internal-api")
NO_PROVENANCE = "no provenance.json: the job failed before writing it"
STOPPED = ("cancelled", "timed_out", "failure")
CANCELLED = ("cancelled", "timed_out")
STRAY = ("a stray run: GitHub started it after its dispatch was abandoned and its replicate was dispatched again; "
         "its calls count in the spend, its scores are not the replicate's")
# What the record adds to a download made before it.
RECORD = ("generate.started_at", "generate.ended_at", "generate.exit_status", "enrich.started_at",
          "enrich.ended_at", "enrich.exit_status", "archive_check", "vens_binary_sha256")
IDENTITY = ("run_id", "run_attempt", "job", "context", "replicate", "provider", "model", "llm_batch_size",
            "vens_ref", "vens_sha")


def parse_name(name):
    """(model, context, replicate, attempt) of baseline-<model>-<context>-r<n>-a<k>, read from the end since model
    ids hold dashes; None when the name does not parse with a known context."""
    m = re.fullmatch(r"baseline-(.+)-r(\d+)-a(\d+)", name)
    if not m:
        return None
    ctx = [c for c in CONTEXTS if m.group(1).endswith("-" + c) and len(m.group(1)) > len(c) + 1]
    if len(ctx) != 1:
        return None
    return {"model": m.group(1)[:-len(ctx[0]) - 1], "context": ctx[0], "replicate": int(m.group(2)),
            "attempt": int(m.group(3))}


def _record(path):
    """attempt.json, None when there is none; Refused when it does not read or a step in it is no object."""
    if path is None:
        return None
    rj = load_object(path)
    for step in ("generate", "enrich"):
        if rj.get(step) is not None and not isinstance(rj[step], dict):
            raise Refused(f"{path}: {step} is a JSON {type(rj[step]).__name__}, not an object")
    return rj


def check_arm(where, arm, line, rj):
    """Refused when the caller's arm, the dispatch log's and attempt.json's are not one: the log's line, and the
    record the workflow wrote from it, name what was run, and an argument never overrides them."""
    given = {source: value for source, value in (("the argument", arm), ("the dispatch log", (line or {}).get("arm")),
                                                 ("attempt.json", (rj or {}).get("arm"))) if value is not None}
    if len(set(given.values())) > 1:
        raise Refused(f"{where}: arms that disagree, " + ", ".join(f"{v} from {s}" for s, v in given.items()))


def _part(load, path, problems):
    """A file of the attempt read by load, or None, its problem added, when it is cut short or not of its shape: a
    failed job's artefact can hold a file vens was writing when it stopped."""
    if path is None:
        return None
    try:
        return load(path)
    except Refused as e:
        problems.append(str(e))
        return None


def _files(folder):
    names = os.listdir(folder)

    def one(pred, what):
        found = sorted(n for n in names if pred(n))
        if len(found) > 1:
            raise Refused(f"{folder}: {len(found)} {what}")
        return os.path.join(folder, found[0]) if found else None

    calls_dir = os.path.join(folder, "calls")
    run_dirs = callmod.run_folders(calls_dir) if os.path.isdir(calls_dir) else None
    answers = os.path.join(run_dirs[0], "answers.json") if run_dirs and len(run_dirs) == 1 else None
    return {
        "record": one(lambda n: n == "attempt.json", "records"),
        "provenance": one(lambda n: n == "provenance.json", "provenance files"),
        "vex": one(lambda n: n.startswith("vex") and n.endswith(".cdx.json")
                   and not n.endswith(".attestation.cdx.json"), "VEX files"),
        "attestation": one(lambda n: n.endswith(".attestation.cdx.json"), "attestations"),
        "log": one(lambda n: n.startswith("vens") and n.endswith(".log"), "logs"),
        "run_dirs": run_dirs,
        "answers": answers if answers and os.path.exists(answers) else None,
    }


def _pick(*values):
    return next((v for v in values if v is not None), None)


def run_meta(run):
    """What a baseline.yml run was dispatched with, from its run-name in run.json (the API's run object): provider,
    model, batch size, replicates, vens ref, the archived run and the dispatch id, as dispatch metadata, not as an
    attestation."""
    m = re.fullmatch(r"baseline · (.+) · ([^/ ]+)/(.+) · batch (\d+) · x(\d+) · vens (\S+)(?: · dispatch (\S+))?",
                     run.get("display_title") or run.get("name") or "")
    if not m:
        return {"run_id": run.get("id")}
    return {"run_id": run.get("id"), "archived_run": m.group(1), "provider": m.group(2), "model": m.group(3),
            "batch_size": int(m.group(4)), "replicates": int(m.group(5)), "vens_ref": m.group(6),
            "dispatch_id": m.group(7)}


def check_name(folder, name, rj, prov):
    """Refused when the folder's name and its records disagree on the attempt, replicate, context or model."""
    if name is None:
        return
    wanted = {"run_attempt": name["attempt"], "replicate": name["replicate"], "context": name["context"],
              "model": name["model"]}
    for source, doc in (("attempt.json", rj), ("provenance.json", prov)):
        for field, value in wanted.items():
            got = (doc or {}).get(field)
            if field == "context" and got is not None:
                got = os.path.basename(got).replace(".yaml", "")
            if got is not None and got != value:
                raise Refused(f"{folder}: the name gives {field} {value}, {source} {got}")


def _what(rj, prov, name, line, arm, meta=None):
    rj, prov, name, line, meta = rj or {}, prov or {}, name or {}, line or {}, meta or {}
    context = _pick(rj.get("context"), name.get("context"),
                    os.path.basename(prov["context"]).replace(".yaml", "") if prov.get("context") else None)
    in_run = _pick(name.get("replicate"), prov.get("replicate"), rj.get("replicate"))
    runner = _pick(rj.get("runner"), "baseline.yml" if name or prov else None)
    job = _pick(rj.get("job"), f"{context} · run {in_run}" if runner == "baseline.yml" and in_run else None)
    return {
        "runner": runner,
        "arm": _pick(line.get("arm"), rj.get("arm"), arm),
        "corpus": _pick(rj.get("archived_scan"), rj.get("report"), prov.get("archived_scan")),
        "config": _pick(rj.get("config"), prov.get("context")),
        "context": context,
        "scenario": rj.get("scenario"),
        "vens_ref": _pick(rj.get("vens_ref"), prov.get("vens_ref"), line.get("vens_ref"), meta.get("vens_ref")),
        "vens_commit": _pick(rj.get("vens_sha"), prov.get("vens_sha")),
        "vens_binary_sha256": rj.get("vens_binary_sha256"),
        "provider": _pick(rj.get("provider"), prov.get("provider"), line.get("provider"), meta.get("provider")),
        "model": _pick(rj.get("model"), prov.get("model"), line.get("model"), meta.get("model"), name.get("model")),
        "batch_size": _pick(rj.get("llm_batch_size"), prov.get("llm_batch_size"), line.get("batch_size"),
                            meta.get("batch_size")),
        "replicate": _pick(line.get("replicate"), rj.get("replicate"), prov.get("replicate"), name.get("replicate")),
        "replicate_in_run": in_run,
        "run_id": _pick(rj.get("run_id"), prov.get("run_id"), line.get("run_id"), meta.get("run_id")),
        "run_attempt": _pick(rj.get("run_attempt"), prov.get("run_attempt"), name.get("attempt"), rj.get("attempt")),
        "job": job,
        "campaign": rj.get("campaign"),
        "key_env": rj.get("key_env"),
        "retry_cap": rj.get("retry_cap"),
        "timeout_seconds": rj.get("timeout_seconds"),
        "parallelism": rj.get("parallelism"),
    }


def _failure(kind, step, cause, source):
    return {"kind": kind, "step": step, "cause": cause, "cause_source": source if cause else None}


def _job_cause(job, step):
    """A step left without its exit status: (cause, source, problem). A job that stopped gives the cause; a job that
    succeeded contradicts the record."""
    conclusion = (job or {}).get("conclusion")
    if conclusion in STOPPED:
        return f"job {conclusion}", "jobs.json", None
    if conclusion is None:
        return None, None, None
    return None, None, f"job {conclusion}, yet attempt.json gives {step} no exit status"


def _record_fields(rj):
    gen, enrich = rj.get("generate") or {}, rj.get("enrich") or {}
    fields = {"generate.started_at": gen.get("started_at"), "generate.ended_at": gen.get("ended_at"),
              "generate.exit_status": gen.get("exit_status"), "vens_binary_sha256": rj.get("vens_binary_sha256")}
    if rj.get("runner") == "baseline.yml":
        fields.update({"enrich.started_at": enrich.get("started_at"), "enrich.ended_at": enrich.get("ended_at"),
                       "enrich.exit_status": enrich.get("exit_status"), "archive_check": rj.get("archive_check")})
        if "log_complete" in gen:
            fields["generate.log_complete"] = gen["log_complete"]
    return fields


def _stopped(job):
    """The job's cancel or timeout from jobs.json, which names the cause even of a command that exited non-zero:
    the cancel can be what made it exit."""
    conclusion = (job or {}).get("conclusion")
    return conclusion if conclusion in CANCELLED else None


def _stopped_failure(kind, step, conclusion, detail):
    return {**_failure(kind, step, f"job {conclusion}", "jobs.json"), "detail": detail}


def _excluded(line):
    return STRAY if (line or {}).get("action") == dispatch.STRAY else None


def _from_record(rj, provenance_present, job):
    """(outcome, failure, steps, unknown, problems) from attempt.json: the first step that did not end with 0."""
    gen, enrich = rj.get("generate") or {}, rj.get("enrich") or {}
    baseline = rj.get("runner") == "baseline.yml"
    steps = {"generate": gen, "enrich": enrich or None, "archive_check": rj.get("archive_check"),
             "provenance": provenance_present}
    if "record_check" in rj:
        steps["record_check"] = rj["record_check"]
    unknown = [f for f, v in _record_fields(rj).items() if v is None]
    problems = [f"attempt.json lacks {f}" for f in IDENTITY if baseline and rj.get(f) is None]
    if gen.get("exit_status") is None:
        # a launch that failed says so whatever start it recorded
        if gen.get("started_at") is None or rj.get("setup_error"):
            cause = rj.get("setup_error")
            return FAILED, _failure(None, None, cause, "attempt.json"), steps, unknown + ["failure.kind"], problems + (
                [] if cause else ["attempt.json records neither the start nor the exit status of vens generate"])
        if gen.get("timed_out") or gen.get("interrupted"):
            return FAILED, _failure(INTERRUPTED, "generate", gen.get("interrupted") or "timeout", "attempt.json"), \
                steps, unknown, problems
        cause, source, problem = _job_cause(job, "vens generate")
        if problem:
            return FAILED, _failure(None, "generate", None, None), steps, unknown + ["failure.kind"], problems + [
                problem]
        return FAILED, _failure(INTERRUPTED, "generate", cause, source), steps, unknown, problems
    if gen["exit_status"] != 0:
        stopped = _stopped(job)
        if stopped:
            return FAILED, _stopped_failure(INTERRUPTED, "generate", stopped,
                                            f"vens generate exited {gen['exit_status']}"), steps, unknown, problems
        return FAILED, _failure(SCORING, "generate", None, None), steps, unknown, problems
    if not baseline:
        outcome, failure, found = _record_check(rj)
        return outcome, failure, steps, unknown + (["failure.cause"] if found else []), problems + found
    outcome, failure, found = _later_steps(rj, gen, enrich, provenance_present, job)
    return outcome, failure, steps, unknown, problems + found


def _record_check(rj):
    """(outcome, failure, problems) of the scenario runner's step after a scoring that completed: its check that the
    attempt left a complete record (record_gaps). Records written without that step are complete at exit 0."""
    if "record_check" not in rj:
        return COMPLETE, None, []
    check = rj["record_check"]
    if check is None:
        return FAILED, _failure(LATER_STEP, "record_check", None, None), [
            "attempt.json gives the record check no result: the runner stopped before it"]
    if check.get("passed") is not True:
        return FAILED, _failure(LATER_STEP, "record_check", check.get("cause"), "attempt.json"), []
    return COMPLETE, None, []


def _readable(load, path, what, gaps):
    if path is None:
        gaps.append(f"no {what}")
        return None
    try:
        return load(path)
    except Refused:
        gaps.append(f"{what} that does not read")
        return None


def record_gaps(folder, arm, provider, model):
    """What an attempt whose `vens generate` exited 0 left short of a complete record: the VEX, the attestation and,
    for the after, answers.json, each there and readable, and the archive check restated on its calls: one run
    folder, every call with its reply, the prompt hashes and the model attested. [] for a complete record."""
    files, gaps = _files(folder), []
    _readable(cdx.ratings, files["vex"], "VEX", gaps)
    evidence = _readable(cdx.evidence, files["attestation"], "attestation", gaps)
    if arm == "after":
        _readable(answersmod.load, files["answers"], "answers.json", gaps)
    run_dirs = files["run_dirs"] or []
    if len(run_dirs) != 1:
        gaps.append(f"{len(run_dirs)} run folders under calls/")
    elif evidence is not None:
        try:
            passed, reason = callmod.archive_check(run_dirs, callmod.load(run_dirs[0]), evidence, provider, model)
        except Refused as e:
            passed, reason = False, str(e)
        if not passed:
            gaps.append(f"the archive check: {reason}")
    return gaps


def _later_steps(rj, gen, enrich, provenance_present, job):
    """(outcome, failure, problems) of baseline.yml's steps after a scoring that completed, the first that did not
    end well: the log capture, vens enrich, the archive check, provenance.json."""
    def unended(step, what):
        cause, source, problem = _job_cause(job, what)
        return FAILED, _failure(LATER_STEP, step, cause, source), [problem] if problem else []

    if "log_complete" in gen and gen["log_complete"] is None:
        return unended("log_capture", "the log capture")
    if "log_complete" in gen and gen["log_complete"] is not True:
        return FAILED, _failure(LATER_STEP, "log_capture", "vens's log was not captured whole", "attempt.json"), []
    if enrich.get("exit_status") is None:
        return unended("enrich", "vens enrich")
    if enrich["exit_status"] != 0:
        stopped, detail = _stopped(job), f"vens enrich exited {enrich['exit_status']}"
        return FAILED, (_stopped_failure(LATER_STEP, "enrich", stopped, detail) if stopped else
                        _failure(LATER_STEP, "enrich", detail, "attempt.json")), []
    check = rj.get("archive_check")
    if check is None:
        return unended("archive_check", "the archive check")
    if check != "success":
        return FAILED, _failure(LATER_STEP, "archive_check", f"archive check {check}", "attempt.json"), []
    if not (rj.get("provenance") and provenance_present):
        return FAILED, _failure(LATER_STEP, "provenance", "provenance.json not written", "attempt.json"), []
    return COMPLETE, None, []


def _without_record(folder, files, failure_line, job):
    """(outcome, failure, steps, implied, unknown, problems) for a download made before the record: provenance.json,
    written last, means every step passed (baseline.yml's order under set -euo pipefail); without it the attempt failed
    at a step the download does not name. The artefact is uploaded whatever the job's end, the VEX in it, so a VEX
    without provenance.json is a job that failed after scoring wrote it, or a truncated download of one that passed:
    its job's conclusion tells them apart, and a job that succeeded or is not listed is refused."""
    if files["provenance"] is not None:
        steps = {"generate": {"exit_status": 0}, "enrich": {"exit_status": 0}, "archive_check": "success",
                 "provenance": True}
        implied = ["generate.exit_status", "enrich.exit_status", "archive_check"]
        return COMPLETE, None, steps, implied, [f for f in RECORD if f not in implied], []
    problems = []
    if files["vex"] is not None:
        conclusion = (job or {}).get("conclusion")
        if conclusion in (None, "success"):
            raise Refused(f"{folder}: a VEX but no provenance.json and no attempt.json, its job "
                          f"{conclusion or 'not listed'}; a truncated download is not a failed job")
        problems = [f"a VEX but no provenance.json, the job ended {conclusion}: read as a failed attempt at a step the "
                    f"download does not name"]
    error = (failure_line or {}).get("error")
    failure = {**_failure(None, None, error, "failures.txt"), "reason": NO_PROVENANCE}
    steps = {"generate": None, "enrich": None, "archive_check": None, "provenance": False}
    unknown = list(RECORD) + ["failure.kind", "failure.step"] + ([] if error else ["failure.cause"])
    return FAILED, failure, steps, [], unknown, problems


def _cross_check(outcome, failure, summary, gen_exit):
    """The run summary against the exit status: a run vens says failed is a failed scoring whatever its exit."""
    if summary is None:
        return outcome, failure, []
    said = summary.get("failed")
    scored = outcome == COMPLETE or (failure or {}).get("kind") == LATER_STEP
    if said is True and scored:
        return FAILED, _failure(SCORING, "generate", None, None), [
            f"vens generate exited {gen_exit if gen_exit is not None else 0}, yet its run summary says failed=true"]
    if said is False and (failure or {}).get("kind") == SCORING:
        return outcome, failure, [f"vens generate exited {gen_exit}, yet its run summary says failed=false"]
    return outcome, failure, []


def _run_failed(summary, outcome, failure):
    """Whether `vens generate` itself failed, None when nothing says: a later step's failure leaves a run that
    completed, whose summary's counters hold."""
    if summary is not None:
        return summary.get("failed")
    if outcome == COMPLETE or failure["kind"] == LATER_STEP:
        return False
    return True if failure["kind"] in (SCORING, INTERRUPTED) else None


def check_files(folder, files, rj, job):
    """Refused when a job that succeeded, or a record that says provenance.json was written, left a download without
    the files such a job uploads: a truncated download is not a failed job."""
    lacking = [n for n, f in (("provenance.json", files["provenance"]), ("VEX", files["vex"])) if f is None]
    if (job or {}).get("conclusion") == "success" and lacking:
        raise Refused(f"{folder}: its job succeeded, yet the download holds no {' and no '.join(lacking)}; a "
                      f"truncated download is not a failed job")
    if (rj or {}).get("provenance") and files["provenance"] is None:
        raise Refused(f"{folder}: attempt.json says provenance.json was written, yet the download holds none; a "
                      f"truncated download is not a failed job")


def check_commits(folder, rj, prov, arm, commits):
    """Refused when attempt.json and provenance.json give two vens commits, or one other than the arm's expected
    commit."""
    given = {src: doc["vens_sha"] for src, doc in (("attempt.json", rj), ("provenance.json", prov))
             if doc and doc.get("vens_sha")}
    if len(set(given.values())) > 1:
        raise Refused(f"{folder}: attempt.json gives vens {given['attempt.json']}, provenance.json "
                      f"{given['provenance.json']}")
    for src, sha in given.items():
        if commits and arm in commits and sha != commits[arm]:
            raise Refused(f"{folder}: {src} gives vens {sha}, not the {arm}'s {commits[arm]}")


def read_attempt(folder, *, arm=None, line=None, job=None, failure_line=None, meta=None, commits=None):
    """The record of one attempt. arm: 'before' or 'after' when the caller knows it (the dispatch log's line gives
    it otherwise); line: the dispatch log's line for this attempt; job: its jobs.json entry; failure_line: the
    failures.txt entry for its job (downloads made before the record); meta: its run's dispatch metadata
    (run_meta), the last source of what was dispatched; commits: {arm: vens commit}, each arm's expected commit.

    scores_usable is true only for a complete attempt whose arm is known, whose VEX reads with each CVE listed and
    rated once (vex_problems empty), whose archive check passes restated from its calls and attestation, whose record
    is not incomplete (the after with its answers.json), and whose answers.json, for the after, matches its VEX with
    no CVE listed twice (answers' problems empty). The other problems are reported beside the scores and leave them
    usable: logs, summaries, counters or defects that disagree, calls out of vens's order, a missing summary. A VEX,
    an attestation or an answers.json that does not read is a problem of the attempt, its content unknown. Arms
    that disagree, commits that disagree and a record or provenance.json that does not read are refused. excluded
    says why an attempt that read is not its replicate's, a stray run of an abandoned dispatch: its calls and cost
    are still the campaign's."""
    files = _files(folder)
    rj = _record(files["record"])
    prov = load_object(files["provenance"]) if files["provenance"] else None
    name = parse_name(os.path.basename(os.path.normpath(folder)))
    if rj is None and prov is None and name is None:
        raise Refused(f"{folder}: no attempt.json, no provenance.json and not an artefact's name")
    check_name(folder, name, rj, prov)
    check_files(folder, files, rj, job)
    check_arm(folder, arm, line, rj)
    what = _what(rj, prov, name, line, arm, meta)
    problems = []
    check_commits(folder, rj, prov, what["arm"], commits)
    if rj is not None:
        outcome, failure, steps, unknown, found = _from_record(rj, files["provenance"] is not None, job)
        implied = []
        problems += found
    else:
        outcome, failure, steps, implied, unknown, found = _without_record(folder, files, failure_line, job)
        problems += found
    if what["vens_commit"] is None:
        unknown.append("vens_commit")

    recs = venslog.read(files["log"]) if files["log"] else None
    if recs is None:
        unknown += ["log", "summary"]
    summary = venslog.summary(recs) if recs is not None else None
    gen_exit = ((rj or {}).get("generate") or {}).get("exit_status")
    outcome, failure, found = _cross_check(outcome, failure, summary, gen_exit)
    problems += found
    if failure is not None and failure["kind"] == SCORING and recs is not None:
        failure = {**failure, "cause": venslog.cause(recs), "cause_source": "vens log"}
    if failure is not None and failure["cause"] is None:
        unknown.append("failure.cause")

    run_dirs = files["run_dirs"]
    archived = _part(callmod.load, run_dirs[0], problems) if run_dirs and len(run_dirs) == 1 else None
    if archived is None:
        unknown.append("calls")
    kinds, why = callmod.classify(archived, what["arm"]) if archived is not None else (None, None)
    if why:
        problems.append(why)
    rec = recovery.breakdown(summary, recs, archived, kinds, _run_failed(summary, outcome, failure))
    problems += rec.pop("problems")
    estimate = cost.estimate(archived, kinds, what["model"])

    evidence = _part(cdx.evidence, files["attestation"], problems)
    attested = [[e.get("provider"), e.get("model")] for e in evidence] if evidence is not None else None
    if attested is None:
        unknown.append("models_attested")
    if evidence is not None and archived is not None:
        check = callmod.archive_check(run_dirs, archived, evidence, what["provider"], what["model"])
    elif files["attestation"] is not None and evidence is None:
        check = (None, "the attestation does not read")
    else:
        check = (None, "no attestation or no archived calls")
    unread = []
    ratings, vex_problems = _part(cdx.ratings, files["vex"], unread) or (None, [])
    vex_problems = unread + vex_problems

    doc = _part(answersmod.load, files["answers"], problems)
    answers = None
    if doc is not None:
        rated, unrated = answersmod.entries(doc)
        found = (answersmod.duplicates(doc) + answersmod.unrated_shape(doc)
                 + (answersmod.check(doc, ratings) if ratings is not None else []))
        answers = {"rated": len(rated), "unrated": len(unrated), "counters": doc["counters"],
                   "defects": doc["defects"], "problems": found,
                   "per_cve": {vid: answersmod.per_cve(e) for vid, e in {**rated, **unrated}.items()}}
        if summary is not None and (summary["counters"], summary["defects"]) != (doc["counters"], doc["defects"]):
            problems.append("answers.json's counters or defects differ from the run summary's")

    incomplete = [] if what["arm"] in ("before", "after") else ["arm unknown"]
    if outcome == COMPLETE and what["arm"] == "after" and doc is None:
        incomplete.append("a complete run's VEX without its answers.json" if files["answers"] is None else
                          "a complete run's answers.json that does not read")
    if outcome == COMPLETE and ratings is None:
        incomplete.append("a complete attempt without a VEX" if files["vex"] is None else
                          "a complete attempt whose VEX does not read")
    if outcome == COMPLETE and recs is not None and summary is None:
        problems.append("the log holds no run summary")
    excluded = _excluded(line)
    usable = (outcome == COMPLETE and ratings is not None and not vex_problems and check[0] is True
              and not incomplete and not (answers or {}).get("problems") and excluded is None)
    if outcome == COMPLETE and check[0] is not True:
        problems.append(f"archive check, restated: {check[1]}")
    return {
        "folder": folder, "record": "attempt.json" if rj is not None else None, "what": what,
        "models_attested": attested, "outcome": outcome, "failure": failure, "steps": steps,
        "implied": implied, "unknown": sorted(set(unknown)), "job": job, "summary": summary,
        "calls": {"archived": None if archived is None else len(archived),
                  "with_reply": None if archived is None else sum(1 for c in archived if c.response is not None),
                  "kinds": kinds},
        "recovery": rec, "cost_estimate": estimate, "archive_check": {"passed": check[0], "reason": check[1]},
        "answers": answers, "ratings": ratings, "vex_problems": vex_problems, "scores_usable": usable,
        "excluded": excluded, "incomplete": incomplete, "problems": problems,
        "retry_cap_reached": (rj or {}).get("retry_cap_reached"),
    }


def without_artefact(job, model, run_id, line=None, arm=None):
    """An attempt jobs.json lists, its job not successful, with no artefact downloaded: a failed attempt of which
    only the job is known. With no record of a scoring start, its kind stays unknown, the job's conclusion its cause.
    Its arm is the dispatch log's line's, else the caller's; refused when the two disagree."""
    check_arm(f"run {run_id} job {job.get('id')}", arm, line, None)
    m = re.fullmatch(r"(.+) · run (\d+)", job["name"])
    what = {"runner": "baseline.yml", "context": m.group(1) if m else None,
            "replicate_in_run": int(m.group(2)) if m else None, "model": model, "run_id": run_id,
            "run_attempt": job.get("run_attempt"), "job": job["name"], "arm": _pick((line or {}).get("arm"), arm),
            "replicate": (line or {}).get("replicate")}
    unknown = list(RECORD) + ["artefact", "calls", "log", "summary", "vens_commit", "models_attested", "failure.kind",
                              "failure.step"]
    return {"folder": None, "record": None, "what": what, "models_attested": None, "outcome": FAILED,
            "failure": _failure(None, None, f"job {job.get('conclusion')}", "jobs.json"),
            "steps": {"generate": None, "enrich": None, "archive_check": None, "provenance": None}, "implied": [],
            "unknown": sorted(unknown), "job": job, "summary": None,
            "calls": {"archived": None, "with_reply": None, "kinds": None}, "recovery": None, "cost_estimate": None,
            "archive_check": {"passed": None, "reason": "no artefact"}, "answers": None, "ratings": None,
            "vex_problems": [], "scores_usable": False, "excluded": _excluded(line),
            "incomplete": [] if what["arm"] else ["arm unknown"], "problems": ["artefact missing"],
            "retry_cap_reached": None}


def not_downloaded(line, why, arm=None, reason="not downloaded"):
    """A run attempt the dispatch log names, or jobs.json lists, with no artefact folder and no job scoring a
    context, or one a pending line asked for: flagged, its outcome unknown. line: its line of the log, or what the
    download says of it. Refused when the caller's arm is not the line's."""
    check_arm(why, arm, line, None)
    what = {"runner": "baseline.yml", "arm": _pick(line.get("arm"), arm), "model": line.get("model"),
            "replicate": line.get("replicate"), "run_id": line.get("run_id"), "run_attempt": line.get("run_attempt"),
            "vens_commit": line.get("vens_commit")}
    return {"folder": None, "record": None, "what": what, "models_attested": None, "outcome": None, "failure": None,
            "steps": None, "implied": [], "unknown": ["outcome"] + list(RECORD), "job": None, "summary": None,
            "calls": {"archived": None, "with_reply": None, "kinds": None}, "recovery": None, "cost_estimate": None,
            "archive_check": {"passed": None, "reason": reason}, "answers": None, "ratings": None,
            "vex_problems": [], "scores_usable": False, "excluded": _excluded(line), "incomplete": [],
            "problems": [why], "retry_cap_reached": None}
