"""The attempt record: its four outcomes told apart, and a download made before the record
read with its added fields unknown, none inferred."""
import json
import os
import re
import tempfile
import unittest

from chain import attempt, dispatch
from tests import support as s

B = "CVE-2099-0002"

A = "CVE-2099-0001"
COUNTS = ("planned", "again_omission", "again_unreadable", "split_halves", "recovery_calls")
GEN_OK = {"started_at": "2026-11-20T10:00:00Z", "ended_at": "2026-11-20T10:01:00Z", "exit_status": 0}
CAUSE = f"failed to generate risk scores: model returned no answer to Motive (M) for {A} after asking again; " \
        f"stopping the run"


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name

    def folder(self, record, **kw):
        return self.folder_at(1001, record, **kw)

    def folder_at(self, run_id, record, **kw):
        kw.setdefault("log", [s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=0, splits=0, calls__M=1,
                                             calls__O=1, failed=False)])
        return s.baseline_folder(self.root, run_id, "internal", 1, 1, record=record, **kw)


class TestOutcomes(Base):
    def test_a_complete_attempt(self):
        rec = attempt.read_attempt(self.folder(s.COMPLETE_RECORD))
        self.assertEqual((rec["outcome"], rec["failure"], rec["scores_usable"]), ("complete", None, True))
        self.assertEqual(rec["record"], "attempt.json")
        self.assertEqual(rec["what"]["arm"], "after")
        self.assertEqual(rec["archive_check"], {"passed": True, "reason": ""})
        self.assertEqual(rec["ratings"][A]["vector"], s.VECTOR)
        self.assertEqual(rec["problems"], [])
        self.assertEqual(rec["models_attested"], [["openai", s.MODEL], ["openai", s.MODEL]])

    def test_exit_0_with_a_summary_that_says_failed(self):
        log = [s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=0, splits=0, calls__M=1, calls__O=1,
                              failed=True), s.error_line(CAUSE)]
        rec = attempt.read_attempt(self.folder(s.COMPLETE_RECORD, log=log))
        self.assertEqual(rec["outcome"], "failed")
        self.assertEqual(rec["failure"], {"kind": "scoring", "step": "generate", "cause": CAUSE,
                                          "cause_source": "vens log"})
        self.assertIn("vens generate exited 0, yet its run summary says failed=true", rec["problems"])
        self.assertFalse(rec["scores_usable"])

    def test_no_start_and_no_exit_is_not_interrupted(self):
        rec = attempt.read_attempt(self.folder({"generate": {}}, log=[], vex_file=False, provenance=False,
                                               answers=False))
        self.assertEqual((rec["outcome"], rec["failure"]["kind"]), ("failed", None))
        self.assertIn("failure.kind", rec["unknown"])
        self.assertIn("attempt.json records neither the start nor the exit status of vens generate", rec["problems"])

    def test_a_stop_before_vens_generate_with_its_cause(self):
        cause = "secret OPENAI_API_KEY_AFTER is not set: each arm runs on its own key"
        rec = attempt.read_attempt(self.folder({"setup_error": cause, "generate": {}}, log=None, calls=[],
                                               vex_file=False, provenance=False, answers=False))
        self.assertEqual((rec["outcome"], rec["failure"]), ("failed", {"kind": None, "step": None, "cause": cause,
                                                                      "cause_source": "attempt.json"}))
        self.assertNotIn("failure.cause", rec["unknown"])
        self.assertEqual([p for p in rec["problems"] if "neither the start" in p], [])

    def test_a_cancel_names_the_cause_of_a_command_that_exited_non_zero(self):
        for conclusion in ("cancelled", "timed_out"):
            job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": conclusion}
            gen = attempt.read_attempt(self.folder({"generate": {**GEN_OK, "exit_status": 130}}, log=[s.error_line(
                "context canceled")], vex_file=False, provenance=False, answers=False), job=job)
            self.assertEqual(gen["failure"], {"kind": "interrupted", "step": "generate", "cause": f"job {conclusion}",
                                              "cause_source": "jobs.json", "detail": "vens generate exited 130"})
            enrich = attempt.read_attempt(self.folder({**s.COMPLETE_RECORD, "enrich": {
                **s.COMPLETE_RECORD["enrich"], "exit_status": 1}, "archive_check": "skipped", "provenance": False},
                provenance=False), job=job)
            self.assertEqual(enrich["failure"], {"kind": "later_step", "step": "enrich", "cause": f"job {conclusion}",
                                                 "cause_source": "jobs.json", "detail": "vens enrich exited 1"})
        failed = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "failure"}
        rec = attempt.read_attempt(self.folder({"generate": {**GEN_OK, "exit_status": 1}}, log=[s.error_line(CAUSE)],
                                               vex_file=False, provenance=False, answers=False), job=failed)
        self.assertEqual(rec["failure"], {"kind": "scoring", "step": "generate", "cause": CAUSE,
                                          "cause_source": "vens log"})

    def test_the_log_capture_after_a_scoring_that_completed(self):
        cancelled = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "cancelled"}
        held = attempt.read_attempt(self.folder({"generate": {**GEN_OK, "log_complete": None}}, provenance=False),
                                    job=cancelled)
        self.assertEqual((held["failure"], held["steps"]["generate"]["exit_status"]), ({
            "kind": "later_step", "step": "log_capture", "cause": "job cancelled", "cause_source": "jobs.json"}, 0))
        self.assertIn("generate.log_complete", held["unknown"])
        cut = attempt.read_attempt(self.folder({**s.COMPLETE_RECORD, "generate": {**GEN_OK, "log_complete": False},
                                                "archive_check": "failure", "provenance": False}, provenance=False))
        self.assertEqual(cut["failure"], {"kind": "later_step", "step": "log_capture",
                                          "cause": "vens's log was not captured whole", "cause_source": "attempt.json"})
        whole = attempt.read_attempt(self.folder({**s.COMPLETE_RECORD, "generate": {**GEN_OK, "log_complete": True}}))
        self.assertEqual((whole["outcome"], whole["scores_usable"]), ("complete", True))

    def test_a_job_that_succeeded_without_an_exit_status(self):
        job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "success"}
        rec = attempt.read_attempt(self.folder({"generate": {"started_at": "2026-11-20T10:00:00Z"}}, log=[]), job=job)
        self.assertEqual((rec["failure"]["kind"], rec["failure"]["cause"]), (None, None))
        self.assertIn("job success, yet attempt.json gives vens generate no exit status", rec["problems"])

    def test_a_job_that_succeeded_with_its_files_missing_is_refused(self):
        job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "success"}
        folder = self.folder(s.COMPLETE_RECORD, vex_file=False, provenance=False, answers=False)
        with self.assertRaisesRegex(attempt.Refused, "its job succeeded, yet the download holds no provenance.json "
                                                     "and no VEX; a truncated download is not a failed job"):
            attempt.read_attempt(folder, job=job)

    def test_a_record_that_says_provenance_without_the_file_is_refused(self):
        folder = self.folder(s.COMPLETE_RECORD, provenance=False)
        with self.assertRaisesRegex(attempt.Refused, "attempt.json says provenance.json was written, yet the download "
                                                     "holds none"):
            attempt.read_attempt(folder)

    def test_commits_that_contradict_each_other_or_the_arm(self):
        folder = self.folder(s.COMPLETE_RECORD)
        prov = os.path.join(folder, "provenance.json")
        with open(prov) as fh:
            doc = json.load(fh)
        s.write(prov, {**doc, "vens_sha": s.BEFORE_SHA})
        with self.assertRaisesRegex(attempt.Refused, "attempt.json gives vens .*, provenance.json"):
            attempt.read_attempt(folder)
        other = self.folder_at(1002, s.COMPLETE_RECORD, commit=s.BEFORE_SHA)
        with self.assertRaisesRegex(attempt.Refused, "attempt.json gives vens .*, not the after's"):
            attempt.read_attempt(other, commits={"before": s.BEFORE_SHA, "after": s.AFTER_SHA})

    def test_an_unknown_arm_is_incomplete(self):
        folder = self.folder({**s.COMPLETE_RECORD, "arm": None})
        rec = attempt.read_attempt(folder)
        self.assertEqual((rec["outcome"], rec["incomplete"], rec["scores_usable"]),
                         ("complete", ["arm unknown"], False))

    def test_a_complete_attempt_whose_log_has_no_summary(self):
        rec = attempt.read_attempt(self.folder(s.COMPLETE_RECORD, log=[s.line("INFO", "Config loaded")]))
        self.assertIn("the log holds no run summary", rec["problems"])
        self.assertTrue(rec["scores_usable"])

    def test_the_commit_of_another_arm_is_refused(self):
        folder = self.folder({**s.COMPLETE_RECORD, "arm": None})
        commits = {"before": s.BEFORE_SHA, "after": s.AFTER_SHA}
        self.assertTrue(attempt.read_attempt(folder, arm="after", commits=commits)["scores_usable"])
        with self.assertRaisesRegex(attempt.Refused, "not the before's"):
            attempt.read_attempt(folder, arm="before", commits=commits)

    def test_a_name_its_record_contradicts_is_refused(self):
        folder = self.folder({**s.COMPLETE_RECORD, "run_attempt": 2})
        with self.assertRaisesRegex(attempt.Refused, "the name gives run_attempt 1, attempt.json 2"):
            attempt.read_attempt(folder)

    def test_a_cve_twice_in_the_vex(self):
        folder = self.folder(s.COMPLETE_RECORD)
        s.write(os.path.join(folder, "vex-internal.cdx.json"),
                s.vex([(A, s.VECTOR, s.SEVERITY, s.SCORE), (A, s.VECTOR, s.SEVERITY, s.SCORE)]))
        rec = attempt.read_attempt(folder)
        self.assertIn(f"{A}: listed 2 times in the VEX", rec["vex_problems"])
        self.assertFalse(rec["scores_usable"])

    def test_a_cve_twice_in_answers_json(self):
        folder = self.folder(s.COMPLETE_RECORD)
        path = os.path.join(folder, "calls", "run-1", "answers.json")
        for doc in (s.answers_doc([(A, s.VECTOR), (A, s.VECTOR)]), s.answers_doc([(A, s.VECTOR)], [(A, ["M"])])):
            s.write(path, doc)
            rec = attempt.read_attempt(folder)
            self.assertIn(f"{A}: listed 2 times in answers.json", rec["answers"]["problems"])
            self.assertFalse(rec["scores_usable"])

    def test_answers_json_off_its_vector(self):
        folder = self.folder(s.COMPLETE_RECORD)
        s.write(os.path.join(folder, "calls", "run-1", "answers.json"),
                s.answers_doc([(A, s.VECTOR.replace("EE:5", "EE:3"))]))
        rec = attempt.read_attempt(folder)
        self.assertEqual(rec["answers"]["problems"], [f"{A}: answers.json's levels differ from the vector's"])
        self.assertEqual((rec["outcome"], rec["scores_usable"]), ("complete", False))

    def test_a_scoring_that_fails(self):
        log = [s.again_line("M", [A]), s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=1, splits=0,
                                                      calls__M=2, failed=True), s.error_line(CAUSE)]
        calls = [(s.SYSTEM, s.after_human("Q M?", [A]), s.reply([A], skip=[A]))] * 2
        record = {"generate": {**GEN_OK, "exit_status": 1}}
        rec = attempt.read_attempt(self.folder(record, log=log, calls=calls, vex_file=False, provenance=False,
                                               answers=False), arm="after")
        self.assertEqual(rec["outcome"], "failed")
        self.assertEqual(rec["failure"], {"kind": "scoring", "step": "generate", "cause": CAUSE,
                                          "cause_source": "vens log"})
        self.assertEqual((rec["summary"]["failed"], rec["recovery"]["recovery_calls"]), (True, 1))
        self.assertEqual(rec["calls"]["kinds"], ["planned", "again_omission"])
        self.assertFalse(rec["scores_usable"])

    def test_a_scoring_that_completes_and_an_enrichment_that_fails(self):
        record = {**s.COMPLETE_RECORD, "enrich": {"exit_status": 1}, "archive_check": "skipped", "provenance": False}
        rec = attempt.read_attempt(self.folder(record, provenance=False), arm="after")
        self.assertEqual(rec["outcome"], "failed")
        self.assertEqual(rec["failure"], {"kind": "later_step", "step": "enrich", "cause": "vens enrich exited 1",
                                          "cause_source": "attempt.json"})
        self.assertEqual((rec["calls"]["archived"], rec["recovery"]["planned"]), (2, 2))
        self.assertIsNotNone(rec["ratings"])
        self.assertFalse(rec["scores_usable"])

    def test_a_scoring_that_completes_and_an_archive_check_that_fails(self):
        record = {**s.COMPLETE_RECORD, "archive_check": "failure", "provenance": False}
        rec = attempt.read_attempt(self.folder(record, provenance=False), arm="after")
        self.assertEqual(rec["failure"], {"kind": "later_step", "step": "archive_check",
                                          "cause": "archive check failure", "cause_source": "attempt.json"})
        self.assertEqual(rec["calls"]["archived"], 2)
        self.assertFalse(rec["scores_usable"])

    def test_an_interrupted_scoring_cancelled(self):
        record = {"generate": {"started_at": "2026-11-20T10:00:00Z"}}
        job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "cancelled"}
        rec = attempt.read_attempt(self.folder(record, log=[], vex_file=False, provenance=False, answers=False),
                                   job=job, arm="after")
        self.assertEqual(rec["failure"], {"kind": "interrupted", "step": "generate", "cause": "job cancelled",
                                          "cause_source": "jobs.json"})
        self.assertIn("generate.exit_status", rec["unknown"])
        self.assertNotIn("generate.started_at", rec["unknown"])
        self.assertEqual(rec["calls"]["archived"], 2)

    def test_an_interrupted_scoring_timed_out_with_no_calls_uploaded(self):
        folder = self.folder({"generate": {"started_at": "2026-11-20T10:00:00Z"}}, log=[], vex_file=False,
                             provenance=False, answers=False)
        for name in os.listdir(os.path.join(folder, "calls", "run-1")):
            os.remove(os.path.join(folder, "calls", "run-1", name))
        os.rmdir(os.path.join(folder, "calls", "run-1"))
        os.rmdir(os.path.join(folder, "calls"))
        job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "timed_out"}
        rec = attempt.read_attempt(folder, job=job, arm="after")
        self.assertEqual(rec["failure"]["cause"], "job timed_out")
        self.assertIn("calls", rec["unknown"])
        self.assertIsNone(rec["calls"]["archived"])

    def test_a_scenario_run_timed_out(self):
        folder = os.path.join(self.root, "scenario")
        s.write(os.path.join(folder, "attempt.json"), {"record": 1, "runner": "scenarios", "arm": "after",
                                                       "generate": {"started_at": "2026-11-20T10:00:00Z",
                                                                    "ended_at": "2026-11-20T10:03:00Z",
                                                                    "timed_out": True}})
        rec = attempt.read_attempt(folder)
        self.assertEqual(rec["failure"], {"kind": "interrupted", "step": "generate", "cause": "timeout",
                                          "cause_source": "attempt.json"})

    def test_a_complete_run_without_answers_json_is_an_incomplete_record(self):
        rec = attempt.read_attempt(self.folder(s.COMPLETE_RECORD, answers=False), arm="after")
        self.assertEqual(rec["outcome"], "complete")
        self.assertEqual(rec["incomplete"], ["a complete run's VEX without its answers.json"])
        self.assertFalse(rec["scores_usable"])

    def test_the_before_writes_no_answers_json(self):
        rec = attempt.read_attempt(self.folder(s.COMPLETE_RECORD, arm="before"))
        self.assertEqual((rec["what"]["arm"], rec["incomplete"], rec["scores_usable"]), ("before", [], True))

    def test_an_arm_the_record_contradicts_is_refused(self):
        with self.assertRaisesRegex(attempt.Refused, "arms that disagree, before from the argument, after from "
                                                     "attempt.json"):
            attempt.read_attempt(self.folder(s.COMPLETE_RECORD), arm="before")

    def test_reply_unreadable_in_answers_json_and_the_summary(self):
        log = [s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=0, splits=0, calls__M=1, calls__O=1,
                              defects__reply_unreadable=1, failed=False)]
        folder = self.folder(s.COMPLETE_RECORD, log=log)
        path = os.path.join(folder, "calls", "run-1", "answers.json")
        s.write(path, s.answers_doc([(A, s.VECTOR)], defects={"reply_unreadable": 1}))
        rec = attempt.read_attempt(folder)
        self.assertEqual((rec["summary"]["defects"], rec["answers"]["defects"], rec["problems"]),
                         ({"reply_unreadable": 1}, {"reply_unreadable": 1}, []))
        s.write(path, s.answers_doc([(A, s.VECTOR)]))
        rec = attempt.read_attempt(folder)
        self.assertIn("answers.json's counters or defects differ from the run summary's", rec["problems"])

    def test_another_attested_model(self):
        folder = self.folder(s.COMPLETE_RECORD)
        att = os.path.join(folder, "vex-internal.attestation.cdx.json")
        s.write(att, s.attestation(s.after_calls(A), "openai", "gpt-5.4-mini"))
        rec = attempt.read_attempt(folder, arm="after")
        self.assertFalse(rec["scores_usable"])
        self.assertIn("attested [('openai', 'gpt-5.4-mini')]", rec["archive_check"]["reason"])


class TestBeforeTheRecord(Base):
    def test_a_complete_download_its_added_fields_unknown(self):
        rec = attempt.read_attempt(self.folder(None, log=None, arm="before"), arm="before")
        self.assertEqual((rec["record"], rec["outcome"]), (None, "complete"))
        self.assertEqual(rec["implied"], ["generate.exit_status", "enrich.exit_status", "archive_check"])
        for field in ("generate.started_at", "generate.ended_at", "enrich.started_at", "enrich.ended_at",
                      "vens_binary_sha256", "log", "summary"):
            self.assertIn(field, rec["unknown"])
        self.assertIsNone(rec["summary"])
        self.assertEqual(rec["recovery"]["archived_calls"], 2)
        self.assertTrue(rec["scores_usable"])

    def test_a_failed_download_without_a_vex_read_as_0b_read_it(self):
        folder = self.folder(None, log=None, provenance=False, vex_file=False, arm="before")
        os.remove(os.path.join(folder, "vex-internal.attestation.cdx.json"))
        failure = {"attempt": 1, "job": "internal · run 1", "error": CAUSE}
        rec = attempt.read_attempt(folder, arm="before", failure_line=failure)
        self.assertEqual(rec["failure"], {"kind": None, "step": None, "cause": CAUSE, "cause_source": "failures.txt",
                                          "reason": attempt.NO_PROVENANCE})
        for field in ("failure.kind", "failure.step", "generate.exit_status"):
            self.assertIn(field, rec["unknown"])
        self.assertEqual((rec["implied"], rec["problems"]), ([], []))

    def test_a_vex_without_provenance_its_job_failed(self):
        folder = self.folder(None, log=None, provenance=False, arm="before")
        job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "failure"}
        failure = {"attempt": 1, "job": "internal · run 1", "error": "vens enrich: exit 1"}
        rec = attempt.read_attempt(folder, arm="before", job=job, failure_line=failure)
        self.assertEqual(rec["outcome"], "failed")
        self.assertEqual(rec["failure"], {"kind": None, "step": None, "cause": "vens enrich: exit 1",
                                          "cause_source": "failures.txt", "reason": attempt.NO_PROVENANCE})
        for field in ("failure.kind", "failure.step", "generate.exit_status", "enrich.exit_status", "archive_check"):
            self.assertIn(field, rec["unknown"])
        self.assertIn("a VEX but no provenance.json, the job ended failure: read as a failed attempt at a step the "
                      "download does not name", rec["problems"])
        self.assertIsNotNone(rec["ratings"])
        self.assertFalse(rec["scores_usable"])

    def test_a_vex_without_provenance_its_job_succeeded_or_not_listed(self):
        folder = self.folder(None, log=None, provenance=False, arm="before")
        job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "success"}
        with self.assertRaisesRegex(attempt.Refused, "its job succeeded, yet the download holds no provenance.json; "
                                                     "a truncated download is not a failed job"):
            attempt.read_attempt(folder, arm="before", job=job)
        with self.assertRaisesRegex(attempt.Refused, "its job not listed; a truncated download is not a failed job"):
            attempt.read_attempt(folder, arm="before")

    def test_calls_alone_its_job_succeeded(self):
        folder = self.folder(None, log=None, provenance=False, vex_file=False, arm="before")
        job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "success"}
        with self.assertRaisesRegex(attempt.Refused, "a truncated download is not a failed job"):
            attempt.read_attempt(folder, arm="before", job=job)

    def test_a_before_call_whose_human_prompt_is_missing_stays_unknown(self):
        folder = self.folder(None, log=None, provenance=False, vex_file=False, arm="before")
        for part in ("human.prompt", "response"):
            os.remove(os.path.join(folder, "calls", "run-1", f"batch-00002.{part}"))
        failure = {"attempt": 1, "job": "internal · run 1", "error": CAUSE}
        rec = attempt.read_attempt(folder, arm="before", failure_line=failure)
        self.assertEqual(rec["calls"]["kinds"], ["planned", None])
        self.assertIn("call 2's human prompt does not read: it and the calls after it are not classified",
                      rec["problems"])
        self.assertEqual({k: rec["recovery"][k] for k in COUNTS}, dict.fromkeys(COUNTS))
        self.assertEqual(sorted(rec["cost_estimate"]["by_kind"]), ["planned", "unclassified"])
        log = os.path.join(folder, "vens-internal.log")
        s.write(log, s.summary_line(rows=2, cves=1, llm_calls=2, asked_again=0, splits=0, failed=True) + "\n")
        rec = attempt.read_attempt(folder, arm="before", failure_line=failure)
        self.assertEqual(rec["calls"]["kinds"], ["planned", None])
        self.assertEqual({k: rec["recovery"][k] for k in COUNTS},
                         {"planned": 2, "again_omission": 0, "again_unreadable": 0, "split_halves": 0,
                          "recovery_calls": 0})
        self.assertEqual(sorted(rec["cost_estimate"]["by_kind"]), ["planned", "unclassified"])


class TestFilesThatDoNotRead(Base):
    def cut(self, folder, name):
        path = os.path.join(folder, name)
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path, "wb") as fh:
            fh.write(data[:len(data) // 2])
        return path

    def test_a_vex_cut_mid_write(self):
        folder = self.folder(s.COMPLETE_RECORD)
        path = self.cut(folder, "vex-internal.cdx.json")
        rec = attempt.read_attempt(folder)
        self.assertEqual((rec["outcome"], rec["ratings"], rec["scores_usable"]), ("complete", None, False))
        self.assertEqual(rec["incomplete"], ["a complete attempt whose VEX does not read"])
        self.assertTrue(rec["vex_problems"][0].startswith(f"{path}: not readable as JSON, a file cut short"))

    def test_answers_json_cut_mid_write(self):
        folder = self.folder(s.COMPLETE_RECORD)
        path = self.cut(folder, os.path.join("calls", "run-1", "answers.json"))
        rec = attempt.read_attempt(folder)
        self.assertEqual((rec["answers"], rec["scores_usable"]), (None, False))
        self.assertEqual(rec["incomplete"], ["a complete run's answers.json that does not read"])
        self.assertTrue(any(p.startswith(f"{path}: not readable as JSON") for p in rec["problems"]))

    def test_an_attestation_cut_or_malformed(self):
        malformed = ({"declarations": {"evidence": [{"data": [{"name": "model"}]}]}}, {"declarations": []},
                     {"declarations": {"evidence": [{"data": [{"name": "model", "contents": {"attachment": {
                         "content": "/w==", "encoding": "base64"}}}]}]}})
        for n, doc in enumerate((None,) + malformed):
            folder = self.folder_at(1100 + n, s.COMPLETE_RECORD)
            name = "vex-internal.attestation.cdx.json"
            path = self.cut(folder, name) if doc is None else s.write(os.path.join(folder, name), doc)
            rec = attempt.read_attempt(folder)
            self.assertEqual((rec["models_attested"], rec["archive_check"]["passed"], rec["scores_usable"]),
                             (None, None, False))
            self.assertTrue(any(p.startswith(f"{path}: not") for p in rec["problems"]), rec["problems"])

    def test_a_record_cut_mid_write_or_of_another_shape_is_refused_by_name(self):
        folder = self.folder(s.COMPLETE_RECORD)
        path = self.cut(folder, "attempt.json")
        with self.assertRaisesRegex(attempt.Refused, f"^{re.escape(path)}: not readable as JSON, a file cut short"):
            attempt.read_attempt(folder)
        for doc in ([], {**s.COMPLETE_RECORD, "generate": "done"}):
            s.write(path, doc)
            with self.assertRaisesRegex(attempt.Refused, f"^{re.escape(path)}: (a JSON list|generate is a JSON str)"):
                attempt.read_attempt(folder)


class TestNames(unittest.TestCase):
    def test_model_ids_with_dashes(self):
        self.assertEqual(attempt.parse_name("baseline-gpt-5.4-mini-2026-03-17-internal-api-r1-a2"),
                         {"model": "gpt-5.4-mini-2026-03-17", "context": "internal-api", "replicate": 1, "attempt": 2})
        self.assertEqual(attempt.parse_name("baseline-claude-sonnet-4-6-internal-r10-a1")["context"], "internal")
        self.assertIsNone(attempt.parse_name("baseline-x-elsewhere-r1-a1"))

    def test_run_meta(self):
        meta = attempt.run_meta({"id": 7, "display_title": "baseline · 2026-09-23 · anthropic/claude-sonnet-4-6 · "
                                                           "batch 1 · x10 · vens 9ac9ef4"})
        self.assertEqual(meta, {"run_id": 7, "archived_run": "2026-09-23", "provider": "anthropic",
                                "model": "claude-sonnet-4-6", "batch_size": 1, "replicates": 10,
                                "vens_ref": "9ac9ef4", "dispatch_id": None})

    def test_run_meta_with_a_dispatch_id(self):
        title = dispatch.title("2026-09-23", "openai", "gpt-5.4-mini-2026-03-17", 1, "b7c0435", "0f3c9a2b7d41")
        meta = attempt.run_meta({"id": 7, "display_title": title})
        self.assertEqual((meta["model"], meta["vens_ref"], meta["replicates"], meta["dispatch_id"]),
                         ("gpt-5.4-mini-2026-03-17", "b7c0435", 1, "0f3c9a2b7d41"))


if __name__ == "__main__":
    unittest.main()
