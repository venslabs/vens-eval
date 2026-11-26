"""The recovery calls, every call beyond the planned ones, asked_again + 2 x splits, by kind, on synthetic summaries,
logs and archives with known counts; vens's mock never asks again after an unreadable reply nor splits a call."""
import os
import tempfile
import unittest

from chain import calls as callmod
from chain import recovery, venslog
from tests import support as s

A, B = "CVE-2099-0001", "CVE-2099-0002"
TEN = [f"CVE-2099-{i:04d}" for i in range(1, 11)]
Q = "How motivated are they?"


def case(calls, log, summary, arm="after", failed=False):
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = s.write_calls(os.path.join(tmp, "run-1"), calls)
        archived = callmod.load(run_dir)
    kinds, problem = callmod.classify(archived, arm)
    recs = venslog.records("\n".join(log)) if log is not None else None
    summ = venslog.summary(venslog.records(s.summary_line(**summary))) if summary is not None else None
    return recovery.breakdown(summ, recs, archived, kinds, failed), kinds, problem


def counts(out):
    keys = ("planned", "again_omission", "again_unreadable", "split_halves", "recovery_calls")
    return {k: out[k] for k in keys}


class TestRecoveryCalls(unittest.TestCase):
    def test_an_ask_again_after_an_omission(self):
        calls = [(s.SYSTEM, s.after_human(Q, [A]), s.reply([A], skip=[A])),
                 (s.SYSTEM, s.after_human(Q, [A]), s.reply([A]))]
        out, kinds, _ = case(calls, [s.again_line("M", [A]), s.scored_line(A)],
                             dict(llm_calls=2, asked_again=1, splits=0, failed=False))
        self.assertEqual(kinds, ["planned", "again_omission"])
        self.assertEqual(counts(out), {"planned": 1, "again_omission": 1, "again_unreadable": 0, "split_halves": 0,
                                       "recovery_calls": 1})
        self.assertEqual(out["problems"], [])

    def test_an_ask_again_after_an_unreadable_reply(self):
        calls = [(s.SYSTEM, s.after_human(Q, [A]), "not json"), (s.SYSTEM, s.after_human(Q, [A]), s.reply([A]))]
        out, kinds, _ = case(calls, [s.unreadable_line("M"), s.again_line("M", [A]), s.scored_line(A)],
                             dict(llm_calls=2, asked_again=1, splits=0, defects__reply_unreadable=1, failed=False))
        self.assertEqual(kinds, ["planned", "again_unreadable"])
        self.assertEqual(counts(out), {"planned": 1, "again_omission": 0, "again_unreadable": 1, "split_halves": 0,
                                       "recovery_calls": 1})
        self.assertEqual(out["problems"], [])

    def test_an_answer_that_is_no_object_is_unreadable(self):
        self.assertTrue(callmod.unreadable(b'{"answers": [{"vulnId": "x"}, 3]}'))
        self.assertTrue(callmod.unreadable(b'{"answers": null}'))
        self.assertTrue(callmod.unreadable(b'{"answers": [NaN]}'))
        self.assertTrue(callmod.unreadable(b"[]"))
        self.assertFalse(callmod.unreadable(b'{"answers": []}'))
        self.assertFalse(callmod.unreadable(b'{"other": 1}'))
        self.assertFalse(callmod.unreadable(b'{"answers": [{"vulnId": "x", "answer": ' + b"9" * 5000 + b"}]}"))

    def test_a_split_at_batch_10_with_no_ask_again(self):
        calls = [(s.SYSTEM, s.after_human(Q, TEN), None),
                 (s.SYSTEM, s.after_human(Q, TEN[:5]), s.reply(TEN[:5])),
                 (s.SYSTEM, s.after_human(Q, TEN[5:]), s.reply(TEN[5:]))]
        out, kinds, _ = case(calls, [s.split_line("M", 10)], dict(llm_calls=3, asked_again=0, splits=1, failed=False))
        self.assertEqual(kinds, ["planned", "half", "half"])
        self.assertEqual(counts(out), {"planned": 1, "again_omission": 0, "again_unreadable": 0, "split_halves": 2,
                                       "recovery_calls": 2})

    def test_a_split_whose_half_is_asked_again(self):
        calls = [(s.SYSTEM, s.after_human(Q, TEN), None),
                 (s.SYSTEM, s.after_human(Q, TEN[:5]), s.reply(TEN[:5], skip=[TEN[2]])),
                 (s.SYSTEM, s.after_human(Q, TEN[5:]), s.reply(TEN[5:])),
                 (s.SYSTEM, s.after_human(Q, [TEN[2]]), s.reply([TEN[2]]))]
        out, kinds, _ = case(calls, [s.split_line("M", 10), s.again_line("M", [TEN[2]])],
                             dict(llm_calls=4, asked_again=1, splits=1, failed=False))
        self.assertEqual(kinds, ["planned", "half", "half", "again_omission"])
        self.assertEqual(counts(out), {"planned": 1, "again_omission": 1, "again_unreadable": 0, "split_halves": 2,
                                       "recovery_calls": 3})

    def test_a_split_whose_half_is_asked_again_in_main(self):
        rows = [(A, "p1"), (A, "p2"), (B, "p3"), (B, "p4")]
        calls = [(s.SYSTEM, s.before_human(rows), None),
                 (s.SYSTEM, s.before_human(rows[:2]), '{"results": []}'),
                 (s.SYSTEM, s.before_human(rows[1:2]), '{"results": [{"vulnId": "x"}]}'),
                 (s.SYSTEM, s.before_human(rows[2:]), '{"results": []}')]
        log = [s.line("WARN", "LLM truncated the batch; retrying with smaller batches", **{"from": 4}, to=2),
               s.line("WARN", "Model skipped vulnerabilities; asking again for those alone", skipped=1, of=2, vulns=A)]
        out, kinds, _ = case(calls, log, dict(llm_calls=4, asked_again=1, splits=1, failed=False), arm="before")
        self.assertEqual(kinds, ["planned", "half", "again_omission", "half"])
        self.assertEqual(counts(out), {"planned": 1, "again_omission": 1, "again_unreadable": 0, "split_halves": 2,
                                       "recovery_calls": 3})
        self.assertEqual(out["problems"], [])

    def test_a_stop_on_an_ask_again(self):
        calls = [(s.SYSTEM, s.after_human(Q, [A]), s.reply([A], skip=[A])),
                 (s.SYSTEM, s.after_human(Q, [A]), s.reply([A], skip=[A]))]
        log = [s.again_line("M", [A]), s.error_line(f"failed to generate risk scores: model returned no answer to "
                                                   f"Motive (M) for {A} after asking again; stopping the run")]
        out, kinds, _ = case(calls, log, dict(llm_calls=2, asked_again=1, splits=0, failed=True), failed=True)
        self.assertEqual(kinds, ["planned", "again_omission"])
        self.assertEqual(counts(out), {"planned": 1, "again_omission": 1, "again_unreadable": 0, "split_halves": 0,
                                       "recovery_calls": 1})

    def test_a_stop_after_a_split_first_half_counted_from_the_archive(self):
        calls = [(s.SYSTEM, s.after_human(Q, TEN), None), (s.SYSTEM, s.after_human(Q, TEN[:5]), None)]
        log = [s.split_line("M", 10), s.error_line("failed to generate risk scores: LLM evaluation failed: 503")]
        out, kinds, _ = case(calls, log, dict(llm_calls=2, asked_again=0, splits=1, failed=True), failed=True)
        self.assertEqual(kinds, ["planned", "half"])
        self.assertEqual(out["source"], "archive")
        self.assertEqual(counts(out), {"planned": 1, "again_omission": 0, "again_unreadable": 0, "split_halves": 1,
                                       "recovery_calls": 1})

    def test_a_failed_split_run_without_its_archive_is_unknown(self):
        summ = venslog.summary(venslog.records(s.summary_line(llm_calls=2, asked_again=0, splits=1, failed=True)))
        out = recovery.breakdown(summ, None, None, None, True)
        self.assertIsNone(out["recovery_calls"])
        self.assertIsNone(out["split_halves"])

    def test_adjustments_are_planned(self):
        calls = [(s.SYSTEM, s.after_human(Q, [A]), s.reply([A])), (s.SYSTEM, s.adjust_human(A), '{"reasoning": "r"}')]
        out, kinds, _ = case(calls, [], dict(llm_calls=2, asked_again=0, splits=0, calls__adjustment=1, failed=False))
        self.assertEqual(kinds, ["planned", "adjustment"])
        self.assertEqual((out["planned"], out["adjustment"], out["recovery_calls"]), (2, 1, 0))

    def test_a_summary_and_an_archive_that_disagree(self):
        calls = [(s.SYSTEM, s.after_human(Q, [A]), s.reply([A]))]
        out, _, _ = case(calls, [], dict(llm_calls=2, asked_again=1, splits=0, failed=False))
        self.assertTrue(any("recovery calls: summary 1, archive 0" in p for p in out["problems"]))
        self.assertTrue(any("llm_calls 2, archived calls 1" in p for p in out["problems"]))

    def test_calls_out_of_order_are_not_classified(self):
        calls = [(s.SYSTEM, s.after_human(Q, [A]), s.reply([A])), (s.SYSTEM, "free text", "x")]
        _, kinds, problem = case(calls, [], dict(llm_calls=2, asked_again=0, splits=0, failed=False))
        self.assertEqual(kinds, ["planned", None])
        self.assertIn("does not follow", problem)


if __name__ == "__main__":
    unittest.main()
