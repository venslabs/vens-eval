import unittest

from chain import venslog
from tests import support as s


class TestFields(unittest.TestCase):
    def test_quoted_values_and_groups(self):
        got = venslog.fields(s.summary_line(rows=3, cves=2, llm_calls=5, asked_again=1, splits=0, calls__M=2,
                                            counters__motive_cannot_tell=1, failed=False))
        self.assertEqual(got["msg"], "Scoring run finished")
        self.assertEqual(got["calls.M"], "2")
        self.assertEqual(got["failed"], "false")

    def test_go_escapes(self):
        got = venslog.fields(r'time=t level=ERROR msg=Error error="a \"quoted\" \x41 é tab\there"')
        self.assertEqual(got["error"], 'a "quoted" A é tab\there')

    def test_a_line_slog_did_not_write(self):
        self.assertEqual(venslog.fields("panic: runtime error: index out of range"), {})
        self.assertEqual(venslog.fields(""), {})


class TestSummary(unittest.TestCase):
    def test_after_summary(self):
        recs = venslog.records("\n".join([
            s.line("INFO", "Config loaded", schema_version=2),
            s.summary_line(rows=1, cves=1, llm_calls=11, asked_again=0, splits=0, calls__M=1, calls__PV=1,
                           counters__detection_undeclared=1, defects__reply_unreadable=2, failed=False)]))
        got = venslog.summary(recs)
        self.assertEqual((got["llm_calls"], got["asked_again"], got["splits"], got["failed"]), (11, 0, 0, False))
        self.assertEqual(got["calls"], {"M": 1, "PV": 1})
        self.assertEqual(got["counters"], {"detection_undeclared": 1})
        self.assertEqual(got["defects"], {"reply_unreadable": 2})

    def test_before_summary_has_no_groups(self):
        got = venslog.summary(venslog.records(s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=1, splits=0,
                                                             failed=True)))
        self.assertEqual((got["llm_calls"], got["failed"], got["calls"], got["defects"]), (2, True, {}, {}))

    def test_no_summary_before_scoring(self):
        self.assertIsNone(venslog.summary(venslog.records(s.error_line("config: has no schema_version"))))


class TestCause(unittest.TestCase):
    def test_the_last_error_line(self):
        recs = venslog.records("\n".join([
            s.line("ERROR", "failed to write a debug file", file="x", error="disk full"),
            s.error_line("failed to generate risk scores: model returned no answer to Motive (M) for CVE-2099-0001 "
                         "after asking again; stopping the run")]))
        self.assertTrue(venslog.cause(recs).startswith("failed to generate risk scores: model returned no answer"))

    def test_an_error_line_of_another_message(self):
        recs = venslog.records(s.line("ERROR", "failed to write a debug file", file="x", error="disk full"))
        self.assertEqual(venslog.cause(recs), "failed to write a debug file: disk full")

    def test_no_error(self):
        self.assertIsNone(venslog.cause(venslog.records(s.summary_line(failed=False))))


class TestAskAgains(unittest.TestCase):
    def test_kinds(self):
        recs = venslog.records("\n".join([
            s.again_line("M", ["CVE-2099-0001"]),
            s.unreadable_line("O"),
            s.again_line("O", ["CVE-2099-0001"]),
            s.scored_line("CVE-2099-0001"),
            s.unreadable_line("M"),
            s.scored_line("CVE-2099-0002"),
            s.again_line("M", ["CVE-2099-0003"]),
        ]))
        self.assertEqual(venslog.ask_agains(recs), [("M", "omission"), ("O", "unreadable"), ("M", "omission")])

    def test_main_has_no_unreadable_kind(self):
        recs = venslog.records(s.line("WARN", "Model skipped vulnerabilities; asking again for those alone",
                                      skipped=1, of=1, vulns="CVE-2099-0001"))
        self.assertEqual(venslog.ask_agains(recs), [(None, "omission")])

    def test_splits(self):
        recs = venslog.records("\n".join([s.split_line("M", 10), s.line(
            "WARN", "LLM truncated the batch; retrying with smaller batches", **{"from": 10}, to=5)]))
        self.assertEqual(venslog.splits(recs), 2)


if __name__ == "__main__":
    unittest.main()
