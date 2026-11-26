import os
import tempfile
import unittest

from chain import calls as callmod
from chain import cost
from tests import support as s


class TestEstimate(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_dir = s.write_calls(os.path.join(tmp.name, "run-1"), [
            ("s" * 400, "h" * 400, "r" * 100),
            ("s" * 400, "h" * 400, None),
        ])
        self.calls = callmod.load(run_dir)

    def test_by_kind_at_the_list_price(self):
        got = cost.estimate(self.calls, ["planned", "again_omission"], "gpt-5.4-mini-2026-03-17")
        planned = (800 / 4 * 0.75 + 100 / 4 * 4.50) / 1e6
        again = 800 / 4 * 0.75 / 1e6
        self.assertAlmostEqual(got["by_kind"]["planned"], planned)
        self.assertAlmostEqual(got["by_kind"]["again_omission"], again)
        self.assertAlmostEqual(got["total"], planned + again)
        self.assertEqual(got["calls_without_reply"], 1)
        self.assertTrue(got["label"].startswith("estimate, not measured"))

    def test_no_price_no_figure(self):
        got = cost.estimate(self.calls, ["planned", "planned"], "mock")
        self.assertEqual((got["total"], got["by_kind"]), (None, None))
        self.assertIn("no list price", got["why"])

    def test_no_archive_no_figure(self):
        self.assertEqual(cost.estimate(None, None, "claude-sonnet-4-6")["why"], "no archived calls")

    def test_a_dated_snapshot_priced_as_its_model(self):
        self.assertEqual(cost.price("gpt-5.4-mini-2026-03-17"), cost.price("gpt-5.4-mini"))
        self.assertIsNone(cost.price("claude-sonnet-5"))

    def test_the_third_model_dated_or_not(self):
        for model in ("claude-haiku-4-5-20251001", "claude-haiku-4-5"):
            self.assertEqual(cost.price(model), (1.0, 5.0))
        got = cost.estimate(self.calls, ["planned", "planned"], "claude-haiku-4-5-20251001")
        self.assertAlmostEqual(got["total"], (1600 / 4 * 1.0 + 100 / 4 * 5.0) / 1e6)

    def test_the_pair_priced_as_before(self):
        for model in ("gpt-5.4-mini-2026-03-17", "gpt-5.4-mini"):
            self.assertEqual(cost.price(model), (0.75, 4.50))
        self.assertEqual(cost.price("claude-sonnet-4-6"), (3.0, 15.0))


if __name__ == "__main__":
    unittest.main()
