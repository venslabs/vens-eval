import unittest

from chain import contract, runvens, venslog, verdicts


class TestTheCheck(unittest.TestCase):
    def test_the_answer_ids_name_one_question_each(self):
        self.assertEqual(len(set(contract.ANSWER_IDS.values())), len(contract.ANSWER_IDS))
        human = "VULNERABILITIES\n[]\n\nQUESTION\nq?\n\nANSWERS\n" + "".join(
            f"- {a}: text\n" for a in contract.ANSWER_IDS["LAC"]) + "\nAnswer every vulnerability."
        self.assertEqual(contract.question_of(human), "LAC")
        self.assertIsNone(contract.question_of("FLAGGED VULNERABILITY\n{}"))


if __name__ == "__main__":
    unittest.main()
