import json
import os
import tempfile
import unittest

from chain import answers, cdx, errors
from tests import support as s

A, B = "CVE-2099-0001", "CVE-2099-0002"


def load(doc):
    with tempfile.TemporaryDirectory() as tmp:
        return answers.load(s.write(os.path.join(tmp, "answers.json"), doc))


def ratings(rows):
    with tempfile.TemporaryDirectory() as tmp:
        return cdx.ratings(s.write(os.path.join(tmp, "vex.cdx.json"), s.vex(rows)))


class TestAnswers(unittest.TestCase):
    def test_levels_equal_the_vector(self):
        doc = load(s.answers_doc([(A, s.VECTOR)]))
        r, problems = ratings([(A, s.VECTOR, s.SEVERITY, s.SCORE)])
        self.assertEqual((problems, answers.check(doc, r)), ([], []))

    def test_a_level_off_the_vector(self):
        doc = load(s.answers_doc([(A, s.VECTOR.replace("EE:5", "EE:3"))]))
        r, _ = ratings([(A, s.VECTOR, s.SEVERITY, s.SCORE)])
        self.assertEqual(answers.check(doc, r), [f"{A}: answers.json's levels differ from the vector's"])

    def test_a_rated_cve_missing_and_one_extra(self):
        doc = load(s.answers_doc([(B, s.VECTOR)]))
        r, _ = ratings([(A, s.VECTOR, s.SEVERITY, s.SCORE)])
        self.assertEqual(answers.check(doc, r), [f"{A}: rated in the VEX, no rated entry in answers.json",
                                                 f"{B}: a rated entry the VEX does not rate"])

    def test_a_batch_1_cve_marked_unrated_after_its_first_answers(self):
        # At batch 1 only a stop on a later question of the same CVE, such as a strict run's cannot_tell, leaves it.
        doc = load(s.answers_doc([(A, s.VECTOR)], unrated=[(B, ["M", "O", "EE"])]))
        rated, unrated = answers.entries(doc)
        self.assertEqual((sorted(rated), sorted(unrated)), ([A], [B]))
        got = answers.per_cve(unrated[B])
        self.assertEqual((got["unrated"], sorted(got["factors"])), (True, ["EE", "M", "O"]))
        self.assertIsNone(got["factors"]["M"]["level"])
        self.assertEqual(answers.unrated_shape(doc), [])
        r, _ = ratings([(A, s.VECTOR, s.SEVERITY, s.SCORE)])
        self.assertEqual(answers.check(doc, r), [])

    def test_an_unrated_entry_with_a_level(self):
        doc = s.answers_doc([], unrated=[(B, ["M"])])
        doc["vulnerabilities"][0]["factors"][0]["level"] = 4
        self.assertEqual(answers.unrated_shape(load(doc)), [f"{B}: an unrated entry with a level or a source"])

    def test_not_answers_json(self):
        for doc in ({"vulnerabilities": []}, {"vulnerabilities": [{"vulnId": ["x"], "factors": []}], "counters": {},
                                              "defects": {}}):
            with self.assertRaisesRegex(errors.Refused, "not answers.json"):
                load(doc)

    def test_a_cve_listed_twice(self):
        for doc in (s.answers_doc([(A, s.VECTOR), (A, s.VECTOR)]), s.answers_doc([(A, s.VECTOR)], [(A, ["M"])]),
                    s.answers_doc([], [(A, ["M"]), (A, ["M", "O"])])):
            self.assertEqual(answers.duplicates(load(doc)), [f"{A}: listed 2 times in answers.json"])
        self.assertEqual(answers.duplicates(load(s.answers_doc([(A, s.VECTOR)], [(B, ["M"])]))), [])


class TestVex(unittest.TestCase):
    def test_a_cve_listed_twice(self):
        r, problems = ratings([(A, s.VECTOR, s.SEVERITY, s.SCORE), (A, s.VECTOR, s.SEVERITY, s.SCORE),
                               (B, s.VECTOR, s.SEVERITY, s.SCORE)])
        self.assertEqual((sorted(r), problems), ([B], [f"{A}: listed 2 times in the VEX"]))

    def test_subscores(self):
        r, _ = ratings([(A, s.VECTOR, s.SEVERITY, s.SCORE)])
        got = r[A]
        self.assertEqual((got["L"], got["T"], got["B"], got["impact"]), (7.25, 8.5, 4.0, 8.5))
        self.assertEqual(got["L"] * got["impact"], s.SCORE)

    def test_missing_and_doubled_ratings(self):
        doc = s.vex([(A, None, None, None)])
        doc["vulnerabilities"].append({"id": B, "ratings": [{"method": "OWASP", "vector": s.VECTOR}] * 2})
        with tempfile.TemporaryDirectory() as tmp:
            r, problems = cdx.ratings(s.write(os.path.join(tmp, "v.json"), doc))
        self.assertEqual((r, problems), ({}, [f"{A}: 0 OWASP ratings", f"{B}: 2 OWASP ratings"]))

    def test_main_rule_on_the_before(self):
        vector = "SL:3/M:3/O:3/S:3/ED:4/EE:4/A:4/ID:4/LC:2/LI:2/LAV:2/LAC:2/FD:3/RD:3/NC:3/PV:3"
        r, _ = ratings([(A, vector, "low", 8.75), (B, vector, "medium", 9.0)])
        self.assertEqual(cdx.main_rule({A: r[A]}), [])
        self.assertEqual(cdx.main_rule({B: r[B]}), [f"{B}: score 9.0, main's rule gives 8.75",
                                                    f"{B}: severity medium, main's thresholds give low"])
        r, _ = ratings([(A, vector.replace("M:3", "M:4"), "low", 8.75)])
        self.assertEqual(cdx.main_rule(r), [f"{A}: a group's four levels differ"])

    def test_a_vector_of_another_shape(self):
        with self.assertRaises(ValueError):
            cdx.levels("SL:9/M:1")
        with self.assertRaises(ValueError):
            cdx.levels(s.VECTOR.replace("M:1", "X:1"))

    def test_a_missing_or_null_score_stays_none(self):
        main_vector = "SL:3/M:3/O:3/S:3/ED:4/EE:4/A:4/ID:4/LC:2/LI:2/LAV:2/LAC:2/FD:3/RD:3/NC:3/PV:3"
        doc = s.vex([(A, s.VECTOR, s.SEVERITY, None), (B, main_vector, "low", None), ("CVE-2099-0003", s.VECTOR,
                                                                                    s.SEVERITY, "61.625")])
        del doc["vulnerabilities"][1]["ratings"][0]["score"]
        with tempfile.TemporaryDirectory() as tmp:
            path = s.write(os.path.join(tmp, "vex.cdx.json"), doc)
            r, problems = cdx.ratings(path)
            rows = cdx.vex_rows(path)
        self.assertEqual({vid: x["score"] for vid, x in r.items()}, {A: None, B: None, "CVE-2099-0003": None})
        self.assertEqual(r[A]["L"], 7.25)
        self.assertEqual(problems, [f"{A}: score None, not a number", f"{B}: score None, not a number",
                                    "CVE-2099-0003: score '61.625', not a number"])
        self.assertEqual([row[3] for row in rows], ["NaN", "NaN", "NaN"])
        self.assertEqual(cdx.main_rule({B: r[B]}), [f"{B}: score None, main's rule gives 8.75"])

    def test_a_null_or_missing_vector(self):
        doc = s.vex([(A, s.VECTOR, s.SEVERITY, s.SCORE), (B, s.VECTOR, s.SEVERITY, s.SCORE)])
        doc["vulnerabilities"][0]["ratings"][0]["vector"] = None
        del doc["vulnerabilities"][1]["ratings"][0]["vector"]
        with tempfile.TemporaryDirectory() as tmp:
            path = s.write(os.path.join(tmp, "vex.cdx.json"), doc)
            r, problems = cdx.ratings(path)
            rows = cdx.vex_rows(path)
        self.assertEqual((r, problems), ({}, [f"{A}: vector None: not a string", f"{B}: vector None: not a string"]))
        self.assertEqual(rows, [(A, "", s.SEVERITY, repr(s.SCORE)), (B, "", s.SEVERITY, repr(s.SCORE))])

    def test_a_file_that_is_no_vex_or_cut_short(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, content in (("list.json", []),
                                  ("ratings.json", {"vulnerabilities": [{"id": A, "ratings": {"method": "OWASP"}}]}),
                                  ("noid.json", {"vulnerabilities": [{"ratings": []}]}),
                                  ("cut.json", json.dumps(s.vex([(A, s.VECTOR, s.SEVERITY, s.SCORE)]))[:50])):
                path = s.write(os.path.join(tmp, name), content)
                for read in (cdx.ratings, cdx.vex_rows):
                    with self.assertRaisesRegex(errors.Refused, f"{name}: (a JSON list|not a VEX|not readable)"):
                        read(path)


if __name__ == "__main__":
    unittest.main()
