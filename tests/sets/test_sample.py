"""The sampler on synthetic frames and fixed seeds: quotas, determinism, exactness against a brute force, refill,
caps, minimums, families, reserve, the seed's binding and the command line."""
import hashlib
import io
import itertools
import json
import os
import random
import stat
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout

from tests.sets.test_drand import NOW, ROUND, recorded
from vkpi.sets import commit, drand
from vkpi.sets import sample as s
from vkpi.sets.common import Refused, load_json

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "sample")
SEED = hashlib.sha256(b"vens-kpi/1.0/sets/test").digest()
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
VECTORS = ("v3", "v2-only", "v4-only", "absent")
V070 = {  # the sealed set's quotas in the v0.7.0 campaign design
    "format": "vens-kpi/1.0/quotas",
    "n": 100,
    "rows": {"attribute": "severity", "quotas": {"CRITICAL": 20, "HIGH": 30, "MEDIUM": 30, "LOW": 10, "UNKNOWN": 10}},
    "margins": [{"attribute": "vector", "quotas": {"v3": 70, "v2-only": 10, "v4-only": 10, "absent": 10}}],
    "caps": [{"attribute": "image", "max": 25}],
    "minimums": [
        {"attribute": "multi_package", "value": True, "min": 10},
        {"attribute": "non_nvd_source", "value": True, "min": 10},
        {"attribute": "fixed_version", "value": True, "min": 40},
        {"attribute": "fixed_version", "value": False, "min": 40},
    ],
    "family": "family",
}
SEVERITY_QUOTAS = V070["rows"]["quotas"]
VECTOR_QUOTAS = V070["margins"][0]["quotas"]


def frame(size, seed, severity=(10, 25, 35, 20, 10), vector=(75, 10, 6, 9), multi=0.2, family_size=1, image=None,
          start=0):
    rng = random.Random(seed)
    rows = []
    for i in range(start, start + size):
        rows.append({"id": f"CVE-2099-{i:05d}", "severity": rng.choices(SEVERITIES, severity)[0],
                     "vector": rng.choices(VECTORS, vector)[0],
                     "image": image(rng) if image else f"image-{rng.randrange(10):02d}",
                     "multi_package": rng.random() < multi, "non_nvd_source": rng.random() < 0.4,
                     "fixed_version": rng.random() < 0.5, "family": f"family-{i // family_size:05d}"})
    return rows


def draw(rows, spec=V070, seed=SEED):
    selected, report = s.sample(rows, s.parse_spec(spec), seed)
    by_id = {row["id"]: row for row in rows}
    return [by_id[x["id"]] | {"stage": x["stage"]} for x in selected], report


def tally(rows, attribute):
    return Counter(row[attribute] for row in rows)


def seeds(count):
    return [hashlib.sha256(k.to_bytes(2, "big")).digest() for k in range(count)]


def ids(selected):
    return [x["id"] for x in selected]


class TestQuotas(unittest.TestCase):
    def test_every_quota_on_a_rich_frame(self):
        chosen, report = draw(frame(3000, seed=1))
        self.assertEqual(len(chosen), 100)
        self.assertEqual(tally(chosen, "severity"), SEVERITY_QUOTAS)
        self.assertEqual(tally(chosen, "vector"), VECTOR_QUOTAS)
        self.assertLessEqual(max(tally(chosen, "image").values()), 25)
        self.assertGreaterEqual(tally(chosen, "multi_package")[True], 10)
        self.assertGreaterEqual(tally(chosen, "non_nvd_source")[True], 10)
        self.assertGreaterEqual(min(tally(chosen, "fixed_version").values()), 40)
        self.assertEqual((report["full"], report["stages"]["refill"]), (True, 0))
        self.assertEqual(s.summary(report)[-1], "every quota met")


class TestDeterminism(unittest.TestCase):
    def setUp(self):
        self.rows = frame(1500, seed=2)
        self.spec = s.parse_spec(V070)

    def test_the_same_inputs_give_the_same_bytes(self):
        first = s.sample(self.rows, self.spec, SEED)
        second = s.sample(json.loads(json.dumps(self.rows)), s.parse_spec(V070), SEED)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_the_line_order_plays_no_part(self):
        shuffled = self.rows[:]
        random.Random(9).shuffle(shuffled)
        self.assertEqual(s.sample(shuffled, self.spec, SEED), s.sample(self.rows, self.spec, SEED))

    def test_the_seed_decides(self):
        first = set(ids(s.sample(self.rows, self.spec, SEED)[0]))
        second = set(ids(s.sample(self.rows, self.spec, hashlib.sha256(b"another").digest())[0]))
        self.assertNotEqual(first, second)

    def test_the_order_is_sha256_of_seed_and_id(self):
        rows = [{"id": f"GHSA-{i}"} for i in range(30)]
        selected, _ = s.sample(rows, s.parse_spec({"format": s.SPEC_FORMAT, "n": 5}), SEED)
        lowest = sorted((row["id"] for row in rows), key=lambda rid: hashlib.sha256(SEED + rid.encode()).digest())
        self.assertEqual(ids(selected), lowest[:5])


class TestRecorded(unittest.TestCase):
    """A synthetic frame, spec and seed recorded once, with the selection the rule gave them: a refill, a family rule,
    a cap reached and a reserve tier. A change to the rule shows here first."""

    def test_the_recorded_selection(self):
        expected = load_json(os.path.join(FIXTURES, "expected.json"), "expected")
        spec = s.parse_spec(load_json(os.path.join(FIXTURES, "spec.json"), "spec"))
        rows = s.read_frame(os.path.join(FIXTURES, "frame.jsonl"))
        selected, report = s.sample(rows, spec, bytes.fromhex(expected["seed"]))
        self.assertEqual(selected, expected["selected"])
        self.assertEqual(report, expected["report"])
        self.assertTrue(report["stages"]["refill"] and report["reserve"]["tier_used"]
                        and report["caps"][0]["values_at_max"])


def _brute_levels(spec, pick):
    """(rows, rows within margin quotas, rows toward the minimums) of a selection, or None when it breaks a limit."""
    if len(pick) > spec["n"] or ("family" in spec and len({r["fam"] for r in pick}) < len(pick)):
        return None
    if any(sum(r["s"] == value for r in pick) > quota for value, quota in spec["rows"]["quotas"].items()):
        return None
    for cap in spec.get("caps", []):
        counts = Counter(v for r in pick for v in (r[cap["attribute"]] if isinstance(r[cap["attribute"]], list)
                                                    else [r[cap["attribute"]]]))
        if counts and max(counts.values()) > cap["max"]:
            return None
    within = sum(min(sum(r[m["attribute"]] == v for r in pick), q)
                 for m in spec.get("margins", []) for v, q in m["quotas"].items())
    toward = sum(min(sum(r[k["attribute"]] is k["value"] for r in pick), k["min"]) for k in spec.get("minimums", []))
    return len(pick), within, toward


def brute_force(spec, rows, seed):
    """The first best selection in rank order, by enumerating every subset."""
    order = sorted(rows, key=lambda r: hashlib.sha256(seed + r["id"].encode()).digest())
    best = None
    for size in range(spec["n"] + 1):
        for pick in itertools.combinations(range(len(order)), size):
            levels = _brute_levels(spec, [order[i] for i in pick])
            if levels is not None:
                key = (levels, tuple(i in pick for i in range(len(order))))
                best = max(best, key) if best else key
    return [order[i]["id"] for i, taken in enumerate(best[1]) if taken]


def small_case(rng):
    n = rng.randint(2, 5)

    def split(parts):
        cuts = sorted(rng.randint(0, n) for _ in range(parts - 1))
        return [b - a for a, b in zip([0] + cuts, cuts + [n])]

    strata = [f"S{i}" for i in range(rng.randint(1, 3))]
    spec = {"format": s.SPEC_FORMAT, "n": n,
            "rows": {"attribute": "s", "quotas": dict(zip(strata, split(len(strata))))},
            "caps": [cap for cap, wanted in (({"attribute": "img", "max": rng.randint(1, 2)}, rng.random() < 0.7),
                                             ({"attribute": "pkg", "max": rng.randint(1, 2)}, rng.random() < 0.4))
                     if wanted]}
    spec["margins"] = [{"attribute": f"m{m}", "quotas": dict(zip(values, split(len(values))))}
                       for m, values in enumerate([["a", "b"], ["x", "y", "z"]][:rng.randint(0, 2)])]
    if rng.random() < 0.5:
        spec["minimums"] = [{"attribute": "flag", "value": True, "min": rng.randint(1, n // 2 + 1)}]
    if rng.random() < 0.5:
        spec["family"] = "fam"
    rows = [{"id": f"r{i}", "s": rng.choice(strata), "img": f"i{rng.randrange(rng.randint(2, 4))}",
             "pkg": rng.sample("pqr", rng.randint(1, 2)), "flag": rng.random() < 0.4, "fam": f"f{rng.randrange(6)}",
             **{m["attribute"]: rng.choice(list(m["quotas"])) for m in spec["margins"]}}
            for i in range(rng.randint(4, 9))]
    return spec, rows


class TestExact(unittest.TestCase):
    """Every constraint at once: strata, one or two margins, a single and a list-valued cap, a minimum, families."""

    def test_the_first_best_selection_of_every_small_frame(self):
        rng, full = random.Random(15), 0
        for trial in range(300):
            spec, rows = small_case(rng)
            seed = hashlib.sha256(trial.to_bytes(2, "big")).digest()
            selected, report = s.sample(rows, s.parse_spec(spec), seed)
            self.assertEqual(ids(selected), brute_force(spec, rows, seed), (spec, rows))
            self.assertEqual(report["full"], not s.has_shortfall(report))
            full += report["full"]
        self.assertTrue(30 < full < 270, full)


class TestReviewCases(unittest.TestCase):
    """The frames on which the first look-ahead ended short, from the review of PR #6."""

    def test_room_left_in_a_cap_counts(self):
        spec = {"format": s.SPEC_FORMAT, "n": 3, "rows": {"attribute": "s", "quotas": {"A": 2, "B": 1}},
                "caps": [{"attribute": "img", "max": 2}], "reserve": "tier"}
        rows = [{"id": "b0", "s": "B", "img": "i0", "tier": 0}, {"id": "b1", "s": "B", "img": "i2", "tier": 0},
                {"id": "a0", "s": "A", "img": "i2", "tier": 0}, {"id": "a1", "s": "A", "img": "i2", "tier": 0},
                {"id": "r0", "s": "A", "img": "i9", "tier": 1}]
        selected, report = s.sample(rows, s.parse_spec(spec), bytes([1]) * 32)
        self.assertEqual((sorted(ids(selected)), report["reserve"]["tier_used"]), (["a0", "a1", "b0"], 0))

    def test_a_refill_never_starves_a_stratum(self):
        spec = {"format": s.SPEC_FORMAT, "n": 4, "rows": {"attribute": "s", "quotas": {"A": 3, "B": 1}},
                "margins": [{"attribute": "m", "quotas": {"x": 4, "y": 0}}], "caps": [{"attribute": "img", "max": 1}]}
        rows = [{"id": f"id{i}", "s": st, "m": m, "img": img} for i, (st, m, img) in
                enumerate((("A", "x", "i1"), ("B", "x", "i2"), ("A", "y", "i2"), ("B", "y", "i2"), ("B", "x", "i1"),
                           ("B", "y", "i0")))]
        seed = bytes.fromhex("624b60c58c9d8bfb6ff1886c2fd605d2adeb6ea4da576068201b6c6958ce93f4")
        selected, report = s.sample(rows, s.parse_spec(spec), seed)
        self.assertEqual(sorted(ids(selected)), ["id0", "id2", "id5"])
        self.assertEqual(report["rows"]["values"]["A"]["selected"], 2)

    def test_two_margins_are_checked_together(self):
        spec = {"format": s.SPEC_FORMAT, "n": 2, "rows": {"attribute": "s", "quotas": {"A": 2}},
                "margins": [{"attribute": "m1", "quotas": {"0": 1, "1": 1}},
                            {"attribute": "m2", "quotas": {"0": 1, "1": 1}}]}
        rows = [{"id": rid, "s": "A", "m1": rid[1], "m2": rid[2]} for rid in ("r00", "r01", "r10")]
        seed = next(candidate for candidate in seeds(5000) if sorted(
            ("r00", "r01", "r10"), key=lambda rid: hashlib.sha256(candidate + rid.encode()).digest())[0] == "r00")
        selected, report = s.sample(rows, s.parse_spec(spec), seed)
        self.assertEqual((sorted(ids(selected)), report["full"], report["stages"]["refill"]), (["r01", "r10"], True, 0))

    def test_cap_room_before_the_cap_is_full(self):
        spec = {"format": s.SPEC_FORMAT, "n": 3, "rows": {"attribute": "s", "quotas": {"A": 1, "B": 1, "C": 1}},
                "caps": [{"attribute": "img", "max": 2}]}
        rows = [{"id": "ax", "s": "A", "img": "x"}, {"id": "ay", "s": "A", "img": "y"},
                {"id": "bx", "s": "B", "img": "x"}, {"id": "cx", "s": "C", "img": "x"}]
        seed = next(candidate for candidate in seeds(5000) if min(
            ("ax", "ay", "bx", "cx"), key=lambda rid: hashlib.sha256(candidate + rid.encode()).digest()) == "ax")
        selected, report = s.sample(rows, s.parse_spec(spec), seed)
        self.assertEqual((sorted(ids(selected)), report["full"]), (["ay", "bx", "cx"], True))


class TestNeverExceeds(unittest.TestCase):
    def test_only_a_refill_goes_past_a_margin_and_nothing_past_a_stratum_or_a_cap(self):
        frames = (frame(1200, seed=4), frame(600, seed=5, vector=(85, 3, 3, 9)),
                  frame(300, seed=6, severity=(4, 20, 50, 20, 6), multi=0.02),
                  frame(600, seed=22, image=lambda rng: f"image-{min(int(rng.expovariate(0.6)), 4)}"))
        for rows in frames:
            for seed in seeds(4):
                chosen, report = draw(rows, seed=seed)
                with self.subTest(rows=len(rows), seed=seed.hex()[:8]):
                    self.assertLessEqual(len(chosen), 100)
                    for value, count in tally(chosen, "severity").items():
                        self.assertLessEqual(count, SEVERITY_QUOTAS[value])
                    self.assertLessEqual(max(tally(chosen, "image").values()), 25)
                    refilled = tally([row for row in chosen if row["stage"] == "refill"], "vector")
                    for value, count in tally(chosen, "vector").items():
                        self.assertLessEqual(count - VECTOR_QUOTAS[value], refilled[value])
                    self.assertEqual(len({row["family"] for row in chosen}), len(chosen))


class TestRefill(unittest.TestCase):
    def test_a_margin_the_frame_cannot_fill_is_refilled_from_the_same_strata(self):
        rows = frame(2000, seed=7, vector=(85, 0, 7, 8))
        rows += [dict(rows[0], id=f"CVE-2099-9000{i}", vector="v2-only", severity="MEDIUM", family=f"lone-{i}")
                 for i in range(4)]
        chosen, report = draw(rows)
        margin = report["margins"][0]
        self.assertEqual((margin["values"]["v2-only"]["selected"], margin["values"]["v2-only"]["status"]), (4, "short"))
        self.assertEqual((margin["status"], margin["shortfall"], margin["refilled"]), ("refilled", 6, 6))
        self.assertEqual((len(chosen), report["stages"]["refill"], report["full"]), (100, 6, False))
        self.assertEqual(tally(chosen, "severity"), SEVERITY_QUOTAS)

    def test_a_stratum_the_frame_cannot_fill_stays_short(self):
        rows = frame(2000, seed=8, severity=(10, 25, 35, 20, 0))
        rows += [dict(rows[0], id=f"CVE-2099-9100{i}", severity="UNKNOWN", vector="absent", family=f"lone-{i}")
                 for i in range(7)]
        chosen, report = draw(rows)
        unknown = report["rows"]["values"]["UNKNOWN"]
        self.assertEqual((unknown["selected"], unknown["shortfall"], unknown["status"]), (7, 3, "short"))
        self.assertEqual((len(chosen), report["shortfall"]), (97, 3))
        self.assertEqual(tally(chosen, "severity"), dict(SEVERITY_QUOTAS, UNKNOWN=7))
        self.assertEqual((report["margins"][0]["refilled"], report["margins"][0]["status"]), (0, "short"))
        self.assertLessEqual({row["id"] for row in chosen}, {row["id"] for row in rows})


class TestCaps(unittest.TestCase):
    def test_one_image_cannot_take_over(self):
        rows = frame(2500, seed=9,
                     image=lambda rng: "image-00" if rng.random() < 0.7 else f"image-{rng.randrange(1, 10):02d}")
        chosen, report = draw(rows)
        self.assertEqual(tally(chosen, "image")["image-00"], 25)
        self.assertEqual((report["caps"][0]["values_at_max"], report["caps"][0]["status"]), (1, "held"))
        self.assertFalse(s.has_shortfall(report))

    def test_a_row_in_several_images_counts_toward_each(self):
        rows = [{"id": f"r{i}", "image": images} for i, images in
                enumerate((["a", "b"], ["a"], ["b"], ["a", "c"], ["c"], ["d"], ["b", "d"]))]
        spec = s.parse_spec({"format": s.SPEC_FORMAT, "n": 5, "caps": [{"attribute": "image", "max": 2}]})
        selected, report = s.sample(rows, spec, SEED)
        images = {row["id"]: row["image"] for row in rows}
        counts = Counter(image for x in selected for image in images[x["id"]])
        self.assertEqual((len(selected), max(counts.values()), report["caps"][0]["status"]), (5, 2, "held"))

    def test_a_value_listed_twice_counts_once(self):
        rows = [{"id": "r0", "image": ["a", "a"]}, {"id": "r1", "image": "a"}]
        spec = s.parse_spec({"format": s.SPEC_FORMAT, "n": 2, "caps": [{"attribute": "image", "max": 2}]})
        selected, report = s.sample(rows, spec, SEED)
        self.assertEqual((len(selected), report["caps"][0]["largest"]), (2, 2))


class TestMinimums(unittest.TestCase):
    def test_a_rare_attribute_reaches_its_minimum(self):
        rows = frame(3000, seed=10, multi=0.005)
        self.assertLess(sum(row["multi_package"] for row in rows), 30)
        chosen, report = draw(rows)
        self.assertGreaterEqual(tally(chosen, "multi_package")[True], 10)
        self.assertFalse(s.has_shortfall(report))

    def test_an_impossible_minimum_is_short_and_blocks_nothing(self):
        rows = frame(3000, seed=11, multi=0.0)
        rows += [dict(rows[i], id=f"CVE-2099-9200{i}", multi_package=True, family=f"lone-{i}") for i in range(5)]
        chosen, report = draw(rows)
        multi = report["minimums"][0]
        self.assertEqual((multi["selected"], multi["shortfall"], multi["status"]), (5, 5, "short"))
        self.assertEqual(len(chosen), 100)
        self.assertEqual((report["shortfall"], report["margins"][0]["shortfall"]), (0, 0))

    def test_a_value_matches_on_its_type(self):
        rows = [dict(row, fixed_version=int(row["fixed_version"])) for row in frame(1500, seed=12)]
        _, report = draw(rows)
        self.assertEqual((report["minimums"][2]["available"], report["minimums"][2]["status"]), (0, "short"))


class TestFamily(unittest.TestCase):
    def test_one_row_per_family(self):
        chosen, report = draw(frame(3000, seed=13, family_size=3))
        self.assertEqual(len({row["family"] for row in chosen}), len(chosen))
        self.assertEqual((report["family"]["rows"], report["family"]["families"]), (3000, 1000))

    def test_a_family_gives_its_first_row_that_fits(self):
        rows = [{"id": rid, "family": "A"} for rid in ("a1", "a2", "a3")] + [{"id": "b1", "family": "B"}]
        selected, _ = s.sample(rows, s.parse_spec({"format": s.SPEC_FORMAT, "n": 2, "family": "family"}), SEED)
        lowest = min(("a1", "a2", "a3"), key=lambda rid: hashlib.sha256(SEED + rid.encode()).digest())
        self.assertEqual(set(ids(selected)), {lowest, "b1"})


class TestLookAhead(unittest.TestCase):
    """UNKNOWN rows only ever lack a vector, and LOW rows lacking one are plenty: read in rank order, a plain greedy
    spends the 10 "absent" slots on LOW rows and leaves UNKNOWN short. The frame can fill every quota."""

    SPEC = {"format": "vens-kpi/1.0/quotas", "n": 100, "rows": V070["rows"], "margins": V070["margins"]}

    @staticmethod
    def rows():
        rng, rows = random.Random(14), []
        for count, severity, vectors in ((12, "UNKNOWN", ["absent"]), (80, "LOW", ["absent", "v3"]),
                                         (60, "CRITICAL", ["v3"]),
                                         (120, "HIGH", ["v3", "v3", "v3", "v2-only", "v4-only"]),
                                         (150, "MEDIUM", ["v3", "v3", "v3", "v2-only", "v4-only"])):
            rows += [{"id": f"CVE-2099-{len(rows) + i:05d}", "severity": severity, "vector": rng.choice(vectors)}
                     for i in range(count)]
        return rows

    @staticmethod
    def plain_greedy(rows, seed):
        taken = Counter()
        for row in sorted(rows, key=lambda r: hashlib.sha256(seed + r["id"].encode()).digest()):
            if taken[row["severity"]] < SEVERITY_QUOTAS[row["severity"]] and \
                    taken[row["vector"]] < VECTOR_QUOTAS[row["vector"]]:
                taken.update((row["severity"], row["vector"]))
        return sum(taken[value] for value in SEVERITY_QUOTAS)

    def test_the_walk_fills_what_a_plain_greedy_misses(self):
        rows, spec = self.rows(), s.parse_spec(self.SPEC)
        self.assertTrue(any(self.plain_greedy(rows, seed) < 100 for seed in seeds(10)))
        for seed in seeds(10):
            selected, report = s.sample(rows, spec, seed)
            self.assertEqual((len(selected), report["full"]), (100, True))


class TestReserve(unittest.TestCase):
    def test_the_first_tier_with_a_full_selection(self):
        rows = ([dict(row, tier=0) for row in frame(1500, seed=16, vector=(85, 8, 0, 7))]
                + [dict(row, tier=1) for row in frame(40, seed=17, vector=(0, 0, 1, 0), start=50000)]
                + [dict(row, tier=2) for row in frame(40, seed=18, start=60000)])
        chosen, report = draw(rows, dict(V070, reserve="tier"))
        self.assertEqual(report["reserve"], {"attribute": "tier", "last_tier": 2, "tier_used": 1})
        self.assertTrue(report["full"])
        self.assertTrue(all(row["tier"] <= 1 for row in chosen))

    def test_every_tier_then_a_refill(self):
        rows = [dict(row, tier=k % 3) for k, row in enumerate(frame(1500, seed=19, vector=(85, 8, 0, 7)))]
        _, report = draw(rows, dict(V070, reserve="tier"))
        margin = report["margins"][0]
        self.assertEqual(report["reserve"]["tier_used"], 2)
        self.assertEqual((margin["values"]["v4-only"]["selected"], margin["status"], margin["refilled"]),
                         (0, "refilled", 10))


class TestRefusals(unittest.TestCase):
    def test_specs(self):
        for doc in ({**V070, "format": "other"}, {**V070, "n": 0}, {**V070, "seed": "00"},
                    {**V070, "rows": {"attribute": "severity", "quotas": {"HIGH": 99}}},
                    {**V070, "rows": {"attribute": "severity", "quotas": {"HIGH": 100.0}}},
                    {**V070, "margins": [{"attribute": "severity", "quotas": VECTOR_QUOTAS}]},
                    {**V070, "caps": [{"attribute": "image", "max": 0}]},
                    {**V070, "minimums": [{"attribute": "x", "value": True, "min": 101}]},
                    {**V070, "minimums": [{"attribute": "x", "value": 1.5, "min": 1}]}):
            with self.subTest(doc=doc), self.assertRaises(Refused):
                s.parse_spec(doc)

    def test_rows(self):
        good, spec = frame(5, seed=20), s.parse_spec(V070)
        for rows in (good + [dict(good[0])], [{k: v for k, v in good[0].items() if k != "vector"}],
                     [dict(good[0], severity="NEGLIGIBLE")], [dict(good[0], vector=None)],
                     [dict(good[0], family="")], [dict(good[0], image=[])], [dict(good[0], id="")], ["row"],
                     [dict(good[0], id="\ud800")]):
            with self.subTest(rows=rows), self.assertRaises(Refused):
                s.sample(rows, spec, SEED)
        with self.assertRaises(Refused):
            s.sample([dict(good[0], tier=-1)], s.parse_spec(dict(V070, reserve="tier")), SEED)
        with self.assertRaises(Refused):
            s.sample(good, spec, SEED[:31])

    def test_a_refusal_names_the_row_and_field_never_a_value(self):
        good, spec = frame(5, seed=20), s.parse_spec(V070)
        for rows, said in (([*good[:2], dict(good[2], severity="CVE-2099-77777")], "frame row 3: field 'severity'"),
                           ([*good, dict(good[1])], "frame row 6 repeats the id of frame row 2"),
                           ([dict(good[0], id="\ud800")], "frame row 1: the id is not valid UTF-8")):
            with self.subTest(said=said), self.assertRaises(Refused) as caught:
                s.sample(rows, spec, SEED)
            self.assertIn(said, str(caught.exception))
            self.assertNotIn("CVE-2099", str(caught.exception))

    def test_a_duplicate_key_is_refused_without_its_name(self):
        with self.assertRaises(Refused) as caught:
            s.parse_frame(b'{"id": "a", "CVE-2099-1": 1, "CVE-2099-1": 2}\n', "frame")
        self.assertIn("a duplicate key", str(caught.exception))
        self.assertNotIn("CVE-2099", str(caught.exception))

    def test_a_line_separator_inside_a_json_string_is_not_a_new_row(self):
        rows = s.parse_frame('{"id": "a", "note": "x y\u0085z"}\r\n\n{"id": "b"}\n'.encode(), "frame")
        self.assertEqual([row["id"] for row in rows], ["a", "b"])


class TestSeed(unittest.TestCase):
    def test_the_context_binds_the_frame_the_spec_and_the_sampler(self):
        aggregate, spec, sampler = bytes(range(32)), b'{"n": 1}', bytes(32)
        spelled = ((32).to_bytes(8, "big") + b"vens-kpi/1.0/sets/sample-context" + aggregate
                   + hashlib.sha256(spec).digest() + sampler)
        context = s.context_hash(aggregate, spec, sampler)
        self.assertEqual(context, hashlib.sha256(spelled).digest())
        self.assertNotEqual(context, s.context_hash(bytes(32), spec, sampler))
        self.assertNotEqual(context, s.context_hash(aggregate, spec + b" ", sampler))
        self.assertNotEqual(context, s.context_hash(aggregate, spec, bytes([1]) * 32))

    def test_the_revision_covers_the_code(self):
        self.assertEqual(s.revision(), s.revision())
        self.assertEqual(len(s.revision()), 32)


class TestCli(unittest.TestCase):
    DOMAIN = "vens-kpi/1.0/test-draw"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        root = os.path.join(tmp.name, "sealed")
        os.makedirs(root)
        self.frame = os.path.join(root, "frame.jsonl")
        with open(self.frame, "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(row) + "\n" for row in frame(1500, seed=21))
        self.manifest, self.salts = (os.path.join(tmp.name, name) for name in ("manifest.json", "salts.json"))
        manifest, salts = commit.commit(root, "frame")
        for path, doc in ((self.manifest, manifest), (self.salts, salts)):
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
        self.spec = os.path.join(tmp.name, "quotas.json")
        with open(self.spec, "w", encoding="utf-8") as fh:
            json.dump(V070, fh)
        self.beacon = os.path.join(tmp.name, "beacon.json")
        with open(self.beacon, "w", encoding="utf-8") as fh:
            json.dump(drand.fetch(ROUND, get=recorded, now=NOW), fh)
        self.out = os.path.join(tmp.name, "private", "selection.json")
        os.makedirs(os.path.dirname(self.out))

    def call(self, *extra, out=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = s.main(["--frame", self.frame, "--frame-path", "frame.jsonl", "--manifest", self.manifest,
                           "--salts", self.salts, "--spec", self.spec, "--beacon", self.beacon, "--domain", self.DOMAIN,
                           "--out", out or self.out, *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def expected_seed(self):
        with open(self.spec, "rb") as fh:
            spec_bytes = fh.read()
        context = s.context_hash(bytes.fromhex(load_json(self.manifest, "manifest")["aggregate"]), spec_bytes,
                                 s.revision())
        return drand.derive_seed(self.DOMAIN, bytes.fromhex(load_json(self.beacon, "beacon")["randomness"]), context)

    def test_a_private_selection_from_the_beacon_and_counts_only_on_screen(self):
        code, out, _ = self.call()
        self.assertEqual(code, 0)
        self.assertIn("every quota met", out)
        self.assertNotIn("CVE-2099", out)
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)
        doc = load_json(self.out, "selection")
        with open(self.frame, "rb") as fh:
            self.assertEqual(doc["frame_sha256"], hashlib.sha256(fh.read()).hexdigest())
        self.assertEqual((doc["seed"], doc["binding"]["beacon_round"], doc["binding"]["sampler"]),
                         (self.expected_seed().hex(), ROUND, s.revision().hex()))
        self.assertEqual(len(doc["selected"]), 100)

    def test_a_seed_the_beacon_does_not_give_is_refused(self):
        self.assertEqual(self.call("--seed", self.expected_seed().hex())[0], 0)
        code, _, err = self.call("--seed", "00" * 32, out=os.path.join(self.tmp, "private", "other.json"))
        self.assertEqual(code, 2)
        self.assertIn("is not the seed", err)

    def test_a_frame_that_is_not_the_committed_one_is_refused(self):
        with open(self.frame, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(frame(1, seed=23, start=90000)[0]) + "\n")
        code, _, err = self.call()
        self.assertEqual(code, 2)
        self.assertIn("not the file the manifest commits", err)

    def test_an_output_inside_a_git_working_tree_is_refused(self):
        os.makedirs(os.path.join(self.tmp, "repo", ".git"))
        code, _, err = self.call(out=os.path.join(self.tmp, "repo", "selection.json"))
        self.assertEqual(code, 2)
        self.assertIn("git working tree", err)

    def test_nothing_is_overwritten(self):
        self.assertEqual(self.call()[0], 0)
        code, _, err = self.call()
        self.assertEqual(code, 2)
        self.assertIn("exists already", err)


if __name__ == "__main__":
    unittest.main()
