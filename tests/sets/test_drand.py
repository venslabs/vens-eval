"""drand: the round arithmetic, the seed and the beacon checks, on relay answers recorded on 2026-11-26.

No test reaches the network, except TestLive, which runs only with VKPI_LIVE_DRAND=1.
"""
import hashlib
import io
import json
import os
import random
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from vkpi.sets import drand as d
from vkpi.sets.common import Refused

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "drand")
with open(os.path.join(FIXTURES, "relays.json"), encoding="utf-8") as fh:
    RECORDED = json.load(fh)["answers"]

ROUND = 34282612
RANDOMNESS = "27a2cb1e12989c6c80d3b433e07350e4f08c0e37e561d3c1aac7a36b6aa5c7ae"
SIGNATURE = "b9a466c1fbb326fa2826af86c176f127628064401dd636cff6b174f151eee25ff02046db95652595bc85c9f7385bd949"
OTHER = 34297012
NOW = d.time_of_round(ROUND) + 60


def recorded(url):
    if url not in RECORDED:
        raise Refused(f"{url}: not recorded")
    return RECORDED[url].encode("utf-8")


def answer(host, round_number):
    return json.loads(RECORDED[f"https://{host}/{d.CHAIN_HASH}/public/{round_number}"])


def altered(host, path, change):
    """The recorded answers, with `change` applied to what `host` serves at `path`."""
    def get(url):
        if url == f"https://{host}/{d.CHAIN_HASH}/{path}":
            return json.dumps(change(json.loads(recorded(url)))).encode("utf-8")
        return recorded(url)
    return get


def both(path, change):
    def get(url):
        if url.endswith(f"/{d.CHAIN_HASH}/{path}"):
            return json.dumps(change(json.loads(recorded(url)))).encode("utf-8")
        return recorded(url)
    return get


class TestChain(unittest.TestCase):
    def test_the_pinned_info_hashes_to_the_chain_hash(self):
        self.assertEqual(d.chain_hash(), d.CHAIN_HASH)

    def test_the_recorded_info_is_the_pinned_one(self):
        for host in ("api.drand.sh", "drand.cloudflare.com"):
            info = json.loads(RECORDED[f"https://{host}/{d.CHAIN_HASH}/info"])
            self.assertEqual((info["public_key"], info["period"], info["genesis_time"], info["groupHash"],
                              info["schemeID"], info["metadata"]["beaconID"]),
                             (d.PUBLIC_KEY, d.PERIOD, d.GENESIS_TIME, d.GROUP_HASH, d.SCHEME, d.BEACON_ID))


class TestRounds(unittest.TestCase):
    def test_genesis_is_round_one(self):
        self.assertEqual(d.round_at("2023-08-23T15:09:27Z"), 1)
        self.assertEqual(d.time_of_round(1), d.GENESIS_TIME)
        self.assertEqual(d.first_round_from("2020-01-01T00:00:00Z"), 1)

    def test_the_recorded_rounds_fall_on_their_times(self):
        self.assertEqual(d.round_at("2026-11-26T00:00:00Z"), ROUND)
        self.assertEqual(d.round_at("2026-11-26T12:00:00Z"), OTHER)
        self.assertEqual(d.utc(d.time_of_round(ROUND)), "2026-11-26T00:00:00Z")
        self.assertEqual(d.utc(d.time_of_round(OTHER)), "2026-11-26T12:00:00Z")

    def test_inside_one_period(self):
        self.assertEqual(d.round_at("2026-11-26T00:00:02.999999Z"), ROUND)
        self.assertEqual(d.round_at("2026-11-26T00:00:03Z"), ROUND + 1)
        self.assertEqual(d.first_round_from("2026-11-26T00:00:00Z"), ROUND)
        self.assertEqual(d.first_round_from("2026-11-26T00:00:00.000001Z"), ROUND + 1)

    def test_an_offset_is_read(self):
        self.assertEqual(d.round_at("2026-11-26T01:00:00+01:00"), ROUND)

    def test_the_first_round_a_day_later(self):
        self.assertEqual(d.first_round_from("2026-11-27T00:00:00Z"), ROUND + 86400 // d.PERIOD)

    def test_drand_formulas_on_random_times(self):
        rng = random.Random(3)
        for _ in range(500):
            micros = rng.randrange(d.GENESIS_TIME * 10**6, 2_000_000_000 * 10**6)
            text = d.utc(micros // 10**6)[:-1] + f".{micros % 10**6:06d}Z"
            current, upcoming = d.round_at(text), d.first_round_from(text)
            self.assertEqual(current, (micros - d.GENESIS_TIME * 10**6) // (d.PERIOD * 10**6) + 1)
            self.assertLessEqual(d.time_of_round(current) * 10**6, micros)
            self.assertLess(micros, d.time_of_round(current + 1) * 10**6)
            self.assertLessEqual(micros, d.time_of_round(upcoming) * 10**6)
            self.assertIn(upcoming - current, (0, 1))

    def test_refused_times_and_rounds(self):
        for bad in ("2026-11-26T00:00:00", "yesterday", "2023-08-23T15:09:26Z", "20261127T090000Z",
                    "2026-11-27 09:00:00+00:00", "2026-13-01T00:00:00Z", "2026-11-27T09:00:00.1234567Z"):
            with self.subTest(time=bad), self.assertRaises(Refused):
                d.round_at(bad)
        for bad in (0, -1, True, 1.5, d.MAX_ROUND + 1, 1 << 62):
            with self.subTest(round=bad), self.assertRaises(Refused):
                d.time_of_round(bad)

    def test_the_last_round_still_prints(self):
        self.assertTrue(d.utc(d.time_of_round(d.MAX_ROUND)).startswith("9999-12-31T23:59:"))


class TestSeed(unittest.TestCase):
    CONTEXT = hashlib.sha256(b"frame").digest()

    def test_the_recorded_seed(self):
        seed = d.derive_seed("vens-kpi/1.0/test", bytes.fromhex(RANDOMNESS), self.CONTEXT)
        self.assertEqual(seed, hashlib.sha256(b"vens-kpi/1.0/test" + bytes.fromhex(RANDOMNESS) + self.CONTEXT).digest())
        self.assertEqual(seed.hex(), "20cdbc204c5809983d04bc8614dc87022b460b2d066723e9bd68fc8a18c2c1bc")

    def test_each_input_moves_the_seed(self):
        base = d.derive_seed("a", bytes.fromhex(RANDOMNESS), self.CONTEXT)
        self.assertNotEqual(base, d.derive_seed("b", bytes.fromhex(RANDOMNESS), self.CONTEXT))
        self.assertNotEqual(base, d.derive_seed("a", bytes.fromhex(RANDOMNESS), bytes(32)))
        self.assertNotEqual(base, d.derive_seed("a", bytes(32), self.CONTEXT))

    def test_refused_inputs(self):
        for domain, randomness, context in (("", bytes(32), bytes(32)), ("é", bytes(32), bytes(32)),
                                            ("a\nb", bytes(32), bytes(32)), ("a", bytes(31), bytes(32)),
                                            ("a", bytes(32), bytes(33))):
            with self.assertRaises(Refused):
                d.derive_seed(domain, randomness, context)


class TestFetch(unittest.TestCase):
    def fetch(self, get=recorded, **kwargs):
        return d.fetch(ROUND, get=get, now=kwargs.pop("now", NOW), **kwargs)

    def test_the_recorded_answers_give_a_verified_record(self):
        record = self.fetch()
        self.assertEqual((record["round"], record["randomness"], record["signature"]), (ROUND, RANDOMNESS, SIGNATURE))
        self.assertEqual(record["round_time"], "2026-11-26T00:00:00Z")
        self.assertEqual(record["relays"], list(d.RELAYS))
        self.assertEqual(record["verified_with"], "py-ecc 8.0.0")

    def test_relays_that_disagree(self):
        other = answer("drand.cloudflare.com", OTHER)
        get = altered("drand.cloudflare.com", f"public/{ROUND}", lambda a: {**other, "round": ROUND})
        with self.assertRaisesRegex(Refused, "relays disagree"):
            self.fetch(get)

    def test_a_relay_on_another_chain(self):
        get = altered("drand.cloudflare.com", "info", lambda info: {**info, "public_key": "00" * 96})
        with self.assertRaisesRegex(Refused, "public_key"):
            self.fetch(get)

    def test_a_relay_answering_another_round(self):
        get = altered("api.drand.sh", f"public/{ROUND}", lambda a: {**a, "round": ROUND + 1})
        with self.assertRaisesRegex(Refused, "not round"):
            self.fetch(get)

    def test_randomness_that_is_not_hashed_from_the_signature(self):
        get = both(f"public/{ROUND}", lambda a: {**a, "randomness": "00" * 32})
        with self.assertRaisesRegex(Refused, "not SHA-256 of the signature"):
            self.fetch(get)

    def test_a_signature_of_another_round(self):
        other = answer("api.drand.sh", OTHER)
        get = both(f"public/{ROUND}", lambda a: {**other, "round": ROUND})
        with self.assertRaisesRegex(Refused, "does not verify"):
            self.fetch(get)

    def test_relays_refused(self):
        for relays in (("https://api.drand.sh",), ("https://api.drand.sh", "https://api2.drand.sh"),
                       ("http://api.drand.sh", "https://drand.cloudflare.com"),
                       ("https://api.drand.sh/public", "https://drand.cloudflare.com"),
                       ("https://203.0.113.7", "https://drand.cloudflare.com"),
                       ("https://[2001:db8::1]", "https://drand.cloudflare.com"),
                       ("https://user@api.drand.sh", "https://drand.cloudflare.com"),
                       ("https://api.drand.sh", "https://api.drand.sh."),
                       ("https://API.drand.sh", "https://api.DRAND.sh.")):
            with self.subTest(relays=relays), self.assertRaises(Refused):
                self.fetch(relays=relays)

    def test_a_future_round_is_not_asked_for(self):
        def never(url):
            raise AssertionError(f"asked {url}")
        with self.assertRaisesRegex(Refused, "not yet"):
            self.fetch(never, now=d.time_of_round(ROUND) - 1)

    def test_a_relay_that_fails(self):
        def failing(url):
            if "cloudflare" in url:
                raise Refused(f"{url}: HTTP Error 503")
            return recorded(url)
        with self.assertRaisesRegex(Refused, "503"):
            self.fetch(failing)


class TestSignature(unittest.TestCase):
    def test_the_recorded_rounds_verify(self):
        for round_number in (1, ROUND, OTHER):
            signature = bytes.fromhex(answer("api.drand.sh", round_number)["signature"])
            self.assertTrue(d.bls_verify(round_number, signature))

    def test_a_flipped_bit_or_another_round_fails(self):
        signature = bytes.fromhex(SIGNATURE)
        self.assertFalse(d.bls_verify(ROUND + 1, signature))
        self.assertFalse(d.bls_verify(ROUND, signature[:-1] + bytes([signature[-1] ^ 1])))
        self.assertFalse(d.bls_verify(ROUND, bytes([0xC0]) + bytes(47)))

    def test_the_hash_to_g1_of_rfc_9380(self):
        from py_ecc.bls.hash_to_curve import hash_to_G1
        from py_ecc.optimized_bls12_381 import normalize
        dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"
        vectors = (  # RFC 9380, appendix J.9.1: msg, P.x, P.y
            (b"", "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
             "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"),
            (b"abc", "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
             "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"),
        )
        for message, x, y in vectors:
            px, py = normalize(hash_to_G1(message, dst, hashlib.sha256))
            self.assertEqual((int(px), int(py)), (int(x, 16), int(y, 16)))

    def test_a_saved_record_is_rechecked_offline(self):
        record = d.fetch(ROUND, get=recorded, now=NOW)
        self.assertIs(d.verify_record(record), record)
        for change in ({"randomness": "00" * 32}, {"round": ROUND + 1}, {"round_time": "2026-11-26T00:00:03Z"},
                       {"chain_hash": "00" * 32}, {"extra": 1}, {"verified_with": "py-ecc 7.0.1"},
                       {"relays": ["https://api.drand.sh"]}, {"relays": "https://api.drand.sh"},
                       {"fetched_at": "2026-11-25T23:59:59Z"}, {"fetched_at": "yesterday"},
                       {"round": 1 << 62}, {"randomness": RANDOMNESS[:-4] + "  00"}):
            with self.subTest(change=change), self.assertRaises(Refused):
                d.verify_record({**record, **change})


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = d.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def test_round(self):
        code, out, _ = run("round", "2026-11-26T00:00:00.5Z")
        self.assertEqual(code, 0)
        rounds = json.loads(out)
        self.assertEqual((rounds["round_at"], rounds["first_round_from"]), (ROUND, ROUND + 1))

    def test_verify_and_seed(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "beacon.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(d.fetch(ROUND, get=recorded, now=NOW), fh)
        self.assertEqual(run("verify", path)[0], 0)
        code, out, _ = run("seed", path, "--domain", "vens-kpi/1.0/test", "--context-hash",
                           hashlib.sha256(b"frame").hexdigest())
        self.assertEqual((code, out.strip()), (0, "20cdbc204c5809983d04bc8614dc87022b460b2d066723e9bd68fc8a18c2c1bc"))

    def test_a_refusal_exits_with_2(self):
        code, _, err = run("round", "2026-11-26T00:00:00")
        self.assertEqual(code, 2)
        self.assertIn("offset", err)
        code, _, err = run("fetch", str(1 << 62), "--out", os.devnull)
        self.assertEqual(code, 2)
        self.assertIn("a round is an integer", err)


@unittest.skipUnless(os.environ.get("VKPI_LIVE_DRAND") == "1", "reaches api.drand.sh and drand.cloudflare.com: "
                                                                 "set VKPI_LIVE_DRAND=1")
class TestLive(unittest.TestCase):
    def test_the_relays_still_serve_the_recorded_round(self):
        record = d.fetch(ROUND)
        self.assertEqual((record["randomness"], record["signature"]), (RANDOMNESS, SIGNATURE))


if __name__ == "__main__":
    unittest.main()
