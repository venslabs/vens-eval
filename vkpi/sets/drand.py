"""The public random value of a draw: a round of drand's quicknet chain, fetched from relays of distinct operators
that must agree, its BLS signature checked against the chain's public key, then turned into a seed.

Quicknet is pinned below. Its chain hash is what drand computes from the other pinned values (chain.Info.Hash: the
period as 4 bytes and the genesis time as 8 bytes, big-endian, the public key, the group hash, the beacon id), and
`chain_hash()` recomputes it, so the public key is bound to the hash F0 freezes.

    round_at(t)           the round current at t, drand's CurrentRound: (t - genesis) // period + 1
    time_of_round(r)      when round r is emitted, drand's TimeOfRound: genesis + (r - 1) * period
    first_round_from(t)   the first round emitted at or after t, for "the first round at least 24 h after"
    seed = SHA-256(domain || randomness || context_hash)
        domain: printable ASCII, frozen in F0; randomness and context_hash: 32 bytes each, so the split is unambiguous

A beacon is accepted only if all of these hold:
    1. each relay's /info is the pinned chain info;
    2. the relays return the same round, randomness and signature;
    3. randomness = SHA-256(signature), drand's definition of it;
    4. e(signature, g2) = e(H(m), public key), m = SHA-256(round as 8 bytes, big-endian), H the RFC 9380 hash to G1
       with the DST below, computed by py_ecc 8.0.0.
`verify` re-checks 3 and 4 on a saved record, offline.

    python3 -m vkpi.sets.drand round TIME
    python3 -m vkpi.sets.drand fetch ROUND --out BEACON.json [--relay URL --relay URL ...]
    python3 -m vkpi.sets.drand verify BEACON.json
    python3 -m vkpi.sets.drand seed BEACON.json --domain DOMAIN --context-hash HEX
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from importlib import metadata
from types import SimpleNamespace

from vkpi.sets.common import Refused, from_hex, load_json, parse_json, pretty_json, write_new

CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
PUBLIC_KEY = ("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d"
              "1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a")
GROUP_HASH = "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e"
GENESIS_TIME = 1692803367
PERIOD = 3
SCHEME = "bls-unchained-g1-rfc9380"
BEACON_ID = "quicknet"
DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
RELAYS = ("https://api.drand.sh", "https://drand.cloudflare.com")
PY_ECC_VERSION = "8.0.0"
RECORD_FORMAT = "vens-kpi/1.0/drand-beacon"
RECORD_KEYS = {"chain_hash", "fetched_at", "format", "randomness", "relays", "round", "round_time", "scheme",
               "signature", "verified_with"}
TIMEOUT = 20
MAX_BODY = 1 << 16

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MICRO = 1_000_000
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})")
MAX_ROUND = (253402300799 - GENESIS_TIME) // PERIOD + 1  # the last round emitted before the year 10000


def chain_hash():
    """drand's chain hash of the pinned chain info."""
    digest = hashlib.sha256(PERIOD.to_bytes(4, "big") + GENESIS_TIME.to_bytes(8, "big", signed=True))
    digest.update(bytes.fromhex(PUBLIC_KEY))
    digest.update(bytes.fromhex(GROUP_HASH))
    digest.update(BEACON_ID.encode("ascii"))
    return digest.hexdigest()


def utc(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _micros(when):
    """An RFC 3339 time with its offset, or an aware datetime, as microseconds since the epoch."""
    if isinstance(when, str):
        if not _RFC3339.fullmatch(when):
            raise Refused(f"{when!r}: not an RFC 3339 time with its offset, such as 2026-11-27T09:00:00Z")
        try:
            when = datetime.fromisoformat(when)
        except ValueError as e:
            raise Refused(f"{when!r}: not a valid time: {e}") from e
    if not isinstance(when, datetime) or when.tzinfo is None:
        raise Refused(f"{when!r}: a time needs its offset, Z for UTC")
    return (when - _EPOCH) // timedelta(microseconds=1)


def _since_genesis(when):
    return _micros(when) - GENESIS_TIME * _MICRO


def round_at(when):
    """The round current at `when`: the last one emitted at or before it."""
    since = _since_genesis(when)
    if since < 0:
        raise Refused(f"{when}: before quicknet's genesis, {utc(GENESIS_TIME)}")
    return since // (PERIOD * _MICRO) + 1


def first_round_from(when):
    """The first round emitted at or after `when`."""
    since = _since_genesis(when)
    if since <= 0:
        return 1
    return -(-since // (PERIOD * _MICRO)) + 1


def check_round(round_number):
    if isinstance(round_number, bool) or not isinstance(round_number, int) or not 1 <= round_number <= MAX_ROUND:
        raise Refused(f"{round_number!r}: a round is an integer from 1 to {MAX_ROUND}")
    return round_number


def time_of_round(round_number):
    """When the round is emitted, in seconds since the epoch."""
    return GENESIS_TIME + (check_round(round_number) - 1) * PERIOD


def derive_seed(domain, randomness, context_hash):
    """SHA-256(domain || randomness || context_hash), as bytes."""
    if not isinstance(domain, str) or not domain or not domain.isascii() or not domain.isprintable():
        raise Refused(f"{domain!r}: a domain is a non-empty printable ASCII string")
    if len(randomness) != 32 or len(context_hash) != 32:
        raise Refused("the randomness and the context hash are 32 bytes each")
    return hashlib.sha256(domain.encode("ascii") + randomness + context_hash).digest()


def _curve():
    """py_ecc's BLS12-381 functions, once the installed py_ecc is the pinned one."""
    try:
        installed = metadata.version("py-ecc")
    except metadata.PackageNotFoundError as e:
        raise Refused(f"checking a drand signature needs py-ecc=={PY_ECC_VERSION} (pip install -e .)") from e
    if installed != PY_ECC_VERSION:
        raise Refused(f"py-ecc {installed} is installed; the draw is verified with py-ecc {PY_ECC_VERSION} only")
    from py_ecc.bls.hash_to_curve import hash_to_G1
    from py_ecc.bls.point_compression import decompress_G1, decompress_G2
    from py_ecc.optimized_bls12_381 import FQ12, G2, curve_order, final_exponentiate, is_inf, multiply, neg, pairing
    return SimpleNamespace(hash_to_G1=hash_to_G1, decompress_G1=decompress_G1, decompress_G2=decompress_G2, FQ12=FQ12,
                           G2=G2, curve_order=curve_order, final_exponentiate=final_exponentiate, is_inf=is_inf,
                           multiply=multiply, neg=neg, pairing=pairing)


def bls_verify(round_number, signature):
    """True when `signature` (48 bytes, a compressed G1 point) is quicknet's signature of the round."""
    curve = _curve()
    try:
        point = curve.decompress_G1(int.from_bytes(signature, "big"))
    except ValueError:
        return False
    if curve.is_inf(point) or not curve.is_inf(curve.multiply(point, curve.curve_order)):
        return False
    key = bytes.fromhex(PUBLIC_KEY)
    # The key is pinned and bound to the chain hash, so it is not re-checked for subgroup membership here.
    public = curve.decompress_G2((int.from_bytes(key[:48], "big"), int.from_bytes(key[48:], "big")))
    message = hashlib.sha256(check_round(round_number).to_bytes(8, "big")).digest()
    hashed = curve.hash_to_G1(message, DST, hashlib.sha256)
    product = (curve.pairing(public, hashed, final_exponentiate=False)
               * curve.pairing(curve.neg(curve.G2), point, final_exponentiate=False))
    return curve.final_exponentiate(product) == curve.FQ12.one()


def verify_record(record):
    """The record, once its randomness is SHA-256 of its signature and its signature verifies against quicknet."""
    if not isinstance(record, dict) or set(record) != RECORD_KEYS:
        raise Refused(f"a beacon record holds exactly {', '.join(sorted(RECORD_KEYS))}")
    if (record["format"], record["chain_hash"], record["scheme"]) != (RECORD_FORMAT, CHAIN_HASH, SCHEME):
        raise Refused("not a quicknet beacon record of this format")
    round_number = check_round(record["round"])
    if record["round_time"] != utc(time_of_round(round_number)):
        raise Refused(f"round {round_number} is emitted at {utc(time_of_round(round_number))}, "
                      f"not {record['round_time']}")
    if _micros(record["fetched_at"]) < time_of_round(round_number) * _MICRO:
        raise Refused(f"round {round_number}: fetched at {record['fetched_at']}, before it was emitted")
    if not isinstance(record["relays"], list) or not all(isinstance(relay, str) for relay in record["relays"]):
        raise Refused("relays: a list of origins")
    check_relays(record["relays"])
    if record["verified_with"] != f"py-ecc {PY_ECC_VERSION}":
        raise Refused(f"verified_with {record['verified_with']!r}: this code verifies with py-ecc {PY_ECC_VERSION}")
    randomness = from_hex(record["randomness"], 32, "randomness")
    signature = from_hex(record["signature"], 48, "signature")
    if hashlib.sha256(signature).digest() != randomness:
        raise Refused(f"round {round_number}: the randomness is not SHA-256 of the signature")
    if not bls_verify(round_number, signature):
        raise Refused(f"round {round_number}: the signature does not verify against quicknet's public key")
    return record


def _is_address(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def check_relays(relays):
    """Https origins named by hostname, without a trailing dot, of at least two operators. An operator is read from
    the hostname's last two labels (drand.sh, cloudflare.com): a heuristic, which is why the signature check, not
    this, is what counts."""
    relays = tuple(relays)
    operators = set()
    for relay in relays:
        url = urllib.parse.urlsplit(relay)
        if (url.scheme != "https" or not url.hostname or url.hostname.endswith(".") or "@" in url.netloc
                or url.path not in ("", "/") or url.query or url.fragment or _is_address(url.hostname)):
            raise Refused(f"{relay}: a relay is an https origin named by its hostname, such as {RELAYS[0]}")
        operators.add(".".join(url.hostname.lower().split(".")[-2:]))
    if len(operators) < 2:
        raise Refused("give relays of at least two operators, such as " + " and ".join(RELAYS))
    return tuple(relay.rstrip("/") for relay in relays)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_get(url):
    """The body of `url`; a redirect, an error status or an answer over MAX_BODY bytes is refused."""
    request = urllib.request.Request(url, headers={"User-Agent": "vens-kpi", "Accept": "application/json"})
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            body = response.read(MAX_BODY + 1)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise Refused(f"{url}: {e}") from e
    if len(body) > MAX_BODY:
        raise Refused(f"{url}: an answer larger than {MAX_BODY} bytes")
    return body


def _answer(get, url):
    try:
        text = get(url).decode("utf-8")
    except UnicodeDecodeError as e:
        raise Refused(f"{url}: not UTF-8") from e
    return parse_json(text, url)


def _check_info(info, relay):
    expected = {"public_key": PUBLIC_KEY, "period": PERIOD, "genesis_time": GENESIS_TIME, "hash": CHAIN_HASH,
                "groupHash": GROUP_HASH, "schemeID": SCHEME}
    if not isinstance(info, dict):
        raise Refused(f"{relay}: /info is not an object")
    for key, value in expected.items():
        if info.get(key) != value:
            raise Refused(f"{relay}: /info gives {key} = {info.get(key)!r}, quicknet's is {value!r}")
    meta = info.get("metadata")
    if not isinstance(meta, dict) or meta.get("beaconID") != BEACON_ID:
        raise Refused(f"{relay}: /info is not the {BEACON_ID} beacon")


def _beacon(answer, round_number, relay):
    if not isinstance(answer, dict) or type(answer.get("round")) is not int or answer["round"] != round_number:
        raise Refused(f"{relay}: the answer is not round {round_number}")
    randomness, signature = answer.get("randomness"), answer.get("signature")
    from_hex(randomness, 32, f"{relay}: randomness")
    from_hex(signature, 48, f"{relay}: signature")
    return randomness.lower(), signature.lower()


def fetch(round_number, relays=RELAYS, get=http_get, now=None):
    """The beacon record of `round_number`, once every relay agrees and the signature verifies."""
    check_round(round_number)
    relays = check_relays(relays)
    moment = time.time() if now is None else now
    due = time_of_round(round_number)
    if due > moment:
        raise Refused(f"round {round_number} is emitted at {utc(due)}, not yet")
    answers = {}
    for relay in relays:
        _check_info(_answer(get, f"{relay}/{CHAIN_HASH}/info"), relay)
        answers[relay] = _beacon(_answer(get, f"{relay}/{CHAIN_HASH}/public/{round_number}"), round_number, relay)
    if len(set(answers.values())) != 1:
        detail = "; ".join(f"{relay}: randomness {r}, signature {s}" for relay, (r, s) in answers.items())
        raise Refused(f"the relays disagree on round {round_number}: {detail}")
    randomness, signature = answers[relays[0]]
    record = {"chain_hash": CHAIN_HASH, "fetched_at": utc(int(moment)), "format": RECORD_FORMAT,
              "randomness": randomness, "relays": list(relays), "round": round_number, "round_time": utc(due),
              "scheme": SCHEME, "signature": signature, "verified_with": f"py-ecc {PY_ECC_VERSION}"}
    return verify_record(record)


def _cmd_round(args):
    current, upcoming = round_at(args.time), first_round_from(args.time)
    print(json.dumps({"time": args.time, "round_at": current, "round_at_time": utc(time_of_round(current)),
                      "first_round_from": upcoming, "first_round_from_time": utc(time_of_round(upcoming))},
                     indent=2))
    return 0


def _cmd_fetch(args):
    record = fetch(args.round, relays=args.relay or RELAYS)
    write_new(args.out, pretty_json(record))
    print(f"round {record['round']} ({record['round_time']}): randomness {record['randomness']}")
    print(f"relays agree ({', '.join(record['relays'])}); signature verified with {record['verified_with']}")
    return 0


def _cmd_verify(args):
    record = verify_record(load_json(args.beacon, "beacon"))
    print(f"ok: round {record['round']}, randomness {record['randomness']}, signature verified with "
          f"py-ecc {PY_ECC_VERSION}")
    return 0


def _cmd_seed(args):
    record = verify_record(load_json(args.beacon, "beacon"))
    context = from_hex(args.context_hash, 32, "--context-hash")
    print(derive_seed(args.domain, bytes.fromhex(record["randomness"]), context).hex())
    return 0


def _parser():
    parser = argparse.ArgumentParser(prog="python3 -m vkpi.sets.drand",
                                     description="drand quicknet: round times, verified beacons and draw seeds.")
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("round", help="the round current at TIME and the first one emitted at or after it")
    cmd.add_argument("time", help="RFC 3339 with its offset, such as 2026-11-27T09:00:00Z")
    cmd = sub.add_parser("fetch", help="fetch a past round, cross-check the relays and verify the signature")
    cmd.add_argument("round", type=int)
    cmd.add_argument("--out", required=True, help="the beacon record to write")
    cmd.add_argument("--relay", action="append", help=f"a relay origin, repeatable; default {' and '.join(RELAYS)}")
    cmd = sub.add_parser("verify", help="re-check a saved beacon record, offline")
    cmd.add_argument("beacon")
    cmd = sub.add_parser("seed", help="the seed of a draw from a verified beacon record")
    cmd.add_argument("beacon")
    cmd.add_argument("--domain", required=True, help="the domain string F0 freezes for this draw")
    cmd.add_argument("--context-hash", required=True, help="the committed context's SHA-256, in hex")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    commands = {"round": _cmd_round, "fetch": _cmd_fetch, "verify": _cmd_verify, "seed": _cmd_seed}
    try:
        return commands[args.command](args)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
