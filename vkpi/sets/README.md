# vkpi/sets: commitments, the drand draw and the stratified sampler

The code is public. The sets it builds stay private until they are revealed.

| Module | What it does | What it writes |
|---|---|---|
| `commit` | salted commitments to a folder of private files | a public manifest, private salts |
| `drand` | the public random value of a draw, cross-checked and verified | a beacon record |
| `sample` | the deterministic stratified sample of a frame | a private selection |

Python 3.12. `pip install -e .` installs the pins of `pyproject.toml`; only `drand`'s signature check needs them.
Tests: `python3 -m unittest` from the repository root, $0 and offline; `VKPI_LIVE_DRAND=1` adds one live fetch.

## What stays private

- The committed files, their salts, the frame and the selection. `commit` refuses a salts path that lands inside a
  git working tree (`.git` entry, symbolic links followed), and `sample` an output path that does: write them to a
  private folder, then into the encrypted store.
- The seed is public once its round is out: the randomness is drand's, and the context hash is published. Anyone can
  then rerun the sampler on the frame, so the frame, image list included, is what keeps the selection sealed until
  the reveal.

## Commitments (`commit.py`)

With `frame(x)` = the length of `x` as 8 bytes, big-endian, followed by `x`:

```
file commitment = SHA-256( frame("vens-kpi/1.0/sets/file")
                         || salt             32 bytes from secrets.token_bytes, one per file, not framed
                         || frame(path)      the relative path, "/"-separated, UTF-8, as the manifest spells it
                         || frame(content) ) the file's bytes, unchanged

aggregate       = SHA-256( frame("vens-kpi/1.0/sets/aggregate") || frame(canonical) )
canonical       = {"files": {path: commitment}, "format": "vens-kpi/1.0/commitments", "set": name}
                  as JSON, keys sorted, no whitespace, ASCII
```

Every field has a fixed length or a length prefix, so no two (path, content) pairs give the same bytes. The salt
hides the content; the set name is bound into the aggregate.

Check values, from `tests/sets/test_commit.py`: salt = bytes 0 to 31, path `a/b.json`, content `{}` give
`95ac77d32ddad8357c93c2b29ae9e77d3104a81c033986c9e637b9451bc362a7`; that file alone in the set `demo` gives the
aggregate `95c6c63c1c7a533850614cd3ebfa503de983e8dfb4409dce71284b23516d60bc`.

The manifest is the canonical object plus `"aggregate"`; how it is laid out on disk plays no part. The salts file
holds `aggregate`, `format` (`vens-kpi/1.0/salts`), `salts` (path to 64 hex characters) and `set`, and is written
readable by its owner only.

Paths are public, so `commit` refuses a hidden file, a symbolic link, a special file, a name outside ASCII letters,
digits and `_ . + -`, and a path holding a CVE, GHSA or TEMP id, whatever the separator (`-`, `_`, `.`, `/` or
none). It never skips a file silently. The id check is a guard against slips, not a proof: name the files opaquely.

```
python3 -m vkpi.sets.commit commit ROOT --set NAME --manifest PUBLIC.json --salts PRIVATE.json
python3 -m vkpi.sets.commit verify ROOT --manifest PUBLIC.json --salts PRIVATE.json   # the whole set
python3 -m vkpi.sets.commit verify ROOT --manifest PUBLIC.json --salt HEX --file PATH # one file
python3 -m vkpi.sets.commit reveal --manifest PUBLIC.json --path PATH --salt HEX --content FILE
```

`verify` lists every file missing, added or changed, refuses salts from another commit, and refuses a file reached
through a symbolic link. `reveal` checks one revealed file (path, salt, content) against the public manifest alone.
Exit codes: 0 match, 1 mismatch, 2 refused.

## The draw (`drand.py`)

drand's quicknet chain, pinned:

| | |
|---|---|
| chain hash | `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` |
| genesis, period | 1692803367 (2023-08-23T15:09:27Z), 3 s |
| scheme | `bls-unchained-g1-rfc9380`: signatures on G1, public key on G2 |
| public key | `83cf0f28...ece45a` (in the code), bound to the chain hash |

drand's chain hash is SHA-256 of the period (4 bytes) and the genesis time (8 bytes), big-endian, then the public
key, the group hash and the beacon id. `chain_hash()` recomputes it from the pinned values, so the public key follows
from the hash F0 freezes.

**Rounds.** Round r is emitted at genesis + (r - 1) × 3 s. `round_at(t)` is the round current at t (drand's
CurrentRound), and `first_round_from(t)` the first round emitted at or after t, for "the first round at least 24 h
after the commitment". Times are RFC 3339 with an offset (`2026-11-27T09:00:00Z`); anything else is refused. A round
runs from 1 to the last one emitted before the year 10000.

**Fetch and verification.** `fetch(r)` asks each relay for `/info` and `/public/r`. The relays are https origins
named by hostname, never redirected, by default `https://api.drand.sh` and `https://drand.cloudflare.com`. They must
come from at least two operators, read from the hostnames' last two labels: a heuristic, which is why check 4, not
this one, is what the draw rests on. `fetch` refuses a round not yet emitted, and accepts the beacon only if:

1. each relay's `/info` is the pinned chain;
2. every relay returns the same round, randomness and signature;
3. randomness = SHA-256(signature);
4. the BLS signature verifies: e(signature, g2) = e(H(SHA-256(r as 8 bytes, big-endian)), public key), with H the
   RFC 9380 hash to G1 and the DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`.

**Status:** check 4 runs with py_ecc 8.0.0, the Ethereum Foundation's BLS12-381 code, pinned exactly; another
installed version is refused. The tests check py_ecc's hash to G1 against the vectors of RFC 9380 (appendix J.9.1),
three recorded quicknet beacons that verify, and a flipped bit or another round's signature that does not. The
relays' agreement is a second check, not the only one. `verify BEACON.json` reruns checks 3 and 4 offline, for
anyone holding the record, and checks its relays, that it was fetched after its round, and which py_ecc verified it.

**Seed.** `seed = SHA-256(domain || randomness || context_hash)`, the domain an ASCII string F0 freezes, the
randomness and the context hash (for instance the committed frame's aggregate) 32 bytes each.

```
python3 -m vkpi.sets.drand round 2026-11-27T09:00:00Z
python3 -m vkpi.sets.drand fetch ROUND --out BEACON.json
python3 -m vkpi.sets.drand verify BEACON.json
python3 -m vkpi.sets.drand seed BEACON.json --domain DOMAIN --context-hash HEX
```

## The sampler (`sample.py`)

**Frame.** JSONL, one object per line: a unique `id` and every attribute the spec names. A missing attribute, or a
stratum or margin value with no quota, is refused: nothing is invented. A refusal names the row by its position in
the frame, never by its id.

**Spec.** The sealed set of the v0.7.0 design:

```json
{
  "format": "vens-kpi/1.0/quotas",
  "n": 100,
  "rows": {"attribute": "severity", "quotas": {"CRITICAL": 20, "HIGH": 30, "MEDIUM": 30, "LOW": 10, "UNKNOWN": 10}},
  "margins": [{"attribute": "vector", "quotas": {"v3": 70, "v2-only": 10, "v4-only": 10, "absent": 10}}],
  "caps": [{"attribute": "image", "max": 25}],
  "minimums": [
    {"attribute": "multi_package", "value": true, "min": 10},
    {"attribute": "non_nvd_source", "value": true, "min": 10},
    {"attribute": "fixed_version", "value": true, "min": 40},
    {"attribute": "fixed_version", "value": false, "min": 40}
  ],
  "family": "family",
  "reserve": "tier"
}
```

- `rows`: the strata, exact; their quotas add up to n.
- `margins`: exact too, each adding up to n, each on its own attribute.
- `caps`: at most `max` rows per value. A list value (a CVE found in several images) counts toward each of its
  values.
- `minimums`: at least `min` rows whose attribute equals `value`, type included (`1` is not `true`).
- `family`: one row per value, for "one CVE per advisory/package family". A CVE in several families carries the key
  of their union.
- `reserve`: an integer, 0 for the main frame, then 1, 2, ... for the listed reserve in its order. Ids are unique
  across tiers: a CVE found in several tiers carries the lowest.

Only `format` and `n` are required, so the same tool draws the rotating batch (n = 30, a cap of 8 per ecosystem),
the INV bases or the sentinels.

**The rule**, written before any data exists:

1. **Order.** A row's rank is SHA-256(seed || id), the id in UTF-8. Rows are read by increasing rank, and the line
   order plays no part.
2. **One per family.** Each family keeps its lowest-rank row among the tiers in use, before any quota. A reserve row
   of lower rank can thus become its family's representative once its tier is in use.
3. **Reserve.** The sample is drawn from tiers 0 to k, for the smallest k at which nothing is short: no stratum, no
   minimum and no margin value, refilled or not. A margin value the main frame cannot fill calls the next reserve
   tier before any refill. Otherwise the sample is drawn from every tier.
4. **Greedy.** A row is taken only if it exceeds no quota (stratum, margin, cap, n) and keeps the quotas reachable:
   the most rows the remaining strata can still take, and for each margin the most rows the remaining strata and
   margin quotas can still take (a max-flow from strata to margin values over the selectable rows), each drop by
   exactly one. A row that fills a cap withdraws the rest of that cap's rows from those counts first, so it cannot
   quietly starve a stratum. Two passes:
   - *minimum*: the minimums one at a time, the scarcest first, each taking the rows that count toward it until it
     is met;
   - *quota*: any row.

   With one margin and no cap reached, this fills every stratum and margin quota the frame can fill; a test checks
   it against every subset of 400 small frames.
5. **Refill**, the pre-written rule. The rows a stratum still lacks are taken in order from that same stratum: first
   rows that fit every margin, then any row, the margins no longer binding. Caps hold, no stratum is exceeded, and a
   stratum the frame cannot fill stays short.
6. **Report.** Each stratum and minimum is `met` or `short`. Each margin value is `met`, `short`, or `over` by
   refill. Each margin is `met`, `refilled` (its whole shortfall taken from the same strata) or `short`. Each cap is
   `held`. Every line carries its counts, available rows included.

Precedence, highest first: caps and families, strata, margins, minimums. Only the refill goes past a margin quota,
and only by the rows it adds there.

```
python3 -m vkpi.sets.sample --frame FRAME.jsonl --spec QUOTAS.json --seed HEX --out SELECTION.json
```

The selection holds the ids in the order taken with their stage (`minimum`, `quota`, `refill`), the report, the seed
and the SHA-256 of the frame and of the spec. Rerunning it on the same three inputs gives the same bytes. The
screen shows counts only, never an id, refusals included.

**Determinism**, by test: the same inputs give the same bytes, a shuffled frame gives the same selection, the order
is SHA-256(seed || id), and `tests/sets/fixtures/sample/` pins one recorded selection (both passes, a refill, a
family rule, a cap reached, a reserve tier).
