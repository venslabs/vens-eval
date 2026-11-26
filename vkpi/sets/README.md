# vkpi/sets: commitments, the drand draw and the stratified sampler

The code is public. The sets it builds stay private until they are revealed.

| Module | What it does | What it writes |
|---|---|---|
| `commit` | salted commitments to a folder of private files | a public manifest, private salts |
| `drand` | the public random value of a draw, cross-checked and verified | a beacon record |
| `sample` | the deterministic stratified sample of a frame | a private selection |

Python 3.12. The base install of vens-kpi is the standard library alone; the set tools take the `sets` extra,
`pip install -e ".[sets]"`, which installs the exact pins of `pyproject.toml`: py_ecc for `drand`'s signature check,
scipy and numpy for `sample`'s integer programs. `commit` needs none of them. Without the extra, `drand`'s signature
check and `sample` refuse to run and name it, and they refuse any other version of these packages too.

Tests: `python3 -m unittest discover -s tests -t .` from the repository root, $0 and offline; `VKPI_LIVE_DRAND=1` adds
one live fetch. CI installs the extra before running every test.

## What stays private

- The committed files, their salts, the frame and the selection. `commit` refuses a salts path that lands inside a
  git working tree (`.git` entry, symbolic links followed), and `sample` an output path that does: write them to a
  private folder, then into the encrypted store.
- The seed is public once its round is out: the randomness is drand's, and the context hash is published. Anyone can
  then rerun the sampler on the frame, so the frame, image list included, is what keeps the selection sealed until
  the reveal.
- A refusal never echoes what it refuses: it names the file, the line or row, the field and the kind of error, never
  a value or a key of the frame.

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
randomness and the context hash 32 bytes each. For a sample, the context binds the frame, the spec and the sampler
(see below), and `sample` recomputes the seed itself from the verified record.

```
python3 -m vkpi.sets.drand round 2026-11-27T09:00:00Z
python3 -m vkpi.sets.drand fetch ROUND --out BEACON.json
python3 -m vkpi.sets.drand verify BEACON.json
python3 -m vkpi.sets.drand seed BEACON.json --domain DOMAIN --context-hash HEX
```

## The sampler (`sample.py`)

**Frame.** JSONL, one object per line: a unique `id` and every attribute the spec names. A missing attribute, or a
stratum or margin value with no quota, is refused: nothing is invented. A refusal names the row by its position in
the frame and the field, never the id or the value.

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
- `family`: at most one row per value, for "one CVE per advisory/package family". A CVE in several families carries
  the key of their union.
- `reserve`: an integer, 0 for the main frame, then 1, 2, ... for the listed reserve in its order. Ids are unique
  across tiers: a CVE found in several tiers carries the lowest.

Only `format` and `n` are required, so the same tool draws the rotating batch (n = 30, a cap of 8 per ecosystem),
the INV bases or the sentinels.

**The rule**, written before any data exists:

1. **Order.** A row's rank is SHA-256(seed || id), the id in UTF-8. Rows are read by increasing rank, and the line
   order plays no part.
2. **Full selection.** Exactly n rows, every stratum and every margin value at its quota, every minimum met, no cap
   exceeded and at most one row per family, all at once.
3. **Reserve.** The pool is tiers 0 to k, for the smallest k at which a full selection exists; otherwise every tier.
   A margin value the main frame cannot fill thus calls the next reserve tier before any refill.
4. **Walk.** Rows are read in rank order. A row is kept if and only if the rows kept so far, this one included, can
   still be completed into the best selection the pool allows, from rows not yet read. When a full selection exists,
   the walk returns the first full selection in rank order. A family gives the first of its rows that fits.
5. **No full selection.** The best selection then has, in this order of priority:
   - the most rows, with no stratum, cap, family or n exceeded and margin values allowed past their quota;
   - among those, the most rows within their margin quotas;
   - among those, the most rows toward the minimums, each counted up to its minimum;
   - among those, the first in rank order, by the walk.

   A row past its margin quota is the pre-written refill: it comes from its own stratum and never takes a stratum
   past its quota. A stratum the pool cannot fill stays short, and every shortfall is reported.
6. **Report.** Each stratum and minimum is `met` or `short`. Each margin value is `met`, `short`, or `over` by
   refill. Each margin is `met`, `refilled` (its whole shortfall taken from the same strata) or `short`. Each cap is
   `held`. `full` says whether the pool had a full selection. A kept row is marked `refill` when, in rank order, it
   comes after one of its margin values reached its quota, otherwise `quota`.

Precedence, highest first: caps, families and n, strata, margins, minimums, rank.

**Exactness.** Every keep-or-pass decision, and every level in step 5, is an integer program over all the
constraints at once: one 0/1 variable per row, one per margin value and one per minimum. HiGHS solves it through
`scipy.optimize.milp`: scipy 1.18.1 and numpy 2.5.4, pinned and enforced at run time, no gap, no time limit. A row's
answer cannot change until a row is kept, so the rows up to the next one the last solution keeps are tested together,
and halved to find the first that fits; the decisions are those of the row-by-row walk.

Limits, stated:
- **Infeasible needs both solver settings.** Each program is solved with presolve off, and again with presolve on
  only when the first run says infeasible. "Infeasible" is the answer only when both say so; a selection either run
  returns is checked in exact integers, so a feasible answer stands on its own.
  - Why: with presolve on, HiGHS once called a feasible program infeasible. That was 1 frame in 12,300 of the review's
    brute force, and over about 176,000 calls the two settings disagreed twice, presolve on saying infeasible both
    times. With presolve off, 0 frames in 15,000 differed.
  - After the fix, 18,000 frames of the same brute force give 0 differences (seed 4: 3,000; seeds 5 to 8: 3,750
    each). In the last 15,000, presolve off said infeasible 58,860 times and presolve on agreed every time.
  - An infeasibility answer still carries no certificate: it is the solver's, twice.
- **Every selection is re-checked.** Each selection the solver returns is checked in exact integer arithmetic before
  use. The run stops on a mismatch, or on any answer other than optimal or infeasible.
- **Tests.**
  - The selection is compared with a brute force over every subset of the review's 3,000 seed-4 frames: strata, up to
    two margins, single and list-valued caps, typed minimums, families, reserve tiers.
  - The five frames that once went wrong are run as tests: four where the earlier look-ahead ended short, and the one
    where presolve answered wrongly.
- **Time:** about 1 to 3 s for n = 100 on frames of 1,000 to 5,000 rows on a laptop, depending on how tight the frame
  is; about 6 s for 10,000 rows.

**The draw policy.** Every input of the seed that someone could re-draw after the round is fixed beforehand, in a
public file published before the round: re-salting the frame, adding a space to the spec, touching the code, or
choosing another round or domain would each give a new seed. F0 signs one policy per draw. It names:
- the draw;
- the round;
- the domain;
- the frame's aggregate, from its commitment manifest;
- the spec file's SHA-256;
- the sampler revision.

`policy` writes it, and refuses a round already emitted. `draw` refuses any of these that differs:
- the beacon's round;
- the manifest's aggregate;
- the spec's bytes;
- the code's revision.

`draw` takes the domain from the policy. Whether the policy was published before its round is a fact of the public
git history, not something the tool can check.

**Seed and context.** `sample` takes no free seed. It verifies the beacon record and checks that the frame is the
file the manifest commits under `--frame-path`, with its salt. Then it computes:

```
context = SHA-256( frame("vens-kpi/1.0/sets/sample-context") || frame aggregate (32 bytes, from the manifest)
                   || SHA-256 of the spec file's bytes || sampler revision )
seed    = SHA-256( domain || randomness || context )
```

The sampler revision is SHA-256 over every module of `vkpi/sets`, by name, each framed with its source (line ends as
LF). `--seed` is optional, and accepted only when it equals the seed recomputed from the record and the policy.

```
python3 -m vkpi.sets.sample policy --draw NAME --round ROUND --domain DOMAIN --manifest PUBLIC.json \
    --spec QUOTAS.json --out POLICY.json
python3 -m vkpi.sets.sample draw --frame FRAME.jsonl --frame-path PATH --manifest PUBLIC.json --salts PRIVATE.json \
    --spec QUOTAS.json --policy POLICY.json --beacon BEACON.json --out SELECTION.json
```

Each input is read once: what is hashed and committed is what is parsed. The selection holds:
- the ids in rank order, with their stage;
- the report;
- the seed and what it binds: draw, round, randomness, domain, context, frame aggregate and path, spec hash, sampler
  revision, and the policy's SHA-256;
- the frame's SHA-256.

The screen shows counts only, never an id, refusals included.

**Determinism**, by test: the same inputs give the same bytes, a shuffled frame gives the same selection, the order
is SHA-256(seed || id), and `tests/sets/fixtures/sample/` pins one recorded selection (a refill, families, a cap
reached, a reserve tier).
