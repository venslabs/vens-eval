"""A deterministic stratified sample: the frame rows a seed selects under exact strata and margins, caps, minimums
and families.

The rule, fixed before any data exists:

1. Order. A row's rank is SHA-256(seed || id), the id in UTF-8. Rows are read by increasing rank; the frame's line
   order plays no part.
2. A full selection has exactly n rows, every stratum and every margin value at its quota, every minimum met, no cap
   exceeded (a list value counts toward each of its values) and at most one row per family.
3. Reserve. With a reserve attribute (0 for the main frame, then 1, 2, ... for the listed reserve, in its order), the
   pool is tiers 0 to k for the smallest k at which a full selection exists; otherwise every tier.
4. Walk. Rows are read in rank order, and a row is kept if and only if the rows kept so far, this one included, can
   still be completed into the best selection the pool allows, from rows not yet read. When a full selection exists,
   that best is a full selection, and the walk returns the first one in rank order.
5. Best selection when no full selection exists: the most rows, no stratum, cap, family or n exceeded and margin
   values allowed past their quota; among those, the most rows within their margin quotas; among those, the most rows
   toward the minimums, each counted up to its minimum; then rank, by the walk. A row past its margin quota is the
   refill: it comes from its own stratum and never takes a stratum past its quota. Every shortfall is reported.
6. Exactness. Each check is one integer program over every constraint at once, solved by HiGHS through
   scipy.optimize.milp (scipy 1.18.1, numpy 2.5.4, no gap, no time limit), with presolve off and, only when that
   says infeasible, again with presolve on: "infeasible" needs both. Every selection either run returns is checked
   again in exact integer arithmetic before use, and the run stops if one fails.

    python3 -m vkpi.sets.sample policy --draw NAME --round ROUND --domain DOMAIN --manifest PUBLIC.json \\
        --spec QUOTAS.json --out POLICY.json
    python3 -m vkpi.sets.sample draw --frame FRAME.jsonl --frame-path PATH --manifest PUBLIC.json \\
        --salts PRIVATE.json --spec QUOTAS.json --policy POLICY.json --beacon BEACON.json --out SELECTION.json

The draw policy, published before its round, names the round, the domain, the frame's aggregate, the spec's SHA-256
and the sampler's revision; `draw` refuses any of them that differs. The seed is recomputed from the verified beacon:
SHA-256(domain || randomness || context), the context binding the frame's aggregate, the spec's bytes and the
sampler's revision (`context_hash`).
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from importlib import metadata
from types import SimpleNamespace

from vkpi.sets import commit, drand
from vkpi.sets.common import (Refused, decode, framed, from_hex, load_json, parse_json, pretty_json, read_bytes,
                              require_private, write_new)

SPEC_FORMAT = "vens-kpi/1.0/quotas"
SELECTION_FORMAT = "vens-kpi/1.0/selection"
SCIPY_VERSION = "1.18.1"
NUMPY_VERSION = "2.5.4"
CONTEXT_TAG = b"vens-kpi/1.0/sets/sample-context"
REVISION_TAG = b"vens-kpi/1.0/sets/sampler"
POLICY_FORMAT = "vens-kpi/1.0/draw-policy"
STAGES = ("quota", "refill")
_SPEC_KEYS = {"caps", "family", "format", "margins", "minimums", "n", "reserve", "rows"}
_POLICY_KEYS = {"domain", "draw", "format", "frame_aggregate", "round", "sampler", "spec_sha256"}
_DRAW_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_MISSING = object()


@dataclass(frozen=True)
class Margin:
    attribute: str
    quotas: dict


@dataclass(frozen=True)
class Cap:
    attribute: str
    max: int


@dataclass(frozen=True)
class Minimum:
    attribute: str
    value: object
    min: int


@dataclass(frozen=True)
class Spec:
    n: int
    rows: Margin | None
    margins: tuple
    caps: tuple
    minimums: tuple
    family: str | None
    reserve: str | None


@dataclass(frozen=True)
class _Row:
    id: str
    rank: bytes
    stratum: str
    cells: tuple
    caps: tuple
    marks: tuple
    family: str | None
    tier: int


def _count(value, what, least=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < least:
        raise Refused(f"{what}: an integer of at least {least}")
    return value


def _name(value, what):
    if not isinstance(value, str) or not value:
        raise Refused(f"{what}: an attribute name")
    return value


def _scalar(value):
    return isinstance(value, (str, int))


def _fields(doc, keys, what):
    if not isinstance(doc, dict) or set(doc) != keys:
        raise Refused(f"{what}: an object with exactly {', '.join(sorted(keys))}")
    return doc


def _list(value, what):
    if not isinstance(value, list):
        raise Refused(f"{what}: a list")
    return value


def _margin(doc, n, what):
    _fields(doc, {"attribute", "quotas"}, what)
    quotas = doc["quotas"]
    if not isinstance(quotas, dict) or not quotas:
        raise Refused(f"{what}: quotas map each value to its count")
    counts = {value: _count(count, f"{what} {value}") for value, count in quotas.items()}
    if sum(counts.values()) != n:
        raise Refused(f"{what}: the quotas add up to {sum(counts.values())}, not n = {n}")
    return Margin(_name(doc["attribute"], what), counts)


def _cap(doc, what):
    _fields(doc, {"attribute", "max"}, what)
    return Cap(_name(doc["attribute"], what), _count(doc["max"], f"{what} max", least=1))


def _minimum(doc, n, what):
    _fields(doc, {"attribute", "min", "value"}, what)
    if not _scalar(doc["value"]):
        raise Refused(f"{what}: the value is a string, an integer or a boolean")
    count = _count(doc["min"], f"{what} min")
    if count > n:
        raise Refused(f"{what}: a minimum of {count} cannot fit n = {n}")
    return Minimum(_name(doc["attribute"], what), doc["value"], count)


def parse_spec(doc):
    """The quota specification, checked: every margin adds up to n, each on its own attribute."""
    if not isinstance(doc, dict) or not set(doc) <= _SPEC_KEYS or doc.get("format") != SPEC_FORMAT:
        raise Refused(f"a spec is an object of format {SPEC_FORMAT}, keys among {', '.join(sorted(_SPEC_KEYS))}")
    n = _count(doc.get("n"), "n", least=1)
    rows = _margin(doc["rows"], n, "rows") if "rows" in doc else None
    margins = tuple(_margin(m, n, f"margins[{i}]") for i, m in enumerate(_list(doc.get("margins", []), "margins")))
    caps = tuple(_cap(c, f"caps[{i}]") for i, c in enumerate(_list(doc.get("caps", []), "caps")))
    minimums = tuple(_minimum(m, n, f"minimums[{i}]")
                     for i, m in enumerate(_list(doc.get("minimums", []), "minimums")))
    stratified = [m.attribute for m in margins] + ([rows.attribute] if rows else [])
    if len(set(stratified)) != len(stratified):
        raise Refused("each margin needs its own attribute, distinct from the strata's")
    family = _name(doc["family"], "family") if "family" in doc else None
    reserve = _name(doc["reserve"], "reserve") if "reserve" in doc else None
    return Spec(n, rows, margins, caps, minimums, family, reserve)


def _value(doc, attribute, where):
    value = doc.get(attribute, _MISSING)
    if value is _MISSING:
        raise Refused(f"{where}: field {attribute!r} missing, and nothing is invented")
    return value


def _cell(doc, margin, where):
    if not isinstance(_value(doc, margin.attribute, where), str) or doc[margin.attribute] not in margin.quotas:
        raise Refused(f"{where}: field {margin.attribute!r} holds a value with no quota")
    return doc[margin.attribute]


def _cap_keys(doc, index, cap, where):
    value = _value(doc, cap.attribute, where)
    values = value if isinstance(value, list) else [value]
    if not values or not all(_scalar(v) for v in values):
        raise Refused(f"{where}: field {cap.attribute!r} is not a string, an integer, a boolean or a non-empty list "
                      "of them")
    return {(index, type(v).__name__, v) for v in values}


def _same(a, b):
    return type(a) is type(b) and a == b


def _row(doc, spec, seed, where):
    """One frame row, parsed. A refusal names the row by `where`, its position in the frame, and the field, never a
    value: the frame is sealed."""
    if not isinstance(doc, dict):
        raise Refused(f"{where}: not an object")
    rid = doc.get("id")
    if not isinstance(rid, str) or not rid:
        raise Refused(f"{where}: field 'id' missing or not a string")
    try:
        encoded = rid.encode("utf-8")
    except UnicodeEncodeError as e:
        raise Refused(f"{where}: the id is not valid UTF-8") from e
    stratum = _cell(doc, spec.rows, where) if spec.rows else ""
    cells = tuple(_cell(doc, m, where) for m in spec.margins)
    caps = tuple(sorted(set().union(*(_cap_keys(doc, i, cap, where) for i, cap in enumerate(spec.caps)))))
    marks = tuple(_same(_value(doc, m.attribute, where), m.value) for m in spec.minimums)
    family = _value(doc, spec.family, where) if spec.family else None
    if spec.family and (not isinstance(family, str) or not family):
        raise Refused(f"{where}: field {spec.family!r} is not a non-empty string")
    tier = _value(doc, spec.reserve, where) if spec.reserve else 0
    if isinstance(tier, bool) or not isinstance(tier, int) or tier < 0:
        raise Refused(f"{where}: field {spec.reserve!r} is not an integer of at least 0")
    return _Row(rid, hashlib.sha256(seed + encoded).digest(), stratum, cells, caps, marks, family, tier)


def _pinned(package, version):
    try:
        installed = metadata.version(package)
    except metadata.PackageNotFoundError as e:
        raise Refused(f'the sampler needs {package}=={version}, from the sets extra: pip install -e ".[sets]"') from e
    if installed != version:
        raise Refused(f"{package} {installed} is installed; the sampler runs on {package} {version} only, from the "
                      'sets extra: pip install -e ".[sets]"')


def _solver():
    """scipy's MILP interface, once the installed scipy and numpy are the pinned ones."""
    _pinned("scipy", SCIPY_VERSION)
    _pinned("numpy", NUMPY_VERSION)
    import numpy
    from scipy.optimize import Bounds, LinearConstraint, milp
    from scipy.sparse import csr_array
    return SimpleNamespace(np=numpy, Bounds=Bounds, LinearConstraint=LinearConstraint, milp=milp, csr_array=csr_array)


def _groups(spec, pool):
    """The limits (each stratum, cap value and family of two rows or more, with its bound), then the rows of each
    margin value and of each minimum, as positions in the pool."""
    strata, caps, families, cells = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    marks = [[] for _ in spec.minimums]
    for i, row in enumerate(pool):
        strata[row.stratum].append(i)
        for key in row.caps:
            caps[key].append(i)
        if spec.family:
            families[row.family].append(i)
        for m, value in enumerate(row.cells):
            cells[(m, value)].append(i)
        for k, mark in enumerate(row.marks):
            if mark:
                marks[k].append(i)
    quotas = spec.rows.quotas if spec.rows else {"": spec.n}
    limits = [(quota, strata[value]) for value, quota in quotas.items()]
    limits += [(spec.caps[key[0]].max, members) for key, members in caps.items()]
    limits += [(1, members) for members in families.values() if len(members) > 1]
    return limits, cells, marks


class _Program:
    """The integer program of one pool in rank order: a 0/1 variable per row, then one per margin value (its kept
    rows, up to the quota) and one per minimum (its kept rows, up to the minimum)."""

    def __init__(self, spec, pool):
        self.lib, self.spec, self.pool = _solver(), spec, pool
        self.cells = [(m, value) for m, margin in enumerate(spec.margins) for value in margin.quotas]
        self.limits, self.cell_rows, self.mark_rows = _groups(spec, pool)
        self.limits_of, self.cells_of = [[] for _ in pool], [[] for _ in pool]
        for index, (_, members) in enumerate(self.limits):
            for i in members:
                self.limits_of[i].append(index)
        for j, cell in enumerate(self.cells):
            for i in self.cell_rows[cell]:
                self.cells_of[i].append(j)
        self._build()

    def _build(self):
        np, spec, size = self.lib.np, self.spec, len(self.pool)
        first_cell, first_mark = size, size + len(self.cells)
        self.width = first_mark + len(spec.minimums)
        entries, lower, upper = [], [], []

        def add(columns, low, high):
            entries.extend((len(lower), column, coefficient) for column, coefficient in columns)
            lower.append(low)
            upper.append(high)
            return len(lower) - 1

        self.total_row = add([(i, 1) for i in range(size)], 0, spec.n)
        for bound, members in self.limits:
            add([(i, 1) for i in members], 0, bound)
        for j, cell in enumerate(self.cells):
            add([(first_cell + j, 1)] + [(i, -1) for i in self.cell_rows[cell]], -np.inf, 0)
        for k, members in enumerate(self.mark_rows):
            add([(first_mark + k, 1)] + [(i, -1) for i in members], -np.inf, 0)
        self.margin_row = add([(first_cell + j, 1) for j in range(len(self.cells))], -np.inf, np.inf)
        self.minimum_row = add([(first_mark + k, 1) for k in range(len(spec.minimums))], -np.inf, np.inf)
        rows, columns, values = (list(part) for part in zip(*entries))
        self.matrix = self.lib.csr_array((values, (rows, columns)), shape=(len(lower), self.width))
        self.lower, self.upper = np.array(lower, dtype=float), np.array(upper, dtype=float)
        quotas = [spec.margins[m].quotas[value] for m, value in self.cells]
        self.high = np.array([1] * size + quotas + [m.min for m in spec.minimums], dtype=float)
        self.integrality = np.array([1] * size + [0] * (self.width - size))

    def _weights(self, part):
        """Minimised: minus the rows, minus the margin variables, minus the minimum variables, the rank, or nothing."""
        np, size = self.lib.np, len(self.pool)
        weights = np.zeros(self.width)
        if part == "rows":
            weights[:size] = -1
        elif part == "margins":
            weights[size:size + len(self.cells)] = -1
        elif part == "minimums":
            weights[size + len(self.cells):] = -1
        elif part == "rank":
            weights[:size] = np.arange(size)
        return weights

    def solve(self, part, total, within=0, toward=0, kept=(), passed=(), some=()):
        """The rows of a selection holding every limit and n, with a row count in `total` (low, high), at least
        `within` rows within margin quotas and `toward` toward the minimums, keeping `kept`, leaving `passed` and
        holding at least one row of `some` when given; None when there is none. `part` names the objective.

        HiGHS's presolve once answered "infeasible" for a feasible program (1 frame in 12,300, PR #6 review), so the
        program is solved with presolve off, and again with it on only when that says infeasible: None needs both. A
        selection either run returns is checked in exact integers, so a feasible answer stands on its own."""
        np = self.lib.np
        lower, upper = self.lower.copy(), self.upper.copy()
        lower[self.total_row], upper[self.total_row] = total
        lower[self.margin_row], lower[self.minimum_row] = within, toward
        low, high = np.zeros(self.width), self.high.copy()
        low[list(kept)], high[list(passed)] = 1, 0
        constraints = [self.lib.LinearConstraint(self.matrix, lower, upper)]
        if some:
            row = np.zeros(self.width)
            row[list(some)] = 1
            constraints.append(self.lib.LinearConstraint(row.reshape(1, -1), 1, np.inf))
        for presolve in (False, True):
            result = self.lib.milp(self._weights(part), integrality=self.integrality,
                                   bounds=self.lib.Bounds(low, high), constraints=constraints,
                                   options={"mip_rel_gap": 0, "presolve": presolve})
            if result.status != 2:
                break
        else:
            return None
        if result.status != 0:
            raise Refused(f"the solver gave no answer ({result.message}): the run stops")
        chosen = [i for i in range(len(self.pool)) if result.x[i] > 0.5]
        levels = self.measure(chosen)
        if (levels is None or not total[0] <= levels[0] <= total[1] or levels[1] < within or levels[2] < toward
                or not set(kept) <= set(chosen) or set(passed) & set(chosen) or (some and not set(some) & set(chosen))):
            raise Refused("the solver returned a selection that breaks the program: the run stops")
        return chosen

    def measure(self, chosen):
        """(rows, rows within margin quotas, rows toward the minimums) of a selection, in exact integers; None when it
        breaks a limit or n."""
        chosen = set(chosen)
        if len(chosen) > self.spec.n or any(len(chosen.intersection(m)) > bound for bound, m in self.limits):
            return None
        within = sum(min(len(chosen.intersection(self.cell_rows[cell])), self.spec.margins[cell[0]].quotas[cell[1]])
                     for cell in self.cells)
        toward = sum(min(len(chosen.intersection(members)), minimum.min)
                     for members, minimum in zip(self.mark_rows, self.spec.minimums))
        return len(chosen), within, toward

    def full_levels(self):
        spec = self.spec
        return spec.n, spec.n * len(spec.margins), sum(minimum.min for minimum in spec.minimums)

    def full(self):
        """A full selection of the pool, or None when there is none."""
        rows, within, toward = self.full_levels()
        return self.solve("rank", (rows, rows), within, toward)

    def best(self):
        """The best levels the pool allows, maximised in order (rows, rows within margin quotas, rows toward the
        minimums), and a selection that reaches them."""
        rows = len(self._sure(self.solve("rows", (0, self.spec.n))))
        within = self.measure(self._sure(self.solve("margins", (rows, rows))))[1]
        chosen = self._sure(self.solve("minimums", (rows, rows), within))
        return (rows, within, self.measure(chosen)[2]), chosen

    @staticmethod
    def _sure(chosen):
        if chosen is None:
            raise Refused("the solver found no selection where one exists: the run stops")
        return chosen

    def walk(self, levels, witness):
        """The rows kept in rank order: each one only if the levels stay reachable with it, from rows not yet read.

        `witness` is a selection reaching the levels: a row it holds is kept without a solve. Until a row is kept,
        whether a row can be kept does not depend on the rows passed before it, so the rows between the next one and
        the next row of the witness are tested together, then halved to find the first one that can be kept."""
        rows, within, toward = levels
        exact = (rows, within) == self.full_levels()[:2]
        kept, passed, current, tally = set(), set(), set(witness), Counter()
        i = 0
        while len(kept) < rows and i < len(self.pool):
            if i not in current:
                stop = min(j for j in current if j > i)
                block = [j for j in range(i, stop) if not self._blocked(j, tally, exact)]
                first, found = self._first_keepable(block, levels, kept, passed)
                passed.update(range(i, stop if first is None else first))
                if first is None:
                    i = stop
                    continue
                i, current = first, set(found)
            kept.add(i)
            tally.update(self.limits_of[i])
            tally.update(("cell", j) for j in self.cells_of[i])
            i += 1
        if len(kept) != rows:
            raise Refused("the walk ended short of the levels the pool allows: the run stops")
        return sorted(kept)

    def _first_keepable(self, block, levels, kept, passed):
        """The first row of `block` that can be kept, with a selection keeping it, or (None, None). The block's first
        row is tried alone, then the rest together, then halved."""
        rows, within, toward = levels

        def keeping(i):
            # A witness that favours early rows lets later rows be kept without a solve.
            return self.solve("rank", (rows, rows), within, toward, kept | {i}, passed)

        if not block:
            return None, None
        found = keeping(block[0])
        if found is not None:
            return block[0], found
        rest = block[1:]
        if not rest or self.solve("none", (rows, rows), within, toward, kept, passed, rest) is None:
            return None, None
        low, high = 0, len(rest)
        while high - low > 1:
            middle = (low + high) // 2
            if self.solve("none", (rows, rows), within, toward, kept, passed, rest[low:middle]) is None:
                low = middle
            else:
                high = middle
        return rest[low], keeping(rest[low])

    def _blocked(self, i, tally, exact):
        """True when the rows kept already fill one of this row's limits, or, in a full selection, its margin
        value."""
        if any(tally[index] >= self.limits[index][0] for index in self.limits_of[i]):
            return True
        return exact and any(tally[("cell", j)] >= self.spec.margins[self.cells[j][0]].quotas[self.cells[j][1]]
                             for j in self.cells_of[i])


def _choose(spec, pool, last):
    """The positions kept in the pool and whether they form a full selection; None when the pool has no full
    selection and a later reserve tier is left to try."""
    if not pool:
        return ([], False) if last else (None, False)
    program = _Program(spec, pool)
    witness = program.full()
    if witness is not None:
        return program.walk(program.full_levels(), witness), True
    if not last:
        return None, False
    levels, witness = program.best()
    return program.walk(levels, witness), False


def _stages(spec, rows):
    """Each kept row in rank order, marked refill when a margin value of its had reached its quota before it."""
    seen = [Counter() for _ in spec.margins]
    out = []
    for row in rows:
        over = False
        for m, value in enumerate(row.cells):
            over = over or seen[m][value] >= spec.margins[m].quotas[value]
            seen[m][value] += 1
        out.append((row, "refill" if over else "quota"))
    return out


def _quota_line(quota, selected, available):
    status = "met" if selected == quota else ("short" if selected < quota else "over")
    return {"available": available, "over": max(0, selected - quota), "quota": quota, "selected": selected,
            "shortfall": max(0, quota - selected), "status": status}


def _strata_report(spec, rows, pool):
    counts, available = Counter(r.stratum for r in rows), Counter(r.stratum for r in pool)
    values = {v: _quota_line(q, counts[v], available[v]) for v, q in spec.rows.quotas.items()}
    return {"attribute": spec.rows.attribute, "shortfall": sum(v["shortfall"] for v in values.values()),
            "values": values}


def _margin_report(rows, pool, m, margin):
    counts, available = Counter(r.cells[m] for r in rows), Counter(r.cells[m] for r in pool)
    values = {v: _quota_line(q, counts[v], available[v]) for v, q in margin.quotas.items()}
    shortfall = sum(v["shortfall"] for v in values.values())
    refilled = sum(v["over"] for v in values.values())
    status = "met" if shortfall == 0 else ("refilled" if refilled == shortfall else "short")
    return {"attribute": margin.attribute, "refilled": refilled, "shortfall": shortfall, "status": status,
            "values": values}


def _minimum_report(rows, pool, k, minimum):
    got = sum(r.marks[k] for r in rows)
    return {"attribute": minimum.attribute, "available": sum(r.marks[k] for r in pool), "min": minimum.min,
            "selected": got, "shortfall": max(0, minimum.min - got),
            "status": "met" if got >= minimum.min else "short", "value": minimum.value}


def _cap_report(rows, index, cap):
    counts = list(Counter(key for r in rows for key in r.caps if key[0] == index).values())
    largest = max(counts, default=0)
    return {"attribute": cap.attribute, "largest": largest, "max": cap.max,
            "status": "held" if largest <= cap.max else "exceeded",
            "values_at_max": sum(count == cap.max for count in counts)}


def _report(spec, pool, kept, full, tier, last_tier):
    rows = [row for row, _ in kept]
    stages = Counter(stage for _, stage in kept)
    return {
        "caps": [_cap_report(rows, i, cap) for i, cap in enumerate(spec.caps)],
        "family": None if spec.family is None else {"attribute": spec.family, "families": len({r.family for r in pool}),
                                                    "rows": len(pool)},
        "full": full,
        "margins": [_margin_report(rows, pool, m, margin) for m, margin in enumerate(spec.margins)],
        "minimums": [_minimum_report(rows, pool, k, minimum) for k, minimum in enumerate(spec.minimums)],
        "n": spec.n,
        "reserve": None if spec.reserve is None else {"attribute": spec.reserve, "last_tier": last_tier,
                                                      "tier_used": tier},
        "rows": None if spec.rows is None else _strata_report(spec, rows, pool),
        "selected": len(rows),
        "shortfall": spec.n - len(rows),
        "stages": {stage: stages[stage] for stage in STAGES},
    }


def has_shortfall(report):
    return bool(report["shortfall"] or any(m["shortfall"] for m in report["margins"])
                or any(m["shortfall"] for m in report["minimums"]))


def sample(frame, spec, seed):
    """The rows the seed selects, as {"id", "stage"} in rank order, and the report. `frame` is a list of row objects,
    `spec` a parsed Spec and `seed` 32 bytes."""
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise Refused("a seed is 32 bytes")
    parsed = [_row(doc, spec, seed, f"frame row {i}") for i, doc in enumerate(frame, 1)]
    first = {}
    for i, row in enumerate(parsed, 1):
        if row.id in first:
            raise Refused(f"frame row {i} repeats the id of frame row {first[row.id]}")
        first[row.id] = i
    rows = sorted(parsed, key=lambda row: (row.rank, row.id))
    tiers = sorted({row.tier for row in rows}) or [0]
    for tier in tiers:
        pool = [row for row in rows if row.tier <= tier]
        chosen, full = _choose(spec, pool, tier == tiers[-1])
        if chosen is not None:
            kept = _stages(spec, [pool[i] for i in chosen])
            return [{"id": row.id, "stage": stage} for row, stage in kept], _report(spec, pool, kept, full, tier,
                                                                                   tiers[-1])


def parse_frame(data, what):
    """The frame's rows from its bytes: JSON objects, one per line, lines split on "\\n" only."""
    text = decode(data, what)
    return [parse_json(line, f"{what} line {i}") for i, line in enumerate(text.split("\n"), 1) if line.strip()]


def read_frame(path):
    return parse_frame(read_bytes(path, "frame"), f"frame {path}")


def revision():
    """The sampler's revision: SHA-256 over every module of vkpi/sets, by name, each framed with its source, line ends
    as LF. Any change to the code changes it."""
    folder = os.path.dirname(os.path.abspath(__file__))
    digest = hashlib.sha256(framed(REVISION_TAG))
    for name in sorted(entry for entry in os.listdir(folder) if entry.endswith(".py") and entry[:-3].isidentifier()):
        source = read_bytes(os.path.join(folder, name), "source").replace(b"\r\n", b"\n")
        digest.update(framed(name.encode("ascii")) + framed(source))
    return digest.digest()


def context_hash(frame_aggregate, spec_bytes, sampler):
    """SHA-256(frame(tag) || frame aggregate || SHA-256 of the spec's bytes || sampler revision), the last three 32
    bytes each: what the seed binds besides the drand round and the domain."""
    if len(frame_aggregate) != 32 or len(sampler) != 32:
        raise Refused("the frame aggregate and the sampler revision are 32 bytes each")
    return hashlib.sha256(framed(CONTEXT_TAG) + frame_aggregate + hashlib.sha256(spec_bytes).digest()
                          + sampler).digest()


def summary(report):
    """The report in a few lines, counts only."""
    stages = report["stages"]
    lines = [f"selected {report['selected']} of n = {report['n']} (quota {stages['quota']}, refill "
             f"{stages['refill']}); {'a full selection' if report['full'] else 'no full selection in the pool'}"]
    if report["rows"]:
        lines += [f"{report['rows']['attribute']} {value}: {line['selected']} of {line['quota']}, short"
                  for value, line in report["rows"]["values"].items() if line["status"] != "met"]
    for margin in report["margins"]:
        lines += [f"{margin['attribute']} {value}: {line['selected']} of {line['quota']}, {line['status']}"
                  for value, line in margin["values"].items() if line["status"] != "met"]
        if margin["shortfall"]:
            lines.append(f"{margin['attribute']}: {margin['status']}, {margin['refilled']} of its "
                         f"{margin['shortfall']} missing rows taken from the same strata")
    lines += [f"minimum {m['attribute']} = {json.dumps(m['value'])}: {m['selected']} of at least {m['min']}, short"
              for m in report["minimums"] if m["status"] != "met"]
    if report["reserve"]:
        lines.append(f"reserve: tiers 0 to {report['reserve']['tier_used']} of {report['reserve']['last_tier']}")
    if not has_shortfall(report):
        lines.append("every quota met")
    return lines


def check_policy(policy):
    """A draw policy, checked: the draw's name, its round, its domain, and the three SHA-256 values it fixes."""
    if not isinstance(policy, dict) or set(policy) != _POLICY_KEYS or policy["format"] != POLICY_FORMAT:
        raise Refused(f"a draw policy is an object of format {POLICY_FORMAT}, with exactly "
                      f"{', '.join(sorted(_POLICY_KEYS))}")
    if not isinstance(policy["draw"], str) or not _DRAW_NAME.fullmatch(policy["draw"]):
        raise Refused("draw: a name of ASCII letters, digits and . _ -, at most 100 characters")
    drand.check_round(policy["round"])
    domain = policy["domain"]
    if not isinstance(domain, str) or not domain or not domain.isascii() or not domain.isprintable():
        raise Refused("domain: a non-empty printable ASCII string")
    for key in ("frame_aggregate", "sampler", "spec_sha256"):
        if not isinstance(policy[key], str) or not _DIGEST.fullmatch(policy[key]):
            raise Refused(f"{key}: 64 lowercase hex characters")
    return policy


def make_policy(draw, round_number, domain, frame_aggregate, spec_bytes):
    """The policy of one draw, to publish before its round: the round, the domain, and what the seed binds."""
    return check_policy({"domain": domain, "draw": draw, "format": POLICY_FORMAT, "frame_aggregate": frame_aggregate,
                         "round": round_number, "sampler": revision().hex(),
                         "spec_sha256": hashlib.sha256(spec_bytes).hexdigest()})


def _bind(args, frame_bytes, spec_bytes, policy_bytes):
    """The draw's seed, recomputed from the verified beacon record under the draw policy, and what it binds. The
    frame must be the file the manifest commits under --frame-path."""
    policy = check_policy(parse_json(decode(policy_bytes, f"policy {args.policy}"), f"policy {args.policy}"))
    manifest = load_json(args.manifest, "manifest")
    salts = commit.check_salts(load_json(args.salts, "salts file"), manifest)
    if args.frame_path not in salts:
        raise Refused(f"{commit.shown(args.frame_path)}: no salt for it in the salts file")
    if not commit.verify_file(manifest, args.frame_path, salts[args.frame_path], frame_bytes):
        raise Refused(f"{commit.shown(args.frame)}: not the file the manifest commits as "
                      f"{commit.shown(args.frame_path)}")
    record = drand.verify_record(load_json(args.beacon, "beacon"))
    sampler = revision()
    for what, got, named in (("round", record["round"], policy["round"]),
                             ("frame aggregate", manifest["aggregate"], policy["frame_aggregate"]),
                             ("spec's SHA-256", hashlib.sha256(spec_bytes).hexdigest(), policy["spec_sha256"]),
                             ("sampler revision", sampler.hex(), policy["sampler"])):
        if got != named:
            raise Refused(f"the {what} is not the one the draw policy names")
    context = context_hash(bytes.fromhex(manifest["aggregate"]), spec_bytes, sampler)
    seed = drand.derive_seed(policy["domain"], bytes.fromhex(record["randomness"]), context)
    if args.seed is not None and from_hex(args.seed, 32, "--seed") != seed:
        raise Refused("--seed is not the seed the beacon and the draw policy give")
    binding = {"beacon_round": record["round"], "context": context.hex(), "domain": policy["domain"],
               "draw": policy["draw"], "frame_aggregate": manifest["aggregate"], "frame_path": args.frame_path,
               "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(), "randomness": record["randomness"],
               "sampler": sampler.hex(), "spec_sha256": policy["spec_sha256"]}
    return seed, binding


def _cmd_policy(args):
    due = drand.time_of_round(drand.check_round(args.round))
    if due <= time.time():
        raise Refused(f"round {args.round} was emitted at {drand.utc(due)}: a policy names a round still to come")
    manifest = load_json(args.manifest, "manifest")
    commit.check_manifest(manifest)
    spec_bytes = read_bytes(args.spec, "spec")
    parse_spec(parse_json(decode(spec_bytes, f"spec {args.spec}"), f"spec {args.spec}"))
    data = pretty_json(make_policy(args.draw, args.round, args.domain, manifest["aggregate"], spec_bytes))
    write_new(args.out, data)
    print(f"draw policy {args.out}, SHA-256 {hashlib.sha256(data).hexdigest()}")
    print(f"publish it before round {args.round}, emitted at {drand.utc(due)}")
    return 0


def _cmd_draw(args):
    require_private(args.out, "the selection")
    if os.path.lexists(args.out):
        raise Refused(f"{args.out} exists already: nothing is overwritten")
    frame_bytes, spec_bytes, policy_bytes = (read_bytes(path, what) for path, what in
                                             ((args.frame, "frame"), (args.spec, "spec"), (args.policy, "policy")))
    seed, binding = _bind(args, frame_bytes, spec_bytes, policy_bytes)
    spec = parse_spec(parse_json(decode(spec_bytes, f"spec {args.spec}"), f"spec {args.spec}"))
    selected, report = sample(parse_frame(frame_bytes, f"frame {args.frame}"), spec, seed)
    document = {"binding": binding, "format": SELECTION_FORMAT, "report": report, "seed": seed.hex(),
                "frame_sha256": hashlib.sha256(frame_bytes).hexdigest(), "selected": selected}
    write_new(args.out, pretty_json(document), private=True)
    for line in summary(report):
        print(line)
    print(f"seed {seed.hex()} from round {binding['beacon_round']}; sampler revision {binding['sampler']}")
    return 0


def _parser():
    parser = argparse.ArgumentParser(prog="python3 -m vkpi.sets.sample",
                                     description="A deterministic stratified sample of a committed frame.")
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("policy", help="write a draw policy, to publish before its round")
    cmd.add_argument("--draw", required=True, help="the draw's name, such as sealed-v0.7.0")
    cmd.add_argument("--round", required=True, type=int, help="the quicknet round, still to come")
    cmd.add_argument("--domain", required=True, help="the draw's domain string")
    cmd.add_argument("--manifest", required=True, help="the public manifest that commits the frame")
    cmd.add_argument("--spec", required=True, help=f"the quotas, format {SPEC_FORMAT}")
    cmd.add_argument("--out", required=True, help="the policy to write")
    cmd = sub.add_parser("draw", help="draw the sample under a published draw policy")
    cmd.add_argument("--frame", required=True, help="JSONL, one object per line: an id and the spec's attributes")
    cmd.add_argument("--frame-path", required=True, help="the frame's path in the commitment manifest")
    cmd.add_argument("--manifest", required=True, help="the public manifest that commits the frame")
    cmd.add_argument("--salts", required=True, help="that commitment's private salts")
    cmd.add_argument("--spec", required=True, help=f"the quotas, format {SPEC_FORMAT}")
    cmd.add_argument("--policy", required=True, help="the draw policy, published before the round")
    cmd.add_argument("--beacon", required=True, help="the drand beacon record of the policy's round")
    cmd.add_argument("--seed", help="the seed expected, in hex; refused unless the beacon and the policy give it")
    cmd.add_argument("--out", required=True, help="the selection to write, outside every git working tree")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        return {"policy": _cmd_policy, "draw": _cmd_draw}[args.command](args)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
