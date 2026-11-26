"""A deterministic stratified sample: the frame rows a seed selects under exact margins, caps and minimums.

The rule, fixed before any data exists:

1. Order. A row's rank is SHA-256(seed || id), the id in UTF-8; rows are read by increasing rank, ties broken by id.
   The frame's line order plays no part.
2. One per family. With a family key, each family keeps its lowest-rank row among the tiers in use, before any
   quota applies.
3. Reserve. With a reserve attribute (0 for the main frame, then 1, 2, ... for the listed reserve, in its order), the
   sample is drawn from tiers 0 to k for the smallest k at which nothing is short: no stratum, no minimum and no
   margin value, refilled or not. Otherwise it is drawn from every tier.
4. Greedy. Two passes over the order; a row is taken only if
     - it exceeds no quota: its stratum's (`rows`), each margin's, each cap and the total n; and
     - it keeps the strata and every margin reachable: the most rows the remaining stratum quotas can still take
       from the selectable rows, and for each margin the most rows the remaining stratum and margin quotas can still
       take (a max-flow from strata to margin values), each drop by exactly one. A cap the row fills withdraws the
       rest of that cap's rows first, so a row that would starve a stratum through a cap waits.
   The "minimum" pass takes the minimums one at a time, the scarcest first (fewest matching rows, ties in the spec's
   order), each with the rows that count toward it until it is met; the "quota" pass then takes any row. With one
   margin and no cap reached, the greedy fills every stratum and margin quota the frame can fill.
5. Refill. The rows a stratum still lacks are taken in order from that same stratum: first rows that fit every
   margin, then any row, the margins no longer binding. Caps still hold, no stratum is exceeded and nothing is
   invented: a stratum the frame cannot fill stays short.
6. Report. Each stratum and minimum is met or short; each margin value met, short, or over by refill; each margin
   met, refilled (its whole shortfall taken from the same strata) or short; each cap held.

Precedence, highest first: caps and families, strata, margins, minimums.

    python3 -m vkpi.sets.sample --frame FRAME.jsonl --spec QUOTAS.json --seed HEX --out SELECTION.json
"""
import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from vkpi.sets.common import (Refused, from_hex, load_json, parse_json, pretty_json, require_private, sha256_file,
                              write_new)

SPEC_FORMAT = "vens-kpi/1.0/quotas"
SELECTION_FORMAT = "vens-kpi/1.0/selection"
STAGES = ("minimum", "quota", "refill")
_SPEC_KEYS = {"caps", "family", "format", "margins", "minimums", "n", "reserve", "rows"}
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
        raise Refused(f"{where}: no {attribute!r}, and nothing is invented")
    return value


def _cell(doc, margin, where):
    value = _value(doc, margin.attribute, where)
    if not isinstance(value, str) or value not in margin.quotas:
        raise Refused(f"{where}: {margin.attribute} = {value!r} has no quota; the quotas name "
                      f"{', '.join(margin.quotas)}")
    return value


def _cap_keys(doc, index, cap, where):
    value = _value(doc, cap.attribute, where)
    values = value if isinstance(value, list) else [value]
    if not values or not all(_scalar(v) for v in values):
        raise Refused(f"{where}: {cap.attribute} is a string, an integer, a boolean or a non-empty list of them")
    return {(index, type(v).__name__, v) for v in values}


def _same(a, b):
    return type(a) is type(b) and a == b


def _row(doc, spec, seed, where):
    """One frame row, parsed. A refusal names the row by `where`, its position in the frame, never by its id, which
    is sealed."""
    if not isinstance(doc, dict):
        raise Refused(f"{where}: not an object")
    rid = doc.get("id")
    if not isinstance(rid, str) or not rid:
        raise Refused(f"{where}: no id")
    stratum = _cell(doc, spec.rows, where) if spec.rows else ""
    cells = tuple(_cell(doc, m, where) for m in spec.margins) if spec.margins else ("",)
    caps = tuple(sorted(set().union(*(_cap_keys(doc, i, cap, where) for i, cap in enumerate(spec.caps)))))
    marks = tuple(_same(_value(doc, m.attribute, where), m.value) for m in spec.minimums)
    family = _value(doc, spec.family, where) if spec.family else None
    if spec.family and (not isinstance(family, str) or not family):
        raise Refused(f"{where}: {spec.family} is a non-empty string")
    tier = _value(doc, spec.reserve, where) if spec.reserve else 0
    if isinstance(tier, bool) or not isinstance(tier, int) or tier < 0:
        raise Refused(f"{where}: {spec.reserve} is an integer of at least 0")
    rank = hashlib.sha256(seed + rid.encode("utf-8")).digest()
    return _Row(rid, rank, stratum, cells, caps, marks, family, tier)


def max_flow(supply, demand, capacity):
    """The most rows the remaining quotas can take: a flow from strata (`supply`) to margin values (`demand`) through
    `capacity[(stratum, value)]`, the selectable rows of each pair."""
    graph = defaultdict(dict)

    def link(a, b, amount):
        graph[a][b] = graph[a].get(b, 0) + amount
        graph[b].setdefault(a, 0)

    for stratum, amount in supply.items():
        link("source", ("stratum", stratum), amount)
    for value, amount in demand.items():
        link(("value", value), "sink", amount)
    for (stratum, value), amount in capacity.items():
        if amount > 0 and stratum in supply and value in demand:
            link(("stratum", stratum), ("value", value), amount)
    total = 0
    while (path := _augmenting_path(graph)) is not None:
        push = min(graph[a][b] for a, b in path)
        for a, b in path:
            graph[a][b] -= push
            graph[b][a] += push
        total += push
    return total


def _augmenting_path(graph):
    parent = {"source": None}
    queue = deque(["source"])
    while queue:
        node = queue.popleft()
        for nxt, room in graph[node].items():
            if room > 0 and nxt not in parent:
                parent[nxt] = node
                queue.append(nxt)
    if "sink" not in parent:
        return None
    path, node = [], "sink"
    while parent[node] is not None:
        path.append((parent[node], node))
        node = parent[node]
    return path


def _left(quotas, counts, extra=None):
    """The quotas still open, one fewer for the value `extra` takes."""
    out = {}
    for value, quota in quotas.items():
        left = quota - counts[value] - (value == extra)
        if left > 0:
            out[value] = left
    return out


def _quota_line(quota, selected, available):
    status = "met" if selected == quota else ("short" if selected < quota else "over")
    return {"available": available, "over": max(0, selected - quota), "quota": quota, "selected": selected,
            "shortfall": max(0, quota - selected), "status": status}


class _Draw:
    """One draw over a pool in rank order: the passes, then the report."""

    def __init__(self, spec, pool):
        self.spec = spec
        self.pool = pool
        self.strata_quota = spec.rows.quotas if spec.rows else {"": spec.n}
        self.margins = spec.margins or (Margin("", {"": spec.n}),)
        self.taken, self.taken_ids, self.blocked = [], set(), set()
        self.strata, self.cap_counts = Counter(), Counter()
        self.cells = [Counter() for _ in self.margins]
        self.marks = [0] * len(spec.minimums)
        self.by_cap = defaultdict(list)
        self.avail = [Counter() for _ in self.margins]
        for row in pool:
            for key in row.caps:
                self.by_cap[key].append(row)
            for m, cell in enumerate(row.cells):
                self.avail[m][(row.stratum, cell)] += 1
        self.reach = self._reach()

    def run(self):
        available = [sum(row.marks[k] for row in self.pool) for k in range(len(self.spec.minimums))]
        for k in sorted(range(len(available)), key=lambda k: (available[k], k)):
            for row in self.pool:
                if self.marks[k] >= self.spec.minimums[k].min:
                    break
                if row.marks[k] and self._fits(row) and self._keeps_reach(row):
                    self._take(row, "minimum")
        for row in self.pool:
            if self._fits(row) and self._keeps_reach(row):
                self._take(row, "quota")
        for margins_bind in (True, False):
            for row in self.pool:
                if self._fits(row, margins_bind):
                    self._take(row, "refill")
        return self

    def _fits(self, row, margins_bind=True):
        if row.id in self.taken_ids or row.id in self.blocked or len(self.taken) >= self.spec.n:
            return False
        if self.strata[row.stratum] >= self.strata_quota[row.stratum]:
            return False
        if margins_bind and any(self.cells[m][cell] >= self.margins[m].quotas[cell]
                                for m, cell in enumerate(row.cells)):
            return False
        return all(self.cap_counts[key] < self.spec.caps[key[0]].max for key in row.caps)

    def _keeps_reach(self, row):
        return all(after == before - 1 for after, before in zip(self._reach(row), self.reach))

    def _take(self, row, stage):
        self.taken.append((row, stage))
        self.taken_ids.add(row.id)
        self.strata[row.stratum] += 1
        for m, cell in enumerate(row.cells):
            self.cells[m][cell] += 1
        for k, mark in enumerate(row.marks):
            self.marks[k] += mark
        self._withdraw(row)
        for key in row.caps:
            self.cap_counts[key] += 1
            if self.cap_counts[key] == self.spec.caps[key[0]].max:
                for other in self._still_open(key):
                    self.blocked.add(other.id)
                    self._withdraw(other)
        self.reach = self._reach()

    def _still_open(self, key):
        return [row for row in self.by_cap[key] if row.id not in self.taken_ids and row.id not in self.blocked]

    def _withdraw(self, row):
        for m, cell in enumerate(row.cells):
            self.avail[m][(row.stratum, cell)] -= 1

    def _gone_with(self, row):
        """The rows taking `row` withdraws: itself, and the rest of any cap it fills."""
        gone = {row.id: row}
        for key in row.caps:
            if self.cap_counts[key] + 1 == self.spec.caps[key[0]].max:
                gone.update((other.id, other) for other in self._still_open(key))
        return list(gone.values())

    def _reach(self, extra=None):
        """The most rows the remaining stratum quotas can still take, then the same per margin, once `extra` is taken
        when given."""
        gone = self._gone_with(extra) if extra is not None else []
        supply = _left(self.strata_quota, self.strata, extra.stratum if extra is not None else None)
        selectable = Counter()
        for (stratum, _), count in self.avail[0].items():
            selectable[stratum] += count
        for row in gone:
            selectable[row.stratum] -= 1
        out = [sum(min(left, selectable[stratum]) for stratum, left in supply.items())]
        for m, margin in enumerate(self.margins):
            capacity = self.avail[m].copy()
            for row in gone:
                capacity[(row.stratum, row.cells[m])] -= 1
            demand = _left(margin.quotas, self.cells[m], extra.cells[m] if extra is not None else None)
            out.append(max_flow(supply, demand, capacity))
        return tuple(out)

    def report(self, frame_rows, tier, last_tier):
        stages = Counter(stage for _, stage in self.taken)
        spec = self.spec
        return {
            "caps": [self._cap_report(i, cap) for i, cap in enumerate(spec.caps)],
            "family": None if spec.family is None else {"attribute": spec.family, "kept": len(self.pool),
                                                        "rows": frame_rows},
            "margins": [self._margin_report(m, margin) for m, margin in enumerate(spec.margins)],
            "minimums": [self._minimum_report(k, minimum) for k, minimum in enumerate(spec.minimums)],
            "n": spec.n,
            "reserve": None if spec.reserve is None else {"attribute": spec.reserve, "last_tier": last_tier,
                                                          "tier_used": tier},
            "rows": None if spec.rows is None else self._strata_report(),
            "selected": len(self.taken),
            "shortfall": spec.n - len(self.taken),
            "stages": {stage: stages[stage] for stage in STAGES},
        }

    def _strata_report(self):
        available = Counter(row.stratum for row in self.pool)
        values = {value: _quota_line(quota, self.strata[value], available[value])
                  for value, quota in self.spec.rows.quotas.items()}
        return {"attribute": self.spec.rows.attribute, "shortfall": sum(v["shortfall"] for v in values.values()),
                "values": values}

    def _margin_report(self, m, margin):
        available = Counter(row.cells[m] for row in self.pool)
        values = {value: _quota_line(quota, self.cells[m][value], available[value])
                  for value, quota in margin.quotas.items()}
        shortfall = sum(v["shortfall"] for v in values.values())
        refilled = sum(v["over"] for v in values.values())
        status = "met" if shortfall == 0 else ("refilled" if refilled == shortfall else "short")
        return {"attribute": margin.attribute, "refilled": refilled, "shortfall": shortfall, "status": status,
                "values": values}

    def _minimum_report(self, k, minimum):
        got = self.marks[k]
        return {"attribute": minimum.attribute, "available": sum(row.marks[k] for row in self.pool),
                "min": minimum.min, "selected": got, "shortfall": max(0, minimum.min - got),
                "status": "met" if got >= minimum.min else "short", "value": minimum.value}

    def _cap_report(self, index, cap):
        counts = [count for key, count in self.cap_counts.items() if key[0] == index]
        largest = max(counts, default=0)
        return {"attribute": cap.attribute, "largest": largest, "max": cap.max,
                "status": "held" if largest <= cap.max else "exceeded",
                "values_at_max": sum(count == cap.max for count in counts)}


def has_shortfall(report):
    return bool(report["shortfall"] or any(m["shortfall"] for m in report["margins"])
                or any(m["shortfall"] for m in report["minimums"]))


def _one_per_family(rows):
    """Each family's lowest-rank row, `rows` being in rank order."""
    seen, kept = set(), []
    for row in rows:
        if row.family not in seen:
            seen.add(row.family)
            kept.append(row)
    return kept


def sample(frame, spec, seed):
    """The rows the seed selects, as {"id", "stage"} in the order taken, and the report. `frame` is a list of row
    objects, `spec` a parsed Spec and `seed` 32 bytes."""
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
        draw = _Draw(spec, _one_per_family(pool) if spec.family else pool).run()
        report = draw.report(len(pool), tier, tiers[-1])
        if not has_shortfall(report) or tier == tiers[-1]:
            return [{"id": row.id, "stage": stage} for row, stage in draw.taken], report


def read_frame(path):
    """The frame's rows, one JSON object per line. Lines split on "\\n" only: a U+2028 inside a JSON string stays."""
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            lines = fh.read().split("\n")
    except (OSError, UnicodeDecodeError) as e:
        raise Refused(f"frame {path}: {e}") from e
    return [parse_json(line, f"frame {path} line {i}") for i, line in enumerate(lines, 1) if line.strip()]


def summary(report):
    """The report in a few lines, counts only."""
    stages = report["stages"]
    lines = [f"selected {report['selected']} of n = {report['n']} (minimum {stages['minimum']}, "
             f"quota {stages['quota']}, refill {stages['refill']})"]
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


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -m vkpi.sets.sample",
                                     description="A deterministic stratified sample of a frame.")
    parser.add_argument("--frame", required=True, help="JSONL, one object per line: an id and the spec's attributes")
    parser.add_argument("--spec", required=True, help=f"the quotas, format {SPEC_FORMAT}")
    parser.add_argument("--seed", required=True, help="64 hex characters, as `drand seed` prints them")
    parser.add_argument("--out", required=True, help="the selection to write, outside every git working tree")
    args = parser.parse_args(argv)
    try:
        require_private(args.out, "the selection")
        if os.path.lexists(args.out):
            raise Refused(f"{args.out} exists already: nothing is overwritten")
        spec = parse_spec(load_json(args.spec, "spec"))
        seed = from_hex(args.seed, 32, "--seed")
        selected, report = sample(read_frame(args.frame), spec, seed)
        document = {"format": SELECTION_FORMAT, "frame_sha256": sha256_file(args.frame), "report": report,
                    "seed": seed.hex(), "selected": selected, "spec_sha256": sha256_file(args.spec)}
        write_new(args.out, pretty_json(document), private=True)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    for line in summary(report):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
