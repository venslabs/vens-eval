from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from vkpi.a9 import proxy, usage

FORMAT = "vens-kpi/a9-run/1"


@dataclass(frozen=True)
class Spec:
    vens: Path
    provider: str
    n: int
    report: Path
    vex: Path
    prices: Path
    log: Path
    vens_args: tuple[str, ...] = ()
    upstreams: dict[str, str] = field(default_factory=dict)


def run(spec: Spec, env: dict[str, str]) -> dict:
    _check(spec)
    grid = load_grid(spec.prices)
    identity = {
        "format": FORMAT,
        "provider": spec.provider,
        "vens_sha256": _sha256(spec.vens),
        "prices": {"date": grid["date"], "sha256": _sha256(spec.prices)},
        "default_upstreams": not spec.upstreams,
        "n": spec.n,
    }
    command = [str(spec.vens), "generate", "--llm", spec.provider, *spec.vens_args, str(spec.report), str(spec.vex)]
    with proxy.running(spec.log, spec.upstreams) as server:
        timing = _timed(command, {**env, **proxy.base_url_env(server.url)}, spec.vex)
    return {**identity, **timing, **summarize(_read_log(spec.log), grid, spec.n)}


def summarize(records: list[dict], grid: dict, n: int) -> dict:
    by_model: dict[str, dict] = {}
    gaps: Counter = Counter()
    for record in records:
        if record["provider"] is None:
            gaps["request outside the provider routes"] += 1
            continue
        if record["status"] is None or not 200 <= record["status"] < 300:
            continue
        model = record["model"] or "unknown model"
        stats = by_model.setdefault(
            model, {"responses": 0, "without_usage": 0, "served": [], "service_tiers": [], "tokens": {}}
        )
        stats["responses"] += 1
        _add_once(stats["served"], record["model_served"])
        _add_once(stats["service_tiers"], record["service_tier"])
        counted = usage.tokens(record["provider"], record["usage"])
        if counted is None:
            stats["without_usage"] += 1
            gaps[f"{model}: {record['status']} response without usable usage"] += 1
            continue
        stats["tokens"] = _sum(stats["tokens"], counted)

    for model, stats in by_model.items():
        stats["usd"], why = price(stats["tokens"], grid["models"].get(model))
        if stats["without_usage"]:
            stats["usd"] = None
        elif why:
            gaps[f"{model}: {why}"] += 1
    usd = None if gaps else sum((stats["usd"] for stats in by_model.values()), 0.0)

    attempts = [record["attempt"] for record in records]
    tokens: dict[str, int] = {}
    for stats in by_model.values():
        tokens = _sum(tokens, stats["tokens"])
    return {
        "calls": None if None in attempts else attempts.count(1),
        "attempts": len(records),
        "statuses": dict(sorted(Counter(_status(r["status"]) for r in records).items())),
        "request_bytes": sum(record["request_bytes"] for record in records),
        "response_bytes": sum(record["response_bytes"] for record in records),
        "models": by_model,
        "tokens": tokens,
        "usd": usd,
        "usd_per_cve": None if usd is None else usd / n,
        "usd_not_measured": dict(sorted(gaps.items())),
    }


def price(tokens: dict[str, int], model: dict | None) -> tuple[float | None, str | None]:
    if model is None:
        return None, "not in the price grid"
    usd = 0.0
    for category, count in tokens.items():
        if count == 0:
            continue
        rate = model["prices"].get(category)
        if rate is None:
            return None, f"no {category} price in the grid"
        usd += count * rate / 1_000_000
    return usd, None


def load_grid(path: Path) -> dict:
    grid = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(grid, dict) or not isinstance(grid.get("models"), dict):
        raise ValueError(f"{path}: no models")
    datetime.date.fromisoformat(str(grid.get("date")))
    for name, model in grid["models"].items():
        prices = model.get("prices") if isinstance(model, dict) else None
        if not isinstance(prices, dict) or not str(model.get("source", "")).startswith("https://"):
            raise ValueError(f"{path}: {name} needs a source URL and prices")
        for category, rate in prices.items():
            if category not in usage.CATEGORIES:
                raise ValueError(f"{path}: {name} has an unknown category {category!r}")
            if rate is not None and (isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate < 0):
                raise ValueError(f"{path}: {name} {category} must be a number or null")
    return grid


def _check(spec: Spec) -> None:
    if spec.n <= 0:
        raise ValueError("--n must be a positive number of CVEs")
    if any(arg == "--llm" or arg.startswith("--llm=") for arg in spec.vens_args):
        raise ValueError("set the provider with --provider: the proxy routes by provider")
    if not os.access(spec.vens, os.X_OK):
        raise ValueError(f"{spec.vens} is not an executable")
    for path in (spec.vex, spec.log):
        if path.exists():
            raise ValueError(f"{path} already exists")


def _timed(command: list[str], env: dict[str, str], vex: Path) -> dict:
    launched = time.time_ns()
    started = time.monotonic_ns()
    process = subprocess.Popen(command, env=env)
    try:
        exit_code = process.wait()
    except KeyboardInterrupt:
        exit_code = process.wait()
    elapsed = time.monotonic_ns() - started
    written = vex.stat().st_mtime_ns if vex.exists() else None
    complete = exit_code == 0 and written is not None
    return {
        "exit_code": exit_code,
        "complete": complete,
        "launched_ns": launched,
        "vex_written_ns": written,
        "seconds": _seconds(launched, elapsed, written) if complete else None,
        "seconds_to_exit": elapsed / 1e9,
    }


def _seconds(launched: int, elapsed: int, written: int | None) -> float | None:
    # vens writes the VEX to a temp file and renames it into place, so the
    # file's mtime is the moment its last byte was written.
    if written is None or not launched <= written <= launched + elapsed:
        return None
    return (written - launched) / 1e9


def _read_log(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as lines:
        return [json.loads(line) for line in lines if line.strip()]


def _sum(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    return {key: a.get(key, 0) + b.get(key, 0) for key in sorted(a.keys() | b.keys())}


def _add_once(values: list, value: object) -> None:
    if value is not None and value not in values:
        values.append(value)


def _status(status: int | None) -> str:
    return "none" if status is None else str(status)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as data:
        for chunk in iter(lambda: data.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m vkpi.a9.run",
        description="Run one vens generate through the A9 recording proxy; write its cost and time.",
        epilog="Arguments after -- go to vens generate, e.g. -- --config-file config.yaml --sbom-serial-number urn:uuid:...",
    )
    parser.add_argument("--vens", type=Path, required=True, help="vens binary")
    parser.add_argument("--provider", required=True, choices=sorted(proxy.UPSTREAMS))
    parser.add_argument("--n", type=int, required=True, help="incoming CVEs in the scan")
    parser.add_argument("--input", type=Path, required=True, help="scan report for vens generate")
    parser.add_argument("--vex", type=Path, required=True, help="VEX vens generate writes; must not exist")
    parser.add_argument("--prices", type=Path, required=True, help="price grid")
    parser.add_argument("--log", type=Path, required=True, help="JSONL log, one line per request; must not exist")
    parser.add_argument("--out", type=Path, required=True, help="run JSON; must not exist")
    parser.add_argument("--upstream", action="append", default=[], metavar="PROVIDER=URL",
                        help="send PROVIDER's calls to URL instead of its API (tests)")
    parser.add_argument("vens_args", nargs="*", metavar="-- VENS_ARGS")
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise ValueError(f"{args.out} already exists")
        spec = Spec(
            vens=args.vens,
            provider=args.provider,
            n=args.n,
            report=args.input,
            vex=args.vex,
            prices=args.prices,
            log=args.log,
            vens_args=tuple(args.vens_args),
            upstreams=proxy.parse_upstreams(args.upstream),
        )
        result = run(spec, dict(os.environ))
        with args.out.open("x", encoding="utf-8") as out:
            json.dump(result, out, indent=2, sort_keys=True)
            out.write("\n")
    except (OSError, ValueError) as err:
        print(f"vkpi.a9.run: {err}", file=sys.stderr)
        return 2
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
