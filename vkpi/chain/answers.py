"""answers.json, which the after writes once per run under --debug-dir, failed runs included.

Per CVE, each factor's answer as the reply wrote it, its reading, its level and the level's source; a failed run also
lists, marked `unrated`, the CVEs of its failing batch already answered, with their answers and readings only.
"""
import collections

from chain.cdx import FACTORS
from chain.errors import Refused, load_json


def load(path):
    """The document; Refused when it is cut short or not answers.json's shape."""
    doc = load_json(path)
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise Refused(f"{path}: not answers.json, no vulnerabilities list")
    for key in ("counters", "defects"):
        if not isinstance(doc.get(key), dict):
            raise Refused(f"{path}: not answers.json, no {key} object")
    for e in doc["vulnerabilities"]:
        factors = e.get("factors") if isinstance(e, dict) else None
        if not isinstance(factors, list) or not isinstance(e.get("vulnId"), str) or any(
                not isinstance(f, dict) or "factor" not in f for f in factors):
            raise Refused(f"{path}: not answers.json, an entry without vulnId or factors")
    return doc


def duplicates(doc):
    """The problems of a CVE listed more than once, rated or unrated: its entries cannot be told apart."""
    counts = collections.Counter(e["vulnId"] for e in doc["vulnerabilities"])
    return [f"{vid}: listed {n} times in answers.json" for vid, n in sorted(counts.items()) if n > 1]


def entries(doc):
    """{vulnId: entry} split into the rated and the unrated; a CVE listed twice is one of duplicates()'s."""
    rated = {e["vulnId"]: e for e in doc["vulnerabilities"] if not e.get("unrated")}
    unrated = {e["vulnId"]: e for e in doc["vulnerabilities"] if e.get("unrated")}
    return rated, unrated


def per_cve(entry):
    """One entry: whether it is unrated, how its adjustment read, its counters, and per factor {answer, reading,
    level, source, adjusted}, absent keys as None."""
    keys = ("answer", "reading", "level", "source", "adjusted")
    return {"unrated": bool(entry.get("unrated")), "adjustment": entry.get("adjustment"),
            "counters": entry.get("counters") or [],
            "factors": {f["factor"]: {k: f.get(k) for k in keys} for f in entry["factors"]}}


def check(doc, vex_ratings):
    """answers.json against the VEX: each rated CVE's 16 levels, in the vector's order, equal its vector's; every
    CVE the VEX rates has a rated entry, and no rated entry is missing from the VEX. The problems found."""
    rated, _ = entries(doc)
    problems = []
    for vid, r in sorted(vex_ratings.items()):
        e = rated.get(vid)
        if e is None:
            problems.append(f"{vid}: rated in the VEX, no rated entry in answers.json")
            continue
        names = tuple(f.get("factor") for f in e["factors"])
        got = [f.get("level") for f in e["factors"]]
        if names != FACTORS or got != [r["levels"][f] for f in FACTORS]:
            problems.append(f"{vid}: answers.json's levels differ from the vector's")
    problems += [f"{vid}: a rated entry the VEX does not rate" for vid in sorted(set(rated) - set(vex_ratings))]
    return problems


def unrated_shape(doc):
    """The problems of the unrated entries: each lists only questions answered, with no level and no source."""
    _, unrated = entries(doc)
    problems = []
    for vid, e in sorted(unrated.items()):
        if not e["factors"]:
            problems.append(f"{vid}: an unrated entry with no answer")
        if any("level" in f or "source" in f for f in e["factors"]):
            problems.append(f"{vid}: an unrated entry with a level or a source")
    return problems
