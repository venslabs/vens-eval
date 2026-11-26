"""The scanner's report, the VEX vens publishes and its attestation, read as published."""
import base64
import collections

from chain.errors import Refused, load_json

FACTORS = ("SL", "M", "O", "S", "ED", "EE", "A", "ID", "LC", "LI", "LAV", "LAC", "FD", "RD", "NC", "PV")
# The attestation fields the chain reads. raw_response is never one of them: the chain reads what vens published.
EVIDENCE_FIELDS = ("provider", "model", "prompt_hash")


def _load(path):
    return load_json(path)


def score_of(rating):
    """A rating's published score as a number, None when it is missing, null or not a number: never 0."""
    score = rating.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    return float(score)


def _vulns(path):
    """The VEX's vulnerabilities; Refused when the file does not read or they are not objects with an id and a list
    of rating objects."""
    doc = _load(path)
    if not isinstance(doc, dict):
        raise Refused(f"{path}: a JSON {type(doc).__name__}, not a VEX")
    vulns = doc.get("vulnerabilities") or []
    if not isinstance(vulns, list) or not all(
            isinstance(v, dict) and isinstance(v.get("id"), str) and isinstance(v.get("ratings") or [], list)
            and all(isinstance(r, dict) for r in v.get("ratings") or []) for v in vulns):
        raise Refused(f"{path}: not a VEX, its vulnerabilities not objects with an id and a list of ratings")
    return vulns


def report_ids(path):
    """The distinct vulnerability ids of a Trivy or a Grype report: the CVEs its VEX must hold, each once."""
    doc = _load(path)
    if "matches" in doc:
        return {m["vulnerability"]["id"] for m in doc["matches"]}
    return {v["VulnerabilityID"] for r in doc.get("Results") or [] for v in r.get("Vulnerabilities") or []}


def levels(vector):
    """The 16 levels of an OWASP vector, in the vector's order; ValueError for any other shape."""
    if not isinstance(vector, str):
        raise ValueError("not a string")
    parts = vector.split("/")
    if len(parts) != len(FACTORS):
        raise ValueError(f"{len(parts)} factors, not 16")
    out = {}
    for part, factor in zip(parts, FACTORS):
        name, sep, value = part.partition(":")
        if name != factor or not sep or not value.isdigit():
            raise ValueError(f"{part!r} where {factor} was expected")
        out[factor] = int(value)
    return out


def subscores(lv):
    """Likelihood, its two halves, the technical and business impacts and max(T, B), from the levels alone."""
    total = lambda names: sum(lv[f] for f in names)
    t, b = total(FACTORS[8:12]) / 4, total(FACTORS[12:16]) / 4
    return {"L": total(FACTORS[:8]) / 8, "TA": total(FACTORS[:4]) / 4, "VU": total(FACTORS[4:8]) / 4,
            "T": t, "B": b, "impact": max(t, b)}


def main_severity(score):
    """vens main's severity on its score (pkg/riskconfig/config.go at 43ab10b): its 60/40/20/5 thresholds."""
    return "critical" if score >= 60 else "high" if score >= 40 else "medium" if score >= 20 else \
        "low" if score >= 5 else "info"


def main_rule(ratings):
    """The before's ratings against main's own rule (43ab10b): each group's four levels equal, the score
    ((TA + VU) / 2) x ((T + B) / 2) on the group levels, the severity its thresholds on that score. The problems."""
    problems = []
    for vid, r in sorted(ratings.items()):
        groups = [[r["levels"][f] for f in FACTORS[i:i + 4]] for i in (0, 4, 8, 12)]
        if any(len(set(g)) != 1 for g in groups):
            problems.append(f"{vid}: a group's four levels differ")
            continue
        ta, vu, t, b = (g[0] for g in groups)
        score = ((ta + vu) / 2) * ((t + b) / 2)
        if r["score"] != score:
            problems.append(f"{vid}: score {r['score']}, main's rule gives {score}")
        if r["severity"] != main_severity(score):
            problems.append(f"{vid}: severity {r['severity']}, main's thresholds give {main_severity(score)}")
    return problems


def _owasp(vuln):
    return [r for r in vuln.get("ratings") or [] if r.get("method") == "OWASP"]


def vex_rows(path):
    """(vulnId, vector, severity, score) per OWASP rating, and (vulnId, '', '', '') for a CVE listed without one:
    what the Java check reads, a missing rating included. A missing or null vector goes empty, a rating without one;
    a score missing or not a number goes as NaN, which no score equals."""
    text = lambda value: "" if value is None else str(value)
    out = []
    for v in _vulns(path):
        out += [(v["id"], text(r.get("vector")), text(r.get("severity")),
                 "NaN" if score_of(r) is None else repr(score_of(r))) for r in _owasp(v)] or [(v["id"], "", "", "")]
    return out


def ratings(path):
    """{vulnId: rating} for each CVE listed and rated once whose vector reads, with its published vector, severity
    and score, a score missing or not a number kept as None, and the sub-scores its vector gives; and the problems: a
    CVE listed twice, listed without an OWASP rating, rated twice, a vector missing, null or not 16 levels, or a score
    missing, null or not a number. Refused when the file is no VEX."""
    out, problems = {}, []
    vulns = _vulns(path)
    listed = collections.Counter(v["id"] for v in vulns)
    problems += [f"{vid}: listed {n} times in the VEX" for vid, n in sorted(listed.items()) if n > 1]
    for v in vulns:
        owasp, vid = _owasp(v), v["id"]
        if listed[vid] > 1:
            continue
        if len(owasp) != 1:
            problems.append(f"{vid}: {len(owasp)} OWASP ratings")
            continue
        r = owasp[0]
        try:
            lv = levels(r.get("vector"))
        except ValueError as e:
            problems.append(f"{vid}: vector {r.get('vector')!r}: {e}")
            continue
        if score_of(r) is None:
            problems.append(f"{vid}: score {r.get('score')!r}, not a number")
        out[vid] = {"vector": r["vector"], "severity": r.get("severity"), "score": score_of(r), "levels": lv,
                    **subscores(lv)}
    return out, problems


def evidence(path):
    """The attestation's evidence per call, in order: provider, model and prompt_hash. Refused when the file is not
    an attestation of that shape."""
    calls = []
    try:
        for e in _load(path)["declarations"]["evidence"]:
            call = {}
            for item in e.get("data") or []:
                if item.get("name") not in EVIDENCE_FIELDS:
                    continue
                att = item["contents"]["attachment"]
                value = att.get("content", "")
                if att.get("encoding") == "base64":
                    value = base64.b64decode(value).decode("utf-8")
                call[item["name"]] = value
            calls.append(call)
    except (KeyError, TypeError, AttributeError, ValueError) as e:
        raise Refused(f"{path}: not an attestation's evidence: {e!r}") from e
    return calls
