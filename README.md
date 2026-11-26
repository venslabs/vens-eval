# vens-kpi

The evaluation framework for [vens](https://github.com/venslabs/vens): the KPIs measured on a vens release, how they are read, and later the scripts that run them. A KPI is the measured quantity on one line of an axis; an axis is read by state, never as one number.

## Status

**DRAFT, not frozen.** The spec is [`spec/1.0/vens-kpi-1.0.md`](spec/1.0/vens-kpi-1.0.md). The maintainer chose V1 to V4, V6 and V7 on 2026-11-26; none of them is signed yet, and V5 stays open until the human panel. Nothing in this repo is yet a verdict on any vens release.

## The nine axes

Read in tiers 0 to 3, with no weights, sums or averages between axes. R is the last shipped version of vens, identified by its artifacts, rerun with the candidate in the same window (interleaved order) or replayed on the same answers. A9 cost and time need comparable real runs of both versions.

| Tier | Axis | Question |
|---|---|---|
| 0 | A7 Coverage and functioning | Does every CVE in the scan come out rated, or listed as unrated? |
| 1 | A1 OWASP conformity | Does the published policy comply with the OWASP text? |
| 1 | A2 Correctness | Does each output apply the published policy exactly? |
| 2 | A3 Risk validity | Would independent judges give this band in this context, and would they distinguish the same CVEs? |
| 2 | A4 Context sensitivity | If the declared context changes, does the band move in the right direction, and does it stay put otherwise? |
| 3 | A5 Stability | Same input: same band from one run to another and from one model to another, without flattening the bands? |
| 3 | A6 Input invariance | Does a neutral paraphrase or an instruction slipped into a CVE leave the band intact? |
| 3 | A8 Explanation and provenance | Can each band be traced back to the facts and rules that justify it, and does the user understand it? |
| 3 | A9 Cost and rescoring time | For the same scan, does vens cost more or take longer than R, and does it hold the signed caps, if any? |

## States

- **SATISFIED**: the requirement is met, with evidence.
- **PROGRESS ESTABLISHED**: satisfied, and the Holm-corrected lower bound of the gain against R is above 0, with the gain's size printed; for A9, the Holm-corrected U95 of candidate / R must be at most 0.95, a gain of at least 5%.
- **FAILED**: a blocking rule is violated, or a loss beyond the margin δ is established against R.
- **UNDETERMINED**: measured, but the data cannot decide; it is not a half-pass.
- **NOT MEASURED**: the instrument was not applied; it never counts as SATISFIED.

## Delivery verdicts

- **validated without waiver**: every blocking line measured at P2 (frozen protocol, fresh answers, same window) and SATISFIED or PROGRESS ESTABLISHED.
- **shipped under waivers**: each FAILED covered by a waiver sheet, each UNDETERMINED and NOT MEASURED shown, nothing that cannot be waived.
- **inconclusive**: the evidence does not allow the conclusion sought.
- **requirements not met**: a failure without a waiver sheet, or one that cannot be waived.

## What comes next

- The frozen spec, with its hash and its signatures.
- Scripts: `check` ($0, on a mock), `run` (your key, a spend cap), `read` (recompute a published verdict), `verify` (check the commitments).
- Sealed sets, published only as salted hashes and revealed after use.
- Daily data releases, at $0.

## Related

- [venslabs/vens](https://github.com/venslabs/vens): the CVE prioritizer that vens-kpi evaluates.
- [venslabs/vens-benchmark](https://github.com/venslabs/vens-benchmark): benchmarking LLMs for context-aware CVE risk scoring, for vens.

## License

Code is under [Apache-2.0](LICENSE). The spec, its text and future data sets are under [CC BY 4.0](LICENSE-CC-BY-4.0). See [NOTICE](NOTICE).
