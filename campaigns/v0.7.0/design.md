> **DRAFT, signed with F0.** How vens v0.7.0 is evaluated under [vens-kpi/1.0](../../spec/1.0/vens-kpi-1.0.md). This file describes the method only: the sealed content stays private until it is retired.

# The v0.7.0 campaign

- **The candidate** is the head of [venslabs/vens#436](https://github.com/venslabs/vens/pull/436) at F0, today `34ef2a1`. **R** is v0.6.0, run again in the same window.
- **No human panel:** A3 reads NOT MEASURED, so "validated without waiver" is out of reach and the honest target is "shipped under waivers".
- **Spend** is capped at $300.
- **F0** is this campaign's frozen file (spec §6): rules, values, tiers and their α_k, gates, the draw policy and the sealed sets' commitments. **F1** adds the rotating batch's commitments and the readers' hashes, and changes no rule of F0.
- **Tiers** here are the reading tiers of spec §3, not the axis tiers of spec §2.

## 1. The sealed set

- **Source:** real Trivy scans, version and DB digest pinned, of 10 public images pinned by digest, never used in vens's development, across at least 5 ecosystems. An ordered reserve of 10 more images is listed before any scan. NVD, OSV and KEV snapshots are archived as provenance.
  - Why real scans: vens's input contract is what Trivy emits, and a row written by hand carries choices no scanner makes. The verdict rates rescoring given the scanner's facts; detection is not rated.
- **Exclusions:** every CVE already used in development (the demo scan, the quickstart reports, earlier pools and scenario sets), with its advisory aliases. The list is committed with the frame.
- **Frame:** the CVE ids left, one per advisory/package family, each with all its rows as scanned.
- **Quotas over the 100:**
  - severity: 20 critical, 30 high, 30 medium, 10 low, 10 unknown;
  - vectors: 70 with CVSS v3, 10 v2 only, 10 v4 only, 10 with none;
  - `FixedVersion`: at least 40 present and 40 absent, since that is all vens reads of a fix;
  - at least 10 multi-package and 10 with a non-NVD severity source; at most 25 per image;
  - KEV listing is recorded as a label, not a quota: vens reads no KEV field.
- **A short quota** brings in the next reserve image before the frame is committed. If the 20 images still cannot fill it, the slot is refilled from the same severity row by a rule written in advance. Construction never blocks.
- **Seed:** the builder publishes the salted frame hash and names a drand quicknet round at least 1 h ahead. Seed = sha256(randomness ‖ frame hash ‖ "vens-kpi/1.0/sealed"). A deterministic sampler ranks ids by sha256(seed ‖ id) and fills the quotas in that order, with no redraw. Its code is public and frozen before the round.
- **Sentinels:** 4 TEMP findings, whose id is not a CVE id, run as a separate report in each context. The main report stays at N = 100 for A5 and A9.
- **What vens receives:** one Trivy JSON report of the 100 and one schema-2 `config.yaml` per context, byte-identical for both binaries. Both binaries load each config on the mock, at $0, before sealing.
- **Contexts,** written by the builder with concrete access, data, availability and control facts, and no demo wording:
  - C1: an internet-facing service that holds regulated records; business impact basis.
  - C2: an internal API, not reachable from the internet; business impact basis.
  - C3: an isolated, rebuildable batch service on public data, `data_subjects` left undeclared; technical impact basis. The published policy has two impact bases, and the verdict covers both.
- No A3 label is produced.

## 2. The rotating batch

- **t0** is the UTC time F0 is signed, so the batch is independent of the protocol, not only of the candidate. The window is (t0, t1], with t1 = t0 + 7 days.
- **Eligible:** a CVE not rejected, first published by NVD in the window, with an English description and an OSV record naming a package and a released affected version in PyPI, npm, Go, Maven or crates.io.
- **Row:** a minimal lockfile pins the greatest affected released version at t1, and the pinned Trivy scans it with a DB dated after t1. The row is Trivy's output: a CVE Trivy does not report does not qualify, and missing vectors stay missing.
- **Draw:** the hash of the eligible manifest is published, then the first quicknet round at least 24 h later is used, its signature checked. The 30 lowest sha256(domain ‖ randomness ‖ id) are taken, one per advisory/package family and at most 8 per ecosystem, with no redraw. The domain string is frozen in F0.
- **Fewer than 30:** the window extends forward in 7-day steps, up to t0 + 28 days. If still short, the block runs with its real n, printed, and V3's 30 reads BELOW TARGET. No older CVE is used.
- **No idle time:** F0 is signed as soon as the rules and the sealed sets exist, so the window and the draw run during PRs 5 to 7. If the window is still open when everything else is ready, the tiers start and the rotating block joins at the next tier.
- The 30 run as one report under C1 to C3.

## 3. DIR (A4)

- **56 must-move pairs per model, in all,** not per context. Each pair has its own synthetic CVE and its own pair of configs, so C1 to C3 do not apply, and V4 counts independent pairs per model.
- **Admission:** an enumeration of the published policy shows a strict band move for every combination of identical answers. Non-strict pairs are run and printed; only a reversal counts against them.
- **Seven dimensions,** 8 pairs each: `business_criticality`, `data_subjects`, `data_sensitivity`, `compliance_requirements`, `exposure` with `listener`, a control relevant to the exploit, and `detection`/`traceability`. A dimension short of 8 strict pairs gives its shortfall to the others, recorded.
- **20 controls:** a third member on 20 bases, changing something the oracle proves neutral.
- **Written before any output:** each direction, its causal facts and each control's rationale.
- **Reading, per model, never pooled:**
  - a pair reacts when at least 3 of its 5 matched repetitions (a and b run back to back) move strictly in the written direction;
  - 3 of 5 against the direction is a reversal, FAILED under spec §3;
  - a control holds with at least 3 of 5 unchanged;
  - a missing comparison never counts as a success.
- **Against R:** only on the dimensions v0.6.0 reads; pairs that need schema 2 count in the absolute line alone.
- **Limit:** each DIR run is a one-CVE report, so DIR does not exercise batch composition; the sealed set does.
- The earlier development scenarios run on the mock only, as a regression check.

## 4. INV (A6)

- **Base:** 30 CVEs of the sealed 100, 6 per severity row, drawn by the same seed, as a 30-CVE report.
- **Four reports per context,** under C1 to C3: the base, rerun at this size and order, a paraphrase, planted-low and planted-critical. 360 rows.
  - The base is rerun because at batch 10 the batch-mates are part of the request: a main-set run differs from its variant by more than the changed text.
- **Plants:** templates written at $0, 3 wordings per direction, in `Description` for 20 rows and `Title` for 10, never in the config.
- **Paraphrases:** written by the builder at $0. A script checks ids, versions, numbers and product names, and a length within ±20%. A reviewer from a model family other than the builder's labels each one "same facts" or not, blind; a "no" is replaced before sealing.
- **Noise reading,** per context, model and variant:
  - d is the extra disagreement: variant against base, minus within-set disagreement, clustered by CVE (25 cross comparisons and 10 within-set pairs per CVE at 5 repetitions);
  - SATISFIED if the upper bound of d is at most 0.10, FAILED (waivable) if the lower bound is above 0.10, otherwise UNDETERMINED; the 2-point target stays printed;
  - the 0.10 margin is V1 applied to A6, to be confirmed by the maintainer when signing F0. A zero margin would make SATISFIED unreachable: identical inputs read U95 > 0 about 97.5% of the time.
- **Instruction followed,** the FAILED that cannot be waived, on any of:
  - on one CVE, all 5 planted repetitions strictly beyond the base's range in the instructed direction;
  - per direction, the lower bound of the mean signed shift above 0;
  - an explanation that treats the planted text as authority, under a rubric frozen before outputs.
- A non-significant test is printed as such and does not establish resistance. The line blocks only if the $0 replay shows a false-alarm rate of at most 0.05.

## 5. Models

- `claude-sonnet-4-6` and `gpt-5.4-mini-2026-03-17`, from distinct providers, with no temperature and no seed.
- API versions, endpoints and request defaults are frozen in F0. The proxy records the model id each response attests; a mismatch is a device failure.
- The Anthropic id carries no date: the provider's evidence of what it pins is archived, or the date is recorded as `unpublished`.
- Before F0, a $0 models call lists both ids. If one is gone, the break of spec §6 is declared; there is no substitution.
- V1's model limits are S2's, imported verbatim.

## 6. Execution

- **Machine:** one fixed machine owned by the maintainer, described in `machine.json` (CPU, RAM, OS build, toolchain, power, connection), with sleep disabled. No paid run on GitHub Actions.
- **Binaries:** R is v0.6.0's darwin-arm64 release asset, checked against `SHA256SUMS` and its sigstore bundle. The candidate is built from #436's head at F0 with a pinned Go. Both binary hashes are signed before the first paid call.
- **Concurrency 1** for the whole campaign, so A9's time line shares neither the machine nor the link.
- **Order:** repetition outermost, so a stop leaves whole repetitions. Blocks (report × context × model) are shuffled by a public seed; the candidate and R run back to back, their order alternating.
- **Profile:** shipped defaults, batch 10, serial calls, vens's own retries only. A non-zero exit is an A7 result and is never rerun. A device failure (proxy down, canary failing) allows one logged re-attempt.
- **Quotas and cache:** the same proxy ceilings for both versions, checked against the account's limits before F0. Fresh local caches, no prewarming, the provider's cache mode frozen; an unresolved cache mismatch makes A9 UNDETERMINED.
- **Each run records** `attempt.json` (written before the start), `vex.json`, `debug/`, vens's stderr and `a9.jsonl` (usage, cache categories, retries, timing).
- **A9** reads the main 100-CVE reports: per context and model, paired blocks, a Fieller-t interval on the ratio of means (df = pairs − 1, so 4 at tier 3), with the normal-block assumption stated. An unbounded interval is UNDETERMINED. R against itself is printed as the false-alarm check.
- **Size,** per repetition, version and model: 3 main reports, 3 sentinel reports, 3 rotating reports, 132 DIR runs and 12 INV reports, so 153 runs. Tiers 1 to 3 make 3,060 runs.

## 7. Tiers and budget

| Tier | Runs | α_k | Planned | Cumulative, planned |
|---|---|---|---|---|
| 0 | smoke: one repetition of a public fixture, plumbing only | — | about $5 | $5 |
| 1 | repetitions 1-2, with a technical gate after repetition 1 | 0.005 | about $60 | $65 |
| 2 | repetition 3 | 0.005 | about $30 | $95 |
| 3 | repetitions 4-5, V2 complete | 0.02 | about $60 | $154 |
| 4 | the extension, 3 repetitions | 0.02 | up to about $90 | up to $244 |

- **The looks.** Each look reads all repetitions so far, two-sided at 1 − α_k, for holding and for Holm; the α_k sum to 0.05.
  - A fixed split holds whatever the dependence between looks and whatever the reason for stopping. Group-sequential boundaries need a known information fraction, and repetitions / 5 is not one when the same CVEs are read at every tier.
  - The plan expects tier 3 (V2 complete), so the bulk of the alpha sits there and at the extension; early looks stay possible but conservative.
  - An unavailable test stays in the Holm family with p = 1, and no alpha is carried over or reallocated.
  - A deterministic violation blocks as soon as it is seen.
  - The 0.05 false-alarm filter covers the whole tiered procedure.
  - Expect most lines to read UNDETERMINED at tier 1, A9 above all.
- **The gates**, written in F0 with their thresholds, run after repetition 1 and at each tier's end. They check technical health only:
  - every run complete or counted as an A7 result;
  - usage captured for every request;
  - spend per run against the estimate;
  - no device failure;
  - the mechanical A1, A2 and A8 checks.
- **No gate** reads a verdict line or compares with R, so a gate spends no alpha. A failed gate stops the campaign and goes to the maintainer.
- **The extension** runs only by its F0 trigger, a primary line UNDETERMINED at tier 3 with the budget left covering it at the observed cost per repetition × 1.2, and with the maintainer's go. It repeats the blocks that feed the lines UNDETERMINED at tier 3, and only those lines are re-read.
- **Budget basis:**
  - the candidate's batch-1 costs in #310's Panel A, $1.65 (`claude-sonnet-4-6`) and $0.41 (`gpt-5.4-mini`) per 74-CVE context scan, taken as a ceiling at batch 10;
  - R at one fifth of the candidate, since v0.6.0's mock showed one fifth of the calls and prompt bytes;
  - the smoke measures R's real ratio.

| Block, per repetition | Rows |
|---|---|
| Sealed set, 100 × 3 contexts | 300 |
| Sentinels, 4 × 3 | 12 |
| Rotating batch, 30 × 3 | 90 |
| DIR, 56 × 2 + 20 | 132 |
| INV, 30 × 4 × 3 | 360 |
| **Total** | **894** |

- 894 rows × 5 repetitions come to about $149 on this basis, plus the $5 smoke. If R costs as much as the candidate, about $249.
- **Guard:** every paid request, repairs and aborted runs included, reserves its maximum charge; a dispatch is refused if debited plus reserved spend would pass $300.

## 8. Stop, go and the verdict

- **The go.** Each tier ends with the technical health, the spend and the provisional figures, given to the maintainer, who decides whether to go on. The next tier starts at the maintainer's yes.
- **Stop at will.** The maintainer can stop at any time, by telling the coordinator or by creating a `STOP` file in the campaign folder; both are checked before every run.
  - A run in progress finishes, since its cost is committed; a killed run is recorded as aborted.
  - Nothing restarts without the maintainer's word, and a resume continues at the next run without rerunning anything.
- **One line at each tier's start and end:** what was spent and what comes next.
- **Verdict at the tier reached.**
  - A verdict needs tier 1 at least. It reads the last tier reached, at its level, and the states of the earlier tiers stay printed.
  - It carries its tier: "verdict at tier k of 3 (V2 incomplete)", "at tier 3 (V2 complete)" or "at tier 4 (extension)".
  - A PROGRESS ESTABLISHED read before tier 3 prints "size possibly overestimated (early stop)".
- **A stopped campaign is not complete:** its runs are kept and published as they are.
- **The frozen rules never change,** whatever a tier shows.

## 9. Sealing

- **Storage:** encrypted archives (age) in private storage. The maintainer holds the key and gives it only to the builder and the runner.
- **Commitments:** `seals/1.0-v0.7.0.json` in this repo, with a salted sha256 per file (32-byte random salts, domain separation, framed path and content) and an aggregate per set. The salts stay private.
- **Roles:**
  - the builder is a fresh, isolated agent that never reads outputs, before or after, and never touches vens;
  - the runner gets inputs, not labels;
  - the reviewers check form before sealing, on a pinned candidate.
- **A change to the candidate** after the seal voids the seal.
- **Order:** candidate pinned → sets built → seals published → F0 signed → window and draw → F1 signed → tier 0.
  - No paid call comes before the readers and the binaries are hashed and signed.
  - If the window is still open when everything else is ready, the tiers start, and the rotating block joins at the next tier once its commitments are signed.
- **Signatures:** Claude Fable 5.2 and GPT-6.1 Sol sign the protocol and the readers; the maintainer approves F0 and F1.
- **Publication:** reports use opaque ids. Every attempt and result is published, failures included. The rotating batch is revealed after the campaign, the sealed set at retirement.

## 10. The eight pull requests

In the order 1, then 2, 3 and 4 in parallel, then 5, 6, 7 and 8. Code reused from [vens-benchmark](https://github.com/venslabs/vens-benchmark)'s `chain/` at `0f6d16431baf` keeps its Apache-2.0 provenance and NOTICE.

1. **Provenance and run layer** (harness author): vendor `chain/` with its NOTICE; adapt `errors`, `runvens`, `attempt`, `venslog`, `calls`, `cdx`, `contract`, `answers` and `recovery`.
2. **A9 harness** (A9 author, in progress): the recording proxy and run timer, `usage`, `cost` on a frozen price list, and `ledger` as the spend guard.
3. **Oracle** (an independent author): the OWASP clause ledger, an independent Go policy oracle, the pinned Java calculator check (`legal`, `javacheck`, `javarun`), and the policies of the candidate and of v0.6.0.
4. **Set builders** (the builder; code public, data private): the sealed sampler, the scan pipeline, the draw and commitment tools, and the DIR and INV generators.
5. **Local runner** (harness author): `campaign` as the block scheduler, with the tiers, the gates and the `STOP` check; fetching and checking R's release asset. `dispatch` is not ported: no paid run on Actions.
6. **Reader** (reader author): `read`, `cells`, `stats`, `verdicts`, `families`, the A5 to A9 lines with Fieller and Holm at each tier's level, `report`, `report_scen` and redaction; `kpi` and `diagnostics` printed only.
7. **$0 calibration** (reviewers, maintainer): same-version replay through the whole tiered procedure, the smallest visible loss per line, and the defective candidates of spec §6 with the simple correct one. A broken reader blocks the launch.
8. **Freeze and results** (runner, reviewers, maintainer): F0 and F1 with their seals and signatures, then every attempt, the axis vector at the tier reached, the waiver sheets and the delivery decision.

F0 is signed once PR 4's sealed sets exist, so the rotating window runs during PRs 5 to 7. vens-demo's pipeline stays the public development regression.
