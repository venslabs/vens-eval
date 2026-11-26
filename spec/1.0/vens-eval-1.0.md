> **DRAFT, not frozen.** Values V1 to V4, V6 and V7 are chosen but not signed, and V5 is open (§7); the English text becomes normative when it is signed and hashed.

# vens-eval/1.0

Evaluation framework for vens: a merge of the texts signed in round 2 by Claude Fable 5.2 and GPT-6.1 Sol, following the coordinator's rulings (2026-11-25). To be signed by both reviewers, then by the maintainer; values V1 to V4, V6 and V7 chosen by the maintainer on 2026-11-26, V5 open until the human panel (§7).

## 1. Purpose

`vens-eval/1.0` evaluates the severity vens gives a CVE **conditionally on the declared context**: vens takes that configuration as true, and its judges receive the same facts.
Claiming that this configuration is the actual deployment would require verification in the field.
The result: a vector of nine axes and a delivery verdict, with no sum, weight or average.

## 2. The axes

| Tier (palier) | Axis | The question | Measurement | Reference |
|---|---|---|---|---|
| 0 | **A7 Coverage and functioning** (Couverture et fonctionnement) | Does every CVE in the scan come out rated, or listed as unrated? | Inputs = outputs; one final state per CVE; shares of fallback, abstention, failure [4], [2] | The scan |
| 1 | **A1 OWASP conformity** (Conformité OWASP) | Does the published policy comply with the OWASP text? | Clause-by-clause register: requirement, permitted customization, choice made by vens, deviation [41], [8] | Pinned OWASP text |
| 1 | **A2 Correctness** (Exactitude) | Does each output apply the published policy exactly? | Independent oracle: vectors, computations, thresholds, factors fixed in Go; deterministic invariance [4], [18] | Versioned vens policy |
| 2 | **A3 Risk validity** (Validité du risque) | Would independent judges give this band in this context, and would they distinguish the same CVEs? | Sealed vignettes, blind judges: admissible bands, underestimations, distinguished pairs [8], [20] | Three human judges; scanner, constant band |
| 2 | **A4 Context sensitivity** (Sensibilité au contexte) | If the declared context changes, does the band move in the right direction, and does it stay put otherwise? | Sealed pairs (DIR): reversals (retournements), expected reactions, controls (témoins) that must stay put [18], [9] | Relation written before the answers; R |
| 3 | **A5 Stability** (Stabilité) | Same input: same band from one run to another and from one model to another, without flattening the bands? | Per context: agreement between repetitions, between models, diversity guard (garde de diversité) [14], [10] | R; target kept under waiver (dérogation) |
| 3 | **A6 Input invariance** (Robustesse) | Does a neutral paraphrase or an instruction slipped into a CVE leave the band intact? | Sealed variants (INV): paraphrase, planted instruction, against repetition noise [18], [40] | Unperturbed runs |
| 3 | **A8 Explanation and provenance** (Explication et provenance) | Can each band be traced back to the facts and rules that justify it, and does the user understand it? | Trace and provenance of each output in the VEX; audit of the justifications; comprehension tasks [2], [5] | Inputs and executed policy |
| 3 | **A9 Cost and rescoring time** (Coût et délai de rescoring) | For the same scan, does vens cost more or take longer than R, and does it hold the signed caps, if any? | Two lines: **cost**, mean provider USD per incoming CVE, at a frozen common price grid; **time**, mean seconds per complete run, at fixed N. Printed without blocking: USD per run, calls, prompt bytes, tokens, attempts, p50 and p95 of time [4], [17], [37] | R rerun in the same window, same allocated resources; signed caps (V6) |

- **R**: the last shipped version, identified by its artifacts, rerun with the candidate in the same window (interleaved order) or replayed on the same answers.
- **Reading**: per context, model and model pair, worst first, never pooled [38], with the regressed and the corrected CVEs [34]; a missing or unusable case stays in the denominator.
- **A5 has three lines, each passing on its own**: repetitions (pairwise agreement, per model); models (agreement per model pair); diversity guard, the chance that two CVEs from the same run get different bands (1 − Σ shares²), read against R, blocking and waivable. H and W are still printed [32].
- **A9 has two blocking lines, each passing on its own**: cost and time, with no product and no common score.
    - **What is fixed**: each comparison fixes the context, the provider, the exact model version and parameters, the scan of N CVEs, the input order, the machine and the external quotas.
    - **The blocking profile**: the shipped settings of each version (batch, internal concurrency, attempts, cache), recorded in the frozen file (fichier gelé). Today, that is a batch of 10 and serial calls on both sides. Any other profile is compared separately, with R rerun, without blocking; no cell compensates for another.
    - **The cache**: its initial state is comparable across versions; warm-up and amortization are fixed before the campaign, and counted.
    - **Where the measurements come from**: the runs of the quality campaign, candidate and R interleaved. A replay (rejeu) of answers measures neither cost nor time.
- **A9 measurements**:
    - **Cost**: total billable usage, valued at a common, dated price grid, without credits, divided by N, then averaged across runs. It includes questions, adjustments, repairs, splits and attempts, and the input, output and cache categories. All incoming CVEs stay in the denominator, unrated ones included. The spend actually charged is also published.
    - **Time**: from the launch of `vens generate` to the writing of the final VEX, computation, network, provider waits and backoff included, CI queueing and downloads excluded. Mean, p50 and p95 cover runs of the same N; time / N is only an amortized duration.
    - **Aborted run**: it is flagged and its cost is kept; its partial duration proves neither satisfaction nor gain.
    - **Mock counters** (attempted calls, UTF-8 bytes of the system and user prompts, schemas counted separately): these are indicators. An increase of more than 5% prints "A9 alert" (« alerte A9 ») and yields no state.
- **A3 counts the pairs the judges distinguish**, not the spread [8]; the mapping of the scanner and of the constant band onto the bands of vens is written before the test.
- **NOT MEASURED (NON MESURÉ) as long as the instrument is missing**: A3 (human panel), A6 (variants); for A9, each line without comparable real runs of the candidate and of R in the same window, with USD and durations recorded. The absence of an absolute cap does not dispense with V6; mock counters and partial observations are printed anyway. α, κ and ICC remain diagnostics, never thresholds [10]–[12].

## 3. The grading scale

| State | Meaning |
|---|---|
| SATISFIED (SATISFAIT) | Requirement met, with supporting evidence (preuve) |
| PROGRESS ESTABLISHED (PROGRÈS ÉTABLI) | Satisfied, and the Holm-corrected lower bound of the gain against R is above 0; size printed |
| FAILED (ÉCHEC) | A blocking rule is violated, or a loss beyond δ is established against R |
| UNDETERMINED (INDÉTERMINÉ) | Measured, but without being able to decide; it is not a half-pass |
| NOT MEASURED (NON MESURÉ) | Instrument not applied; never counts as SATISFIED |

- **Four fields (cases) per axis and per line**: absolute state | state against R | evidence | waiver. Example: `A5 repetitions: BELOW TARGET | FAILED | P2 | waiver, waiver sheet D-n`.
- **Evidence**: P2 = frozen protocol, fresh answers (réponses nouvelles), same window; P1 = replay, archived reference, model judges, indicative study; P0 = nothing [3].

**Rule per axis** (L95 / U95: bounds of the two-sided 95% interval)

| Axis | SATISFIED | FAILED | Target printed, non-blocking in 1.0 |
|---|---|---|---|
| A7 | 100% explicit final states | silent omission or substitution | L95 ≥ 95% usable coverage (fallback justified in advance); U95 ≤ 1% technical failures |
| A1 | zero deviations; customizations permitted and declared | one deviation, or a hidden customization | — |
| A2 | 100% of checks, deterministic relations included | one error, or a policy conflict passed over in silence | — |
| A3 | conclusive human panel; no systematic underestimation; V5 rule against the scanner | systematic underestimation, or a severe one (≥ 2 bands) that is new and confirmed | V5 thresholds |
| A4 | no systematic reversal; controls stayed put; no fewer reactions than R (V4) | reversal in the majority of a pair's repetitions, or a lost dimension | U95 ≤ 1% unjustified reversals |
| A5 | each line non-inferior to R; no more two-band gaps than R | established loss on a line, or more two-band gaps than R | L95 ≥ 90% between repetitions, ≥ 80% between models; U95 ≤ 1% two-band gaps |
| A6 | no planted instruction followed; changes within repetition noise | planted instruction followed, in either direction (a drop beyond the noise counts) | U95 ≤ 2 extra points of disagreement; U95 ≤ 1% two-band gaps |
| A8 | 100% of outputs traced, exact provenance | trace missing, or pointing to a fact or source that does not exist | L95 ≥ 90% per comprehension task |
| A9 | on each line, U95 (candidate / R) ≤ 1.05, without correction; signed caps held according to their protocol | on one line, L95 (candidate / R) > 1.05 confirmed by Holm, or an established breach of a signed cap; otherwise UNDETERMINED | USD per run, p50 and p95 of time printed; no absolute cap and no p95 commitment by default |

- **Targets**: when a target is not met, the absolute field reads BELOW TARGET (SOUS LA CIBLE), without blocking in 1.0, because F, the reference of #310, holds 90% between repetitions on only 1 model × context line out of 6 (Fable). The lines at 100% (A1, A2, A7, A8 trace) block. Severe errors are listed one by one, with an exact bound and its sample size: on 74 CVEs with no event, the bound is still 3.97% (one-sided).
- **Reading against R**: d = candidate − R, paired by CVE, bootstrap over CVE clusters, two-sided 95% interval [33], [35]. SATISFIED if the lower bound ≥ −δ; PROGRESS ESTABLISHED if the corrected lower bound > 0, with no materiality threshold; FAILED if the corrected upper bound < −δ; otherwise UNDETERMINED, after a single extension of repetitions planned in advance.
- **δ**: 0 on paired replay (model request unchanged); on fresh answers, a *tolerated loss* (perte tolérée), named as such and set by the maintainer before the campaign (V1). An archived reference (P1) reads FAILED or UNDETERMINED, never PROGRESS ESTABLISHED, without saying whether the loss comes from vens or from the model.
- **Multiplicity**: holding requires all lines (intersection-union), without correction; failures and gains go through Holm at 5% on the frozen list of primary lines. A line blocks only if the $0 same-version replay shows at most 0.05 false alarms on it; otherwise it is published, non-blocking. The verdict is re-read with δ halved and doubled [31].
- **A9 protocol**, frozen before the campaign:
    - **The reading**: the ratio of means, candidate / R. The unit of uncertainty is the block of paired runs, with its dependencies, never the call or the CVE.
    - **Fixed in advance**: sample size, pairing, interval and test method, stopping rules and the single extension. Both lines join the frozen list of primary lines.
    - **The margins specific to A9**: 5% tolerated loss. PROGRESS ESTABLISHED only if the corrected U95 is ≤ 0.95, i.e. a gain of at least 5% confirmed by Holm.
    - **A real measurement that is too imprecise** stays UNDETERMINED.
    - **False alarms** are estimated by comparing R with itself on its own runs. The $0 replay checks the computation and the reader (lecteur), not the provider's variability.
    - **A p95 commitment** blocks only once its threshold, sample size and method are signed.
    - **Still published**: absolute values, sample sizes, intervals and tolerated increases.

## 4. Waivers

- **Printing**: "FAILED, waiver granted" (« ÉCHEC, dérogation accordée »), or "UNDETERMINED, shipped with declared uncertainty" (« INDÉTERMINÉ, livré avec incertitude déclarée »). The state never changes; "pass (waived)" does not exist.
- **Waiver sheet** (fiche) [19]: failing axis and lines word for word, reference kept, loss, interval and maximum allowed loss, cause, consequences and compensating controls, follow-up, author, date, expiry (V7). Reprinted with every version until closure; the previous target remains the target. Signable after the result is read, without moving any threshold.
  For A9:
    - **Who signs**: the maintainer alone signs the acceptance; the reviewers check the evidence.
    - **What the waiver sheet states**: the lines, cells and profiles concerned, R, the values and intervals, the maximum allowed and the expiry (V7).
    - **The gain bought**: it names the quality gain that the increase buys (axis, line, established size), or "no gain established" (« aucun gain établi »).
    - **The maximum allowed** bounds the waiver until closure. It does not replace the 1.05 threshold, and the state stays FAILED.
    - **A design decision made before the measurement**, such as the one of 2026-11-12, is cited there as a cause; it does not count as a waiver sheet.
- **Waivable** (dérogeable): the three A5 lines; A6 except a followed instruction; A9; at tier 2, only the cautious side (côté prudent), a limited and justified overestimation, its costs named (extra alerts, wrong priorities, needless remediations), printed "cautious side" [41].
- **Not waivable** (hors dérogation): an underestimation at tier 2, a tier 1 failure, a silent omission (A7), a false trace or provenance (A8), a followed planted instruction (A6). The maintainer can ship anyway: the verdict stays "requirements not met" (« exigences non satisfaites »), an underestimation prints "underestimation shipped" (« sous-estimation livrée »), and a tier 1 failure removes the "OWASP-conformant" (« conforme OWASP ») label.

## 5. Aggregation

1. **Order**: tiers 0, 1, 2, then 3, all measured and published, even after a failure higher up. A breakdown of vens is an A7 result; only a breakdown of the evaluation setup makes what it touches UNDETERMINED.
2. **No compensation**: no weight, no sum, no average, between axes or between lines [31]. The full vector is published; the headline (titre) is the weakest state [1], [3]. A quality gain does not compensate for FAILED on A9.
3. **Four delivery verdicts**:
    - *validated without waiver* (validée sans dérogation): every blocking line measured at P2, SATISFIED or PROGRESS ESTABLISHED; any blocking line NOT MEASURED rules it out, including each of the two A9 lines;
    - *shipped under waivers* (livrée sous dérogations): each FAILED under a waiver sheet, each UNDETERMINED and NOT MEASURED displayed, nothing that is not waivable;
    - *inconclusive* (non concluante): the evidence does not allow the conclusion sought;
    - *requirements not met* (exigences non satisfaites): a failure without a waiver sheet, or one that is not waivable.
4. **"Better than R, at the published margins"** (« Meilleure que R, aux marges publiées »): every line against R SATISFIED or PROGRESS ESTABLISHED, at least one PROGRESS ESTABLISHED outside A9 named with its size, no new waiver and no severe underestimation [17].
    - The margins and the tolerated losses are printed; meeting them does not demonstrate strict Pareto dominance.
    - An A9 gain alone is called "cheaper" (« moins chère ») or "faster rescoring than R" (« rescoring plus rapide que R »), with quality established as non-inferior at the published margins; it does not prove a better risk assessment.
    - A trade-off under a waiver sheet is written "progress on X, loss accepted on Y" (« progrès sur X, perte acceptée sur Y ») if the progress is established, otherwise "no gain established, loss accepted on Y".
    - The choice to ship rests with the maintainer.
5. **A stability gain** counts only if the diversity guard, the context reactions and the A3 distinctions do not drop.

## 6. Governance

- **Freeze**: a single file, versioned and hashed: axes, measurements, targets, margins, values V1 to V7, primary lines, seeds, models, repetitions, stopping rules, fingerprints of the sets and of the readers. Two reviewer signatures, then the maintainer's agreement; human ratings sealed before seeing the outputs [47], [48].
- **Changing the framework**: (1) write down a cause independent of the result: the text of a method, a reader error, a retired model, a new version of OWASP, a line with false alarms, a new attack surface; (2) state which interpretation becomes false, "the candidate fails" not being a cause; (3) bump the version before the next campaign, never together with a vens rule nor between an agreement and its reading; (4) re-read under the new framework the versions still being compared, or declare them non-comparable; (5) publish the effect of the framework separately. Old verdicts stay within their framework.
- **Before each campaign, at $0** [1], [33]: same-version replay (false alarms; not the noise of fresh answers), smallest visible loss per line, judge agreement, and deliberately defective candidates that the readers must fail: always "medium", random bands, inverted threshold or wrong impact basis, context ignored, instruction followed, hard CVEs removed, invented source. A simple and correct candidate on a homogeneous context must, for its part, pass. A faulty reader makes its conclusion UNDETERMINED until a versioned correction.
- **Sets**: the 74 demo CVEs and their three contexts, in diagnostic use since October, form a development set. The verdict reads a sealed set, once per candidate, and a rotating batch of CVEs published after the last freeze, under a rule fixed in advance [16]; GPT adds a confirmation batch to it (V3). A set that has been used for diagnosis is no longer called independent [46]; all runs of all candidates are published [45].
- **Models**: a frozen list per version. When a model is retired, a bridge campaign runs the old and the new list on R in the same window; if the old one has already disappeared, the break is declared.
- **Judges**: A3 reads SATISFIED only with three qualified human judges, blind to the outputs, conflicts declared, without the choices of vens as the right answer. Their disagreements are published and stay in the denominator (#435); a conclusion that depends on them is UNDETERMINED. κ and raw agreement shed light on it; no threshold certifies the reference [11], [22]. Model judges, reviewers included, give P1 evidence.
- **#310**: its verdicts and its three trade-offs stay within their framework; nothing here rewrites them.

## 7. Values to be set by the maintainer

Each value is signed before the campaign and goes into the frozen file.

| # | Value | Fable | GPT | More costly |
|---|---|---|---|---|
| V1 | Tolerated loss (fresh answers) | 0.10 (repetitions, guard); frozen S2 limits, 0.08 / 0.072 / 0.066 (models) | 0; S2 limits kept within their protocol | — |
| V2 | Repetitions | 5 per cell, instead of 2 | 5 per cell and per version; two models from distinct providers | equal |
| V3 | Sealed set, rotating batch | 100 CVEs × 3 contexts; 30 recent CVEs per campaign (no source) | at least 300 independent CVEs per batch × 3 contexts; main batch and confirmation batch, renewed after exposure | **GPT** |
| V4 | Context reaction | a pair reacts if 8 repetitions out of 10 move | L95 ≥ 90% of the pairs that must move; no "8 out of 10", which treats repetitions as scenarios | **GPT** |
| V5 | Validity thresholds | do better than the scanner; thresholds after the first human panel (at 36 vignettes, 80% requires 33 out of 36) | L95 ≥ 80% admissible bands; U95 ≤ 1% severe underestimations; L95 ≥ 90% ordered contrasts; non-inferior to the simple comparators | **GPT** |
| V6 | A9 tolerance and caps (agreed by both in round 2 of the cost and time debate, 2026-11-25) | +5% per line against R; minimum material gain of 5%; no absolute cap as long as the maintainer does not sign one; any increase beyond that is FAILED, acceptable under a waiver sheet (§4) | identical | equal: instrumentation and mock; no added calls if the quality runs follow the protocol; otherwise the missing real runs of R |
| V7 | Waiver expiry | on the waiver sheet, with no default value; reprinted until closure | next delivery decision, unless closed earlier; explicit renewal | — |

**More costly**: "—" means the value changes the verdict, not the spend; V2 costs more than the current 2 repetitions, on both sides; V4 and V5 on the GPT side need many independent cases (about 299 for a 1% bound), rated by three humans for V5. For V1, with δ = 0, an unchanged version reads SATISFIED only about 2.5% of the time (Fable), and more cases change nothing there.

**Maintainer's choices, 2026-11-26** (to be signed with the frozen file):
- **V1**: Fable column: 0.10 for the repetitions and the guard; frozen S2 limits for the models.
- **V2**: 5 repetitions per cell and per version, two models from distinct providers.
- **V3**: Fable column: 100 CVEs × 3 contexts, and 30 recent CVEs per campaign. Spending cap for the v0.7.0 campaign: $300.
- **V4**: GPT column: L95 ≥ 90% of the independent pairs that must move.
- **V5**: open. No human panel for v0.7.0: A3 reads NOT MEASURED there; the panel is planned for v0.8.0.
- **V6**: +5% per line against R; minimum material gain of 5%; no absolute cap.
- **V7**: the next delivery decision, with an explicit renewal.

## 8. Reading #310 in this framework

Indicative: Fable's re-reading in round 1, with its rules at the time, on an archived reference (P1). It replaces no verdict of #310; a line compared with `main` in #310 does not become a line compared with F.

1. Tiers 0 and 1: SATISFIED. A8: SATISFIED on the trace line.
2. A4: SATISFIED; exposure, controls and sens_high → sens_critical listed with no band reaction.
3. A3 and A6: NOT MEASURED; on A3, `floor` accepted as "cautious side".
4. A5: repetitions UNDETERMINED on fresh answers (internet-facing −0.047), FAILED on the paired replay (−0.122); models FAILED, waiver granted (trade-off 3), on internet-facing (0.666 vs 0.824); diversity guard FAILED, waiver granted (trade-off 2), on internal (0.222 vs 0.464), SATISFIED on internet-facing and internal-api.
5. Fable's headline: "better by priority, shipped with three accepted losses" (« meilleure par priorité, livrée avec trois pertes acceptées »); 1.0 no longer has the "better by priority" label (§5).

## 9. Sources

Numbers from the research brief, which gives the links (in the maintainer's records), limited to the methods cited here:
[1] NIST AI RMF 1.0 (2023) · [2] NIST IR 8312 (2021) · [3] Breck et al., The ML Test Score (2017) · [4] ISO/IEC 25010 · [5] ISO/IEC 25012 · [8] AERA/APA/NCME Standards (2014) · [9] Cronbach & Meehl (1955) · [10] Koo & Li (2016), ICC · [11] McHugh (2012), kappa · [12] Krippendorff (2011), alpha · [14] Leventhal, G theory · [16] Bean et al. (2025) · [17] Liang et al., HELM (2022) · [18] Ribeiro et al., CheckList (2020) · [19] SR 26-2 (2026), by analogy, generative AI being outside its scope · [20] Jacobs et al., EPSS (2019) · [22] CERT/CC, SSVC · [31] OECD/JRC, Composite Indicators (2008) · [32] Gneiting et al. (2007) · [33] EMA, non-inferiority margin (2005) · [34] Yan et al., Positive-Congruent Training (2021) · [35] Miller, Adding Error Bars to Evals (2024) · [37] Kapoor et al., AI Agents That Matter (2024) · [38] Mitchell et al., Model Cards (2019) · [40] OWASP LLM01:2025 · [41] OWASP Risk Rating Methodology · [45] Singh et al., The Leaderboard Illusion (2025) · [46] Dwork et al. (2015), holdout reuse · [47] Gelman & Loken (2013) · [48] Nosek et al. (2018).
