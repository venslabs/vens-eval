# Provenance of vkpi/chain

- **Source:** [venslabs/vens-benchmark](https://github.com/venslabs/vens-benchmark), its `chain/` package and `tests/`.
- **Commit:** `0f6d16431baf4b53ad8d2e1dc5cbb2b0bd712300`.
- **License:** Apache-2.0, the source's `LICENSE` (Copyright 2025 venslabs), the same terms as this repo's code. See
  `LICENSE` and `NOTICE`.

The first commit of this import holds each file below byte for byte as the source has it. Each sha256 is the source
file's at that commit, `git show 0f6d16431baf:<source path> | shasum -a 256`.

## Modules

| Path | Source | sha256 |
|---|---|---|
| `vkpi/chain/__init__.py` | `chain/__init__.py` | `e5fe1595c0725d153702106ac2261b1b29062df449f519ca856784a68dfd975f` |
| `vkpi/chain/errors.py` | `chain/errors.py` | `48caa4d7557d0b862a97f2aeb680b7ba66412f0e9d5b5d1cc3bd8d75bee6dc67` |
| `vkpi/chain/contract.py` | `chain/contract.py` | `825143bc658a5b9ebd200fd6f8fdc01e23603c9b052dd1d3512d1ecca7d24043` |
| `vkpi/chain/runvens.py` | `chain/runvens.py` | `5cab98a7e231a562396f962ffe2fa6a380938a195fd95a87a7c589de042931c1` |
| `vkpi/chain/attempt.py` | `chain/attempt.py` | `0f1506faee6a4faaa337e271b4aee0ff63862fc8ad517b7b43f8745c5fb1332c` |
| `vkpi/chain/venslog.py` | `chain/venslog.py` | `17fd59aaeb14f556e429b9dcf48c81e688e5b188c0011102b80f28cfb55e9ef3` |
| `vkpi/chain/calls.py` | `chain/calls.py` | `83f908073b29f339b826429bf30aedb15718b75e3a9b80cd219c82c178c98ca4` |
| `vkpi/chain/cdx.py` | `chain/cdx.py` | `a47858d024cb52b9168fa6dc0b0861010a89b9714ddc19784787304fdbaa8082` |
| `vkpi/chain/answers.py` | `chain/answers.py` | `cd84421c046d189f331e7aeeb8848635b5c9839bc60c62bdb68aee388d5f5271` |
| `vkpi/chain/recovery.py` | `chain/recovery.py` | `1d0c532f1291d0a83568e00a1128ea3a7e196fa29754942cbe4c20989ccf7b48` |
| `vkpi/chain/cost.py` | `chain/cost.py` | `b7b284b72811d6fdda384e869001e49b361f96455ebe651bc24d8b715ae8baca` |

## Tests

| Path | Source | sha256 |
|---|---|---|
| `tests/chain/__init__.py` | `tests/__init__.py` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `tests/chain/support.py` | `tests/support.py` | `681fbc0ed104105921e8509c2d18b64a69969f4653f6e7828fe537c019a00ae5` |
| `tests/chain/test_answers.py` | `tests/test_answers.py` | `a905e69f05646fe2b99985f6b4fbb88403a4f1eeebb0a5573b2b9745e23b558e` |
| `tests/chain/test_attempt.py` | `tests/test_attempt.py` | `14daea16f15698b3f4250ad35c2684a8b34cf71865171a904d2921fe1c60d940` |
| `tests/chain/test_cost.py` | `tests/test_cost.py` | `80185fce250d7d161b5a1a034b84220ad2d1ade36f1aac61a8873a34513a0d24` |
| `tests/chain/test_recovery.py` | `tests/test_recovery.py` | `22e476fc122a41368475cc839b89a097ca32d351e078f19c3e9aed04430713c6` |
| `tests/chain/test_venslog.py` | `tests/test_venslog.py` | `529bcbac9843838c66ecbd04d8c52c51f713497cd39a746c71a3737aec4dd50c` |
| `tests/chain/test_runvens.py` | `tests/test_runner.py`, an excerpt | `25f382469455b27d37dc6bc431dfe178a1bdc437f0fcd284a7395c470f8e004c` |
| `tests/chain/test_contract.py` | `tests/test_verdicts.py`, an excerpt | `6599721449381549d5623589be97d01be56d607a27f575025fd34f74192fc882` |

The two excerpts are whole lines of their source, in order, nothing else:
- `test_runvens.py`: lines 5, 9-10, 12-15, 17-20, 22, 24, 26-27, 32-34, 137-188, 199-203, 207, 258-264, 430-502, 641,
  715-724 and 1011-1012 of `tests/test_runner.py`. These are runvens's own tests, `TestRunvens` and `TestKeys`'s key
  forms test, with the helpers they use. The rest of the file drives `ctx_runner.py`, `campaign` and `read`.
- `test_contract.py`: lines 13-14, 18, 35-37, 100-107 and 464-465 of `tests/test_verdicts.py`. This is the one contract
  test that needs no scenario corpus.

`vkpi/__init__.py` and `tests/__init__.py` are this repo's own, empty, and not taken from the source.

## Scope

- **`legal` is not vendored,** though PR 1's list names it. It imports `chain.javacheck`, the Java check of PR 3, and
  needs a JDK and the calculator's JAR. Its source sha256 is
  `21a83019d88d4bd5cfe4170a26d02b08fdcc1aeb7d71a23c10b718829b6ff92e`.
- **`cost` is vendored beyond the list,** because `attempt` imports it for each attempt's cost estimate. It uses the
  standard library alone and imports nothing else of `chain`.
- **`dispatch` is not vendored.** `attempt` reads one name from it, `STRAY`.

## Adaptations

The changes after the byte-for-byte copy, one line per change, behavior unchanged:
- `vkpi/chain/answers.py`, `attempt.py`, `calls.py`, `cdx.py`, `recovery.py` and `tests/chain/test_answers.py`,
  `test_attempt.py`, `test_contract.py`, `test_cost.py`, `test_recovery.py`, `test_runvens.py`, `test_venslog.py`: a
  first line, `# Changed from venslabs/vens-benchmark@0f6d164: see vkpi/chain/PROVENANCE.md.`, the notice Apache-2.0
  §4(b) asks of a changed file.
- `vkpi/chain/answers.py`: imports `cdx` and `errors` from `vkpi.chain`, not `chain`.
- `vkpi/chain/calls.py`: imports `errors` from `vkpi.chain`, not `chain`.
- `vkpi/chain/cdx.py`: imports `errors` from `vkpi.chain`, not `chain`.
- `vkpi/chain/recovery.py`: imports `calls` and `venslog` from `vkpi.chain`, not `chain`.
- `vkpi/chain/attempt.py`: imports `answers`, `calls`, `cdx`, `cost`, `recovery`, `venslog` and `errors` from
  `vkpi.chain`, not `chain`, and no longer imports `dispatch`.
- `vkpi/chain/attempt.py`: `_excluded` compares with `"stray"`, the value of `dispatch.STRAY` at the commit, instead of
  reading it from `dispatch`.
- `tests/chain/test_answers.py`, `test_cost.py`, `test_recovery.py`, `test_venslog.py`: import from `vkpi.chain`, and
  `support` from `tests.chain`.
- `tests/chain/test_attempt.py`: imports `attempt` from `vkpi.chain`, `support` from `tests.chain`, and no `dispatch`.
- `tests/chain/test_attempt.py`: `test_run_meta_with_a_dispatch_id` writes out the title `dispatch.title(...)` returns
  at the commit for the same arguments, instead of calling it.
- `tests/chain/test_runvens.py`: imports `attempt` and `runvens` from `vkpi.chain`, without the `campaign` and `read`
  the excerpt does not use, and `support` from `tests.chain`.
- `tests/chain/test_runvens.py`: `ROOT` is three folders up, the repo root, as the file sits in `tests/chain/`.
- `tests/chain/test_runvens.py`: `PARENT` imports `runvens` from `vkpi.chain`.
- `tests/chain/test_contract.py`: imports `contract` from `vkpi.chain`, without the `runvens`, `venslog` and `verdicts`
  the excerpt does not use.

Every other file is byte for byte the source's. No module reads a path of vens-benchmark's layout: `runvens`,
`attempt` and `calls` only join names inside the attempt folder their caller gives them. Docstrings and
comments stay as written, so the files they name (`ctx_runner.py`, `chain/campaign.py`, `chain/verdicts.py`,
`java/Check4.java`) are vens-benchmark's. `tests/chain/support.py`'s `FIXTURES` names `tests/chain/fixtures/`, which is
not vendored: only the source's Java tests read it.

## Dependencies

The standard library alone, on Python 3.12, the source's CI pinning 3.12.12. POSIX only: `runvens` uses
`os.killpg` and `select` on pipes.

## Known staleness

This code encodes older vens rules: those of vens-benchmark's step 4, not those of the v0.7.0 candidate (#436's head,
`34ef2a1`), and only some of R's (v0.6.0, `2654ca7`). A later PR that reads candidate or R output with it must guard
against each point below. Line numbers are this tree's. Measured on 2026-11-26 through `runvens.generate`, on vens's
mock LLM at batch 1, with binaries built from `34ef2a1` and `2654ca7` (`vcs.modified=false`), at $0 and with no key:
- **`contract.py` states vens `b7c0435`'s rules, not the candidate's.** Nothing in `vkpi/chain` imports it. On
  vens-benchmark's `comp_gdpr` scenario it expects 9 questions, M, O, EE, LC, LAC, FD, RD, NC and PV, where the
  candidate asks 6: M, O, EE, LAC, NC and PV. The candidate's `answers.json` also gives 6 other sources: SL
  `worst_case` (`contract.py`: `constant`), LC `cvss` (`answer`), LI and LAV `cvss` (`floor`), FD and RD `criticality`
  (`answer`).
- **`__init__.py:4` and `cdx.py:63-68` describe L × max(T, B).** The candidate rates L × the impact of the declared
  basis, named in each VEX vulnerability's `vens:impact-basis`: business when `data_subjects` is declared, technical
  otherwise. Given v0.6.0's quickstart config with the marker, a technical basis, the candidate scores all 45 CVEs
  L × T, and 20 of those scores differ from L × max(T, B).
- **`cdx.py:71-92`, `main_severity` and `main_rule`, are vens `43ab10b`'s rule.** It holds for R: `pkg/riskconfig` and
  `pkg/owasp` are unchanged from `43ab10b` to `2654ca7`, and v0.6.0's 45 ratings of its own quickstart pass
  `main_rule`.
- **`runvens.py:271-272` passes `--strict`, which v0.6.0 refuses:** it exits 1 with `unknown flag: --strict`.
- **`runvens.py:67-76`, `add_marker`, bypasses the candidate's E1.** The candidate refuses a config without
  `schema_version` ("has no schema_version: it was written for vens v0.6 or earlier (schema 1)") and asks for a
  migration that reconfirms `business_criticality`. v0.6.0's quickstart config, with the marker added, loads on the
  candidate and rates its 45 CVEs.
