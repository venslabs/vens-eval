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

`vkpi/__init__.py` and `tests/__init__.py` are new and empty.

## Scope

- **`legal` is not vendored,** though PR 1's list names it. It imports `chain.javacheck`, the Java check of PR 3, and
  needs a JDK and the calculator's JAR. Its source sha256 is
  `21a83019d88d4bd5cfe4170a26d02b08fdcc1aeb7d71a23c10b718829b6ff92e`.
- **`cost` is vendored beyond the list,** because `attempt` imports it for each attempt's cost estimate. It uses the
  standard library alone and imports nothing else of `chain`.
- **`dispatch` is not vendored.** `attempt` reads one name from it, `STRAY`.
