# Campaign: vens v0.7.0 against v0.6.0

Under [`vens-kpi/1.0`](../../spec/1.0/vens-kpi-1.0.md) (tag `spec-1.0`, sha256 `876bac7ea5d4fa37a3810b91af8acdd138c059f7d2ea92070a6d3bddffeaa763`).

## Status

**Frozen, signed by both reviewers and approved by the maintainer on 2026-11-27; not started.** Published before the first run, as spec §6 requires: the frozen file, the reader's hash and the commitments of the sealed data. Nothing has been read yet. The result will be added here at the stage reached.

## Frozen before the first run

| Item | Value |
|---|---|
| Candidate | venslabs/vens#436 at `34ef2a1a614bca71f90042c9865fdf275704f1ee`, darwin/arm64 binary sha256 `47155d4bbb67177c613b205b4b54b001e29577a8f6a60921869f68208f771cda` (reproducible build, recipe in F0 §1) |
| R | v0.6.0 release asset `vens-v0.6.0-darwin-arm64.tar.gz`, cosign-verified, binary sha256 `da3c2daa19661bdd518066f56a1f4269315570db1bebef635be17cedc653d461` |
| Models | `claude-sonnet-4-6`, `gpt-5.4-mini-2026-03-17` |
| Reader | sha256 `307e67acef0b3d05ca231fb167fcb0bae63bae0eac6d02cd379145d8a47a79f2`; config `ca8fe698ca732ac36f0290aef4f05b553fa9e0b707c328e033882e3f14a09ccb`. The code stays private until the sets retire. |
| Frozen file | [`F0.md`](F0.md); signed original sha256 `2b0a2859c92f777e2d064c7c2cec9ab8dfa5a636cac996e29eabd474333222ad` |
| Spend cap | $300, in stages with a go from the maintainer at each one |

`F0.md` here is the signed file with one sealed CVE id replaced by `[sealed id]` (§11); nothing else differs. The original is published when the sealed set retires.

## Commitments

Salted SHA-256 commitments, one manifest per set in [`commitments/`](commitments/). The salts and the sets stay private until retirement; anyone can then check every file against its line.

| Set | Aggregate |
|---|---|
| `sealed-v0.7.0`: 100 CVEs + 4 sentinels from 20 public images, 3 deployment contexts | `92dd771f65793c3c3b5747872c717bf5b0c982689267b363dc18d26d4d5fa935` |
| `dir-v0.7.0`: context-sensitivity pairs and controls (A4) | `dfc5c42ae90c9d861f98b5df3d34310a60dcab1a626e9674ac58c812266fa00b` |
| `inv-prep-v0.7.0`: input-invariance rules and tools (A6) | `a686495f6e3f1fc6060f308bd9a8969b0525e0fa3cd578be7f666708032ce91f` |
| `inv-data-v0.7.0`: 30 bases, paraphrases and planted variants (A6) | `5eb5b13964f26067c43d580dece4b1054833349c95f1391e899fe346b4d9f412` |
| `frame-v0.7.0`: the population the sealed set was drawn from | `df26654a9e08fa7bfa54b025b8478a82f8bebdfbb4c6e4225814dcdba613e3f0` |

The draw used drand quicknet round 34328212 (2026-11-27T14:00:00Z), randomness `c9153f2f25bc80a87c42f1c28303f240c2bb2d89e4640f1e5f3bbd46d5c365a7`, under a policy committed before the round (sha256 `969eb15540dfbfbe2af2fb5d5f1b5c3901ae109393fc594c9308c4d0bbbea107`).

## After the campaign

Added here: the reading at the stage reached, the calibration, every attempt and result with opaque CVE ids (failures and violations included), the spend charged and the delivery decision.
