# A9 harness: recording proxy and run timer

vens logs neither tokens nor run time. `run.py` starts one `vens generate` behind a local proxy that forwards each provider call unchanged and logs one JSON line per request, then times the run and prices the usage the provider reported at a dated grid. Spec: [vens-kpi 1.0](../../spec/1.0/vens-kpi-1.0.md), §2 and §3, A9.

## Running it

```sh
python3 -m vkpi.a9.run --vens ./vens --provider anthropic --n 74 \
  --input scan.trivy.json --vex out.cdx.json \
  --prices vkpi/a9/prices/2026-11-26.json --log calls.jsonl --out run.json \
  -- --config-file config.yaml --sbom-serial-number urn:uuid:...
```

- The key and the model come from the caller's environment (`ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`, or the `OPENAI_` pair). run.py adds `--llm`, the input and the VEX path, and points both base URLs at the proxy.
- `--n` is the number of incoming CVEs, taken from the frozen file: run.py does not count them.
- `--vens` is resolved to an absolute path once, and that file is the one checked, hashed and launched: `./vens` never falls back to a `vens` on PATH.
- `--vex`, `--log` and `--out` must not exist: one log per run.
- Exit code: 0 for a complete run, 1 when vens failed or wrote no VEX, 2 when the harness refused to start.
- The proxy listens on 127.0.0.1 only. `python3 -m vkpi.a9.proxy --log calls.jsonl` runs it alone and prints the two base URLs to export.

## What each vens version needs

Read in the vens checkout, v0.6.0 tag (2654ca7) and dfa73fd (v0.7.0).

| | v0.6.0 | v0.7.0 (dfa73fd) |
|---|---|---|
| OpenAI base URL | `OPENAI_BASE_URL`, `pkg/llm/providers/openai/openai.go:60`; default `https://api.openai.com/v1/` at `:35` | same lines |
| Anthropic base URL | `ANTHROPIC_BASE_URL`, `pkg/llm/providers/anthropic/anthropic.go:64`; default `https://api.anthropic.com/` at `:45` | same lines |
| Base-URL flag | none in `cmd/vens/commands/generate/generate.go` | none |
| OpenAI call | `Chat.Completions.New`, `openai.go:108`: Chat Completions, not streamed | `openai.go:110`, same |
| Anthropic call | `Messages.New`, `anthropic.go:106`: not streamed | `anthropic.go:109`, same |
| SDKs (`go.mod`) | openai-go v3.90.0, anthropic-sdk-go v1.84.0 | openai-go v3.98.0, anthropic-sdk-go v1.84.0 |
| VEX write | temp file `generate.go:266`, renamed into place `:290`; the `--attest` file comes after, `:330` | `:332`, `:356`; `--attest` after, `:397` |
| Rate-limit loop | `llm.RetryOnRateLimit` (`pkg/llm/llm.go:50`) from `pkg/generator/generator.go:680`, 10 tries 10 s apart (`generator.go:43-44`) | from `pkg/generator/call.go:49`, same values (`generator.go:41-42`) |
| Config | ignores `schema_version` | refuses a config without `schema_version: 2` (`pkg/riskconfig/load.go:50`) |

- No vens code calls a streaming method (`NewStreaming`) in either version, so the proxy reads each response whole and takes its `usage`.
- Both SDKs send `Content-Length` (anthropic-sdk-go `internal/requestconfig/requestconfig.go:482`, openai-go `:620`); the proxy answers 411 to a body without one.
- Both SDKs retry a failed attempt twice (`MaxRetries: 2`, anthropic-sdk-go `requestconfig.go:175`, openai-go `:286`: 408, 409, 429, 5xx, connection errors) and number the attempts in `X-Stainless-Retry-Count` (`:584`, `:682`). The log's `attempt` is that header plus one; a call is an attempt 1. When the SDK gives up on a 429, vens's loop above calls again: a new call.
- The Anthropic SDK gives a non-streaming attempt 10 minutes (`client.go:299`, applied at `message.go:66`); the proxy waits up to 900 s for the provider, so it never cuts an attempt first.
- Neither version sets Anthropic `cache_control`, `inference_geo` or a service tier.

## The log: one line per request

| Field | |
|---|---|
| `provider`, `endpoint` | the route, and the provider path (`/v1/messages`, `/v1/chat/completions`), without the query string |
| `model` | `model` of the request body |
| `model_served`, `service_tier` | from the response; OpenAI puts the tier next to `usage`, Anthropic inside it |
| `attempt` | `X-Stainless-Retry-Count` + 1; null without the header |
| `status` | the provider's status; null when no answer came back (`error` says why, the client got 502 or 504) |
| `forwarded` | true once the connection to the provider is open and the request goes out; false when the proxy answered alone (404, 411, a refused connection) |
| `request_bytes`, `response_bytes` | body bytes as sent and as received (a response may be gzip) |
| `start_ns`, `end_ns` | Unix time in ns: request read by the proxy, response written back |
| `usage` | the provider's `usage` object, verbatim |
| `error` | null, `unknown route`, `request without Content-Length`, `upstream connect <exception>`, `upstream <exception>` or `client <exception>` |

Never logged: request and response bodies, which can hold the deployment context; headers, so neither `Authorization` nor `x-api-key`; the query string. No error message repeats an upstream URL or an `--upstream` argument either, since a URL can carry credentials.

## The run JSON

- `seconds`: from the launch of `vens generate` to the VEX's last write. vens writes a temp file and renames it into place, so the VEX mtime is that write. Null when the run is not complete, or when the mtime falls outside the run. `seconds_to_exit`: launch to exit, on the monotonic clock.
- `complete`: exit 0 and a VEX on disk. An aborted run keeps its cost and has no `seconds`.
- `calls`, `attempts`, `statuses`, `request_bytes`, `response_bytes`.
- `tokens`, by category, also per model under `models`:
    - OpenAI: `input` = `prompt_tokens` − `prompt_tokens_details.cached_tokens`, `cache_read` = `cached_tokens`, `output` = `completion_tokens`, reasoning included.
    - Anthropic: `input` = `input_tokens`, `cache_read` = `cache_read_input_tokens`, `cache_write_5m` and `cache_write_1h` from the `cache_creation` split of `cache_creation_input_tokens`, `output` = `output_tokens`.
- `usd` = Σ tokens × grid price / 10^6, and `usd_per_cve` = `usd` / N. Both are null, with the reasons in `usd_not_measured`, when:
    - a 2xx response has no usable usage (a field missing, null, or not adding up);
    - a response was served at a `service_tier`, or an Anthropic `inference_geo`, other than the grid's (`served at tier priority, grid is default`); a response with no tier counts as `unreported`;
    - a request went out and no answer came back (a reset, a timeout): the provider may have billed it (`request sent, no answer`);
    - a request hit an unknown route, the model is not in the grid, or a category in use has no price.
- An error response reports no usage: it counts as an attempt, with no tokens. A request the proxy stopped before the provider (411, a client error, a refused connection) costs nothing. Nothing is estimated from bytes.
- `vens_sha256`, `prices` (date and sha256 of the grid), and `default_upstreams`, false when `--upstream` sent the calls somewhere other than the provider's API.

## Price grid

`prices/2026-11-26.json`, USD per million tokens, read on 2026-11-26. Each entry keeps the table header and row it was read from, and the `service_tier` its prices are for (`inference_geo` too, for Anthropic).

| Model | Input | 5m cache write | 1h cache write | Cache read | Output | Source |
|---|---|---|---|---|---|---|
| claude-sonnet-4-6 | 3 | 3.75 | 6 | 0.30 | 15 | https://platform.claude.com/docs/en/about-claude/pricing |
| gpt-5.4-mini | 0.75 | | | 0.075 | 4.50 | https://developers.openai.com/api/docs/pricing, Standard |

- No price is null: both pages could be read.
- The OpenAI page gives gpt-5.4-mini no cache-write price. `prompt_tokens_details.cache_write_tokens` stays in the log and is not priced apart: those tokens are in `prompt_tokens − cached_tokens`, priced as input.
- The grid is the standard tier (`standard` for Anthropic, `default` for OpenAI) at the global endpoints, which is what vens asks for: no `inference_geo` (US-only inference costs 1.1x on Claude 4.6 and later), no service tier, and the proxy calls `api.openai.com`, not a regional endpoint ("Regional processing (data residency) endpoints are charged a 10% uplift for models released on or after March 5, 2026"). A response served elsewhere leaves `usd` null rather than being priced at the wrong rates.
- No long-context price applies: Sonnet 4.6 bills its whole 1M context at the standard price, and the OpenAI page lists a single gpt-5.4-mini row.
- The grid values usage; it is not the invoice, which the spec publishes apart.

## Tests

```sh
python3 -m unittest discover -s tests -t .
```

- `test_usage.py`: usage parsing on the response examples of the Chat Completions and Messages references (URLs in the file).
- `test_proxy.py`: a fake provider; forwarding, statuses, retries, timing, gzip, and keys and bodies kept out of the log.
- `test_run.py`: a stand-in vens (`fake_vens.py`) for the timer, the pricing and the refusals; the grid is checked against its quoted rows.
- `test_vens_e2e.py`: the real binaries of both versions through the proxy and a fake provider, for both providers, twice. First a 500 the SDK retries, a 200 vens reads but cannot use, a 400 that ends the run. Then a run that completes: the fake answers each call with the smallest reply its own response schema accepts (v0.7.0 enumerates the CVE ids, v0.6.0 takes the CVE id as a string), so vens writes its VEX and the timer is checked on a real binary. It runs when `VKPI_VENS_V060` and `VKPI_VENS_V070` name the binaries; with `VKPI_E2E_REQUIRED=1` a missing binary fails instead of skipping.

The CI workflow (`.github/workflows/a9.yml`) takes v0.6.0 from its release asset, checked against the release's `SHA256SUMS`, and builds v0.7.0 from dfa73fd with the vens Makefile. No test calls a provider: every upstream is a local fake and the key is a dummy.

## Left for the campaign runner

- N, the scan, its order, the model and the machine are the same for the candidate and R; runs interleaved, one at a time, both through the proxy, never one direct.
- One candidate binary for the whole campaign: two builds of dfa73fd can differ (Go stamps the git state into a build made in a checkout), and each run JSON records the sha256 it ran.
- Each run JSON should read `default_upstreams: true` and `usd_not_measured: {}`; the model and tier served are in `models`.
- OpenAI caches prompt prefixes on its own, so `cache_read` depends on what ran just before: the warm-up and the order belong to the frozen protocol.
- The proxy reaches the provider directly; it does not go through `HTTPS_PROXY`.
- Means, p50, p95, ratios and intervals are the reader's job: run.py writes one run.
- The spend actually charged comes from the provider consoles.
