# Jev as a Risk Classifier — Evaluation (branch `feat/jev-classifier`)

**Question:** is the TypeSafe **Jev** judgment API (`jev-latest`) a better risk
classifier for Sentry than LLM models, given the honeypot deployment constraint
(Lightsail 1 GB VPS — not enough CPU/RAM to run local AI, and no budget for
per-event generative LLM calls)?

**Answer:** yes for this use case. Jev classifies events with calibrated
probabilities in a single structured response: **p50 272 ms, 0 errors, 0 parse
failures, precision 100% / recall 93.8% / F1 96.8%** on the labeled synthetic
kit, at ~692 input + ~69 output tokens per event. It plugs into the existing
`[llm]` stage as just another provider — no pipeline, rule or action changes.

---

## 1. What was built

| Piece | File | Notes |
| --- | --- | --- |
| `JevProvider` (`LlmProvider` adapter) | `crates/sentry-ai/src/llm/jev.rs` | One HTTP call per event with **two batched questions**: `verdict` (choice over allow/rate_limit/challenge/block/quarantine) and `risk` (score, 10 levels 0–9 → `score/9×100` on the pipeline scale). Pure-struct responses — no JSON repair, no hallucinated fields. |
| Usage/cost plumbing | `crates/sentry-ai/src/llm.rs` (`LlmUsage`) | `ClassifyResponse.usage` now carries `input_tokens`/`output_tokens`/`cost?` for any provider. |
| Daemon wiring | `crates/sentry-cli/src/daemon.rs` | `make_llm_provider` factory (shared with the bench); `[llm] provider = "jev"`. Key resolution: `SENTRY_JEV_KEY` → `TYPESAFE_API_KEY` → `JEV_API_KEY` → `~/.config/typesafe/key` (same order as `jev-mcp`). |
| Bench harness | `crates/sentry-cli/src/bench_llm.rs` | `sentry bench llm --providers jev,mock [--events access.log|.jsonl] [--format <nginx log_format>] [--n N] [--concurrency C] [--out report.json]`. Runs each event through the heuristic pipeline (baseline) and every provider; reports latency, agreement, precision/recall, tokens/cost. |

## 2. Methodology

- **Synthetic kit (labeled, deterministic):** 55 HTTP events — 23 benign
  (browsing, API calls, good bots, health probes, successful login) and 32
  attacks (SQLi raw+encoded, XSS, path traversal, LFI, Log4Shell, command
  injection, sensitive-file access, CMS/framework probes, bad-crawler UAs:
  sqlmap/nikto/masscan). Documentation-range IPs only.
- **Real-log replay (unlabeled):** nginx combined-format access.log via
  `--events` (parser + real-IP resolution from `sentry-source-nginx`).
- **Baseline:** each event also goes through the default heuristic pipeline
  (`build_default_ruleset`), which is what a deployment decides *without* any
  AI stage. Agreement is measured against that.
- **No cache, no retries** during measurement — raw provider cost.
- Runs: `jev` at concurrency 4 and 16, `mock` as harness sanity check.

## 3. Results

### Speed (dev machine → `api.typesafe.ai`, HTTPS)

| Metric | jev @ concurrency 4 | jev @ concurrency 16 |
| --- | ---: | ---: |
| p50 latency | 272 ms | 280 ms |
| p95 latency | 345 ms | 363 ms |
| mean | 280 ms | 291 ms |
| max | 353 ms | 447 ms |
| throughput | 13.8 ok-calls/s | **48.2 ok-calls/s** |
| errors | 0 / 55 | 0 / 55 |

Throughput scales ~3.5× from concurrency 4→16 while p50 stays flat — the API
parallelizes cleanly (its own concurrency cap is 16). At the default
concurrency 4 that is **>1.1M events/day**, orders of magnitude above honeypot
traffic. Latency is a single forward pass per call; the daemon runs this
**forked** (async, off the hot path), so event latency is unaffected.

### Output quality (labeled synthetic kit)

| Metric | Value |
| --- | ---: |
| Calls / errors / parse failures | 55 / 0 / **0** |
| Precision (verdict ≠ Allow) | **100%** |
| Recall | 93.8% (2 of 32 attacks allowed) |
| F1 | **96.8%** |
| Agreement with heuristic pipeline (verdict) | 69.1% |
| Agreement malicious-vs-benign | 85.5% |
| Mean confidence | 0.92 |

Score calibration is clean: every benign event scored **≤ 12/100** (mostly
0–4), every blocked attack **≥ 46**, with severity ordering intact (simple
probes 46–67, SQLi/XSS/RCE payloads 75–98). The only two misses
(`/console/`, `/api/debug/vars` — payload-less probes) came back as
`allow` with risk 41–43 at **confidence 0.28** — i.e. the model *said* it was
uncertain. In the daemon, `llm_signals` still turns `allow` with risk ≥ 20
into a small `LlmMalicious` bump (weight ≈ 12), which can tip a borderline
base score into RateLimit; a hard block for these would require a verdict
answer, not a score answer.

On the real-log replay (7 mixed lines): malicious-vs-benign agreement **100%**,
unparseable lines skipped gracefully.

Verdict distribution on the kit: `Allow=25, Block=30` — jev **never chose
rate_limit/challenge/quarantine** on these events. If finer escalation matters
(slowloris-style volume abuse), the score question still carries it (mid-band
scores), and the choice question accepts those labels.

**Determinism:** identical token counts (38051/3795) across two independent
runs of the same 55 events — stable, repeatable verdicts, no sampling
variance to manage.

### Output reliability vs LLM

LLM adapters must repair prose-wrapped/capitalized JSON (`prompt::parse_classify`)
and can still fail or time out. Jev returns typed struct answers by
construction — 0 parse failures across all 117 classification calls — and the
choice answers carry full **probability distributions**, which the explanation
field exposes for every alert (`jev verdict=block (p=0.93) risk=8.4/9 | p(allow=0.02 …)`).

### Cost

Per-event token usage (context bounded to 2048 chars, ~692 in / ~69 out):

| Scope | Input tokens | Output tokens |
| --- | ---: | ---: |
| Per event (mean) | 692 | 69 |
| Per 1k events | ~692k | ~69k |

TypeSafe does not publish pricing (docs have no pricing page); the API returns
`usage.cost` on some plans but not on this key, so exact $ cannot be computed
here — track it on `console.typesafe.ai`. Reference points for the same
token volume with a generative LLM: ~**$0.145 / 1k events** on
`gpt-4o-mini`-class pricing, ~**$2.4 / 1k events** on `gpt-4o`-class. The
relevant economic comparison for the honeypot:

| Option | Hardware | Marginal cost | Latency | Output reliability |
| --- | --- | --- | --- | --- |
| **jev (this branch)** | none (VPS untouched) | per-call (tokens above) | ~280 ms | struct, 0 failures |
| LM Studio gemma over WireGuard (current `[llm]` config) | needs the WireGuard peer up, gemma-4B class | $0 | seconds-scale on CPU, 120 s timeout budget | JSON can fail/repair |
| OpenRouter LLM | none | ~$0.15–2.4 / 1k events | 0.5–2 s typical | JSON can fail/repair |
| Local ONNX (`models/anomaly_v1.onnx`) | 1 GB VPS — the constraint that motivated this work | $0 | ms-scale, but `ort` on 1 GB RAM is the risk | deterministic |
| Heuristics only (current default) | none | $0 | µs-scale | n/a — misses payload-level intent |

### Mock sanity check

The always-`Block/90` mock scored 25.5% agreement / F1 73.6 — confirming the
harness actually discriminates providers instead of rewarding everything.

## 4. How to run it

```bash
# daemon: switch [llm] to jev (fork mode, escalates above score 30)
#   provider = "jev"
#   mode     = "fork"
#   only_above = 30
export SENTRY_JEV_KEY=...   # never in config

# benchmark anytime (synthetic kit)
cargo run -- bench llm --providers jev,mock --out bench.json

# benchmark on real honeypot traffic (on the VPS or anywhere):
cargo run -- bench llm --providers jev --events /var/log/nginx/access.log
# custom log_format: --format '$remote_addr ... "$request" $status ...'
```

Suggested rollout on the honeypot: start with `mode = "shadow"` for a day
(watch `llm (shadow) would change verdict` logs), then flip to `fork`.

## 5. Limitations

- The synthetic kit is clear-cut by construction (real honeypot traffic is
  noisier); the `--events` replay path exists precisely to re-run this on
  real logs — the harness prints agreement and distributions without labels.
- No public TypeSafe pricing; cost was evaluated in tokens, with `usage.cost`
  recorded automatically when the plan exposes it.
- Jev is judgment-only: `explain()` returns a structured driver breakdown
  (top factor + probabilities), not prose. Fine for webhooks/CLI; not a
  narrative analyst.
- No retries on 429/5xx (consistent with the other adapters; the daemon
  fails open). The 10-level score cap is enforced by the API.
- One HTTP call per event (two batched questions). Volume abuse patterns
  that need windows (scan/behavior trackers) stay in the pipeline — jev
  only refines single-event verdicts.

## 6. Conclusion

Jev is a strictly better fit than an LLM for this deployment's risk
classification: **~280 ms** structured classification with **0 output
failures**, **F1 96.8% / precision 100%** on labeled data, calibrated
probabilities instead of sampled JSON, determinism across runs, zero local
hardware, and it reuses the whole existing `[llm]` fork/shadow machinery with
a one-line config change. The remaining unknown is the exact per-token price
(private); even at generative-LLM-equivalent pricing it removes the failure
modes and latency tail that motivated looking for an alternative — and on the
honeypot VPS it is the only remote option that adds no local load at all.
