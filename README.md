# Sentry

Real-time access monitor for internet-exposed services. Detects threats via
deterministic heuristics + AI (local ONNX / optional LLM), computes a risk
level per request/IP, and acts automatically: block, edge challenge
(Cloudflare), rate-limit, or webhook alert.

## Why it exists

Commercial WAFs cover the obvious. Sentry covers the **rest**: encoded
payloads, sensitive-path scanning, malicious crawlers, anomalous access
patterns — combining fast rules (zero known false positives) with AI for the
unknown. All in a single Rust binary, running locally, never shipping your
logs to a third party.

## Stack

| Layer        | Technology                                         |
| ------------ | -------------------------------------------------- |
| Language     | Rust 2021 (MSRV 1.80)                             |
| Async        | tokio                                             |
| CLI / TUI    | clap (derive) + ratatui + crossterm               |
| Storage      | Postgres (sqlx)                                   |
| Config       | figment (TOML + env overlay, `SENTRY_` prefix)    |
| AI           | ort (ONNX, local) + `LlmProvider` trait           |
| Edge actions | `ChallengeProvider` trait (Cloudflare, …)         |
| Geo/ASN      | maxminddb (GeoLite2)                              |

## Architecture

```
Sources (plugins)  →  Pipeline  →  Actions (plugins)
  nginx access.log     rules engine      local blocklist
  tcp capture          heuristics        Cloudflare challenge
  syslog               AI (ONNX/LLM)     webhook (Discord/Slack)
                       geo/ASN enrich    log + persist
```

Every source and action is a plugin behind the `Source` and `Action` traits.
The core (`sentry-core`) is pure: it defines contracts, no heavy I/O. See
[`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full design.

## Workspace

```
crates/
├── sentry-core/               # Event, ProtocolData, traits, rules engine
├── sentry-storage/            # Postgres (sqlx) + migrations
├── sentry-ai/                 # ThreatModel trait (ONNX) + LlmProvider
├── sentry-geo/                # maxminddb geo/ASN enrichment
├── sentry-source-nginx/       # Source plugin: access.log tail
├── sentry-action-cloudflare/  # ChallengeProvider: block/challenge via CF API
├── sentry-action-webhook/     # Action plugin: alerts
├── sentry-action-blocklist/   # Action plugin: in-memory blocklist
└── sentry-cli/                # binary: clap + ratatui + daemon
```

## Quick start

### Docker (recommended for production)

```bash
docker compose -f deploy/docker/docker-compose.yml up -d
```

Secrets go in env vars, never in config:

```bash
export SENTRY_CF_TOKEN=xxx        # Cloudflare API token (optional)
export SENTRY_CF_ZONE=yyy         # Cloudflare zone ID (optional)
export SENTRY_LLM_KEY=zzz         # OpenRouter key (optional)
export SENTRY_STORAGE__POSTGRES__URL=postgres://sentry:secret@db/sentry
```

### Local build (development)

```bash
cargo build --release
./target/debug/sentry config validate
./target/debug/sentry run
```

> **Windows**: use the rustup cargo
> (`C:\Users\<user>\.cargo\bin\cargo.exe`), not the chocolatey one.

### Configuration

Copy `config/sentry.example.toml` → `sentry.toml` and edit. The env overlay
(`SENTRY_<SECTION>__<KEY>`) overrides any TOML field.

## Rules and packs

The rules engine runs **before** heuristics and AI (fast path). Precedence
order: `Allow` > `Block`/`Challenge`/`RateLimit` > `Log`/`Tag` > falls
through to heuristics + AI.

Default packs: `vpn_proxy`, `tor`, `crawlers_bad`, `crawlers_good`,
`sensitive_paths`, `country_blocklist`, `http_anomaly`, `rate_scan`. Each
pack runs in `shadow` (log only), `enforce` (act), or `off`.

**For production rollout**: start with everything in `shadow` and watch the
logs before switching to `enforce`.

## Edge actions (provider-agnostic)

Edge actions (block / challenge / rate-limit at a CDN/WAF) are
provider-agnostic via the `ChallengeProvider` trait, mirroring the
`LlmProvider` pattern. Config uses the canonical form:

```toml
[[action]]
type = "challenge"
provider = "cloudflare"        # extensible: aws_waf, fastly, ...
[action.options]
mode = "managed_challenge"     # block | js_challenge | managed_challenge | rate_limit
ttl_secs = 86400
```

The legacy `type = "cloudflare"` alias is kept for backward compatibility.
Adding a new edge provider = implement `ChallengeProvider` in a new crate +
one match arm in `daemon::build_challenge_action` — no changes to
`ActionKind`, rules, or verdict filtering.

## Tests

```bash
cargo test --all
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

## License

Private. See [`LICENSE`](./LICENSE) if applicable.
