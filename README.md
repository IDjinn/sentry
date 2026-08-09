# Sentry

Monitor de acessos em tempo real para serviços expostos à internet. Detecta
ameaças via heurísticas determinísticas + IA (ONNX local / LLM opcional),
calcula nível de risco por requisição/IP e age automaticamente: block,
challenge na edge (Cloudflare), rate-limit ou alerta via webhook.

## Por que existe

WAFs comerciais cobrem o óbvio. O Sentry cobre o **resto**: payloads
encodados, scanning de rotas sensíveis, crawlers maliciosos, access
patterns anômalos — combinando regras rápidas (zero falso-positivo
conhecido) com IA para o desconhecido. Tudo em um binário Rust, rodando
local, sem enviar seus logs para terceiros.

## Stack

| Camada       | Tecnologia                                         |
| ------------ | -------------------------------------------------- |
| Linguagem    | Rust 2021 (MSRV 1.80)                              |
| Async        | tokio                                              |
| CLI / TUI    | clap (derive) + ratatui + crossterm                |
| Storage      | Postgres (sqlx)                                    |
| Config       | figment (TOML + env overlay, prefixo `SENTRY_`)    |
| IA           | ort (ONNX, local) + trait `LlmProvider`            |
| Geo/ASN      | maxminddb (GeoLite2)                               |

## Arquitetura

```
Sources (plugins)  →  Pipeline  →  Actions (plugins)
  nginx access.log     rules engine      blocklist local
  tcp capture          heurísticas       Cloudflare challenge
  syslog               IA (ONNX/LLM)     webhook (Discord/Slack)
                       geo/ASN enrich    log + persist
```

Cada source e action é um plugin por trás dos traits `Source` e `Action`.
O core (`sentry-core`) é puro: define contratos, sem I/O pesado. Ver
[`ARCHITECTURE.md`](./ARCHITECTURE.md) para o design completo.

## Workspace

```
crates/
├── sentry-core/               # Event, ProtocolData, traits, rules engine
├── sentry-storage/            # Postgres (sqlx) + migrations
├── sentry-ai/                 # trait ThreatModel (ONNX) + LlmProvider
├── sentry-geo/                # maxminddb geo/ASN enrichment
├── sentry-source-nginx/       # plugin Source: tail de access.log
├── sentry-action-cloudflare/  # plugin Action: block/challenge via API CF
├── sentry-action-webhook/     # plugin Action: alertas
├── sentry-action-blocklist/   # plugin Action: blocklist em memória
└── sentry-cli/                # binário: clap + ratatui + daemon
```

## Quick start

### Docker (recomendado para produção)

```bash
docker compose -f deploy/docker/docker-compose.yml up -d
```

Segredos vão em env vars, nunca no config:

```bash
export SENTRY_CF_TOKEN=xxx        # Cloudflare API token (opcional)
export SENTRY_CF_ZONE=yyy         # Cloudflare zone ID (opcional)
export SENTRY_LLM_KEY=zzz         # OpenRouter key (opcional)
export SENTRY_STORAGE__POSTGRES__URL=postgres://sentry:secret@db/sentry
```

### Build local (desenvolvimento)

```bash
cargo build --release
./target/debug/sentry config validate
./target/debug/sentry run
```

> **Windows**: use o cargo do rustup
> (`C:\Users\<user>\.cargo\bin\cargo.exe`), não o do chocolatey.

### Configuração

Copie `config/sentry.example.toml` → `sentry.toml` e edite. O env overlay
(`SENTRY_<SECTION>__<KEY>`) sobrescreve qualquer campo do TOML.

## Regras e packs

O rules engine roda **antes** de heurísticas e IA (fast path). Ordem de
precedência: `Allow` > `Block`/`Challenge`/`RateLimit` > `Log`/`Tag` > cai
para heurísticas + IA.

Packs default: `vpn_proxy`, `tor`, `crawlers_bad`, `crawlers_good`,
`sensitive_paths`, `country_blocklist`, `http_anomaly`, `rate_scan`. Cada
pack roda em `shadow` (só loga), `enforce` (age) ou `off`.

**Para teste em produção**: comece com tudo em `shadow` e observe os logs
antes de mudar para `enforce`.

## Testes

```bash
cargo test --all
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Licença

Privado. Ver [`LICENSE`](./LICENSE) se aplicável.
