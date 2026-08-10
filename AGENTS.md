# AGENTS.md — Guia para agentes de IA trabalharem neste repositório

> Este arquivo orienta agentes (Claude, Copilot, etc.) sobre o projeto **Sentry**.
> Leia antes de qualquer tarefa de código.

## 1. O que é o Sentry

Monitor de acessos em tempo real para serviços expostos à internet. Começa
com nginx (access logs) e escala para qualquer porta/protocolo (HTTP, TCP,
TLS). Usa heurísticas + IA (ONNX local + LLM opcional via OpenRouter) para
detectar ameaças, calcular nível de risco e agir (block, challenge via
Cloudflare, webhook). Infraestrutura modular por plugins (traits `Source` e
`Action`). CLI em Rust com TUI `ratatui`. Suporta Docker e Kubernetes.

**Documentação completa da arquitetura**: [`ARCHITECTURE.md`](./ARCHITECTURE.md).
Leia-o antes de tocar na arquitetura ou adicionar fases.

## 2. Stack

- **Linguagem**: Rust 2021 edition, MSRV 1.80 (devido ao `std::sync::LazyLock`)
- **Async**: tokio
- **CLI**: clap (derive) + ratatui (TUI) + crossterm
- **Storage**: Postgres (sqlx, migrations em `crates/sentry-storage/migrations/`)
- **Config**: figment (TOML + env overlay, prefixo `SENTRY_`)
- **HTTP client**: reqwest (native-tls no Windows / rustls em containers)
- **IA**: ort (ONNX, feature `onnx` opcional) + trait `LlmProvider` (OpenRouter default)
- **Geo**: maxminddb (GeoLite2 local)
- **Erros**: thiserror (lib) + color-eyre (bin)

## 3. Comandos essenciais

```bash
# Build
cargo build
cargo build --release

# Lint (SEMPRE rodar antes de commit)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

# Testes
cargo test --all
cargo test -p sentry-core   # crate específica

# Rodar a CLI (após build)
./target/debug/sentry --help
./target/debug/sentry config validate
./target/debug/sentry run

# Docker
docker build -t sentry .
docker compose -f deploy/docker/docker-compose.yml up

# Kubernetes
kubectl apply -f deploy/k8s/
```

## 4. Estrutura do workspace

```
sentry/
├── Cargo.toml                 # workspace (deps centralizadas em [workspace.dependencies])
├── ARCHITECTURE.md            # design detalhado, fluxogramas, backlog por fase
├── AGENTS.md                  # este arquivo
├── crates/
│   ├── sentry-core/           # lib: Event, ProtocolData, Signal, traits, rules engine
│   ├── sentry-storage/        # Postgres (sqlx) + migrations/*.sql
│   ├── sentry-ai/             # trait ThreatModel (ONNX) + trait LlmProvider
│   ├── sentry-geo/            # maxminddb geo/ASN enrichment
│   ├── sentry-source-nginx/   # plugin Source: tail de access.log
│   ├── sentry-action-cloudflare/  # plugin Action: block/challenge via API CF
│   ├── sentry-action-webhook/     # plugin Action: alertas Discord/Slack/etc
│   ├── sentry-action-blocklist/   # plugin Action: blocklist local em memória
│   └── sentry-cli/            # binário: clap + ratatui + daemon entrypoint
├── deploy/
│   ├── docker/               # Dockerfile + docker-compose
│   └── k8s/                  # manifests Kubernetes
└── config/sentry.example.toml
```

### Convenões de crates

- Toda crate de plugin (`sentry-source-*`, `sentry-action-*`) depende apenas
  de `sentry-core`, nunca de outras plugins.
- `sentry-core` é **pure** (sem I/O pesado, sem HTTP, sem DB). Define contratos.
- Deps compartilhadas ficam em `[workspace.dependencies]` no raiz; cada crate
  referencia via `{ workspace = true }`.
- Features pesadas (ONNX) ficam **opcionais** e desligadas por default.

## 5. Modelo de dados — regra de ouro

O `Event` é **modular via `ProtocolData` enum**. Nunca assuma que um evento
é HTTP. Heurísticas e regras fazem pattern-match em `evt.http()` /
`evt.tcp()` / `evt.tls()` e retornam `None` para variantes que não tratam.

Ao adicionar um novo protocolo: adicione uma variante a `ProtocolData`, um
helper em `impl Event`, e atualize `protocol_kind()`. **Não** adicione campos
soltos no `Event` top-level — coloque no enum.

### Heurísticas — normalização de encoding

Heurísticas (SQLi, XSS, path traversal, etc.) rodam sobre a forma
**URL-decodificada** do path/query (`heuristics::http_text`), para que
payloads encodados (`%27` = `'`, `+` ou `%20` = espaço) não façam bypass.
Ao escrever novas heurísticas, sempre use `http_text(http)` em vez de ler
`http.path` / `http.query` diretamente.

## 6. Rules Engine

Roda **antes** de heurísticas e IA (fast path). Ordem de precedência:
`Allow` (bypass total) > `Block`/`Challenge`/`RateLimit` (short-circuit) >
`Log`/`Tag` (anota e continua) > cai para heurísticas+IA.

Default rule packs (`sensitive_paths` vem em `enforce`; demais em `shadow`):
vpn_proxy, tor, crawlers_bad, crawlers_good, sensitive_paths, country_blocklist,
http_anomaly, rate_scan. Ver `ARCHITECTURE.md` §10 para a lista completa.

### Actions — type-safe

O tipo de action em config é o enum `sentry_core::config::ActionKind`
(`Cloudflare` | `Challenge` | `Webhook` | `Blocklist` | `Log`), **não** uma
string. Erros de digitação em `type = "..."` no TOML falham em tempo de carga,
não em runtime.

- Para actions de **edge** (block/challenge/rate-limit em CDN/WAF), use a
  forma canonical `type = "challenge"` + `provider = "cloudflare"`. O alias
  `type = "cloudflare"` (sem `provider`) é equivalente e mantido por
  compatibilidade.
- Actions de edge são provider-agnostic via trait
  `sentry_core::ChallengeProvider` (espelha o `LlmProvider`):
  `ChallengeAction` (em core) faz o filtro de verdict (`Block`/`Challenge`/
  `RateLimit`) e delega ao provider. O provider só implementa `apply(ip,
  verdict, opts)`.
- **Adicionar um novo provider de edge** (AWS WAF, Fastly, Bunny…):
  1. Crie a crate `sentry-action-<nome>` implementando `ChallengeProvider`.
  2. Adicione-a a `sentry-cli/Cargo.toml`.
  3. Adicione um braço no `match` de `daemon::build_challenge_action`.
  Sem mudar `ActionKind`, regras, ou filtro de verdict.
- Para actions **não-edge** (webhook, blocklist, log), adicione uma variante
  ao `ActionKind` e um braço no `match` de `daemon::build_registry` como
  antes.

## 7. Fases do projeto

- **F0** (concluída): fundação — workspace, core, traits, config, CLI skeleton
- **F1** (concluída): MVP nginx — source, heurísticas, scorer, pipeline, TUI
  - ✅ Heurísticas com URL-decode (SQLi/XSS/PathTraversal/LFI/Log4Shell/
    CmdInjection/SensitivePath/BadCrawler/EmptyUserAgent) — 9 testes + 6 proptests
  - ✅ Rules engine (Rule/RuleMatch/RuleAction/RuleSet, SharedRuleSet) — 7 testes
  - ✅ DSL parser (recursive-descent, AND/OR/NOT/parens) — 14 testes
  - ✅ Default packs (sensitive_paths/crawlers_bad/crawlers_good/empty_ua/
    http_anomaly/vpn_proxy/tor/rate_scan/country_blocklist) — 9 packs
  - ✅ Pipeline (rules→heuristics→route→scorer→decider, hot-reload) — 5 testes
  - ✅ Nginx source (parser + tail com rotação) — 3 testes
  - ✅ Daemon com wiring end-to-end (sources→pipeline→actions coloridas)
  - ✅ Actions type-safe via `ActionKind` (Blocklist/Webhook/Cloudflare/Log)
  - ✅ Edge actions provider-agnostic via trait `ChallengeProvider`
    (`ChallengeAction` filtra verdict, provider só implementa `apply`).
    Cloudflare migrado para provider; canonical config `type = "challenge"`,
    `provider = "cloudflare"` — 5 testes
  - ✅ Storage repos (5 repos: Event/Incident/IpState/Rule/Route) com migrations
    Postgres, `sqlx::query()` runtime, migrations init + routes
  - ✅ Geo enrichment (sentry-geo com maxminddb, graceful no-op se MMDB ausente)
  - ✅ Daemon com geo enrichment + dedupe LRU (TTL 10s) + storage persistence
    (async spawn) + LISTEN/NOTIFY hot-reload (`sentry_rules_changed` channel)
  - ✅ CLI subcommands completos (incidents, ip, routes, rules, report, config,
    model, cloudflare, test, auto) — handlers em `cmd.rs`
  - ✅ TUI `ratatui` standalone (lê eventos recentes do Postgres, scrollável,
    atalhos j/k/Space/g/G/q/Esc)
  - ✅ Fixtures + snapshot tests (11 fixtures nginx, 11 snapshots insta)
  - ✅ CI GitHub Actions (fmt, clippy, test matrix 3 OS, storage com Postgres)
  - ✅ Config example completo (`[geo]`, `[[routes.known]]`, `[scorer]`)
- **F2** (exceto IA): Cloudflare hardening + roteador parametrizado/learn/import + rate-limit + métricas
  - ✅ F2.4 Verdict policy (`policy.rs`, `VerdictPolicy`, `PolicyConfig`,
    `[[policy.override]]` DSL) — 6 testes
  - ✅ F2.5+CF Cloudflare status/test/pull CLI + reaper (deleta regras expiradas)
    + idempotência (duplicate-rule) + registro local antes da req —
    `verify()`/`list_access_rules()`/`delete_access_rule()`/`expired_keys()`/`forget()`
  - ✅ F2.6 Rate-limit (`ratelimit.rs`: `RateLimitBackend` + `InMemoryRateLimiter`
    sliding-window; `rate_redis.rs`: `RedisRateLimiter` feature `rate-redis`) —
    daemon wired + prune task; 7 testes
  - ✅ F2.8 Métricas Prometheus + `/metrics` hyper server (`metrics.rs`),
    `report --from/--export json|csv`, aggregations em `repo.rs`; `[metrics]` em config
  - ✅ F2.9 Rotas parametrizadas (`template_match`: `{id}`, trailing `/*`,
    `MethodNotAllowed` signal) — 7 testes
  - ✅ F2.10 Route learner (`routes_learn.rs`: shape inference, min_hits/min_ips) +
    DB route merge (`RouteValidator::merge(config ∪ db)`) + startup carrega DB +
    `routes_hot_reload` via NOTIFY + `sentry routes learn [--dry-run]` — 6 testes
  - ✅ F2.11 Import OpenAPI/Swagger 2/3 + Postman v2.1 + HAR (`routes_import.rs`:
    parsers JSON/YAML, auto-detect, dedup contra DB, NOTIFY) +
    `sentry routes import <path> [--format] [--dry-run]` — 12 testes
  - ⏸️ F2.1/F2.2 IA local (ONNX/ML/LLM) — **adiada** (decisão ML vs LLM pendente)
- **F3**: Multi-source (TCP, syslog) + LLM (OpenRouter)
- **F4**: Dashboard web

Backlog detalhado em `ARCHITECTURE.md` §15.

### Status atual (verificação contínua)

```bash
# Antes de commitar, rodar:
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
# Resultado esperado: 97 testes passando (75 core + 8 routes-import + 4 fixtures + 3 nginx + 11 snapshots — destes 8 + 4 + 3 são de integração)
```

## 8. Convenões de código

- **Sem `unsafe`** (`#![forbid(unsafe_code)]` em todas as lib crates).
- **Sem comentários** salvo solicitação explícita (doc-comments `///` ok e
  encorajados em itens públicos).
- Erros: `thiserror` em libs, `color_eyre::Result` no binário.
- Nomes: snake_case para tudo, structs em PascalCase. Módulos curtos e
  focados.
- Toda crate lib começa com doc-comment de topo explicando o propósito.
- Traits `Source` e `Action` usam `#[async_trait]`.

## 9. Segurança

- Segredos (tokens Cloudflare, LLM, DB) **nunca** em config commitada. Via
  env (`SENTRY_CF_TOKEN`, `SENTRY_LLM_KEY`, `SENTRY_STORAGE__POSTGRES__URL`).
- `sentry.example.toml` tem placeholders, não valores reais.
- O `sensitive_paths` pack bloqueia `.env`, `.git/`, `.ssh/`, etc. por
  default — ao expor uma rota allowlistada, justifique no PR.

## 10. Antes de commitar

1. `cargo fmt --all -- --check` (ou `cargo fmt --all` para corrigir)
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all`
4. Verifique que não há `println!` de debug sobrando (use `tracing`)
5. Não commitar segredos nem arquivos `target/`

## 11. Notas do ambiente (Windows)

- Toolchain ativo: `stable-x86_64-pc-windows-msvc` (rustup default)
- MSVC Build Tools 2022 instalados em
  `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools`
- `link.exe` do MSVC está disponível; o `link.exe` do Git em
  `C:\Program Files\Git\usr\bin\` pode conflitar — o rustup prioriza o MSVC.
- Postgres para testes locais: rodar via `deploy/docker/docker-compose.yml`
  (serviço `postgres`) ou instalar localmente.

## 12. Documentação (Fumadocs)

A documentação do projeto vive em um repo separado (`IDjinn/sentry-docs`),
montado como **git submodule** em `docs/`, deployado na Vercel em
**https://sentry.lucas-romero.com**.

- **Stack**: Fumadocs 16 + Next.js 16 + Tailwind v4 + Mermaid
- **i18n**: `/pt` (PT-BR, source primária) e `/en` (tradução)
- **Logo**: `sentry.png` na raiz do repo principal é a source of truth;
  cópia em `sentry-docs/public/sentry.png` (atualização manual)

### Editar docs

```bash
cd docs
bun install
bun run dev   # http://localhost:3000 -> /pt
```

Conteúdo está em `content/pt/` e `content/en/` (arquivos `.mdx`).

### Bump do submodule

Após mudanças mergeadas em `sentry-docs`:
```bash
git -C docs pull origin main
git add docs
git commit -m "docs: bump sentry-docs"
```