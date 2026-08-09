# Sentry — TODO de Implementação

## Contexto

Monitor de acessos em tempo real para serviços expostos à internet (nginx →
TCP/TLS). Heurísticas + IA (ONNX + LLM) para detectar ameaças. CLI Rust com
TUI ratatui. Infra modular por plugins (traits `Source` e `Action`).

**Stack**: Rust 2021, tokio, clap, ratatui, figment, sqlx (Postgres), ort,
maxminddb. 9 crates no workspace.

**Comando de build**: `C:\Users\lucas\.cargo\bin\cargo.exe build`
**Lint**: `C:\Users\lucas\.cargo\bin\cargo.exe fmt --all -- --check && clippy --all-targets --all-features -- -D warnings`
**Testes**: `C:\Users\lucas\.cargo\bin\cargo.exe test --all` (56 testes passando: 53 core + 3 nginx)

---

## Concluído (F0 + F1 parcial)

- [x] **Workspace** — 9 crates, deps centralizadas em `[workspace.dependencies]`
- [x] **sentry-core** — Event, ProtocolData, Signal, traits Source/Action, rules engine
- [x] **Heurísticas** — SQLi, XSS, PathTraversal, LFI, Log4Shell, CmdInjection,
  SensitivePath, BadCrawler, EmptyUA (9 testes + 6 proptests)
- [x] **Rules engine** — Rule/RuleMatch/RuleAction/RuleSet, SharedRuleSet
  (Arc<RwLock>), url_decode em match_path, PathOp::StartsWith
- [x] **DSL parser** (`rules/dsl.rs`) — recursive-descent, AND/OR/NOT/parens,
  todas as keys (ip/asn/country/path/ua/method/protocol/status/header/reputation/
  time/rate), 14 testes. Tokenizer sem `Slash`; `split_eq()` para `key=value`
- [x] **Default packs** — sensitive_paths (enforce), crawlers_bad, crawlers_good,
  vpn_proxy, tor, country_blocklist, rate_scan, http_anomaly, empty_ua,
  /.well-known/security.txt allowlist
- [x] **Pipeline** — rules→heuristics→route→scorer→decider, scorer config
  (weights + repetition bonus), hot-reload via `swap_rules()`, tracing::instrument,
  RouteValidator::from_config, 5 testes
- [x] **Nginx source** — parser + tail com rotação (3 testes)
- [x] **Actions type-safe** — ActionKind enum (Cloudflare/Challenge/Webhook/
  Blocklist/Log), trait ChallengeProvider (provider-agnostic), Cloudflare migrado
- [x] **sentry-storage** — EventRepo, IncidentRepo, IpStateRepo, RuleRepo,
  RouteRepo, PgPool, migrations, `sqlx::query()` runtime (não query!),
  migrations: init.sql + routes.sql
- [x] **sentry-geo** — GeoLookup com maxminddb, graceful no-op se MMDB ausente
- [x] **Daemon (M3)** — geo enrichment, dedupe LRU (TTL 10s), storage persistence
  (async spawn), LISTEN/NOTIFY hot-reload (`sentry_rules_changed` channel),
  config-driven routes + scorer, channel buffer from config
- [x] **CLI subcommands (M3b parcial)** — cmd.rs reescrito com: incidents list/show,
  ip block/unblock/info, routes list, rules list/show/add/allow/block/enable/
  disable/delete/packs/test, report, config validate/show, test payload, test rules
- [x] **config.rs** — GeoConfig, RoutesConfig, RouteDefConfig, ScorerConfig adicionados

---

## Pendente — por milestone

### M3b (em andamento) — CLI subcommands
- [ ] **Compilar cmd.rs** — foi reescrito mas pode ter erros de compilação.
  Rodar `cargo build` e corrigir. Pontos de atenção:
  - `PackMode::all_pack_names()` — pode não existir em packs.rs; verificar
  - `ttl_or_note()` — função auxiliar definida no cmd.rs
  - `connect_storage()` — usa `cfg.storage.postgres.url`, falha graceful
  - `notify_rules_changed()` — executa `NOTIFY sentry_rules_changed`
  - Import de `sentry_storage::Repo`, `sentry_storage::PgPool`
- [ ] **main.rs** — já atualizado para tentar carregar config sempre (não só
  para Run/Config), caindo graceful se falhar
- [ ] Verificar que `sentry-cli/Cargo.toml` tem `serde_json` (tem) e que
  `sentry_storage::migrations` é público (é — ver lib.rs)

### M3c — TUI minimal (~200 linhas)
- [ ] Implementar `tui.rs` com ratatui:
  - Header: stats (processed/blocked/dropped_dupes)
  - Stream: lista scrollável de eventos (j/k para navegar, Space para pausar)
  - Footer: atalhos (q=quit, Space=pause, j/k=scroll)
  - Receber eventos de um canal mpsc compartilhado com o daemon
  - Ou: modo standalone que lê eventos recentes do Postgres
- [ ] Features: `tui` já é feature opcional em Cargo.toml (`dep:ratatui`, `dep:crossterm`)

### M4 — Config exemplo
- [ ] Atualizar `config/sentry.example.toml` com:
  - `[geo]` — city_db, asn_db paths
  - `[routes]` com `[[routes.known]]` entries (path + methods)
  - `[scorer]` — weights, repetition_bonus, repetition_window_secs
  - `[storage.postgres]` — url placeholder
  - `[[rules.pack]]` entries com modes
  - `[[source]]` nginx exemplo
  - `[[action]]` exemplos (log, blocklist, webhook)

### M5 — Fixtures + snapshot tests
- [ ] Criar `crates/sentry-source-nginx/tests/fixtures/` com access logs de exemplo
  (clean, SQLi, XSS, path traversal, LFI, log4shell, bad crawler, tor, etc.)
- [ ] Adicionar `insta` snapshot tests em sentry-source-nginx ou sentry-core
  que processam os fixtures e comparam com snapshots
- [ ] `insta` já está em workspace.dependencies e sentry-core dev-deps

### M6 — CI
- [ ] Criar `.github/workflows/ci.yml`:
  - Matrix: ubuntu-latest, windows-latest, macos-latest
  - Steps: checkout, install Rust (rustup), fmt check, clippy (-D warnings),
    test --all, build --release
  - Cache cargo registry + target via `Swatinem/rust-cache@v2`
  - Postgres service container para testes de storage (apenas ubuntu?)

### M7 — Documentação final
- [ ] Atualizar `ARCHITECTURE.md` — marcar F1 items concluídos, atualizar §15 backlog
- [ ] Atualizar `AGENTS.md` §7 — status atual (M3 concluído, testes count)
- [ ] Rodar fmt + clippy + test finais, corrigir warnings

---

## Arquivos chave

| Arquivo | Status |
|---------|--------|
| `Cargo.toml` (workspace) | ✅ proptest + insta adicionados |
| `crates/sentry-core/src/config.rs` | ✅ GeoConfig, RoutesConfig, ScorerConfig |
| `crates/sentry-core/src/heuristics.rs` | ✅ Lfi + proptests |
| `crates/sentry-core/src/rules.rs` | ✅ SharedRuleSet, url_decode, PathOp::StartsWith |
| `crates/sentry-core/src/rules/dsl.rs` | ✅ Parser completo, 14 testes |
| `crates/sentry-core/src/packs.rs` | ✅ 9 packs + expanded crawler list |
| `crates/sentry-core/src/pipeline.rs` | ✅ with_config, swap_rules, repetition, 5 testes |
| `crates/sentry-core/src/lib.rs` | ✅ exports atualizados |
| `crates/sentry-storage/src/repo.rs` | ✅ 5 repos completos |
| `crates/sentry-storage/src/pool.rs` | ✅ PgPool + listen() para LISTEN/NOTIFY |
| `crates/sentry-storage/migrations/20260102000000_routes.sql` | ✅ routes table |
| `crates/sentry-cli/src/daemon.rs` | ✅ geo + dedupe + persist + hot-reload |
| `crates/sentry-cli/src/cmd.rs` | ⚠️ reescrito, NÃO COMPILADO AINDA |
| `crates/sentry-cli/src/main.rs` | ✅ config load graceful |
| `crates/sentry-cli/src/tui.rs` | ❌ stub (12 linhas) |
| `config/sentry.example.toml` | ❌ falta [routes], [scorer], [geo] |
| `.github/workflows/ci.yml` | ❌ não existe |
| `ARCHITECTURE.md` | ⚠️ backlog atualizado, status final pendente |

---

## Próximo passo imediato

1. `cargo build` — compilar cmd.rs e corrigir erros
2. `cargo test --all` — garantir 56 testes passando
3. `cargo clippy --all-targets --all-features -- -D warnings` — zero warnings
4. Seguir para M3c (TUI) → M4 (config) → M5 (fixtures) → M6 (CI) → M7 (docs)

---

## Convenções (do AGENTS.md)

- Sem `unsafe` (`#![forbid(unsafe_code)]` em todas as lib crates)
- Sem comentários inline (doc-comments `///` ok e encorajados)
- Erros: `thiserror` em libs, `color_eyre::Result` no binário
- snake_case para tudo, structs em PascalCase
- Toda crate lib começa com doc-comment de topo
- Traits `Source` e `Action` usam `#[async_trait]`
- `#[warn(missing_docs)]` e `#![forbid(unsafe_code)]` em sentry-core
- Segredos via env (SENTRY_CF_TOKEN, SENTRY_LLM_KEY, SENTRY_STORAGE__POSTGRES__URL)
- Plugin crates dependem apenas de sentry-core, nunca de outras plugins
