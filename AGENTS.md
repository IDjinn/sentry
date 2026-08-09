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
# Build (usar o cargo do rustup, NÃO o do chocolatey que está no PATH)
C:\Users\lucas\.cargo\bin\cargo.exe build
C:\Users\lucas\.cargo\bin\cargo.exe build --release

# Lint (SEMPRE rodar antes de commit)
C:\Users\lucas\.cargo\bin\cargo.exe fmt --all -- --check
C:\Users\lucas\.cargo\bin\cargo.exe clippy --all-targets --all-features -- -D warnings

# Testes
C:\Users\lucas\.cargo\bin\cargo.exe test --all
C:\Users\lucas\.cargo\bin\cargo.exe test -p sentry-core   # crate específica

# Rodar a CLI (após build)
.\target\debug\sentry.exe --help
.\target\debug\sentry.exe config validate
.\target\debug\sentry.exe run

# Docker
docker build -t sentry .
docker compose -f deploy/docker/docker-compose.yml up

# Kubernetes
kubectl apply -f deploy/k8s/
```

> ⚠️ **Importante (Windows)**: o `cargo` em `C:\ProgramData\chocolatey\bin\`
> é um wrapper que usa toolchain GNU e causa erro `dlltool not found`. Use
> sempre `C:\Users\lucas\.cargo\bin\cargo.exe` (toolchain MSVC). Se um
> subcomando falhar com `dlltool`, é sintoma de estar usando o cargo errado.

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
(`Cloudflare` | `Webhook` | `Blocklist` | `Log`), **não** uma string. Erros
de digitação em `type = "..."` no TOML falham em tempo de carga, não em
runtime. Ao adicionar um novo plugin de action, adicione uma variante ao
enum e um braço no `match` de `daemon::build_registry`.

## 7. Fases do projeto

- **F0** (concluída): fundação — workspace, core, traits, config, CLI skeleton
- **F1** (em andamento): MVP nginx — source, heurísticas, scorer, pipeline, TUI
  - ✅ Heurísticas com URL-decode (SQLi/XSS/PathTraversal/Log4Shell/CmdInjection/
    SensitivePath/BadCrawler/EmptyUserAgent) — 9 testes
  - ✅ Rules engine (Rule/RuleMatch/RuleAction/RuleSet) — 7 testes
  - ✅ Default packs (sensitive_paths/crawlers_bad/empty_ua/http_anomaly)
  - ✅ Pipeline (rules→heuristics→route→scorer→decider) — 3 testes
  - ✅ Nginx source (parser + tail com rotação) — 3 testes
  - ✅ Daemon com wiring end-to-end (sources→pipeline→actions coloridas)
  - ✅ Actions type-safe via `ActionKind` (Blocklist/Webhook/Cloudflare/Log)
  - ⬜ TUI `ratatui` (stub — F1.9)
  - ⬜ Storage repos (schema pronto, queries pendentes — F1.3)
  - ⬜ CLI subcommands (stubs — F1.8)
- **F2**: Cloudflare + IA local (ONNX)
- **F3**: Multi-source (TCP, syslog) + LLM (OpenRouter)
- **F4**: Dashboard web

Backlog detalhado em `ARCHITECTURE.md` §15.

### Status atual (verificação contínua)

```bash
# Antes de commitar, rodar:
C:\Users\lucas\.cargo\bin\cargo.exe fmt --all -- --check
C:\Users\lucas\.cargo\bin\cargo.exe clippy --all-targets --all-features -- -D warnings
C:\Users\lucas\.cargo\bin\cargo.exe test --all
# Resultado esperado: 23 testes passando (20 core + 3 nginx)
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
- O `cargo` do chocolatey (`C:\ProgramData\chocolatey\bin\cargo.exe`) é GNU e
  **não serve** — causa `dlltool not found`. Use o do rustup.
- MSVC Build Tools 2022 instalados em
  `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools`
- `link.exe` do MSVC está disponível; o `link.exe` do Git em
  `C:\Program Files\Git\usr\bin\` pode conflitar — o rustup prioriza o MSVC.
- Postgres para testes locais: rodar via `deploy/docker/docker-compose.yml`
  (serviço `postgres`) ou instalar localmente.