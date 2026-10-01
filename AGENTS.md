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
│   ├── sentry-reputation/     # reputation feeds (Tor/Spamhaus/FireHOL) + SSRF-guarded fetcher
│   ├── sentry-source-nginx/   # plugin Source: tail de access.log
│   ├── sentry-source-syslog/  # plugin Source: receptor syslog RFC 5424/3164 (UDP/TCP)
│   ├── sentry-source-cloudflare/  # plugin Source: polling CF Logs API (NDJSON)
│   ├── sentry-source-tcp/     # plugin Source: captura TCP (feature pcap); fingerprint `tcpfp.rs` no sentry-core
│   ├── sentry-edge/           # edge inline: reverse proxy/middleware axum + edge-tcp
│   ├── sentry-action-cloudflare/  # plugin Action: block/challenge via API CF
│   ├── sentry-action-webhook/     # plugin Action: alertas Discord/Slack/etc (HMAC)
│   ├── sentry-action-blocklist/   # plugin Action: blocklist local em memória
│   ├── sentry-action-nginx/       # plugin Action: includes deny/challenge p/ nginx + reload (F7.8)
│   └── sentry-cli/            # binário: clap + ratatui + daemon + server + auth + siem
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

### IP real do cliente (CDN/proxy)

O parser do nginx resolve o IP real automaticamente por precedência fixa
(`$http_cf_connecting_ip` > `$http_true_client_ip` > `$http_x_real_ip` >
XFF primeiro da cadeia > `$remote_addr`) e expõe todo token `http_*` do
`log_format` como header em `HttpData.headers` (`cf_connecting_ip` →
`cf-connecting-ip`). Detalhes em `ARCHITECTURE.md` §8.1.

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
  - ✅ Resolução automática de IP real no parser nginx (CF-Connecting-IP >
    True-Client-IP > X-Real-IP > XFF primeiro da cadeia > remote_addr) +
    todo token `http_*` do log_format vira header em `HttpData.headers`
    (`cf_connecting_ip` → `cf-connecting-ip`, habilita regras DSL `header.X`)
    — 5 testes; ver `ARCHITECTURE.md` §8.1
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
- **F2** (concluída): Cloudflare hardening + roteador parametrizado/learn/import + rate-limit + métricas + escalonamento de reincidentes + detectores de scan + IA clássica (ONNX fork)
  - ✅ F2.4 Verdict policy (`policy.rs`, `VerdictPolicy`, `PolicyConfig`,
    `[[policy.override]]` DSL) — 6 testes
  - ✅ F2.5+CF Cloudflare status/test/pull CLI + reaper restart-safe (deleta
    regras cujo note `sentry:<ts>:<ttl>` expirou) + reconcile no startup
    (verify token, adota regras vivas do edge no cache local, deleta
    expiradas, re-stampa legadas) + idempotência (duplicate-rule CF 10009) +
    registro local antes da req + circuit breaker (`max_failures`, default 3,
    desativa o provider até restart) —
    `verify()`/`list_access_rules()`/`delete_access_rule()`/`reconcile()`/`reap_expired()`/`forget()` — 10 testes
  - ✅ F2.6 Rate-limit (`ratelimit.rs`: `RateLimitBackend` + `InMemoryRateLimiter`
    sliding-window; `rate_redis.rs`: `RedisRateLimiter` feature `rate-redis`) —
    daemon wired + prune task; 7 testes
  - ✅ F2.8 Métricas Prometheus + `/metrics` hyper server (`metrics.rs`),
    `report --from/--export json|csv`, aggregations em `repo.rs`; `[metrics]` em config
  - ✅ Grafana: `/api/events` no mesmo server (`eventlog.rs`: `EventLog`
    ring buffer de 1024 eventos resumidos — ip/method/path/status/verdict/
    level/score/country/asn/signals; filtros `limit/level/verdict`),
    `sentry_signal_kinds_total{kind}` (por SignalKind, chaves do
    `[scorer.weights]`) e `sentry_signals_total` help corrigido (é events
    por level); dashboard pronto `deploy/grafana/` (Prometheus + Infinity)
    — 9 testes
  - ✅ F2.9 Rotas parametrizadas (`template_match`: `{id}`, trailing `/*`,
    `MethodNotAllowed` signal) — 7 testes
  - ✅ F2.10 Route learner (`routes_learn.rs`: shape inference, min_hits/min_ips) +
    DB route merge (`RouteValidator::merge(config ∪ db)`) + startup carrega DB +
    `routes_hot_reload` via NOTIFY + `sentry routes learn [--dry-run]` +
    learner contínuo em background (`[route_learner]`: enabled/interval_secs/
    window_secs/min_hits/min_ips, auto-push via NOTIFY) — 7 testes
  - ✅ F2.11 Import OpenAPI/Swagger 2/3 + Postman v2.1 + HAR (`routes_import.rs`:
    parsers JSON/YAML, auto-detect, dedup contra DB, NOTIFY) +
    `sentry routes import <path> [--format] [--dry-run]` — 12 testes
  - ✅ F2.1 IA local clássica (`sentry-ai`: `features.rs` com 25 features
    normalizadas + `onnx_model.rs` via `ort`, feature `onnx`) rodando como
    **fork assíncrono** no daemon (`[ai]`: mode fork|inline|shadow, trigger,
    cache por hash, semaphore); resultado entra por `Pipeline::rescore_from`
    (só eleva o score, nunca rebaixa)
  - ✅ F2.2 Modelo v1 + treino: `sentry model export [--synthetic]` (features
    extraídas pelo Rust — paridade treino/inferência garantida) +
    `tools/train_model.py` (sklearn → ONNX com `zipmap: false`) + modelo seed
    `models/anomaly_v1.onnx` commitado; build com `--features onnx` p/ carregar
  - ✅ F2.12 Escalonamento de reincidentes (`offender.rs`: `OffenderTracker`
    por IP com strikes/decay; `escalate` no pipeline só eleva verdict —
    challenge_at/block_at) + persistência em `ip_state` (migration com
    `strikes`/`total_violations`/`last_violation_at`) + pre-warm no startup
    (reincidente pós-TTL de CF re-bloqueia no 1º evento violador) +
    `sentry ip forgive`; `[escalation]` em config — 8 testes
  - ✅ F2.13 Detectores de scan (`scan.rs`: `ScanTracker` janela 4xx por IP;
    ≥8 paths distintos → `RandomScan` peso 25; ≥10 4xx → `ScanBehavior`
    peso 35) + fix do pack `rate_scan_404` (filtra `Status(404)` de verdade)
    + `sentry report --unknown-paths`; `[scan]` em config — 8 testes
  - ✅ F2.14 Edge blocking por /64 IPv6 via IP Lists da Cloudflare (IP Access
    Rules aceitam só IP exato): `lists.rs` mantém IP List account-level
    (`sentry_blocks`) + custom rule `ip.src in $sentry_blocks` (action block),
    provisionados no reconcile; opt-in `[action.options] ipv6_prefix = 64`;
    verdicts Block/RateLimit em IPv6 → item /64 com TTL no comment
    (`sentry:<ts>:<ttl>`), Challenge/IPv4 seguem em access rules; dedupe
    cache keyed pelo /64; account id auto-derivado do zone lookup
    (`SENTRY_CF_ACCOUNT` override); soft-disable + fallback access rules sem
    permissões (Account Filter Lists / Zone Rulesets) com self-heal no reaper
    — 10 testes; ver `ARCHITECTURE.md` §8.2
- **F3** (concluída): Multi-source (syslog) + LLM (OpenRouter/Ollama)
  + detecção comportamental + reputation feeds
  - ✅ F3.4 Syslog source (crate `sentry-source-syslog`: parser RFC 5424 com
    fallback RFC 3164, receptor UDP/TCP com framing RFC 6587,
    `ProtocolData::Syslog(SyslogData)`, `RawEvent.transport` distingue UDP;
    wired no daemon via `[[source]] type = "syslog"`) — 11 testes
  - ✅ F3.5 LLM adapters (`sentry-ai/src/llm/`: `OpenRouterProvider` com
    `response_format: json_schema` + `SENTRY_LLM_KEY`, `OllamaProvider`
    local keyless, `MockLlmProvider`; `prompt.rs` com schema strict, context
    builder e parse tolerante; daemon `LlmFork` espelha o `AiFork` —
    fork/shadow, semaphore, cache TTL por payload hash, re-entra por
    `rescore_from` só elevando, sinal `LlmMalicious` peso = score×confidence)
    — 24 testes
  - ✅ F3.8 Detecção comportamental (`behavior.rs`: `BehaviorTracker` janela
    300s por IP; `AuthBruteForce` 401/403 em rotas de login peso 35,
    `CredentialStuffing` ≥3 UAs distintos peso 40, `DirectoryBruteForce`
    wordlist 404 peso 30 com isenção de bons crawlers,
    `SuspiciousLoginSuccess` 2xx em rota de login após ≥3 falhas de auth
    peso 45 — alerta no sucesso, não nas falhas; `[behavior]` em
    config, wired no pipeline + prune no daemon) — 16 testes
  - ✅ F3.7 Reputation feeds (crate `sentry-reputation`: fetcher http/https
    com guarda SSRF — rejeita localhost/loopback/privado/reservado no URL
    pós-DNS e em cada redirect, timeout 30s, cap 10 MB; `ReputationStore`
    longest-prefix-wins v4+v6 com replace por feed; `parse_feed` genérico
    cobre DROP/exit-addresses/netset/lista plana; `Event.reputation` +
    `RuleMatch::Reputation` funcionais — packs `tor`/`vpn_proxy` disparam de
    verdade; sinais `TorExitNode` 15/`KnownBadIp` 50/`VpnProxy` 20 no
    pipeline; regra sintética `feed:<name>` quando a feed declara `action`;
    refresh em background; métricas `sentry_feed_*`; CLI
    `sentry feeds list|refresh|check <ip>`; `[[rules.feeds]]` com
    `tier`/`enabled`) — 15 testes (10 core + 5 crate)
  - ✅ F3.6 Retreinamento (`sentry model export --confirmed` — labels de
    eventos ligados a incidentes; `sentry model reload` via NOTIFY
    `sentry_model_changed` troca o ONNX a quente com `AiFork` em
    `Arc<RwLock<>>`; `sentry model status` mostra describe/version)
  - ✅ F3.3 CF Logs source (crate `sentry-source-cloudflare`: polling
    `/zones/{id}/logs/received` NDJSON → `HttpData`, dedupe por RayID,
    checkpoint de cursor, token via `SENTRY_CF_TOKEN`; Logs API exige plan
    Enterprise — parser coberto por fixture)
  - ✅ F3.2 TCP capture + fingerprint (crate `sentry-source-tcp`: capture
    loop atrás da feature `pcap` (pnet/Npcap); módulos puros testados —
    `tcpfp.rs` fingerprint SYN estilo MuonFP/p0f no **sentry-core**
    (`window:options:MSS:wscale`, assinaturas masscan/zmap/nmap), reassembler
    por flow com stream_id/máquina de estágios; `SignalKind::TcpScanner`
    peso 30 no scorer; `[[source]] type = "tcp"`)
  - ✅ F3.1 + F3.9 Edge inline + modos de deployment (crate `sentry-edge`:
    middleware axum reutilizável Inline/Shadow, reverse proxy `[edge]` com
    health-check obrigatório do backend no startup, verdict→HTTP
    (Block→403/RateLimit→429/Challenge→challenge page), `edge-tcp` listener
    inline para serviços não-HTTP, TLS opcional (feature `edge-tls`), real-IP
    precedência §8.1; `[deployment] mode = "passive"|"inline"` com opt-in
    explícito; fan-in `Incoming::{Raw,Processed}` — edge roda o mesmo
    `Arc<Pipeline>` (trackers não duplo-contam) e entrega o resultado pronto;
    `deploy/k8s/edge-sidecar.yaml`; ver `ARCHITECTURE.md` §8.3)
  - ✅ F3.10 Correlação scan→ataque cross-IP + taxonomia de scanners
    (`correlation.rs`: `CorrelationTracker` com janelas deslizantes por
    /24 (v4), /64 (v6) e ASN, cap 64/chave, prune no daemon; o pipeline
    registra sinais de scan (`RandomScan`/`ScanBehavior`/`TcpScanner` —
    SYNs do source TCP alimentam a mesma janela que sweeps HTTP) e, num
    sinal de ataque de **outro** IP no mesmo prefixo (preferido) ou ASN
    dentro da janela, emite `ScanAttackCorrelation` peso 20 com detail
    `tcp-syn from 198.51.100.7 (same /24) 42s ago`; `[correlation]`
    enabled/window_secs=900; métrica `sentry_correlation_hits_total`.
    Taxonomia como tiers de reputação: `ReputationTier::Authorized` (sem
    sinal; Allow explícito via `reputation = "authorized"`) e
    `ReputationTier::Promiscuous` → sinal `PromiscuousScanner` peso 10;
    parse unificado no DSL (`reputation = "promiscuous"`), feed config
    (`tier = "promiscuous"`) e `sentry feeds check` — 18 testes)
  - ✅ Inline enforcement de bloqueios (BlockTable) — bloqueios que "grudam"
    (`blocks.rs`: `BlockTable` `HashMap<IpAddr, Option<Instant>>`
    compartilhado; fast-path na edge (`sentry_middleware`, `edge-http`,
    `edge-tcp`) nega o IP **antes** do pipeline — 403/`shutdown()`
    imediatos, sem evento (sem spam de webhook), contadores
    `sentry_edge_block_hits_total`/`sentry_block_table_size`; vereditos
    Block do pipeline são espelhados ao `ip_state` (`expires_at =
    now + ttl_secs` da blocklist action, guard `is_blocked` anti-regravar) +
    `NOTIFY sentry_blocks_changed`; dashboard/CLI block/unblock notificam o
    mesmo canal; pre-warm do `ip_state.blocked()` no startup e
    `blocks_hot_reload` LISTEN/NOTIFY por nó — bloqueio num nó nega na edge
    de todos; `BlocklistAction::new(cfg, Arc<BlockTable>)` — 11 testes;
    ver `ARCHITECTURE.md` §8.6)
- **F4** (concluída): Operação & Dashboard
  - ✅ F4.2 Backend HTTP (`server.rs`: `sentry serve` — processo separado,
    axum; `/api/events?limit&level`, `/api/stats` 24h, `/api/incidents` +
    resolve, `/api/ips/blocked` + block/unblock/forgive com NOTIFY, health;
    `[server] host/port`, default loopback)
  - ✅ F4.3 Dashboard web (SPA sem build-step embutida via `include_str!`
    em `assets/dashboard/`: feed de eventos ao vivo com filtro de level,
    stats 24h, incidents com resolve, IPs bloqueados com unblock/forgive,
    block manual; polling 2s, sem CDN)
  - ✅ F4.4 Auth + RBAC (`auth.rs`/`server.rs`: login Argon2id + cookie de
    sessão HMAC-SHA256 (`[server.auth] session_secret_env`, default
    `SENTRY_SESSION_SECRET`) e/ou API tokens com hash SHA-256 e role
    admin/viewer (`[[server.auth.tokens]]`); `mode = "none"|"password"|
    "token"|"both"`; RBAC admin = mutações, viewer = leitura; login limiter
    10/min com DUMMY_HASH anti-enumeration; login/logout na SPA)
  - ✅ F4.5 Alertas bidirecionais (daemon auto-cria incidentes em
    High/Critical com coalescência 1 aberto por IP (`open_incident_for_ip`,
    idempotente por `event_id`); webhook com `X-Sentry-Signature`
    (HMAC do body, `SENTRY_WEBHOOK_SECRET`) + `incident_id`/`ack_url` no
    payload; `POST /api/incidents/{id}/ack` + resolve; dispatch de actions
    via `execute_with_context(ActionContext)` — backward-compatible)
  - ✅ F4.6 Export SIEM (`siem.rs`: serializers puras CEF e LEEF 2.0 +
    syslog RFC5424; `sentry export siem --from <dur> [--format cef|leef|json]
    [--out] [--follow --to udp|tcp://host:514]`)
  - ✅ F4.1 Service mode (`sentry service install|uninstall|status`:
    systemd unit, launchd plist, Windows Service real via `windows-service`
    (feature `service`, dispatcher `--service`); wrappers de binário fixo +
    `validate_service_path`/`sanitize_arg` (sem shell))
  - ✅ F4.7 HA (`events.payload_hash` + índice parcial; insert condicional
    pula payload já persistido por nó irmão na janela de dedupe (10s) — o
    LRU local não enxerga outros nós; `[deployment] instance_id` (default
    hostname) vira gauge `sentry_instance_info{instance}`; docs §8.4:
    estado compartilhado, rate-limit Redis, trackers por-node (limitação
    documentada), background tasks idempotentes)

- **F5** (parte prática entregue; avançada em roadmap): Performance
  - ✅ F5 prática — benchmarks criterion (`crates/sentry-core/benches/
    perf.rs`), prefilter Aho-Corasick nas heurísticas (1 passada SIMD,
    zero regex em tráfego limpo; testes de equivalência gated×ungated +
    proptest de triggers), caches globais de regex/IP-spec em `rules.rs`
    (era Regex::new por regra por evento — 3,4 ms/evento), decode-once do
    path (`EvalCtx`/`DecodedHttp`), trackers com história limitada
    (repetition 128, auth/wordlist 64 por IP), dedupe LRU por `u64` sem
    alocação no hit com sweep 1×/TTL, ingest em lote `recv_many(64)`.
    Pipeline end-to-end: 3,49 ms → 4,36 µs/evento (~800×). Números e
    metodologia em `ARCHITECTURE.md` §22
  - ⏸️ F5 avançada (roadmap `ARCHITECTURE.md` §23.1): budgets de
    regressão no CI, eBPF/aya, io_uring, AF_XDP kernel-bypass, ring
    buffers NUMA, avaliação de kernel module, SIMD explícito
- **F6** (roadmap `ARCHITECTURE.md` §23.2): Integrações de
  firewall/plataforma — providers OPNsense/pfSense (alias tables),
  nginx (deny-list + reload), HAProxy maps, export Suricata/fast.log;
  todos via trait `ChallengeProvider` (sem mudar regras/pipeline)
- **F7** (concluída): Honeypot hardening — trusted IPs, bans de kernel,
  report comunitário, datasets (detalhes em `ARCHITECTURE.md` §8.7)
  - ✅ F7.1 Listas compartilhadas (`lists.rs` fonte única: pack
    `sensitive_paths` + heurística + literais do prefilter derivam da mesma
    tabela) + probes de CVE do honey.conf + pack `honeypot_paths`
    (shadow default) + pack `host_allowlist` (off; `params.domains`,
    Host header fora da allowlist → Block) + wordlist do behavior
    estendida + UAs de scanner curadas (bad-bot-blocker) +
    `HttpData.host` populado pelo parser nginx — testes estrutural/
    corpus em `lists.rs`
  - ✅ F7.2 `[real_ip]` (`TrustSet`/`SharedTrustSet` em `trust.rs`):
    header-borne IPs só vencem de trusted proxies (ranges Cloudflare
    embutidos + refresh diário + `trusted_proxies`); `trusted_ips`
    (TRUSTED_IPS do nginx-honeypot) nunca é banido — Allow no pipeline,
    guard no fast-path da edge e no provider firewall, reputação
    `Authorized`; parser com `compile_with_trust` (matriz CF/spoof
    testada) — 7 testes em `trust.rs`
  - ✅ F7.3 Bans de kernel (`sentry-action-firewall`, provider
    `provider = "firewall"`): backends nftables (table `sentry`, sets
    `sentry_blocks_v4/_v6` com timeout, chain input `-1` drop) / ipset
    (`hash:ip timeout` + `iptables -m set` com `-C` antes de `-I`) /
    firewalld (ipsets runtime) com auto-detect; DB é fonte da verdade —
    sync no startup + reconcile 60s; `sentry firewall status`;
    Linux-only (skip com warning em outro OS) — builders/parsers puros
    testados
  - ✅ F7.4 Report comunitário (`sentry-action-report`,
    `type = "report"`, `provider = "abuseipdb"|"reportedip"`): mapeamento
    SignalKind→categorias (AbuseIPDB 1-23, ReportedIP 63 categorias),
    dedupe LRU por IP com TTL, backoff 429, circuit breaker 5 falhas,
    `min_verdict` configurável; `FeedConfig.headers_env` para feeds
    autenticadas (blacklist do AbuseIPDB como feed)
  - ✅ F7.5 Lookup externo (`[ip_lookup]` +
    `sentry_ai::IpLookupProvider`, AbuseIPDB `/check`): fork async após
    AI/LLM — IPs na banda cinza (score ≥ `trigger_above` ou sinal de
    `on_signals`, verdict ≠ Block) viram sinal `ExternalReputation` com
    peso escalado pelo `abuseConfidenceScore` via `rescore_from`; cache
    TTL por IP + quota `max_per_hour` — 4 testes do fork no daemon
  - ✅ F7.6 Datasets mínimos (`[[rules.feeds]] kind = "user_agent" |
    "path"`): listas uma-por-linha → regra sintética `feed:<name>`
    (alternation literal case-insensitive, cap 5000; action default
    `log`); `parse_string_list`/`dataset_rule`/`MAX_DATASET_ENTRIES` no
    core; exemplo bad-bot-blocker no `sentry.example.toml`. Params de
    packs agora são achatados (`<pack>__<param>`) no daemon — corrigindo
    `country_blocklist__countries`, que nunca chegava ao builder
  - ✅ F7.10 Verificação de bots via rDNS (`botverify.rs` no core +
    `botdns.rs` no CLI, `[bot_verification]` opt-in): UA alega crawler
    (Googlebot/bingbot/Slurp/Baiduspider/YandexBot) → PTR termina nos
    domínios do engine **e** forward-resolve de volta ao IP (mata spoof);
    DNS injetado via trait `BotDnsResolver` (hickory no daemon), fora do
    hot path — pipeline/edge leem o cache `BotVerifier` (TTL 1h/10min;
    miss = `Unknown` + fila pro worker; erro de DNS ≠ PTR vazio, outage
    não marca bot verdadeiro). Verificado → bypass do JS challenge na
    edge; falsificado → sinal `SpoofedBot` (35); pack `crawlers_good`
    divide-se em `crawlers_good_verified` (condição DSL
    `bot_verified = "true"|"false"|engine`) + `crawlers_good_unverified_ok`
    — `sentry bots check <ip> --ua "Googlebot/2.1"`; métrica
    `sentry_bot_verifications_total{result}`
  - ✅ F7.11 JS challenge (F6.2 entregue de quebra): (a) **edge inline**
    (`[edge.challenge]` opt-in, `sentry-edge/src/challenge.rs`): PoW
    SHA-256 stateless (`challenge_id = SHA-256(secret||ip||bucket)`,
    cookie `sentry_ch=<bucket>:<nonce>`, graça de 1 bucket, 503 +
    retry-after, `EdgeRuntime::challenge_gate` compartilhado por
    middleware/proxy, página embutida sem CDN, secret
    `SENTRY_EDGE_CHALLENGE_SECRET` obrigatório quando enabled, PoW nunca
    destrava Block; cookies agora populam `HttpData.cookies`); (b)
    **provider nginx** (crate `sentry-action-nginx`,
    `provider = "nginx"`): gera includes atômicos em `conf_dir`
    (`sentry-deny.conf` / `sentry-challenge.conf` geo map /
    `sentry-challenge-if.conf` p/ módulo getpagespeed js_challenge +
    `sentry-bots.conf` bot_verifier opt-in) com stamps
    `# sentry:<ts>:<ttl>`, worker com debounce ≥1/s + `nginx -t` antes do
    reload, IPv6 CIDR (`ipv6_prefix`), deny reconcile com `ip_state` 60s,
    guard never-ban
  - ⏸️ F7.7-F7.9 (roadmap `ARCHITECTURE.md` §23.3): datasets DB-backed
    com import CLI + prefilter dinâmico, ReportedIP check, feeds CLI p/
    datasets

Backlog detalhado em `ARCHITECTURE.md` §23.

### Status atual (verificação contínua)

```bash
# Antes de commitar, rodar:
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
# Resultado esperado: 420 testes passando sem features; 422 com
# --features sentry-cli/onnx (adiciona os 2 testes de inferência ONNX)
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