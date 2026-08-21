## 15. Plano de Execução — Backlog

Legenda: **F1** = Fase 1 (MVP nginx), **F2** = Cloudflare + IA local, **F3** = Multi-source + LLM, **F4** = Dashboard.

### Fase 0 — Fundação

- [x] **F0.1** Inicializar workspace Cargo + crates skeleton — `Cargo.toml:1-13` (9 crates)
- [x] **F0.2** Definir `sentry-core`: `Event`, `RawEvent`, `Signal`, `RiskLevel`, `Decision`, erros — `event.rs`, `analysis.rs`, `error.rs`
- [x] **F0.3** Traits `Source`, `Action`, `Registry` — `source.rs`, `action.rs`, `registry.rs`, `challenge.rs`
- [x] **F0.4** Config loader (figment: TOML + env) — `sentry-core/src/config.rs`, `sentry-cli/src/config.rs:13-42`
- [~] **F0.5** `tracing` setup com spans por evento — `logging.rs` init ok; **faltam spans por evento**
- [x] **F0.6** CI: fmt, clippy (-D warnings), testes, build multi-OS — `.github/workflows/ci.yml` (lint + test matrix ubuntu/windows/macos + storage com Postgres)

### Fase 1 — MVP nginx (read-only + console)

- [x] **F1.1** `sentry-source-nginx`: tail de arquivo com `notify`/`tokio`, parse de formato custom `$var` — `source.rs` (rotação), `parser.rs` (`LogFormat::compile`)
- [x] **F1.2** Ingestor: normalização → `Event`, dedupe, enriquecimento geo (maxminddb local) — `sentry-geo` pronto; daemon com geo enrichment + dedupe LRU TTL 10s (`daemon.rs`)
- [x] **F1.3** `sentry-storage`: schema Postgres (events, incidents, ip_state, rules, routes) — 5 repos em `repo.rs`; migrations `init.sql` + `routes.sql`; daemon persiste (async spawn)
- [x] **F1.4** Heurísticas: regex SQLi/XSS/LFI/RCE/path-traversal/log4shell, assinaturas — 9 detectores em `heuristics.rs` (SQLi/XSS/PathTraversal/LFI/Log4Shell/CmdInjection/SensitivePath/BadCrawler/EmptyUserAgent)
- [x] **F1.5** Roteador de rotas: config allowlist + modo `learn` — `RouteValidator` em `pipeline.rs` com globs; `RouteValidator::from_config`; modo `learn` pendente (F2)
- [x] **F1.5b** Rules Engine: trait `Rule`/`RuleMatch`/`RuleAction`, avaliador com short-circuit, hot-reload via Postgres LISTEN/NOTIFY, DSL parser para `match` — tipos + avaliador em `rules.rs`; DSL recursive-descent em `rules/dsl.rs` (14 testes); LISTEN/NOTIFY `sentry_rules_changed`
- [x] **F1.5c** Pack `sensitive_paths` (enforce default): lista completa §10.3.1 com normalização de encoding + allowlist `/.well-known/security.txt` — 6 regex + allowlist em `packs.rs`; URL-decode no matcher (`rules.rs`)
- [x] **F1.5d** Packs default: `vpn_proxy`, `tor`, `crawlers_bad`, `crawlers_good`, `empty_ua`, `http_anomaly`, `rate_scan`, `country_blocklist` em modo shadow; `sentry rules` CLI completa (list/show/add/block/allow/enable/disable/delete/packs/test)
- [x] **F1.6** Scorer: combinar sinais → `risk_score`/`level` (pesos em config) — `from_signals` + `score_with_weights` em `pipeline.rs`; `ScorerConfig` (weights + repetition bonus + window); bônus de repetição (`RepetitionTracker`)
- [~] **F1.7** Pipeline assíncrono: `tokio` mpsc, fan-out heurística+rota, fan-in no scorer — fan-in mpsc no daemon; `process()` é sequencial, sem fan-out
- [x] **F1.8** CLI: `sentry`, `tail` (com cores), `incidents list/show`, `ip block/unblock/info`, `routes list`, `rules *`, `report`, `config validate/show`, `test`, `model`, `cloudflare` — handlers reais em `cmd.rs`
- [x] **F1.9** TUI `ratatui`: standalone lê eventos recentes do Postgres, scrollável, atalhos j/k/Space/g/G/q/Esc — `tui.rs` (~250 linhas)
- [x] **F1.10** Fixtures de logs nginx + testes de parse (`insta` snapshots) — 11 fixtures + 11 snapshots em `sentry-source-nginx/tests/`
- [x] **F1.11** Testes de heurísticas com `proptest` (payloads maliciosos catalogados) — 6 proptests em `heuristics.rs`

### Fase 2 — Cloudflare + IA local

- [x] **F2.1** `sentry-ai`: trait `ThreatModel`, impl ONNX via `ort` — `onnx_model.rs` (`OnnxThreatModel`, feature `onnx`) + `features.rs` (25 features normalizadas, single source p/ treino e inferência); daemon roda como **fork assíncrono** (`mode = fork|inline|shadow`, trigger/cache/semaphore via `[ai]`), resultado entra por `Pipeline::rescore_from` (só eleva o score)
- [x] **F2.2** Treinar modelo v1 (dataset de payloads) — `sentry model export [--synthetic]` (features extraídas pelo Rust, paridade garantida) + `tools/train_model.py` (sklearn → ONNX, `zipmap: false`) + modelo seed `models/anomaly_v1.onnx` commitado; teste de inferência ponta-a-ponta
- [x] **F2.3** `sentry-action-cloudflare`: client API (firewall rules, challenge modes), cache de IPs, TTL — `sentry-action-cloudflare/src/lib.rs` (ChallengeProvider, cache, TTL)
- [x] **F2.4** Decisor: política de verdict → action mapping — `policy.rs` com `VerdictPolicy`, `PolicyConfig` em `config.rs`, `[[policy.override]]` DSL; daemon wired; 6 testes
- [x] **F2.5** `sentry cloudflare status/test/pull` — `cloudflare status` (verify token+zone, list access rules), `cloudflare test` (dry-run), `cloudflare pull` (list sentry rules); reaper task que deleta regras expiradas; idempotência de regras duplicadas; `verify()`/`list_access_rules()`/`delete_access_rule()`/`expired_keys()`/`forget()` no provider; registro local antes da req (dedup de concorrência)
- [x] **F2.6** Rate-limiting por IP/ASN (sliding window em memória + Redis opt) — `ratelimit.rs` (`RateLimitBackend`, `InMemoryRateLimiter`), `rate_redis.rs` (`RedisRateLimiter`), `RuleMatch::Rate` wired com backend, daemon build + prune task, `[rate_limit]` em config; 7 testes
- [x] **F2.7** Alertas: `sentry-action-webhook` (Discord/Slack/Telegram genérico) — `sentry-action-webhook/src/lib.rs` (POST JSON com contexto)
- [x] **F2.8** Métricas: counters/histogramas Prometheus + `/metrics` HTTP server — `metrics.rs` (`prometheus` + `hyper`), `report --from/--export json|csv`, aggregations em `repo.rs` (`count_by_level_since`, `count_by_verdict_since`, `top_ips`, `top_paths`, `queries_per_hour`); `[metrics]` em config
- [x] **F2.9** Roteador: rotas parametrizadas (`/users/{id}/posts/{post_id}`) — `template_match` com placeholders nomeados, trailing `/*`, `allows_method` + `MethodNotAllowed` signal; 7 testes em `pipeline.rs`
- [x] **F2.10** Roteador: auto-aprendizado (modo `learn`) — `routes_learn.rs` (`RouteLearner`: shape inference, min_hits/min_ips); `RouteValidator::merge(config ∪ db)`; startup carrega rotas do DB; `routes_hot_reload` via `LISTEN/NOTIFY sentry_routes_changed`; `sentry routes learn [--dry-run] [--min-hits N] [--min-ips N]`; **learner contínuo em background** (`[route_learner]` com `enabled/interval_secs/window_secs/min_hits/min_ips`, auto-push via NOTIFY); 7 testes
- [x] **F2.11** Roteador: import de specs OpenAPI/Swagger 2.0/3.x + Postman + HAR — `routes_import.rs` (parsers JSON/YAML, auto-detect, dedup contra DB, NOTIFY); `sentry routes import <path> [--format openapi|swagger|postman|har|auto] [--dry-run]`; 12 testes (8 unit + 4 fixtures)
- [x] **F2.12** Escalonamento de reincidentes (offender memory) — `offender.rs` (`OffenderTracker`: strikes por IP com decay) + `escalate` no pipeline (challenge_at/block_at, só eleva) + persistência em `ip_state` (`strikes`/`total_violations`/`last_violation_at`, migration) + pre-warm no startup (reincidente pós-TTL de edge rule re-bloqueia no 1º evento) + `sentry ip forgive`; `[escalation]` em config; 8 testes
- [x] **F2.13** Detectores de scan comportamentais — `scan.rs` (`ScanTracker`: janela 4xx por IP; ≥8 paths distintos → `RandomScan` peso 25; ≥10 4xx → `ScanBehavior` peso 35) wired no pipeline + fix do pack `rate_scan_404` (agora filtra `Status(404)` de verdade) + `sentry report --unknown-paths`; `[scan]` em config; 8 testes

### Fase 3 — Multi-source + LLM

- [ ] **F3.1** `sentry-source-http`: middleware axum que recebe cópia da req (modo sidecar/inline leve) — sem crate
- [ ] **F3.2** `sentry-source-tcp`: captura via `pnet` (filtro por porta), reconstrução de stream HTTP quando possível — sem crate
- [ ] **F3.3** `sentry-source-cloudflare`: pull de logs existentes (polling) — sem crate
- [ ] **F3.4** `sentry-source-syslog`: receptor RFC 5424 (UDP/TCP) para equipamentos de rede — sem crate
- [~] **F3.5** LLM provider trait (`ollama`/`openai`): prompt enxuto, JSON schema strict, cache de verdicts — trait `LlmProvider` em `llm.rs`; **zero adapters**
- [ ] **F3.6** Pipeline de retreinamento: exportar incidentes confirmados → dataset → novo modelo
- [ ] **F3.7** Reputation feeds: importar blocklists públicas (Emerging Threats, Spamhaus) periodicamente — config schema + `ReputationTier` existem; sem fetcher
- [~] **F3.8** Detecção de comportamento: scan, brute-force, credential stuffing (janelas deslizantes) — signal kinds existem; **Random-silename scan (`RandomScan`) e 404-scan genérico (`ScanBehavior`) feitos em F2.13**. Sub-padrões a cobrir:
  - **Random-filename scan (`.php`/`.asp`/`.jsp`/`.html` probing)**: mesmo IP hitando muitos paths curtos/aleatórios de extensão de script com 404 (`/lm13.php`, `/1aa.php`, `/aaa.php`, `/cccc.php`, `/666.php`...). Sinais: alta cardinalidade de paths distintos por IP em janela curta + baixa taxa de 200 + nomes não-parametrizáveis (sem segmento dinâmico conhecido, fora da árvore de rotas). Distinto de F2.9/F2.10 (rotas parametrizadas/aprendidas) pois aqui o path é literalmente arbitrário — nenhum template se aplica. **✅ Implementado (F2.13): `ScanTracker` em `scan.rs`, sinal `RandomScan` peso 25 acumulativo, janela deslizante por IP (`[scan]` distinct_paths=8/window 60s), + bônus de repetição e escalonamento de strikes.** Caso real de referência: `20.199.183.210` varrendo 25+ arquivos `.php` aleatórios, todos `404 [UnknownRoute]`, sem UA suspeito — hoje classificado apenas `LOW` por `Rota inexistente` (peso 8).
  - **404-scan genérico** (qualquer extensão/path, sem payload malicioso): contador deslizante de 404 por IP, threshold separado do `rate_scan` pack (hoje `rate_scan` é só burst de reqs, não discrimina 4xx). **✅ Implementado (F2.13): `ScanBehavior` (peso 35, ≥10 4xx/IP em 60s) + pack `rate_scan_404` agora filtra `Status(404)`.**
  - **Brute-force de auth** (401/403 concentrados em poucas rotas): janela deslizante por IP+rota, taxa de 401/403 acima de N.
  - **Credential stuffing** (rotas de login com variação alta de payloads + user-agents rotativos): janela por IP+rota + distinct-UAs.
  - **Directory brute-force** (`/admin`, `/wp-admin`, `/backup`, `/db.sql`, wordlists comuns): integrar com reputation/wordlist `tools/wordlists` (F3.x) — distinguir de scanner legítimo por `crawlers_good` + taxa de 200.
- [ ] **F3.9** Modos de posicionamento do Sentry na borda — duas topologias suportadas, configuráveis via `[deployment] mode = "..."`:
  - **Inline / edge (ativo)**: Sentry na borda, **antes** das regras do nginx/upstream (reverse proxy/TCP listener). Bloqueia/contesta antes do app receber. Sub-variantes:
    - `edge-http` (F3.9a): reverse proxy HTTP(S) na porta `:80`/`:443` (ou outra via `listen`), termina TLS ou repassa, aplica verdict antes de fazer `proxy_pass` para o backend. Concorrente com F3.1 (axum middleware) e F3.9 proxy — unificar num `sentry-edge` crate. Em modo ativo, `Action::Block` descarta a conn/retorna 403/444; `Challenge` retorna challenge JS; `RateLimit` aplica `429`.
    - `edge-tcp` (F3.9b): listener TCP em portas comuns arbitrárias (`:22`, `:3306`, `:6379`, `:5432`...) para serviços expostos sem HTTP — heurísticas específicas por protocolo (banner-grab, auth brute-force). Reusa `sentry-source-tcp` (F3.2) em modo inline.
    - `edge-sidecar` (F3.9c): sidecar/envoy filter/WASM — modo inline leve sem assumir porta pública; útil em k8s (daemonset por node) — ver F4 deploy.
    - Posicionamento "antes do nginx" exigirá documentar ordem de chain: `client → sentry-edge → nginx → app` e que regras de rate-limit/WAF do nginx **não** substituem o Sentry (Sentry atua na camada de decisão de ameaça; nginx mantém suas regras de app).
  - **Passive / out-of-band (read-only)**: modo atual (F1), sem inline. Ouve tráfego sem interceptar — três fontes passivas possíveis:
    - `passive-log` (F3.9d): tail de access.log (já feito por `sentry-source-nginx`, F1.1) — zero risco, mas só detecta **depois** do app responder (404 já foi servido). Apenas alerta/blocklist futura.
    - `passive-mirror` (F3.9e): porta espelho (switch SPAN / `iptables TEE` / `mirror` em Cilium/eBPF) → Sentry escuta cópia read-only do tráfego sem ser path ativo. Detecta em tempo real mas só age **ex-post** (webhook, Cloudflare API, blocklist downstream).
    - `passive-tap` (F3.9f): sniffing promíscuo via `pnet`/`libpcap` (sem IP na interface) — útil em appliances de rede; variantes de `sentry-source-tcp` (F3.2) em modo tap.
  - **Critério de escolha** (documentar em `docs/DEPLOY.md`): inline se o serviço não tolera ataque reaching o app (RCE/0-day risk); passive se a infra não permite mudar path/SSL ou se o objetivo é só observabilidade. **Default = passive** (mantém paridade com F1; inline exige opt-in explícito + health-check do backend).
  - **Métrica chave de comparação**: tempo entre request chegar e verdict aplicado — inline alvo ≤50ms; passive é pós-resposta (apenas para o próximo request do mesmo IP).

### Fase 4 — Operação & Dashboard

- [ ] **F4.1** Modo serviço: integração systemd unit / Windows Service / launchd plist
- [ ] **F4.2** Backend HTTP minimalista (axum) expondo JSON sobre a lib `sentry-core`
- [ ] **F4.3** Dashboard web (Tauri ou SPA) consumindo o backend
- [ ] **F4.4** Auth + RBAC para dashboard
- [ ] **F4.5** Alertas bidirecionais (ack/resolve no dashboard)
- [ ] **F4.6** Export SIEM (CEF/LEEF, syslog forward)
- [ ] **F4.7** Alta disponibilidade: estado em Redis/Postgres compartilhado

### Cross-cutting (contínuo)

- [ ] **X.1** Documentação de plugin (`docs/PLUGIN_DEV.md`) — sem `docs/`
- [ ] **X.2** Catálogo de threat models (`docs/THREAT_MODELS.md`) — sem `docs/`
- [ ] **X.3** Benchmarks de throughput (criterion) — meta: 10k req/s parsed
- [~] **X.4** Hardening: segredos via env/secret manager, nunca em config commitada — env vars ok; sem secret manager
- [ ] **X.5** Release automation: `cargo-dist` ou `cross` → GitHub Releases multi-OS
- [ ] **X.6** Telemetria opt-in de uso (não de dados) para guiar roadmap

> **Legenda**: `[x]` = feito · `[~]` = parcial (ver nota) · `[ ]` = pendente
> **Devs notáveis**: storage é Postgres (não SQLite); `sentry-auto` não tem crate (só CLI stub); 9 packs default implementados; DSL de `match` completo (recursive-descent, 14 testes); TUI ratatui standalone lê do Postgres; offender memory em `ip_state` (strikes persistidos + pre-warm); IA clássica ONNX como fork assíncrono com modelo seed commitado; 130 testes (132 com `--features sentry-cli/onnx`); CI GitHub Actions (fmt/clippy/test 3 OS + storage).

---
