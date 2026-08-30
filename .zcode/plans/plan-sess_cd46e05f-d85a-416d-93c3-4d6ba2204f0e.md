Implementar quatro frentes do backlog (F3.5, F3.4, F3.8, F4.2/F4.3), nesta ordem, com testes em cada etapa e `fmt`/`clippy`/`test` no final.

## 1. F3.5 — Adapters LLM (OpenRouter + Ollama + Mock) + wiring no daemon

**`crates/sentry-ai`** — manter `llm.rs` e criar subdiretório `src/llm/` com:
- `prompt.rs`: schema JSON estrito da `ClassifyResponse` (verdict/risk_score/risk_level/signals/confidence/explanation), `context_from_event(&Event) -> String` (method/path/query/status/UA truncados — custo de token previsível) e `parse_classify(&str)` que tolera cercas de markdown, normaliza verdict/level case-insensitive (`"Block"`→`block`), clampa score e re-deriva `risk_level`.
- `openrouter.rs`: `OpenRouterProvider` (reqwest client no construtor, padrão do `CloudflareProvider`), POST `/api/v1/chat/completions` com `Authorization: Bearer`, `response_format: json_schema`; default `https://openrouter.ai/api/v1` com override `base_url`.
- `ollama.rs`: `OllamaProvider`, POST `{base_url}/api/chat` com `format: "json"` (default `http://localhost:11434`), sem key.
- `mock.rs`: `MockLlmProvider` determinístico para testes.
- `llm.rs` re-exporta os adapters; testes: parse (válido/cercado/maiúsculas/clamp/inválido), body building dos dois adapters (funções puras, sem rede), mock.

**`sentry-core/src/config.rs`**: `LlmConfig` ganha `mode: String` (`fork`|`shadow`, default `fork`). `provider != "none"` continua sendo o switch liga/desliga.

**`sentry-cli/src/daemon.rs`**: `LlmFork` espelhando `AiFork` (cache TTL por `payload_hash`, `Semaphore`, `only_above`, `mode`), mas para `Arc<dyn LlmProvider>`:
- factory `build_llm_fork` (openrouter exige `SENTRY_LLM_KEY`, senão warn+None);
- `should_run`: `verdict == Quarantine || risk_score >= only_above`;
- `evaluate` monta `ClassifyRequest` e mapeia a resposta em `Signal { kind: LlmMalicious, weight: risk_score * confidence }` com explanation no detail; erro → warn + vazio (nunca derruba o pipeline);
- fork mode reusa `Pipeline::rescore_from` + `update_verdict` + re-dispatch de actions; shadow só loga.

## 2. F3.4 — Source syslog (RFC 5424/3164, UDP+TCP)

**`sentry-core/src/event.rs`**: nova variante `ProtocolData::Syslog(SyslogData)` (`facility`, `severity`, `version`, `timestamp`, `hostname`, `app_name`, `proc_id`, `msg_id`, `message`), helper `Event::syslog()`, braço em `protocol_kind()` → `Other`. `RawEvent` ganha campo `transport: Transport` (syslog sobre UDP hoje seria rotulado Tcp pelo `into_event`) — atualizar o único call site no parser do nginx.

**Nova crate `crates/sentry-source-syslog`** (só depende de `sentry-core` + tokio, `#![forbid(unsafe_code)]`):
- `parser.rs`: RFC 5424 (`<PRI>VERSION TS HOST APP PROCID MSGID SD MSG`, NILVALUE `-`) com fallback RFC 3164;
- `source.rs`: `SyslogSourceConfig { bind, transport: udp|tcp }`, `Source::stream()` com `UdpSocket::recv_from` ou `TcpListener` (framing por newline), `client_ip` do peer, `raw` = linha original, `event_channel(1024)`;
- testes: parser (5424 completo, com structured-data, 3164, NIL, malformado) + roundtrip UDP em porta efêmera.

**Wiring**: workspace members + `[workspace.dependencies]` + dep no `sentry-cli`; braço `"syslog"` em `build_registry`; `dedup_key` melhora o fallback não-HTTP (incluir hash do `raw` — senão eventos syslog do mesmo IP seriam dedupe-droppados em rajada); seção `[[source]] type = "syslog"` no `sentry.example.toml`.

## 3. F3.8 — Detecção comportamental (brute-force, credential stuffing, directory brute-force)

**`sentry-core`**: novo `behavior.rs` com `BehaviorTracker` (padrão do `ScanTracker`: janelas deslizantes por IP, re-fire por evento, `prune()`):
- `AuthBruteForce` (peso 35): ≥ N respostas 401/403 por IP em rota de autenticação;
- `CredentialStuffing` (peso 40): mesma janela em rota de login com ≥ K User-Agents distintos (difere do brute-force comum, que usa um UA só);
- `DirectoryBruteForce` (peso 30): ≥ M 404s em wordlist embutida (`/admin`, `/wp-admin`, `/backup`, `/db.sql`, `/phpmyadmin`…), ignorando UAs de bons crawlers (Googlebot/Bingbot).

3 novos `SignalKind` + chaves nos dois maps de pesos do `pipeline.rs`; `[behavior]` em config (`enabled/window_secs/auth_failures/distinct_uas/wordlist_hits/login_patterns`); wiring `with_behavior_tracker` no pipeline + prune task no daemon. Testes no estilo do `scan.rs` (~8).

## 4. F4.2/F4.3 — Backend HTTP (axum) + dashboard

**`sentry-cli`**: novo subcomando `sentry serve` (processo separado, como o ARCHITECTURE.md prevê) em `src/server.rs` + `[server]` em config (`host` default `127.0.0.1`, `port` default `8080`):
- API JSON sobre os repos existentes: `GET /api/events`, `GET /api/stats` (levels/verdicts/top IPs/top paths/hourly), `GET /api/incidents`, `POST /api/incidents/:id/resolve`, `GET /api/ips/blocked`, `POST /api/ips/:ip/block|unblock|forgive`, `GET /api/health`;
- dashboard SPA sem build-step: `assets/dashboard/{index.html,app.js,style.css}` embutidos via `include_str!` (tema escuro, polling de 2s, feed de eventos ao vivo, incidents com botão resolve, IPs bloqueados com unblock) — sem CDN externo;
- sem auth (F4.4 é item separado; bind em localhost por default);
- exige Postgres configurado (erro claro caso contrário); axum entra como workspace dep.

## 5. Docs e verificação

- `BACKLOG.md`: marcar F3.4, F3.5, F3.8 (sub-itens restantes), F4.2 e F4.3 como `[x]`.
- `AGENTS.md`: status F3/F4, nova crate na estrutura, contagem de testes atualizada com o número real.
- `config/sentry.example.toml`: `[llm] mode`, `[[source]] syslog`, `[behavior]`, `[server]`.
- Final: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all` (e `--features sentry-cli/onnx` para os 2 testes ONNX).