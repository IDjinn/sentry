# F8 (SSL/443 inline) + F7.7 (datasets DB) + F6.1 (OPNsense) + Roadmap

Ordem: **F8 → F7.7 → F6.1 → docs/roadmap**. Convenções do AGENTS.md valem sempre: sem `unsafe`, sem comentários triviais, `thiserror` em libs, fmt+clippy+test antes de commit.

---

## F8 — Monitoramento SSL (443) no modo inline

### F8.1 — Listener duplo 80+443 + fixes (config, sentry-edge, daemon)

**`crates/sentry-core/src/config.rs` — `EdgeConfig`** (campos novos, flat, backward-compat):
- `tls_listen: Option<String>` — endereço HTTPS; default efetivo `0.0.0.0:443` quando cert/key presentes.
- `tls_redirect_https: bool` (default false) — com ambos listeners ativos, HTTP responde 301 preservando host+path.
- `tls_allowed_hosts: Vec<String>` — vazio = check desligado; presente → SNI fora da lista vira sinal `TlsSniMismatch`.
- `tls_handshake_events: bool` (default true) — evento `TlsHandshake` por conexão no pipeline.
- Manter `tls_cert`/`tls_key` como estão. Validação no daemon: cert XOR key → erro de config.

**`crates/sentry-edge/src/proxy.rs`**:
- `EdgeProxyConfig` ganha `tls_listen`/`tls_redirect_https`.
- `serve()` roda HTTP e HTTPS **concorrentes** (mesma `EdgeRuntime`/pipeline, mesmo pump de eventos).
- **Fix bug ConnectInfo** (proxy.rs:129): o branch TLS hoje usa `into_make_service()` e o IP do cliente vira `127.0.0.1`. O accept loop manual (abaixo) resolve de graça — inserimos `ConnectInfo<SocketAddr>` por conexão via `map_request`.
- **Fix cookie Secure** (challenge.rs:165-174): ao terminar TLS localmente, o handler injeta `x-forwarded-proto: https` nos headers passados ao `challenge_gate` (hoje só um terminador upstream conseguiria marcar `Secure`).
- Redirect 301 no listener plain quando `tls_redirect_https = true`.
- Se certos configurados sem a feature `edge-tls`: passar a **falhar no startup** (hoje cai silenciosamente em HTTP plain — footgun para quem pediu 443).

**Acceptor TLS**: substituir `axum-server` por loop manual sob a feature `edge-tls`: `TcpListener::accept` → peek do ClientHello (F8.2) → `tokio-rustls` handshake (bytes já lidos realimentados via wrapper `AsyncRead` com prefixo bufferizado, `PrefixedStream`) → servir cada conexão com `hyper-util` auto-builder + serviço axum, injetando `ConnectInfo`. Deps novas (opcionais, `edge-tls`): `tokio-rustls`, `hyper-util`, `md-5` (JA3), `sha2` (JA4), `x509-parser` (expiração do cert); remover `axum-server`. `tokio-rustls`/`rustls` já estão no lock via axum-server.

### F8.2 — Telemetria ClientHello: SNI + JA3 + JA4

**Novo módulo `crates/sentry-edge/src/clienthello.rs`** (puro, testável, sem I/O):
- Parser: record header (5B) → handshake → ClientHello → extensions (SNI, supported_versions, ALPN, supported_groups, ec_point_formats, signature_algorithms).
- **JA3** = md5(`version,ciphers,exts,curves,ecpf`) (padrão clássico).
- **JA4** = spec pública FoxIO (`t13d1516h2_<ciphers>_<exts>` — proto, versão, d/i/n SNI, contagens, ALPN, sha256 truncados ordenados).
- Preenche `TlsData { sni, ja3, ja4, cipher (negociado), version (negociada) }` — cipher/version lidos do `ServerConnection` pós-handshake.

**Fluxo de evento**: handshake completo → se `tls_handshake_events`, `Event::new(SourceKind::EdgeTls (variante nova em event.rs), client_ip, ProtocolData::TlsHandshake(...))` → **mesmo** `EdgeRuntime::process` → pump de decided já existente. Heurísticas HTTP retornam `None` para variante tls (já pattern-match em `http()`) — nenhum falso-positivo.

**Sinais e regras**:
- Novo `SignalKind::TlsSniMismatch` (peso 20, detail com SNI/host): SNI ausente ou fora de `tls_allowed_hosts` — assinatura de scanner/IP-probe no 443 (tema honeypot F7).
- `rules.rs`: nova variante `RuleMatch::TlsSni(StrOp)` (eval contra `evt.tls().sni`); `TlsFingerprint { ja3, ja4 }` já existe e passa a funcionar de verdade.
- `rules/dsl.rs`: condições `tls_ja3 = "..."`, `tls_ja4 = "..."`, `tls_sni = "..."` (hoje só `protocol = "tls"` existe).
- Pack default `tls_sni_mismatch` (shadow default) + exemplo comentado de regra JA3 no `sentry.example.toml`.

**Métricas** (`sentry-cli/src/metrics.rs`, padrão já existente de registro manual):
- `sentry_edge_tls_handshakes_total{version}`, `sentry_edge_tls_handshake_failures_total`, `sentry_edge_tls_sni_mismatch_total`, gauge `sentry_edge_tls_cert_not_after` (unix ts, lido no startup + refresh diário; warn < 14 dias).
- `EdgeRuntime::with_tls_metrics` (mesmo padrão de `with_block_hits`).
- `eventlog.rs`: resumo de eventos tls no `/api/events` (sni + ja3 curto).

**Testes F8**: vetores dourados JA3/JA4 (hellos sintetizados de Chrome/curl/openssl), `PrefixedStream` unit, SniMismatch via pipeline, config parse/validação, redirect 301, integração TLS local com PEM self-signed commitado como fixture de teste (portas efêmeras), ConnectInfo presente no handler TLS.

**Fora do escopo (roadmap)**: TLS no edge-tcp (passthrough), ACME, multi-cert SNI.

---

## F7.7 — Datasets DB-backed (+ fecha F7.9 na prática)

1. **Migration** `20261002000000_datasets.sql`: `datasets (id, name UNIQUE, kind user_agent|path|ja3, source_url NULLABLE, enabled, created_at, updated_at)` + `dataset_entries (dataset_id FK, value, UNIQUE(dataset_id, value))`.
2. **`DatasetRepo`** em `sentry-storage/src/repo.rs` (padrão `RuleRepo`): upsert, replace_entries, list, entries, enable/disable, delete; `NOTIFY sentry_datasets_changed` nas mutações.
3. **Core**: `FeedKind::Ja3` em `reputation.rs`; `dataset_rule` já cobre alternation literal com cap `MAX_DATASET_ENTRIES` (5000) — reutilizar. Novas entradas de dataset `ja3` viram regras sintéticas `feed:<name>` usando `RuleMatch::TlsFingerprint`.
4. **Prefilter dinâmico**: `PREFILTER: LazyLock<FamilyPrefilter>` (heuristics.rs:217) → `ArcSwap<FamilyPrefilter>` (dep nova `arc-swap` no workspace); rebuild mesclando literais builtin + datasets `user_agent`/`path` ativos; trigger no startup e no `LISTEN sentry_datasets_changed`. Testes de equivalência gated×ungated e proptest existentes continuam passando.
5. **Daemon**: load de datasets no startup → regras sintéticas no ruleset; LISTEN para hot-refresh (mesma mecânica de routes/rules).
6. **CLI** (padrão `routes import`): `sentry datasets import <file|url> --kind user_agent|path|ja3 --name <n> [--dry-run]` (uma entrada por linha, dedupe), `datasets list|enable|disable|delete <name>`; `source_url` → re-fetch em `sentry feeds refresh`. Isso fecha F7.9.
7. **Testes**: CRUD do repo (seguir padrão existente de testes de storage), hot-refresh, equivalência do prefilter, CLI dry-run.

---

## F6.1 — Provider OPNsense/pfSense (`ChallengeProvider`)

1. **Crate nova `crates/sentry-action-opnsense`** (depende só de `sentry-core`; sem `unsafe`; `thiserror`).
2. **OPNsense**: REST `/api/firewall/alias_util/add|delete/sentry_blocks`, creds via env `SENTRY_OPN_API_KEY`/`SENTRY_OPN_API_SECRET`, `base_url` em `[action.options]`; provisionamento do alias no startup/reconcile.
3. **pfSense**: `pfctl -t sentry_blocks -T add|delete <ip>` via `Command` com array de args (sem shell, mesmo cuidado do `sentry-action-firewall`); tabela garantida no startup.
4. **Semântica**: `Block`/`Quarantine` aplicam; `Challenge`/`RateLimit` logam warn "unenforced on platform" (limitação documentada no §23.2). TTL: mapa de expiração em memória + reaper 60s (mesma mecânica do provider firewall). Never-ban: respeita `SharedTrustSet` recebido no `build_challenge_action` (daemon.rs:2689).
5. **Wiring**: braço novo no `match` de `build_challenge_action` (`"opnsense"|"pfsense"`), crate em `sentry-cli/Cargo.toml`, bloco de exemplo no `sentry.example.toml` (`type = "challenge"`, `provider = "opnsense"`).
6. **Testes**: builders/parsers das requisições (puros), sanitização de args do pfctl, mapeamento provider/verdict, guard never-ban.

---

## Docs e roadmap

- **ARCHITECTURE.md**: nova §8.8 "TLS edge (F8)" (listener duplo, probe ClientHello, JA3/JA4, SNI mismatch, métricas); §23: marcar F8.1/F8.2 ✅, F6.1 ✅, F7.7 ✅ (e F7.9 ✅), atualizar pendentes (F5.1-F5.7, F6.3-F6.5, F7.8, F8-avançado: edge-tcp TLS, ACME, multi-cert SNI); corrigir o drift do reqwest (rustls→native-tls, linha 99) se tocar no trecho.
- **AGENTS.md**: fases F6/F7/F8 atualizadas, estrutura com `sentry-action-opnsense`, comando `sentry datasets`, contagem de testes real pós-implementação, nota sobre build com `--features sentry-cli/edge-tls`.
- **config/sentry.example.toml**: seção TLS expandida + exemplo OPNsense + exemplo dataset.
- **docs/** (submodule sentry-docs): fora desta rodada — mencionar bump posterior na entrega final.

## Verificação final

1. `cargo fmt --all -- --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all` (baseline 420/422 + novos testes)
4. Smoke manual: Postgres via docker compose, `sentry config validate`, daemon inline com cert self-signed + `curl -k https://...` validando métricas TLS e evento TlsHandshake no `/api/events`.