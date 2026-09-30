# Inline enforcement — bloqueios que funcionam de verdade (BlockTable)

## Problema (verificado em código)

O modo inline já existe e decide por-request (`proxy.rs:254-261`: Block→403 antes do proxy; `tcp_listener.rs:68-75`: Block→shutdown). Mas um bloqueio não "gruda":

1. **`BlocklistAction` é escreva-só**: estado `Arc<RwLock<HashSet>>` privado, apagado no registry como `Arc<dyn Action>` sem downcast — `is_blocked()` tem **zero callers** no workspace.
2. **Dashboard/CLI bloqueiam só no Postgres** (`server.rs:528-560`, `cmd.rs:100-118` → `ip_state` + NOTIFY `sentry_rules_changed`) — e o listener desse canal só recarrega regras (`daemon.rs:1360-1366`). Nada lê `ip_state.blocked()` no startup.
3. **Edge stateless**: IP bloqueado no dashboard manda requisição benigna → pipeline deriva Allow → **proxied**.

## Design

**`BlockTable` em memória (sentry-core), DB como source of truth, NOTIFY para sync, fast-path na edge.**

### A. `crates/sentry-core/src/blocks.rs` (novo)

`BlockTable` seguindo o padrão dos trackers (scan.rs/behavior.rs/correlation.rs):

```rust
pub struct BlockTable { inner: RwLock<HashMap<IpAddr, Option<Instant>>> }
```
- `None` = permanente (dashboard bloqueia sem TTL), `Some(exp)` = TTL.
- API: `new()`, `block(ip, expires_at: Option<Instant>)`, `unblock(ip) -> bool`, `is_blocked(ip) -> bool` (lazy: expirado = não bloqueado), `seed(ip, expires_at)` (merge: mantém expiração mais longa; `None` vence), `reload(iter)` (substitui tudo — usado pelo hot-reload), `prune() -> usize`, `len()`.
- ~7 testes unitários (block/TTL/permanente/expiração/seed-merge/reload/prune). Re-export em `lib.rs`.

### B. `crates/sentry-action-blocklist` — vira escritor da tabela

- `BlocklistAction::new(cfg, table: Arc<BlockTable>)` — `execute` faz `table.block(ip, Some(now + ttl))`; delete do `HashSet` privado e dos métodos mortos; doc-comment corrigido (sem a promessa inexistente de "mirror to ip_state" no nível da crate).

### C. `crates/sentry-edge` — fast-path antes do pipeline

- `EdgeRuntime` (lib.rs:40-45) ganha `block_table: Option<Arc<BlockTable>>` + `block_hits: Option<prometheus::IntCounter>` com builders `with_block_table`/`with_block_hits` e método `is_hard_blocked(ip) -> bool`.
- Checagem **antes** de construir/processar o evento (logo após resolver o client IP):
  - `middleware.rs` handler: blocked → `block_response()` (403), sem pipeline.
  - `proxy.rs` proxy_handler: blocked → `block_response()`, sem pipeline e **sem** enviar ao canal `decided`.
  - `tcp_listener.rs`: blocked → `inbound.shutdown()`, sem pipeline.
- Comportamento: **negação silenciosa** + `tracing::debug!` + counter. Não rodar pipeline nem forçar verdict Block (evita spam de webhook/incidente por request de um IP já bloqueado — incidente já existe de quando o bloco foi decidido). Dep `prometheus` adicionada a sentry-edge (workspace dep, handle injetado pelo daemon).
- Testes: middleware blocked→403 em request benigno; proxy blocked→403 (nunca chega ao upstream); edge-tcp blocked→conexão fechada (bind `127.0.0.1:0`).

### D. `crates/sentry-cli/src/daemon.rs` — wiring completo

1. `block_table` criado no `run()` antes de `build_registry` (nova parâmetro, espelhando o padrão do handle `cf_provider`).
2. **Pre-warm do DB** (espelha offender pre-warm, daemon.rs:315-352): `repo.ip_state().blocked(10_000)` → filtra expirados em Rust (`(expires_at - now).to_std()`; `expires_at = NULL` → permanente) → `table.seed(...)`. Log `block table pre-warmed from db (n)`.
3. Inline block (daemon.rs:548-570): `.with_block_table(table.clone()).with_block_hits(metrics.edge_block_hits.clone())` nos dois `EdgeRuntime`.
4. **Mirror de vereditos para o DB** (loop principal, junto do mirror de offender, daemon.rs:786-799): `Verdict::Block` **e** `!block_table.is_blocked(ip)` (guard anti-spam) → spawn `repo.ip_state().block(ip, reason = primeiro sinal ou "pipeline", expires_at = now + block_ttl)` + `pool.notify("sentry_blocks_changed")`. `block_ttl` extraído para helper compartilhado com `build_registry` (`ttl_secs` da action, default 86400 — daemon.rs:1716).
5. **Hot-reload** `blocks_hot_reload(pool, table)` espelhando `rules_hot_reload` (daemon.rs:1365-1395): LISTEN `sentry_blocks_changed` → reload do DB → `table.reload(...)`; retry com backoff 5s. Spawn quando há repo.
6. Prune task 60s: `block_table.prune()` + `metrics.block_table_size.set(len)`.

Fluxo resultante: pipeline Block → blocklist action alimenta a tabela **e** daemon espessa no `ip_state` → NOTIFY → todos os nós recarregam → edge de qualquer nó nega no fast-path. Restart → pre-warm do DB. Dashboard/CLI block → DB + NOTIFY → teeth imediatas. Unblock → DB delete + NOTIFY → reload tira da tabela.

### E. server.rs + cmd.rs — canal correto

`block_ip`/`unblock_ip` (server.rs:528-560) e `sentry ip block/unblock` (cmd.rs:100-118) passam a notificar **`sentry_blocks_changed`** (hoje reusam `sentry_rules_changed`, que não faz nada para IPs).

### F. metrics.rs

`edge_block_hits: IntCounter` (`sentry_edge_block_hits_total`) + `block_table_size: IntGauge` (`sentry_block_table_size`), criados/registrados no padrão existente.

### G. Config — zero chaves novas

`config/sentry.example.toml`: só comentários atualizados em `[deployment]`/`[edge]`/ação blocklist descrevendo a enforcement persistente (bloqueios grudam, sobrevivem a restart, sincronizam entre nós).

### H. Docs

- **ARCHITECTURE.md**: §8.3 ganha subseção "Bloqueios persistentes (BlockTable)" (fast-path, mirror, NOTIFY `sentry_blocks_changed`, pre-warm); §8.4 revisa o caveat "verdict é stateless por request" (estado de bloco agora é compartilhado via Postgres+NOTIFY); §16 linhas das 2 métricas novas.
- **AGENTS.md**: bullet ✅ na seção F3; contagem esperada de testes atualizada.
- **BACKLOG.md**: item checkado com resumo.
- **Submodule docs** (pt+en, commit só dentro do submodule): `request-flow.mdx` corrige a linha stale "inline is a future phase"; `plugins/actions.mdx` atualiza a descrição do blocklist ("Local state (for inline proxy)" → agora de fato consultado pela edge).

## Não-goals

- Lookup de DB por request na edge (RTT); bloqueio kernel (iptables/eBPF — F5 avançada); integrações de firewall (F6); challenge page verificável; fast-path para RateLimit/Challenge (permanecem por-request); confiança de headers XFF na edge (preexistente, §8.1).

## Decisões registradas (alternativas rejeitadas)

- Downcast de action via `Any` supertrait — recusado; handle concreto fora do registry segue o precedente `cf_provider`/trackers.
- Rodar pipeline + forçar Block no hit do fast-path — recusado: auditória por request vira spam de webhook/incident; negação silenciosa + counter cobre ops.
- Polling periódico do DB além do NOTIFY — recusado (paridade com rules/model/routes que usam só NOTIFY + startup).

## Validação

`cargo fmt --all -- --check` · `cargo clippy --all-targets --all-features -- -D warnings` · `cargo test --all` (baseline 314; espero ~326+ com os novos testes).