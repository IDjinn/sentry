# Incremento: CF-Connecting-IP (IP real) + F2.14 (bloqueio /64 IPv6 via CF IP Lists)

Duas partes que se complementam: sem resolver o IP real do cliente, o /64 seria calculado sobre o IP do edge da Cloudflare — inútil e perigoso.

## Parte A — Resolução automática de IP real (CF-Connecting-IP)

Hoje o parser do nginx (`crates/sentry-source-nginx/src/parser.rs`) só extrai IP de `remote_addr`/`proxy_add_x_forwarded_for`/`http_x_forwarded_for`; `$http_cf_connecting_ip` é ignorado (cai no default e é descartado), e o XFF multi-hop nem chega a casar (a classe de captura `[0-9a-fA-F:.]+` não aceita vírgula → `NoMatch`). Atrás da Cloudflare, `remote_addr` é o IP do edge.

**Mudanças em `parser.rs`:**
1. `parse_line` (parser.rs:68-87): separar dois candidatos —
   - `real_ip`: `http_cf_connecting_ip` > `http_true_client_ip` > `http_x_real_ip` (precedência fixa, primeiro que parseia vence, independente da ordem no format string; valor `-` = header ausente → ignora).
   - `edge_ip`: `http_x_forwarded_for`/`proxy_add_x_forwarded_for` (primeiro da lista, split por vírgula) > `remote_addr` > `remote_addr_v6` (este hoje é capturado mas nunca consumido — corrigir).
   - Resultado: `client_ip = real_ip.or(edge_ip)`. Zero configuração: se o formato contém o header, ele vence automaticamente.
2. Popular `HttpData.headers` (hoje sempre vazio) com todo token `http_*` capturado: nome = token sem prefixo `http_`, lowercase, `_`→`-` (ex.: `cf-connecting-ip`), descartando valor `-`. Ativa as regras DSL `header.X` (`rules/dsl.rs:294`) que hoje nunca casam vindo de log.
3. `make_capture` (parser.rs:170-190): XFF passa a aceitar lista separada por vírgula-espaço (`[0-9a-fA-F:., ]+`); tokens de header real-IP ficam na classe default `\S+` de propósito (para `-` não matar a linha inteira quando o header está ausente em tráfego direto).
4. Testes no `mod tests` (seguindo o padrão existente): cf-connecting-ip vence sobre edge IP (inclusive IPv6), fallback para `remote_addr` quando header `-`, fallback `x_real_ip`, XFF "1.2.3.4, 10.0.0.1" → 1.2.3.4, headers populados.
5. Docs: `config/sentry.example.toml` ganha exemplo comentado `[[source]]` behind-Cloudflare com `"$http_cf_connecting_ip"` no format; seção no ARCHITECTURE.md; nota no AGENTS.md §5.

Nenhuma mudança no daemon: o ingest já usa `raw.client_ip` e o geo/ASN enriquecem automaticamente com o IP corrigido (daemon.rs:391-397).

## Parte B — F2.14: /64 IPv6 no edge via IP List + custom rule

Design (validado contra a API em developers.cloudflare.com — IP Lists disponíveis em todos os planos, Free inclui 1 lista/10k itens; nome `^[a-z0-9_]+$`):
- **Um** IP List account-level `sentry_blocks` (nome configurável) + **uma** custom rule na fase `http_request_firewall_custom` da zona: expressão `ip.src in $sentry_blocks`, **action `block`**. Sem segunda lista de challenge: Free permite 1 lista.
- Roteamento por verdict: IPv6 + `Block`/`RateLimit` → item /64 na lista (`RateLimit`→block, consistente com o fallback atual dos access rules). IPv6 + `Challenge` → access rule /128 (status quo; desafio é interativo). IPv4 → access rules (status quo).
- TTL no `comment` do item, formato `sentry:<ts>:<ttl>` — **reusa** `parse_note`/`plan_rule`/`NoteKind` já testados.
- Cache de dedupe: chave = endereço de rede do /64 como `IpAddr` (via `ipnet`, já é workspace dep).
- Account id **derivado automaticamente** de `GET /zones/{zone}` (`result.account.id` — a `verify()` já faz esse GET); override opcional via env `SENTRY_CF_ACCOUNT`.
- Opt-in: `[action.options] ipv6_prefix = 64` (default 128 = comportamento atual, access rules).
- Degradação suave: falha em criar lista/regra (permissão `Account Filter Lists:Edit` / `Zone Rulesets:Edit` faltando, limite de plano) → soft-disable do modo lista com warn; access rules continuam; **não** conta no circuit breaker principal.
- POST de items é idempotente (duplicata sobrescreve + renova comment) — não precisa de tratamento 10009.

**Mudanças:**
1. Novo `crates/sentry-action-cloudflare/src/lists.rs`: DTOs (`IpList`, `ListItem`, ruleset/`CustomRule`) e métodos no provider: `find_or_create_list`, `list_items` (paginação por cursor), `add_item`, `delete_items` (batch por id), `ensure_custom_rule` (GET entrypoint → append se ausente → PUT preservando regras do usuário).
2. `lib.rs`: `CloudflareProviderConfig` += `ipv6_prefix: u8`, `list_name: String`, `account: Option<String>`; provider += `account_id`/`list_id` (`RwLock<Option<String>>`) e `lists_disabled: AtomicBool`; `verify()` passa a devolver account id (struct pequena; atualizar chamadores em `cmd.rs`); `apply()` roteia v6→lista; `reconcile()` garante lista+regra, adota itens vivos no cache, deleta expirados; `reap_expired()` também reapa itens (mesma task de 300s, sem mudança no daemon); `ReconcileReport` += campos de lista.
3. `daemon.rs` `build_challenge_action` (daemon.rs:1237): lê `ipv6_prefix` (valida 16..=128, default 128) e `SENTRY_CF_ACCOUNT`; `cmd.rs` `build_cf_provider` idem; `sentry cloudflare status` mostra resumo da lista quando habilitada.
4. `sentry-action-cloudflare/Cargo.toml`: + `ipnet { workspace = true }`.
5. Testes (~8, funções puras, sem HTTP mock — padrão da crate): normalização /64, parse de item `"<addr>/64"` + comment, roteamento verdict (List vs AccessRule), builder do body da custom rule (preserva regra de usuário, expressão/action corretos), parse do account id do JSON de zone, body do delete em batch.
6. Docs: `BACKLOG.md` F2.14 → `[x]`; `AGENTS.md` §7 F2 concluída (remove "exceto F2.14") + contagem de testes; `config/sentry.example.toml` (`ipv6_prefix` comentado + nota de permissões do token); `.env.example` += `SENTRY_CF_ACCOUNT`; ARCHITECTURE.md seção Cloudflare. Docs site (submodule sentry-docs) fica para bump posterior, fora do escopo.

Fora do escopo (confirmado): agregação local por /64 nos trackers (offender/scan/behavior/dedupe) — follow-up.

## Validação e entrega
1. `rtk cargo fmt --all -- --check`
2. `rtk cargo clippy --all-targets --all-features -- -D warnings`
3. `rtk cargo test --all` e com `--features sentry-cli/onnx` — atualizar contagens (183/185 hoje) em AGENTS.md/BACKLOG.md conforme o real.
4. Dois commits convencionais: `feat(nginx): resolve real client IP from CF-Connecting-IP/X-Real-IP headers` e `feat(cloudflare): IPv6 /64 edge blocking via IP Lists (F2.14)`.