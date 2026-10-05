# F10 — Inspeção de uploads e corpo de requisição (inline edge)

Objetivo: o Sentry passa a inspecionar o **corpo** de requisições HTTP (uploads multipart, formulários urlencoded, JSON) além de path/query/headers, detectando SQLi/XSS/injection em filenames e campos, e imagens maliciosas (polyglotas, SVG com script, webshell em EXIF, executável disfarçado) — tudo byte-level, sem ML/AV externo, alimentando o pipeline/scorer/verdicts existentes para o verdict nascer **antes de encaminhar ao upstream**.

Limitação estrutural assumida: só funciona em `[deployment] mode = "inline"` (proxy/middleware). Fontes passivas (nginx access.log, syslog, CF Logs) não carregam corpo — documentado como não-goal.

## 1. Core — parser de corpo puro (`crates/sentry-core/src/multipart.rs`, novo)

- `parse_multipart(content_type, body, max_parts, max_part_bytes) -> Vec<UploadPart>`: extrai boundary do `Content-Type`, split CRLF-tolerante (memchr), headers por parte (`name`, `filename` incl. RFC 5987 `filename*`, `content-type`). Multipart aninhado é rejeitado (partes planas).
- `parse_urlencoded(body) -> Vec<(String, String)>` (valores decodificados viram "inputs de texto" para scan).
- JSON: **sem parse estrutural** — o corpo bruto entra como texto no scan (as regexes de SQLi/XSS pegam payload dentro de strings JSON).
- `UploadPart { name, filename, content_type, bytes }` (borrowed, pure, `forbid(unsafe)` mantido).

## 2. Core — modelo de dados (`event.rs`)

- `UploadInfo { field_name, filename, content_type, size, kind }` + `UploadKind { Text, Image, Svg, Archive, Executable, Pdf, Unknown }` (serde snake_case). **Só metadados** — conteúdo nunca persiste.
- `HttpData.uploads: Option<Vec<UploadInfo>>` com `#[serde(default)]`.
- Atualizar todos os construtores com campos explicitados: `sentry-edge/src/middleware.rs:122-146`, `proxy.rs:275-304`, parser nginx, parser Cloudflare, fixtures/snapshots insta.

## 3. Core — sinais (`analysis.rs` + `pipeline.rs`)

- **Reuso**: injeção em filename/campo reemite `SqlInjection`/`Xss`/`CmdInjection`/`Log4Shell`/`PathTraversal` com `detail = "upload:<filename>"` — dashboards/métricas/pesos existentes funcionam de graça.
- **Novos SignalKind**: `UploadTypeMismatch` (peso 30 — magic bytes ≠ content-type/extensão), `UploadPolyglot` (60 — imagem+script/PHP, SVG com `<script>`/event handlers, payload em EXIF), `UploadExecutable` (50 — MZ/ELF/shebang com aparência de imagem ou extensão bloqueada), `UploadFlood` (25 — tracker de volume).
- Atualizar os matches exaustivos `weight_for` (pipeline.rs:735-777) e `weight_for_signal` (781-817), `signal_kind_label` (eventlog.rs:24-29) e serde.

## 4. Core — heurísticas de upload (`heuristics.rs` ou novo `uploads.rs`)

- `DecodedHttp` ganha `uploads: Option<Vec<UploadPart>>` (parse-once em `DecodedHttp::of`, só quando body presente e content-type reconhecido).
- Três novos `Heuristic` impls com `gate_bit() = None` (early-return sem body; **não toca** no prefilter Aho-Corasick, cujo máscara u8 já está cheia):
  - `UploadFilename` — regexes SQLi/XSS/traversal/cmd/log4shell sobre filename + anomalias (extensão dupla, null byte, `.php`/`.jsp`/`.asp` renomeado).
  - `UploadContent` — as mesmas regexes sobre partes textuais (valores urlencoded, JSON, SVG/HTML) + scan literal de marcadores (`<?php`, `<script`, `javascript:`, webshell strings) nos bytes brutos.
  - `UploadImage` — sniffing de magic bytes → classifica `UploadKind`; mismatch declarado×real; poliglotas (marcadores nos primeiros/últimos 4 KiB da parte + scan de EXIF comment); executável disfarçado.
- Registro em `HeuristicEngine::with_defaults()`; testes de equivalência de gating não se aplicam (ungated), mas proptest never-panic em bytes arbitrários sim.

## 5. Core — `UploadTracker` (behavior de upload)

Modelo `ScanTracker`/`behavior.rs`: janela por IP com contagem de uploads, bytes totais e filenames suspeitos distintos → `UploadFlood`. `Pipeline::with_upload_tracker` + feed em `process()` (quando `http.uploads` presente) + prune na task de 60 s do daemon.

## 6. Config (`config.rs`) — `[uploads]`

```toml
[uploads]
enabled = false          # opt-in; ligar só faz sentido em inline
mode = "shadow"          # "shadow" | "enforce"  (configurável — sua escolha em runtime)
inspect_kb = 4096        # cap de inspeção/request; também vira forward cap da edge
max_files = 16
scan_json = true         # você pediu JSON no escopo; desligável por FP
blocked_extensions = ["php", "phtml", "php5", "jsp", "jspx", "asp", "aspx", "exe", "dll", "sh", "bat", "ps1"]

[uploads.flood]
window_secs = 60
max_uploads = 30
max_total_mb = 50
```

- **Shadow**: heurísticas de origem-upload emitem os sinais com peso 0 (contam em métricas/eventlog, não bloqueiam). **Enforce**: pesos plenos → scorer/policy/BlockTable como qualquer veredito. Mecanismo: `HeuristicEngine` e `UploadTracker` recebem `mode` na construção (sem mexer em `weight_for` por superfície).
- `[scorer.weights]` continua sobrescrevendo `upload_polyglot` etc.
- Validação no daemon: `enabled` com `deployment.mode = "passive"` → warning explícito.

## 7. Edge (`sentry-edge`)

- `EdgeRuntime::with_uploads(UploadsRuntimeCfg)` (daemon constrói da config). Proxy (`proxy.rs:232`): forward cap vira `max(body_capture_kb, 1 MiB, inspect_kb)` **quando uploads enabled** — hoje default é 1 MiB/413, então quem habilita uploads passa a aceitar corpos maiores de forma consciente (memória = requisições concorrentes × inspect_kb, documentado). Middleware idem.
- Antes de montar `HttpData`: content-type reconhecido + body ≤ inspect_kb → parser do core preenche `uploads` (metadata). Captura ≠ inspeção: `body_capture_kb` continua controlando o que **persiste** em `HttpData.body`/DB; inspeção usa os bytes e descarta.
- Métrica `sentry_edge_uploads_inspected_total` (padrão `edge_block_hits`: Counter + `with_*` builder).
- Eventlog: `EventSummary.uploads: Option<Vec<UploadSummary>>` sempre serializado (null quando ausente) + atualização do teste `summary_serializes_stable_key_set`.

## 8. Rules DSL (pequeno)

`RuleMatch::UploadFilename(StrOp)` + chave DSL `upload_filename` — permite packs tipo "bloqueia `.php` em `/api/upload`". Um variant + parser + braço no match.

## 9. Testes (~30 novos)

- Parser: CRLF/LF, boundary no conteúdo, `filename*`, sem boundary, caps, urlencoded, JSON-as-text.
- Heurísticas (vetores dourados): SQLi no filename; `shell.php.jpg` com magic MZ; SVG com `<script>`; `GIF8` + `<?php`; PNG limpo; SQLi em campo urlencoded; payload em JSON.
- `UploadTracker`: flood → sinal; prune/decay.
- Edge e2e (espelhar testes de `proxy.rs`/`middleware.rs` com `oneshot`): multipart poliglota → 403 em enforce; em shadow → forward com evento contendo `uploads`; counter incrementa; body > inspect_kb → 413.
- Config: defaults/clamps/warnings; snapshots insta atualizados.

## 10. Docs

`ARCHITECTURE.md` nova seção F10 + atualização §23; `AGENTS.md` (entrada F10, comandos inalterados); `config/sentry.example.toml` com `[uploads]` comentado. Docs do sentry-docs (submodule) ficam como follow-up em repo separado.

## Non-goals explícitos

- **Não tocar** em `sentry-ai/src/features.rs` (quebraria paridade com o ONNX commitado — o vetor de 25 features não muda).
- Sem ClamAV/AV externo, sem ML de visão (NSFW), sem streaming — inspeção no buffer já existente.
- Fontes passivas não inspecionam corpo.
- `serde_json` não entra no core (JSON é scanned como texto).

## Convenções respeitadas

Sem `unsafe`; sem comentários (doc-comments `///` em públicos ok); `cargo fmt` + `clippy -D warnings` + `cargo test --all` antes de commit; segredos fora do TOML; expectativa de crescimento do total de testes (509 → ~540).