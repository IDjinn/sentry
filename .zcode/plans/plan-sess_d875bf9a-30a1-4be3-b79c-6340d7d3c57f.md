## Objetivo

Avaliar o **jev** (API TypeSafe `https://api.typesafe.ai/v1/systemone`, auth `Authorization: Bearer`) como classificador de risco do Sentry, substituto de LLM, no contexto do honeypot (VPS 1 GB sem CPU para IA local). Entregar: provider integrado + harness de benchmark + relatório comparando **velocidade, performance, output e custo**. Branch novo `feat/jev-classifier`.

## 1. Provider `JevProvider` (`crates/sentry-ai/src/llm/jev.rs`)

- Implementa a trait `LlmProvider` existente (classify/explain) — zero mudança em regras/pipeline.
- `JevConfig { api_key, model = "jev-latest", base_url = "https://api.typesafe.ai" }`; reqwest próprio com timeout 20s (mesmo padrão dos outros providers); sem retry (consistente com openrouter/ollama; daemon já faz fail-open).
- `classify()`: **1 chamada HTTP** com 2 perguntas batched no `questions` do `/v1/systemone`:
  - `verdict`: tipo `choice` com opções `allow/rate_limit/challenge/block/quarantine` (descrições na semântica do Sentry) → `ClassifyResponse.verdict`;
  - `risk`: tipo `score` com 11 níveis ordenados (0=benigno … 10=ataque certo) → `risk_score = score × 10` clamp 0–100, `risk_level` derivado;
  - `confidence` das respostas; `explanation` = probabilidades + usage formatados. `state` = `req.context` (já limitado a 2048 chars).
- `explain()`: jev não gera prosa — retorna resumo estruturado (probabilidades/veredito); documentado no módulo.
- Resolução da chave (nunca commitada): `SENTRY_JEV_KEY` → `TYPESAFE_API_KEY` → `JEV_API_KEY` → arquivo `~/.config/typesafe/key` (mesma ordem do jev-mcp).
- Testes unitários puros no padrão do repo (body-builder/parsing, como `openrouter.rs:147-207`): shape do request, mapeamento choice/score/probabilities, normalização de veredito, clamp, ausência de resposta. ~6–8 testes.

## 2. Wiring

- Export do módulo em `llm.rs`.
- `daemon.rs build_llm_fork` (linha ~1377): extrair a construção de provider para um helper compartilhado (`make_llm_provider`) usado pelo daemon E pelo bench; braço `"jev"` (warn + disable se sem chave); atualizar a string de providers conhecidos.
- `config/sentry.example.toml`: comentário de `provider` passa a listar `jev` + env `SENTRY_JEV_KEY`. Docs do submodule (`docs/`) não são tocadas neste branch experimental.

## 3. Bench: novo subcommand `sentry bench llm`

- `cli.rs` `Command::Bench` → `BenchCmd::Llm { providers (default "jev,mock"), events: Option<PathBuf>, n, concurrency (default 4), out: Option<PathBuf> }`; handler em `cmd.rs`.
- Eventos: default = kit sintético determinístico rotulado (~40 benignos: browsing/crawlers bons/API; ~40 maliciosos: SQLi/XSS/traversal/cmd-inj/scanner/brute-force — espelhando os triggers das heurísticas). `--events <access.log>` faz replay de log nginx real do honeypot via parser do `sentry-source-nginx` (dep já existente no cli).
- Referência: cada evento também passa pelo `Pipeline` (como `test_payload`) → veredito/score heurístico como baseline de concordância.
- Execução: semaphore de concorrência, latência por chamada, cache NÃO usado (medir custo bruto).
- Métricas por provider: n, erros, latência p50/p95/média, throughput, distribuição de vereditos, risk_score médio, concordância vs heurísticas, precisão/recall/F1 vs labels (sintético), tokens in/out e `cost` quando a API retornar.
- Saída: tabela markdown no stdout + JSON bruto em `--out`.

## 4. Avaliação + relatório

- Rodar `sentry bench llm` (sintético) com a chave real via env na execução; se houver access.log do honeypot disponível, replay também (senão o comando fica documentado para rodar no VPS depois).
- `JEV_EVALUATION.md` no branch: metodologia, números de latência/throughput/erro, qualidade de output (concordância, precisão/recall, calibração das probabilidades, confiabilidade de output estruturado vs JSON de LLM), custo (tokens/custo por 1k eventos; referências: OpenRouter pago, LM Studio grátis mas exige hardware que o VPS não tem) e recomendação final com snippet pronto de `[llm] provider = "jev"` para o `sentry.toml` do honeypot (a troca em si fica como decisão pós-avaliação).

## 5. Qualidade e commits

- Convenções: sem `unsafe`, sem comentários soltos (doc-comments `///` ok), inglês, MSRV 1.80, workspace deps.
- Gates antes de cada commit: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all` (baseline 334 testes).
- Commits no branch `feat/jev-classifier`; nenhuma chave da API em arquivo commitado.