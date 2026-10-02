# F9.6 — Sintaxe v3.1 do corpo de macros (sentry-protocol)

Rework da sintaxe de `body:`/steps conforme feedback: operadores infixos, remoção de `{}` redundantes, `repeat`→`while`, checks como macros de statement, `neg_if`→`if` com bloco + `not`. Sem shim de compatibilidade (DSL é novo e não commitado). Comportamento validado do VLInt permanece idêntico.

## Sintaxe alvo (game-relay fica assim)

```yaml
VLInt:
  body:
    - b0: "read u8"
    - n: "(b0 and 0x38) >> 3"
    - acc: "b0 and 0x03"
    - while min!(n, 4):
        - bi: "read u8"
        - check_mask!(bi, 0xC0, 0x40)
        - acc: "(acc << 6) or (bi and 0x3F)"
    - sign: "b0 and 0x04"
    - if sign:
        - acc: "-acc"
    - return acc
```

## 1. Novo parser de expressão infix (`src/expr.rs`, novo módulo)

- Gramática Pratt/recursive-descent: `expr := term (OP term)*` com precedência C-like `or < xor < and < shl/shr < add/sub < mul`; unário `-` (negação) e `not` (negação lógica 0↔1).
- Operadores **palavra**: `and or xor shl shr add sub mul not` — e **açúcar simbólico** equivalente: `| & ^ << >> + - *` (palavra é a forma canônica; símbolos aceitos). Nomes reservados: um registrador não pode chamar-se igual a um operador (erro de compile).
- Operandos: nome de registrador, literal int (dec/`0x` hex, negativos), resultado de subexpressão parenthesizada. Sem floats (não há caso de uso; f32/f64 continuam só via `read f32/f64`).
- Reutilizar `tokenize` de `ops.rs` estendido para reconhecer operadores/pontuação como tokens próprios.
- Saída: AST pequeno compilado para `Instr` com alocação de temporários no espaço de registradores da mensagem (respeita `MAX_REGS=16`).

## 2. `schema.rs` — modelo de `Step` v3.1

```rust
enum Step {
    Assign { name: String, expr: String },   // "- acc: \"(b0 and 0x38) >> 3\""
    While { bound: String, body: Vec<Step> },// "- while min!(n, 4):" + bloco
    If { cond: String, body: Vec<Step> },    // "- if sign:" + bloco
    Statement(String),                       // "- check_mask!(bi, 0xC0, 0x40)" / "- return acc"
}
```

- `Deserialize` manual de `Step` (já existe): mantém single-key map para `Assign` (a forma `- acc: "..."` sem chaves é o mesmo YAML — braces passam a ser opcionais, não mais necessários); chave começando com `if ` → `If`, `while ` → `While`; scalar string → `Statement`; `return: acc` (mapa) aceito e normalizado para `Statement("return acc")`.
- **Removidos**: `Repeat`, `MaskOk`/`RangeOk`/`LenOk` como keyword steps, `NegIf` do modelo.
- Statement macros (parser de chamada posicional `name!(arg, arg, …)` em `steps.rs`, args = int/ident/string):
  - `check_mask!(reg, bits, value)` → `Instr::MaskOk`
  - `check_range!(reg, min, max)` → `Instr::RangeOk`
  - `check_len!(reg, min, max)` → `Instr::LenOk` — namespace de statement é separado do atom `check_len!` de framing do `on_message.run` (documentado no header do módulo e na doc da crate)
  - `return <reg>` → `Halt`
- `if <expr>:` — condição é expressão infix; verdadeiro = ≠ 0. `while <bound>:` — bound precisa ser **provável em compile-time**: constante, `min!(expr, const)` ou registrador com cap. `while n:` solto = erro de compile ("unbounded while — wrap in min!(expr, cap)"). Semântica do Loop: itera `min(bound, cap)` (clamp, não violação).
- Doc-comment de topo da crate e exemplo do módulo atualizados para a nova sintaxe.

## 3. `instr.rs` — ajustes no ISA

- **Adicionado**: `Loop { bound_reg: u8, cap: u64, body: Arc<[Instr]> }` (itera `min(reg, cap)`; cap é o teto estático) e `BranchIfZero { cond: Operand, skip: u16 }` (salto **só para frente** sobre o bloco compilado do `if` — não existem saltos para trás, terminação garantida) e `Not { dst, src }` (negação lógica para o operador `not`).
- **Removido**: `NegIf` e `Repeat` (substituído por `Loop`). `Neg` fica (unário `-` da expressão). `MaskOk`/`RangeOk`/`LenOk` permanecem (agora originados das statement macros).
- `MAX_TYPE_DEPTH` (8) passa a cobrir também aninhamento `if`/`while`.

## 4. `compile.rs` — compilação dos novos steps

- `compile_steps`: braços para `Assign` (via novo compilador de expressão), `While` (valida bound provável → `Loop`), `If` (compila corpo, emite `BranchIfZero` com `skip` patchado depois do corpo), `Statement` (dispatch das 4 macros).
- `return` dentro de bloco `if` funciona naturalmente (Halt é pulado pelo branch quando a condição é falsa).
- Budgets existentes mantidos: ≤512 instruções/mensagem, ≤16 registradores, cap de loop estático obrigatório (proteção DoS). `compile_assign` de-operador-prefixo é removido; atribuição vira caso geral da expressão.
- Erros de compile novos, todos com contexto (`schema id`, posição do step): operador desconhecido, registrador com nome reservado, `while` sem bound provável, `check_*!` com aridade errada.

## 5. Atualização de fixtures/testes/bench

- `tests/fixtures/game-relay.protocol.yaml` — corpo do VLInt na nova sintaxe (acima).
- `tests/fixtures/chat-relay.protocol.yaml`, `tests/integration.rs`, `tests/proptests.rs` (schema SIMPLE), `src/engine.rs` (GAME_SCHEMA inline), `src/schema.rs` (GAME_SCHEMA + testes de Step) — migrados; testes novos: expressão com parênteses e precedência, `not`/unário `-`, `if` com `return` dentro, erro de `while` sem cap, aridade errada de `check_*!`, registrador com nome reservado. Proptests continuam passando (bytes arbitrários nunca pânico — agora cobre BranchIfZero/Loop).
- `benches/perf.rs` — sem mudança de API (usa o fixture); recompilação pode mudar levemente os números (branch a mais por frame), rodar `cargo bench -p sentry-protocol` e atualizar a tabela se desvio >10%.

## 6. Docs

- `ARCHITECTURE.md` §24 — exemplo do corpo VLInt atualizado + parágrafo curto sobre a gramática de expressão e as statement macros (namespace separado do run:).
- `AGENTS.md` F9 — linha da F9.6 descrevendo a sintaxe v3.1.
- `lib.rs`/`schema.rs` doc examples atualizados.

## Verificação

`cargo fmt --all` · `cargo clippy --all-targets --all-features -- -D warnings` · `cargo test --all` (490 existentes não podem quebrar além dos ajustados) · `cargo bench -p sentry-protocol` (frame SSO segue ≥5× vs regex baseline; atualizar §24 se necessário).