# Kit de teste — F10 (inspeção de uploads) no honeypot

Payloads + script para exercitar a inspeção de uploads do Sentry no decoy
`http://3.17.156.125/upload`. Config atual do honeypot: `[uploads] enabled,
mode = "enforce", inspect_kb = 1024` (corpos > 1 MiB tomam 413).

Os arquivos são gerados na primeira execução (e regenerados se faltarem);
os payloads de ataque são inofensivos — só marcadores de texto
(`<?ph` + `p system(...)` montado por partes, header `MZ`, `PK\x03\x04`)
para casar com as heurísticas byte-level do Sentry, não malware real.

> Nota: o kit mora aqui dentro do repo de propósito — uma versão anterior
> na pasta Downloads foi quarentenada pelo Windows Defender (arquivo-fonte
> contendo strings de webshell literais).

## Uso

```bash
bash tools/upload-tests/testar-uploads.sh         # gera payloads e roda tudo
bash tools/upload-tests/testar-uploads.sh -n      # só regenera os arquivos
SENTRY_TEST_HOST=http://outra-host bash tools/upload-tests/testar-uploads.sh
```

O script descobre seu IP de saída pelo event log do próprio honeypot e,
**depois de cada caso malicioso**, desbloqueia o IP e zera as strikes via
SSH (`sentry ip <ip> unblock` + `forgive`) — sem isso a escalada de
reincidentes (challenge aos 3 strikes, block aos 5) faria os testes
seguintes devolverem 403 do fast-path, mascarando o resultado real.

Para testar manualmente, arraste um dos arquivos no formulário em
`http://3.17.156.125/upload` e envie — verdict `Challenge` mostra o
interstitial PoW (curl não resolve o proof-of-work, por isso no script os
casos maliciosos caem em 403/429/503).

## Arquivos e o que cada um exercita

| Arquivo | Conteúdo real | Sinal esperado | Peso |
| --- | --- | --- | --- |
| `benigno.png` | PNG verdadeiro (magic + zeros) | nenhum | — |
| `benigno.pdf` | PDF mínimo | nenhum | — |
| `poliglota.gif` | `GIF89a` + webshell PHP mínimo | `upload_polyglot` | 60 |
| `webshell.svg` | SVG com `<scr`+`ipt>` e `alert(document.cookie)` | `xss` (content scan) | 45 |
| `shell.php.jpg` | header `MZ` + extensão dupla `.php.jpg` | `upload_executable` (50) + `upload_type_mismatch` (30) | 80 |
| `renomeado.jpg` | header `MZ` com aparência de imagem | `upload_type_mismatch` | 30 |
| `zip-falso.png` | `PK\x03\x04` (ZIP) renomeado para `.png` | `upload_type_mismatch` | 30 |
| `pdf-php.pdf` | `%PDF` + webshell PHP no corpo | `upload_polyglot` | 60 |
| `grande.bin` | 2 MiB aleatórios | nenhum — rejeitado com **413** (> `inspect_kb`) | — |

Dois casos extras vão só no curl (Windows não cria esses filenames):

- **filename SQLi** — upload benigno com `filename=q' OR '1'='1.png` →
  `sql_injection` (60).
- **filename traversal** — `filename=../../etc/shadow.png` →
  `path_traversal` (40).

E dois testes sem arquivo: campo de formulário urlencoded com `x' OR 1=1--`
e corpo `application/json` com a mesma injeção → `sql_injection` (60).

## Resultados esperados

- Benignos: **200** (`upload received`), sem sinais.
- Maliciosos: **403 / 429 / 503** — o código exato varia com o score
  (Medium → 429, High → interstitial PoW, Critical/LLM-fork → 403) e com o
  fork LLM `jev` do honeypot, que pode escalar Challenge → Block.
- `grande.bin`: **413** fixo.

## Conferir a detecção no servidor

```bash
ssh honeypot "curl -s 'http://172.17.0.1:9100/api/events?limit=40' | jq '.[] | select(.uploads != null) | {ip, path, status, verdict, score, signals, uploads}'"
ssh honeypot "curl -s http://172.17.0.1:9100/metrics | grep -E 'uploads_inspected|signal_kinds_total.kind=.upload'"
```

## Resetar seu IP manualmente

```bash
ssh honeypot "docker exec sentry-sentry-1 sentry ip <SEU_IP> unblock; \
              docker exec sentry-sentry-1 sentry ip <SEU_IP> forgive"
```

(O script descobre `<SEU_IP>` sozinho e já faz isso; este comando é para
quando você testar à mão pelo navegador e ficar bloqueado.)
