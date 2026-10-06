#!/usr/bin/env bash
# testar-uploads.sh — dispara os payloads F10 contra o decoy /upload do
# honeypot e mostra o resultado de cada caso. Entre os casos maliciosos o
# script desbloqueia e zera as strikes do seu IP via SSH, para a escalada
# de um teste não contaminar o seguinte.
#
# Uso (a partir da raiz do repo):
#   bash tools/upload-tests/testar-uploads.sh         # testa tudo
#   bash tools/upload-tests/testar-uploads.sh -n      # só gera payloads
#   SENTRY_TEST_HOST=http://outra-host bash tools/upload-tests/testar-uploads.sh
#
# Os payloads são gerados no próprio diretório (e regenerados se faltarem).
# Marcadores de ataque são montados por concatenação no código abaixo para
# não casar assinaturas de antivírus local no arquivo-fonte.
#
# Requisitos: curl e o alias SSH `honeypot` (descobrir/resetar seu IP).

set -u

HOST="${SENTRY_TEST_HOST:-http://3.17.156.125}"
# UA realista — NÃO coloque marcadores aqui: o pack `crawlers_bad` bloqueia
# UAs contendo substrings genéricas (test|check|scan|probe|monitor|http|...)
# e o veredito sairia por regra de UA antes das heurísticas de upload.
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
DIR="$(cd "$(dirname "$0")" && pwd)"
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=15"

# Marcadores montados por partes (ver comentário acima).
PHP_OPEN='<?ph'; PHP_OPEN="${PHP_OPEN}p "
SYS_CMD='system($_G'; SYS_CMD="${SYS_CMD}ET[\"c\"]); ?>"
EVAL_CMD='eval($_P'; EVAL_CMD="${EVAL_CMD}OST[\"x\"]); ?>"

cd "$DIR"

# ── Geração dos payloads ─────────────────────────────────────────────────
gen() {
  [ -s "$1" ] && return 0
  case "$1" in
    benigno.png)   printf '\x89PNG\r\n\x1a\n' > "$1"; head -c 2048 /dev/zero >> "$1" ;;
    benigno.pdf)   printf '%%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\ntrailer<</Root 1 0 R>>\n%%%%EOF\n' > "$1" ;;
    poliglota.gif) printf 'GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;' > "$1"
                   printf '%s%s' "$PHP_OPEN" "$SYS_CMD" >> "$1" ;;
    webshell.svg)  printf '<svg xmlns="http://www.w3.org/2000/svg"><scr'
                   printf 'ipt>alert(document.cookie)</scr' > "$1"
                   printf 'ipt></svg>\n' >> "$1" ;;
    shell.php.jpg) printf 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' > "$1" ;;
    renomeado.jpg) printf 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' > "$1" ;;
    zip-falso.png) printf 'PK\x03\x04\x14\x00\x00\x00\x00\x00' > "$1"; head -c 512 /dev/zero >> "$1" ;;
    pdf-php.pdf)   printf '%%PDF-1.4\n%s%s\n%%%%EOF\n' "$PHP_OPEN" "$EVAL_CMD" > "$1" ;;
    grande.bin)    head -c 2097152 /dev/urandom > "$1" ;;
  esac
}
for f in benigno.png benigno.pdf poliglota.gif webshell.svg shell.php.jpg renomeado.jpg zip-falso.png pdf-php.pdf grande.bin; do gen "$f"; done

if [ "${1:-}" = "-n" ]; then
  echo "payloads gerados em $DIR"
  exit 0
fi

# ── Descobre o IP de saída desta máquina ─────────────────────────────────
# O SSH vai direto ao host (sem passar pela edge), então $SSH_CLIENT no
# servidor é o nosso IP público — mais confiável que o event log, que fica
# inundado por eventos de SYN/TLS dos scanners (e não persiste evento
# algum quando o fast-path já está nos negando).
discover_ip() {
  ssh $SSH_OPTS honeypot 'echo $SSH_CLIENT' 2>/dev/null | awk '{print $1}'
}
MYIP="$(discover_ip)"
if [ -z "$MYIP" ]; then
  echo "não consegui descobrir seu IP via SSH_CLIENT do honeypot" >&2
  exit 1
fi
echo "host de teste : $HOST"
echo "seu IP        : $MYIP"
echo

# Zera block persistente + strikes do seu IP (o honeypot bloqueia agressivo
# e o fork LLM re-score é assíncrono — pode re-bloquear logo após o reset,
# por isso os chamadores dormem um pouco depois de resetar).
reset_ip() {
  ssh $SSH_OPTS honeypot \
    "docker exec sentry-sentry-1 sentry ip $MYIP unblock >/dev/null 2>&1; \
     docker exec sentry-sentry-1 sentry ip $MYIP forgive >/dev/null 2>&1" \
    && echo "   (ip $MYIP desbloqueado + strikes zerados)"
}

reset_ip
sleep 3

# t <rótulo> <esperado> <args do curl...>  → dispara e imprime o status.
t() {
  local label="$1" expect="$2"; shift 2
  local code
  code="$(curl -s -A "$UA" -o /dev/null -w '%{http_code}' "$@")"
  printf '%-52s -> %s  (esperado: %s)\n' "$label" "$code" "$expect"
}

echo "── Benignos (devem passar com 200) ──────────────────────────"
t "GET /upload (formulário)"                200 "$HOST/upload"
t "benigno.png   (PNG real)"                200 -F "file=@benigno.png;type=image/png" "$HOST/upload"
t "benigno.pdf   (PDF real)"                200 -F "file=@benigno.pdf;type=application/pdf" "$HOST/upload"
t "form urlencoded benigno"                 200 -X POST -d "display_name=relatorio-final" "$HOST/upload"

echo
echo "── Maliciosos (devem ser barrados: 403/429/503) ─────────────"
t "poliglota.gif (GIF + PHP)"          403/429/503 -F "file=@poliglota.gif;type=image/gif" "$HOST/upload"; reset_ip; sleep 3
t "webshell.svg  (SVG com script)"     403/429/503 -F "file=@webshell.svg;type=image/svg+xml" "$HOST/upload"; reset_ip; sleep 3
t "shell.php.jpg (MZ + extensão dupla)" 403/429/503 -F "file=@shell.php.jpg;type=image/jpeg" "$HOST/upload"; reset_ip; sleep 3
t "renomeado.jpg (EXE disfarçado de JPG)" 403/429/503 -F "file=@renomeado.jpg;type=image/jpeg" "$HOST/upload"; reset_ip; sleep 3
t "zip-falso.png (ZIP renomeado p/ PNG)" 403/429/503 -F "file=@zip-falso.png;type=image/png" "$HOST/upload"; reset_ip; sleep 3
t "pdf-php.pdf   (PDF com PHP no corpo)" 403/429/503 -F "file=@pdf-php.pdf;type=application/pdf" "$HOST/upload"; reset_ip; sleep 3
t "filename SQLi (q' OR '1'='1.png)"   403/429/503 -F "file=@benigno.png;filename=q' OR '1'='1.png;type=image/png" "$HOST/upload"; reset_ip; sleep 3
t "filename traversal (../../etc/shadow.png)" 403/429/503 -F "file=@benigno.png;filename=../../etc/shadow.png;type=image/png" "$HOST/upload"; reset_ip; sleep 3
t "campo urlencoded com SQLi"          403/429/503 -X POST -d "display_name=x' OR 1=1--&submit=go" "$HOST/upload"; reset_ip; sleep 3
t "corpo JSON com SQLi"                403/429/503 -X POST -H "content-type: application/json" -d "{\"q\":\"' OR 1=1--\"}" "$HOST/upload"; reset_ip; sleep 3

echo
echo "── Limite de inspeção ───────────────────────────────────────"
t "grande.bin    (2 MiB > inspect_kb=1 MiB)" 413 -F "file=@grande.bin;type=application/octet-stream" "$HOST/upload"

reset_ip
echo
echo "detalhe por evento: ssh honeypot \"curl -s 'http://172.17.0.1:9100/api/events?limit=40' | jq .\""
