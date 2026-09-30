# Honeypot Sentry na VPS Lightsail (1 GB) — Plano de execução

**Meta**: expor a VPS `3.17.156.125` como honeypot para exercitar o Sentry em tráfego real da internet, rodando em Docker, com métricas Prometheus e Grafana, tudo acessível só via túnel SSH/WireGuard. Nada importante na máquina — é descartável.

## 1. Artefatos no repo (novos, sem tocar no código Rust)

```
.github/workflows/docker-publish.yml   # builda imagem linux/amd64 → ghcr.io (workflow_dispatch + push main)
deploy/honeypot/
├── docker-compose.yml                 # 8 serviços, mem-limitado para 1 GB
├── sentry.toml                        # config do daemon honeypot (template; hash admin gerado no setup)
├── prometheus/prometheus.yml          # scrape: sentry:9100 (via host-gateway) + node_exporter:9101
├── grafana/provisioning/…             # datasource + dashboard "Sentry Honeypot" auto-provisionado (JSON autoral)
├── nginx-decoy/ (nginx.conf + html/)  # site/armadilha fake em 80+443 (self-signed), access.log combined p/ Sentry
├── ssh-decoy/ (Dockerfile + sshd_config + entrypoint.sh)  # OpenSSH na 22, password-auth, tudo falha
├── .env.example                       # SENTRY_PG_PASSWORD, SENTRY_SESSION_SECRET, GF_SECURITY_ADMIN_PASSWORD
└── README.md                          # runbook completo (firewall Lightsail, swap, WireGuard, update, troubleshooting)
```

**Compose** (rede bridge; mem limits somam ~1 GB de teto, uso real esperado ~600–700 MB + 2 GB swap):
- `sentry` (daemon `run`): `network_mode: host` + `cap_add: NET_RAW` — necessário p/ fonte tcp (pcap) ver scans em **todas** as portas; `FEATURES=sentry-cli/pcap` na imagem; syslog bind `127.0.0.1:5140`; metrics na 9100 (fechada no firewall do Lightsail); healthcheck `sentry config validate` (padrão do k8s).
- `sentry-dashboard` (`serve`): publica `127.0.0.1:8080` (+ wg0), auth `password` com usuário admin (hash Argon2id gerado com `sentry auth hash-password`).
- `postgres:16-alpine`: interno, `127.0.0.1:5432` p/ o daemon (host-net), `shared_buffers=64MB`, `max_connections=20`, healthcheck, PGDATA em subpath.
- `nginx-decoy`: 80+443, log em volume nomeado montado **ro** no daemon (`/var/log/nginx`); conteúdo fake (login/admin) p/ atrair bots; paths-decoy respondem 200, resto 404 (alimenta detectores de scan/wordlist).
- `ssh-decoy`: publica `22:22` (firewall Lightsail já aberto), tentativas de senha sempre falham, log no `docker logs`.
- `prometheus` (interno, retenção 3d/512 MB) + `grafana` (127.0.0.1:3000 + wg0, provisionado) + `node_exporter` (host-net).

**Config do Sentry** (sentry.toml): sources nginx + syslog + tcp(eth0, portas de honeypot); packs `sensitive_paths`/`crawlers_*`/`http_anomaly`/`rate_scan` em enforce; feeds Tor/FireHOL level1 (exercita sentry-reputation); actions `log` + `blocklist` (sem Cloudflare); scan/behavior/escalation default; AI/LLM/geo desligados (RAM). Dashboard Grafana: ~12 painéis (events/level rate, actions por verdict, pipeline p99, feeds up, CPU/mem/disk/rede do host).

## 2. Workflow ghcr
- Confirma remote GitHub (`IDjinn/sentry`); se não existir, surface ao usuário antes de criar.
- Workflow builda com `build-args: FEATURES=sentry-cli/pcap`, push em `ghcr://<owner>/sentry:latest` (+sha). Após o 1º push, tornar o package público (gh API ou instruções) p/ a VPS fazer pull sem PAT.

## 3. Provisionamento da VPS (via SSH, ordem lockout-safe)
1. Copiar a `.pem` p/ `~/.ssh` com permissão correta (Windows ssh reclama de chave em Downloads).
2. SSH: checar estado (RAM/disk/docker). Criar swap 2G. Instalar Docker + compose plugin.
3. **Firewall Lightsail** (aws CLI se configurado; senão instruções p/ console): abrir `22022/tcp` e `51820/udp`; manter `22`, abrir `80`, `443`. **Não** abrir 3000/8080/9100/9101/5140/5432.
4. WireGuard no host: `wg0` 10.66.66.1/24, peer = PC do usuário 10.66.66.2/32, porta 51820/udp, `wg-quick@wg0` habilitado; gerar `.conf` do cliente em `C:\Users\lucas\Downloads\sentry-honeypot-wg.conf` (instruções de import no README).
5. Mover SSH: **só depois** de `22022` testado e acessível de fora → `Port 22022` no sshd_config, restart, validar login, deixar a 22 p/ o decoy.
6. Copiar `deploy/honeypot/` + `.env` gerado (senhas fortes via `openssl rand`), `docker compose pull && up -d`; validar migrations/logs do daemon, `curl 127.0.0.1:9100/metrics`.
7. Rsyslog opcional: forward local → 5140/udp p/ demonstrar a fonte syslog (limitação documentada: sem análise de conteúdo, client_ip=127.0.0.1).

## 4. Validação ponta a ponta
- Da minha máquina: `curl http://3.17.156.125/.env`, SQLi `/?id=1' OR 1=1--`, path traversal, rajada de 404 (detector de scan), tentativas SSH erradas na 22.
- Conferir: eventos em `/api/events` (via túnel), counters subindo no `/metrics`, incidentes High/Critical criados, blocklist populada, Grafana com painéis vivos (screenshot headless p/ conferir provisionamento).
- Reportar credentials/endereços finais ao usuário (sem commitar segredos).

## 5. Entregáveis finais
Repo com `deploy/honeypot/` + workflow commitados (rodo `cargo fmt/clippy/test` mesmo sem mudanças Rust, por protocolo) e README com runbook; VPS rodando a stack completa; acessos: SSH real `22022`, túnel `ssh -L 3000:localhost:3000` (ou via WG), WireGuard configurado. Se algo do lado AWS (firewall/package ghcr) exigir credencial que não existe localmente, paro nesse passo e entrego instruções exatas de console.