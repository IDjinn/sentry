# Sentry Honeypot — public test VPS

Docker stack that turns a small (1 GB RAM) public VPS into a honeypot for
exercising Sentry against real internet traffic. Nothing on the box has any
value: the only real services are decoys, and all management access goes
through SSH (moved port) or WireGuard.

Reference deployment: **Lightsail `3.17.156.125` (us-east-2), Ubuntu 24.04,
1 GB RAM / 1 vCPU / 38 GB disk**.

## Architecture

```
internet ──► :80/:443  sentry edge (host net, inline mode)
             │ 80: plain HTTP — scored and served
             │ 443: TLS terminated in-app (self-signed cert, F8) — the
             │      decrypted request goes through rules → heuristics →
             │      policy BEFORE anything is answered, so payloads like
             │      /login?test=<script> block on HTTPS exactly like on HTTP
             └──► 127.0.0.1:8081  nginx-decoy (fake company login, plain HTTP;
                    combined access.log → named volume `nginxlogs`, humans only)
internet ──► :22     ssh-decoy (OpenSSH, locked password — everything fails)
internet ──► :any    sentry tcp source (pcap SYN fingerprint, masscan/zmap/nmap)
host rsyslog ──► 127.0.0.1:5140/udp  sentry syslog source (reputation-only)

sentry daemon ──► :9100 /metrics (Prometheus scrape, NOT public)
sentry serve  ──► 127.0.0.1 + wg0 :8080  (dashboard, password auth)
grafana       ──► 127.0.0.1 + wg0 :3000  (pre-provisioned dashboard)
postgres      ──► internal + 127.0.0.1:5432
```

Services and memory limits: postgres 256m, sentry 192m, sentry-dashboard
96m, prometheus 256m, grafana 192m, nginx-decoy 32m, ssh-decoy 48m,
node-exporter 48m (~1 GB of limits; add a 2 GB swapfile — see below).

## One-time provisioning

### 1. Lightsail console firewall

Networking tab → IPv4 firewall. Required state:

| Port | Proto | Purpose | Default |
| --- | --- | --- | --- |
| 22 | TCP | SSH decoy container | already open |
| 80 | TCP | sentry edge (decoy behind it) | already open |
| 443 | TCP | sentry edge (TLS termination, F8) | open manually |
| 22022 | TCP | real SSHD (after `sentry-move-ssh.sh`) | open manually |
| 51820 | UDP | WireGuard | open manually |

Do **not** open 3000, 8080, 9100, 9101, 5140 or 5432 — those stay on
loopback / the WireGuard subnet.

### 2. Host bootstrap

```bash
# 2 GB swap + mild swappiness
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swap.conf
sudo sysctl -p /etc/sysctl.d/99-swap.conf

# Docker + compose plugin
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 wireguard
sudo usermod -aG docker ubuntu   # re-login afterwards
sudo systemctl enable --now docker
```

### 3. Deploy the stack

```bash
sudo mkdir -p /opt/sentry && sudo chown ubuntu /opt/sentry
# copy deploy/honeypot/ → /opt/sentry (scp -r deploy/honeypot/* ubuntu@IP:/opt/sentry/)
cd /opt/sentry

# self-signed cert for the edge TLS listener (mounted into the sentry
# container at /etc/sentry/certs — see [edge] tls_cert/tls_key in sentry.toml)
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/decoy.key -out certs/decoy.crt -days 3650 -nodes \
  -subj "/CN=nimbuscloud.example"

# secrets + dashboard admin
cp .env.example .env
openssl rand -base64 24   # → SENTRY_PG_PASSWORD
openssl rand -base64 32   # → SENTRY_SESSION_SECRET
openssl rand -base64 18   # → GF_SECURITY_ADMIN_PASSWORD, and SENTRY_DASH_ADMIN_PASSWORD comment
docker compose pull
docker run --rm ghcr.io/idjinn/sentry:latest sentry auth hash-password '<DASH_PASSWORD>'
# put the hash into sentry.toml, replacing __ADMIN_PASSWORD_HASH__
sed -i "s|__ADMIN_PASSWORD_HASH__|<HASH>|" sentry.toml

docker compose up -d        # base stack (ssh-decoy stays behind a profile)
```

### 4. Host integrations

```bash
# daily rotation of the decoy access log
sudo cp host/sentry-nginx-logrotate /etc/cron.d/sentry-nginx-logrotate

# forward auth events to the syslog source (reputation-only; see file header)
sudo cp host/30-sentry-syslog.conf /etc/rsyslog.d/
sudo systemctl restart rsyslog
```

### 5. Move real SSH and start the SSH decoy

Open **22022/tcp** in the Lightsail firewall first, keep the current session
open, then:

```bash
chmod +x host/sentry-move-ssh.sh && sudo ./host/sentry-move-ssh.sh
# verify from your machine: ssh -p 22022 ubuntu@IP
```

The script disables Ubuntu 24.04's sshd socket activation, switches the port
(with automatic rollback on failure) and starts `ssh-decoy` on port 22.
Decoy attempts: `docker logs -f ssh-decoy`.

### 6. WireGuard

Server (`/etc/wireguard/wg0.conf`):

```ini
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

[Peer]                      # your workstation
PublicKey = <client-public-key>
AllowedIPs = 10.66.66.2/32
```

```bash
wg genkey | tee server.key | wg pubkey > server.pub
sudo nano /etc/wireguard/wg0.conf && sudo chmod 600 /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
```

Client (`sentry-honeypot-wg.conf` — import into the WireGuard desktop app):

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.66.66.2/32

[Peer]
PublicKey = <server-public-key>
Endpoint = 3.17.156.125:51820
AllowedIPs = 10.66.66.0/24      # split tunnel: only the honeypot
PersistentKeepalive = 25
```

With the tunnel up: Grafana `http://10.66.66.1:3000`, Sentry dashboard
`http://10.66.66.1:8080`, SSH `ssh -p 22022 ubuntu@10.66.66.1`. Without it,
use an SSH tunnel: `ssh -p 22022 -L 3000:127.0.0.1:3000 -L 8080:127.0.0.1:8080 ubuntu@IP`.

## Access

| What | Where |
| --- | --- |
| Grafana | `http://10.66.66.1:3000` (or tunnel) — user `admin`, password from `.env` |
| Sentry dashboard | `http://10.66.66.1:8080` (or tunnel) — user `admin`, generated password |
| Metrics raw | `curl 127.0.0.1:9100/metrics` on the VPS |
| Decoy logs | `docker logs -f nginx-decoy` / `docker logs -f ssh-decoy` |
| Events API | `GET /api/events?limit=50` on the dashboard (session cookie) |

The Grafana dashboard ("Sentry Honeypot") is provisioned automatically:
pipeline stats, events by risk level, actions by verdict, pipeline p99,
reputation feed health, and host CPU/memory/disk/network.

## Updating Sentry

The image is built by the `docker-publish` GitHub Actions workflow
(builds `linux/amd64` with `FEATURES=sentry-cli/pcap,sentry-cli/edge-tls`,
pushes `ghcr.io/idjinn/sentry:latest` — the `edge` tag pins the same image
for the VPS). On the VPS:

```bash
cd /opt/sentry && docker compose pull && docker compose up -d
```

### Migrating a deployment that predates edge TLS (443 on nginx-decoy)

Older stacks published `443:443` on nginx-decoy; the edge now binds 443 on
the host network. If sentry restarts while the old nginx still holds 443,
the TLS bind fails and takes the whole edge (including port 80) down, so
stop the decoy first:

```bash
cd /opt/sentry
docker compose pull
docker compose stop nginx-decoy
docker compose up -d
# verify both listeners: docker logs -f sentry  →
#   edge (inline) listening on http  addr=0.0.0.0:80
#   edge (inline) listening on https addr=0.0.0.0:443
```

Quick functional check (payload must be blocked with the edge's 403 page on
both schemes):

```bash
curl -s -o /dev/null -w '%{http_code}\n'  'http://3.17.156.125/login?test=%3Cscript%3Ealert(1)%3C/script%3E'
curl -sk -o /dev/null -w '%{http_code}\n' 'https://3.17.156.125/login?test=%3Cscript%3Ealert(1)%3C/script%3E'
```

## Limitations (by design or current state)

- **Syslog source analyzes no content**: forwarded auth events are scored via
  IP reputation only, and the client IP is the forwarding peer (`127.0.0.1`).
  SSH brute force is *not* detected by Sentry on this box — it lives in
  `docker logs ssh-decoy`. Parsing `SyslogData` messages (e.g. sshd) is a
  future Sentry feature.
- The **tcp source** needs host networking + `NET_RAW` (compose grants it)
  and the image must be built with `sentry-cli/pcap` (the workflow does).
- The **edge TLS listener** needs the `sentry-cli/edge-tls` build feature
  (the workflow does). Without it, `[edge]` TLS config makes the whole edge
  refuse to start — the plain 80 listener dies with it.
- The nginx decoy is a plain-HTTP upstream on loopback only; it must never
  republish 80/443 or the edge binds collide and TLS escapes the pipeline.
- **Geo enrichment is off** (no MaxMind GeoLite2 files). Drop the `.mmdb`
  files into the `sentrydata` volume to enable country/ASN rules.
- AI (ONNX) is disabled to fit the 1 GB budget. The LLM stage is remote-only
  (TypeSafe jev, key in `.env` as `SENTRY_JEV_KEY`) — zero local compute.
- The nginx decoy is static HTML with no backend; POSTs to `/login` return
  405/404, which still feeds the behavioral detectors.

## Teardown

```bash
cd /opt/sentry && docker compose --profile decoy-ssh down -v
sudo systemctl disable --now wg-quick@wg0
```
