# Incident Report — Distributed MCP/SSE Endpoint Scanner (Honeypot Capture)

Companion to `incident-report-mozi-rce.md`. Real capture from a production
Sentry honeypot deployment; attacker IPs are partially masked.

## TL;DR

A coordinated scanner hunted for exposed **AI infrastructure** — MCP
(Model Context Protocol) servers and SSE endpoints — from **25 different IP
addresses in 3 days**, one cheap probe per IP to stay under per-IP rate
limits. Sentry's curated bad-crawler dataset recognized the tool's
User-Agent on the first request of every probe: **25/25 scored 100/100,
blocked, and banned**. Zero probes ever reached a backend.

## Campaign summary

| Field | Value |
| --- | --- |
| First seen | 2026-10-07 21:00 UTC |
| Last seen | 2026-10-10 22:41 UTC |
| Events / distinct source IPs | 25 / **25** (one probe per IP) |
| User-Agent | `Mozilla/5.0 (compatible; Infrawatch/1.0; +https://infrawat.ch/)` |
| Risk score | **100/100 — critical** (every event) |
| Verdict | **block** (every event) |
| Aftermath | All 25 source IPs banned in `ip_state` |

## What they were looking for

| Path probed | Hits |
| --- | --- |
| `/` (fingerprinting) | 9 |
| `/favicon.ico` | 4 |
| `/mcp` | 3 |
| `/mcp/` | 3 |
| `/sse` | 3 |
| `/api/mcp` | 2 |
| `/onvif/device_service` (IP cameras) | 1 |

The path set is a shopping list of 2026 attack surface: **MCP servers**
(`/mcp`, `/mcp/`, `/api/mcp`) are the new "exposed database" — an unauthenticated
MCP endpoint hands tools and context to anyone who finds it — plus SSE
transport endpoints and a legacy ONVIF camera probe on the side.

A second probe from yet another IP hit `/mcp` with
`python-httpx/0.28.1` as the User-Agent. Same outcome: score 100, block,
ban.

## How Sentry caught it

No heuristics, no scoring model, no LLM — the **`bad_crawler` rule pack**
(a curated scanner/bad-bot User-Agent dataset) matched on the first byte of
the first request:

```
signal: rule_hit / bad_crawler — weight 100 → score 100 → critical → block
```

This is the reputation fast path working as designed: a known-bad tool
identified at the rule stage, before the pipeline spends anything on
heuristics or AI.

## Why this demonstrates effectiveness

- **The evasion is the tell.** Spreading 25 probes across 25 IPs defeats
  naive per-IP rate limiting — but not a reputation list keyed on the
  tool itself.
- **New attack surface, old defense.** MCP/AI endpoints barely existed
  when the rule pack was curated; the dataset still caught the campaign
  because scanner tooling reuses identifiable User-Agents.
- **Zero-cost containment.** 25 blocks, 25 bans, no operator action, no
  backend exposure — the honeypot surface never answered a single probe.
