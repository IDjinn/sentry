# Incident Report — Command Injection via Upload Form Field (Honeypot Capture)

Companion to `incident-report-mozi-rce.md`. Real capture from a production
Sentry honeypot deployment; attacker IPs are partially masked.

## TL;DR

A scanner POSTed a multipart form with a command-injection payload hidden
**inside a form field's content** — invisible to any filter that only
inspects URLs, headers, or query strings. Sentry's request-body inspection
parsed the multipart payload, scanned the field value, and emitted the
`rce` signal from the body: **80/100 critical, blocked with 403**. The
attack surface here is exactly the one most WAF deployments miss.

## Event summary

| Field | Value |
| --- | --- |
| Timestamp | 2026-10-07 09:09:16 UTC |
| Source | `http_proxy` (inline edge, port 80) |
| Attacker | `13.205.xxx.xxx` (masked, cloud-provider range) |
| Method / Path | `POST /` |
| Request body | Multipart form, field `0` carrying command-injection content |
| Risk score | 80 — **critical** |
| Verdict | **block** (HTTP 403) |
| Body persisted | No — only metadata and detection results (by design) |

## The signal chain

```
rce                — "upload field 0: cmd" — weight 70
method_not_allowed — "POST /"              — weight 10
──────────────────────────────────────────────────
score 80 → critical → verdict block → 403
```

The `rce` signal did **not** come from the URL (`/` is empty of payloads)
or from any header. It came from the body pipeline:

1. The edge buffered the request body within its inspection cap.
2. The multipart parser split the form into fields.
3. The `upload_content` heuristic scanned each field's text content and
   matched the **`cmd` (command injection) text family** in field `0`.

The exact payload text is not persisted — Sentry records detection
metadata, never raw bodies — but the match family is the same
command-injection class as the Mozi captures: chained shell commands
attempting execution on the server.

## Why this demonstrates effectiveness

- **Body-level inspection is table stakes for real RCE defense.** Filter
  only the query string and this request scores a 10 and passes as a
  boring `POST /`.
- **Detection survives transport.** Whether injection arrives in a query
  string (`incident-report-mozi-rce.md`) or wrapped in multipart encoding,
  the same heuristic family fires after decoding — no bypass by
  re-encapsulation.
- **Privacy held under attack conditions.** Even while blocking a critical
  request, the pipeline persisted zero raw body bytes — detection
  metadata only.
