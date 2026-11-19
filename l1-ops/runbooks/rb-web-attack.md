# Runbook: web attack on the Juice Shop target

## Trigger

- Custom rule **100100** (L12): SQLi pattern in URL (escalates stock 31164)
- Suricata ET web attack signatures
- nginx error log spikes, HTTP 500s from the app

## Triage (10 min)

1. **What rule fired and what URL/payload**: `' OR 1=1--`, `union select`,
   `../` -> injection or traversal.
2. **Response code**: 200 on a login bypass means access granted -> incident,
   not attempt.
3. **What came after**: authenticated endpoints hit with a token?
   (`GET /api/Users` after a "login" = account takeover + data dump)
4. **Scope**: one endpoint or a crawl/scrape pattern?

## Verdict

- Probe with no success (403/400s only) -> low, log, watch.
- Auth bypass / admin API access / file exfiltrated -> **true positive, P1/P2**.

## Escalate to L2 with

- payload, URL, rule IDs, src IP, timeline
- whether a valid JWT/session was issued (auth bypass proof)
- what data was touched (`/ftp/*`, `/api/*` from access.log)

## Contain (lab)

```bash
sudo iptables -A INPUT -p tcp -s <SRC> -j DROP
# app: invalidate sessions, reset admin password
```

## Document

Add a line to `incident-register.csv`; link case
`soc-practice/cases/02-juice-shop-web-attack` for the full chain.
