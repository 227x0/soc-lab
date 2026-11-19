# Runbook: DNS anomaly / possible exfiltration

## Trigger

Any of:
- Suricata DNS telemetry: burst of queries to one domain with long/random subdomains
- dnsmasq log lines: `query[A] <random>.<domain> from <ip>` repeating
- Sigma-style idea: high query volume + high label entropy + rare domain

## Triage (10-15 min)

1. **Find the events**: Discover -> `wazuh-archives-*` ->
   `data.dns.queries.rrname : *<domain>*` (Suricata view) or text search
   `exfil.lab` (dnsmasq view).
2. **Volume**: how many queries, what window, which src_ip?
3. **Look at the labels**: readable names (www, mail, api) = likely legit;
   base64/hex-looking random chunks = suspect (case SOC-2026-004).
4. **Domain age/reputation**: new or unseen domain in this network = points up.
   (Lab: `exfil.lab` was created for the exercise.)
5. **Response codes**: REFUSED from an internal sink is a flag by itself;
   NOERROR answers to gibberish names mean the tunnel server is answering.

## Verdict

- Few queries, readable names -> normal, close.
- Burst + random labels + rare domain -> **true positive (data exfil over DNS),
  P2** (P1 if sensitive data or many hosts).

## Escalate to L2 with

- src_ip, domain, query count, time window, both telemetry sources
- captured labels (chunks) — L2 can decode/reassemble
- note: data is base64-ENCODED (not encrypted) -> content recoverable

## Contain (lab / prod)

- block src IP at firewall, isolate host
- force DNS through internal resolver only (egress filtering) — closes the pipe

## Document

Add a line to `incident-register.csv`. If it was an exercise, link the case
(soc-practice `cases/04-dns-exfiltration-hunting`).
