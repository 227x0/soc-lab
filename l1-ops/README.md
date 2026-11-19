# L1 Operations — the analyst workstation

This lab emulates a real L1 SOC desk: an alert queue, triage runbooks,
an incident register, and an escalation path. Everything below runs in
the home lab (see ../architecture.md).

## The pipeline

```
attack happens
  -> Wazuh manager matches rules
  -> alert >= level 9 -> email to u1@localhost (postfix on u1)
  -> L1 reads mailbox = the alert queue
  -> triage per runbook (runbooks/)
  -> incident recorded (incident-register.csv)
  -> if real: escalate -> ticket in GLPI (http://192.168.100.22:8080)
  -> shift ends: fill shift-handover.md
  -> learning value -> case in soc-practice repo
```

## Tool stack (what sits on the analyst's desk)

| Layer | Tool | Where | URL / access | Notes |
|---|---|---|---|---|
| SIEM | Wazuh 4.14 | u1 (docker) | https://192.168.100.22 | alerts + archives (`wazuh-archives-*` in Discover) |
| IDS | Suricata 8.x | u3 | eve.json -> agent | ET open ruleset |
| EDR/DFIR | Velociraptor 0.77 | server u1, client u3 | https://192.168.100.22:8889 | admin / VeloLab2026! |
| Ticketing / SD | GLPI 10 | u1 (docker) | http://192.168.100.22:8080 | glpi/glpi -> CHANGE ON FIRST LOGIN |
| Alert queue | postfix + /var/mail/u1 | u1 | `grep "Wazuh notification" /var/mail/u1` | level >= 9 alerts |
| Vulnerability target | OWASP Juice Shop | u3 | http://192.168.100.24 | intentionally vulnerable |
| Attacker toolbox | Kali + PD stack | .20 | ssh | nuclei/httpx/subfinder/katana/naabu/feroxbuster |

## Runbooks

| Alert pattern | Runbook |
|---|---|
| SSH brute-force (Wazuh 40112/5763) | [runbooks/rb-ssh-bruteforce.md](runbooks/rb-ssh-bruteforce.md) |
| DNS anomaly / exfiltration (Suricata dns + dnsmasq log) | [runbooks/rb-dns-anomaly.md](runbooks/rb-dns-anomaly.md) |
| Web attack on Juice Shop (100100 SQLi, 31164) | [runbooks/rb-web-attack.md](runbooks/rb-web-attack.md) |

## Records

- [incident-register.csv](incident-register.csv) — every triaged alert, one line
- [shift-handover.md](shift-handover.md) — template for shift change notes

## Email alert configuration (fixed 2026-11-19)

- `smtp_server` in manager ossec.conf must be the HOST ip (192.168.100.22),
  not `localhost` — inside the container localhost is the container itself.
- postfix on u1 must listen on all interfaces:
  `postconf -e "inet_interfaces = all"` + add docker subnet to `mynetworks`,
  then `systemctl restart postfix` (reload is NOT enough for inet_interfaces).
- `<email_alert_level>9</email_alert_level>` — L12 was too quiet for an L1 queue.
