# Detection Pipeline

How one attack becomes dashboard alerts.

## Path

```
Kali ──HTTP/SSH──▶ u3 ──┬─▶ nginx access.log ─────▶ Wazuh agent (logcollector)
                        │─▶ /var/log/auth.log ──▶        │
                        │─▶ Suricata eve.json ──▶        │
                        ▼                                ▼
                  attack happens              agent → manager :1514/tcp
                                                     │
                              analysisd → wazuh-db → indexer (OpenSearch)
                                                     │
                                              dashboard :443
```

1. The attack hits u3 over the network (HTTP via nginx:80, SSH on :22).
2. Host telemetry: nginx writes the request to `access.log`; sshd writes
   to `/var/log/auth.log`; the Wazuh agent tails both.
3. Network telemetry: Suricata matches packets/streams against ET
   signatures and appends JSON alerts to `eve.json`.
4. The agent batches everything to the manager on TCP 1514.
5. `wazuh-analysisd` decodes and matches rules; correlation rules
   (e.g. 40112 "Multiple authentication failures followed by a success")
   fire on event sequences.
6. Alerts are indexed in OpenSearch and rendered in the dashboard.

## Practical verification per layer

| Layer | Where to look |
|---|---|
| nginx shipped to SIEM | dashboard → Security Events, agent `u3`, event source web |
| Suricata shipped to SIEM | same view, rule group `suricata` (e.g. rule 86601 ET SCAN signatures) |
| Suricata locally | `sudo grep '"event_type":"alert"' /var/log/suricata/eve.json` |
| agent connectivity | `sudo grep "Connected to the server" /var/ossec/logs/ossec.log` |

## Notable built-in detections observed

- SSH brute-force → correlation rule 40112 (level 12), MITRE T1110.
- nmap scans → ET signatures ("Possible Nmap User-Agent Observed"), rule 86601.
- Web SQLi attempts → stock rule **31164** "SQL injection attempt" (L6);
  since SOC-2026-003 escalated by custom rule **100100** (L12, MITRE T1190)
  in the manager's `local_rules.xml`. Verified with `wazuh-logtest`.
