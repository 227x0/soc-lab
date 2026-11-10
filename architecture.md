# Architecture

## Network

Single VirtualBox **Host-only** network `192.168.100.0/24`, gateway/DNS
`192.168.100.1`. All VMs use static addresses so case evidence always maps
to the same hosts. The lab has no route to the internet from the target
side beyond what the host provides.

```
                 Windows host (VirtualBox, 16GB RAM, Ryzen 5 3600)
                ┌────────────────────────────────────────────────────┐
                │               Host-only 192.168.100.0/24            │
                │                                                    │
                │   Kali .20          u1 .22            u3 .24       │
                │  ┌─────────┐     ┌──────────┐     ┌──────────────┐  │
                │  │ red team│     │ SIEM     │     │ target host  │  │
                │  │ attacker │────▶│ Wazuh    │◀────│ Juice Shop   │  │
                │  └─────────┘     │ 4.14     │logs │ + nginx      │  │
                │                  │ (Docker) │     │ + Suricata   │  │
                │                  └──────────┘     └──────────────┘  │
                └────────────────────────────────────────────────────┘
```

## VM Inventory

| VM | IP | Role | Specs |
|---|---|---|---|
| Kali | 192.168.100.20 | Attacker (red team) | rolling |
| u1 | 192.168.100.22 | SIEM server — **never attacked** | Ubuntu Server 26.04, 6GB RAM, 4 vCPU, 30GB disk |
| u3 | 192.168.100.24 | Target / victim host | Ubuntu Server |

## Detection layers on the target

Two independent layers, both verified producing alerts in the dashboard:

1. **Host-based** — the Wazuh agent ships `nginx` access/error logs and
   system logs (`/var/log/auth.log`) to the SIEM. Web attack URLs (SQLi
   patterns in query strings) are visible here.
2. **Network-based** — Suricata 8.x inspects traffic on the target's NIC
   with ~53k Emerging Threats signatures. In a VirtualBox host-only network
   a VM only sees its own traffic, so the IDS lives on the victim itself
   (host-based IDS deployment). Alerts land in `eve.json` and flow through
   the same Wazuh agent.

Any single attack from Kali can therefore surface as two alerts in two
different data sources — the core exercise for L1 correlation.

## Deliberate weaknesses

- Account `u3` has a one-character password by design (SSH brute-force target).
- Juice Shop is an intentionally vulnerable web app.
- Both exist only inside the isolated lab network.
