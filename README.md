# Lab

Documentation of the home SOC lab this repository's cases are produced in.

This is not a write-up of one attack — it is the standing infrastructure:
how the network is laid out, what runs on each VM, how detection is wired,
and how to keep the whole thing alive.

## Files

| File | What's inside |
|---|---|
| [architecture.md](./architecture.md) | Network layout, VM inventory, detection layers |
| [siem-server.md](./siem-server.md) | Wazuh single-node (Docker) on u1: install, hardening, pitfalls |
| [target-host.md](./target-host.md) | u3: Juice Shop behind nginx, Suricata IDS, agent log sources |
| [attacker-host.md](./attacker-host.md) | Kali role, tooling, rules of engagement |
| [detection-pipeline.md](./detection-pipeline.md) | How an event travels from source to dashboard |
| [ops-runbook.md](./ops-runbook.md) | Health checks, snapshots, disk-watch, restart policy |
| [lessons-learned.md](./lessons-learned.md) | Postmortems and gotchas worth remembering |

Credentials and API keys are deliberately not committed. They exist only
inside the VMs.
