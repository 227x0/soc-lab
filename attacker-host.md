# Attacker Host (Kali)

Red team station at `192.168.100.20`. Both manual attacks (case studies) and
an autonomous "red team agent" run from here.

## Tooling used so far

| Tool | Use |
|---|---|
| hydra | SSH password brute-force |
| nmap | port/service scanning (SYN, service detection) |
| curl | manual web attacks (SQLi in URLs and POST bodies) |

## Rules of engagement (self-imposed)

- Only `u3` (192.168.100.24) is a target. The SIEM server `u1` is off
  limits — killing the observer defeats the purpose of the lab.
- Attack sessions are kept short. Long unattended attacker+target uptime
  with the dashboard open is what ballooned the event queue during the
  disk-full incident (see lessons-learned.md).
- After each attack wave, the red team reports the exact techniques and
  commands used. The blue team compares that list against what was
  actually detected — the delta is the learning material.
