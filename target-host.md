# Target Host (u3)

The deliberately vulnerable victim. Everything here exists to be attacked
and detected.

## Services

### Juice Shop (web target)

- `bkimminich/juice-shop` in Docker, bound to `127.0.0.1:3000` only —
  unreachable directly from the network.
- **nginx** reverse proxy on port 80 forwards to it and writes
  `access.log` / `error.log`. This is the detection point: every HTTP
  request (including SQLi strings in URLs) is logged and shipped to the SIEM.

### Suricata (network IDS)

- Version 8.x, listens on the host's NIC (`enp0s3`) in IDS mode.
- Rules: Emerging Threats open set via `suricata-update` (~53k signatures).
- Interface is configured in `/etc/suricata/suricata.yaml` under the
  `af-packet` section (list syntax: `- interface: enp0s3`).
- Output: `/var/log/suricata/eve.json` (JSON) + `fast.log`.

### Wazuh agent

- Manager: `192.168.100.22:1514/tcp`.
- Log sources (`/var/ossec/etc/ossec.conf`):
  `/var/log/auth.log`, `/var/log/syslog`, `/var/log/dpkg.log`,
  nginx `access.log` + `error.log` (format `syslog` — the agent parses
  nginx natively, there is **no** `nginx` log format), and Suricata
  `eve.json` (format `json`).

## Known good agent config note

The agent's `ossec.conf` was rewritten cleanly after a copy-paste
accident duplicated blocks; the working version lists exactly the sources
above. Always back up before sed-editing it, and verify with
`grep -c "</ossec_config>"` (must be 1).
