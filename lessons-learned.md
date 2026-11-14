# Lessons Learned

Hard-won knowledge from breaking and resurrecting this lab. Each item cost
real hours.

## Never native-install Wazuh on Ubuntu 26.04

Native packages support up to 22.04. Attempting it on 26.04 produced:
indexer/manager systemd start timeouts (fixed with `TimeoutStartSec=900`
drop-ins), broken dpkg maintainer scripts exiting 127 (fixed by stubbing
prerm/postrm), a 9.9GB leftover feed archive, and a dashboard stage that
failed silently and rolled everything back. The Docker path worked the
first time (~10 minutes) because the images bundle a supported OS.

## The disk-full incident

Chain of failure: vulnerability-scanner downloaded its multi-GB feed into
`queue/vd` → disk hit 100% → indexer crash-looped (no space even for temp
files) → the manager buffered agent events into `wazuh_queue`, which grew
to 15GB → total death of the dashboard, "No API available".

Recovery highlights:

- Wiping the queue volume freed 15GB but broke `wazuh-db`. It drops
  privileges to uid 999, so recreated directories must be `chown 999:999`,
  not root-owned.
- Foreground-debugging a daemon (`wazuh-remoted -fd`) showed the binary
  and config were fine; the failure was in how the container started it.
- After ~4 hours of triage the winning move was a clean reinstall with
  vulnerability-detection disabled **before** first start.

## Wazuh agent has no `nginx` log_format

An invalid `log_format` value makes the agent refuse to start with
`Invalid value for element 'log_format'`. Ship nginx logs as `syslog`;
Wazuh's built-in decoder parses them.

## Suricata on Ubuntu 26.04

- The interface lives in `/etc/suricata/suricata.yaml` under `af-packet`,
  list syntax (`  - interface: eth0`), mind the two-space + dash indent
  when sed-editing.
- `suricata-update` fetches the ET rule set; without rules the engine
  starts but detects nothing.

## sed + copy-paste = duplicated blocks

Multi-line `sed -i 's|</ossec_config>|...|'` inserts executed twice (or a
block re-run after a failed paste) silently duplicate XML blocks and break
the agent with opaque "Error reading XML" messages. Always verify with
`grep -c` after inserting, and keep a backup before editing.

## SOC lessons

- Correlation "failures → success" (rule 40112) is what turns SSH noise
  into an incident; the success is the story.
- Host + network correlation (nginx logs vs Suricata) is standard L1
  work: one attack, two independent data sources.
- A SIEM can be blinded by resource exhaustion; disk and queue health are
  security properties, not just ops trivia.
