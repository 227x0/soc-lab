# Ops Runbook

Keeping a single-node SIEM alive on a 30GB disk with 6GB RAM is an
exercise in itself. These are the standing procedures.

## First-boot patience

After `docker compose up -d` or a host reboot, **wait ~7 minutes before
judging anything**. The indexer and modulesd take minutes to warm up;
`wazuh-control status` showing daemons "not running" at t+30s is normal.

## Health checks

```bash
# containers up
docker compose -f ~/wazuh-docker/single-node/docker-compose.yml ps

# daemons
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
# expect: db, analysisd, execd, authd, apid, remoted, logcollector,
# syscheckd, modulesd, monitord all running; maild/clusterd/dbd/
# csyslogd/integratord/agentlessd "not running" is normal (unconfigured).

# indexer
curl -k -s -m 60 -u admin:<password> https://localhost:9200/_cluster/health
# yellow or green = ok

# disk, the thing that killed us once
df -h /
```

## Disk policy

Two things fill this disk: the vulnerability-scanner feed (disabled,
keep it that way) and the event queue ballooning when the indexer is down
while agents keep talking. Container log rotation (`max-size: 50m`,
`max-file: 3`) is in the compose file.

Rule of thumb: **browsing the dashboard = only u1 running; attacking =
short u3+Kali sessions.** Never let attackers chat with a dead indexer.

## Snapshots

- u1: `wazuh-works` — taken right after the clean reinstall was verified.
- u3: taken with Juice Shop + Suricata + agent fully configured.

A broken VM rolls back in minutes instead of hours. Re-take snapshots after
any deliberate infrastructure change.

## Email alerts (local postfix)

The manager is configured to email alerts (`localhost` SMTP, local
delivery). Queue is read via `/var/mail/u1` (`grep "Wazuh notification"`).
This emulates the ticket queue L1 works from.

## Clock sync

Lab VMs drift after the host sleeps or VMs are paused (observed 2026-11-14:
u1/u3 ran ~4 days behind, which broke `apt` ("Release file not valid
yet") and would silently corrupt log correlation in the SIEM).

```bash
timedatectl                          # check
sudo timedatectl set-ntp true         # enable timesyncd
# if it must be fixed right now (ntp on refuses manual set):
sudo timedatectl set-ntp false
sudo timedatectl set-time "<UTC time from host: date -u>"
sudo timedatectl set-ntp true
```

Verify all three hosts agree within a minute before any timed exercise.

## Weekly

- `docker compose restart` on u1 (memory hygiene),
- check `df -h /` trend,
- confirm both agents show Active in the dashboard's Endpoints Summary.
