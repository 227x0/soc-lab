# SIEM Server (u1)

Wazuh 4.14 single-node deployment via the official `wazuh-docker` stack
(branch `v4.14.0`), directory `~/wazuh-docker/single-node` on u1
(Ubuntu Server 26.04, 6GB RAM, 4 vCPU, 30GB disk, grown from 10GB after
the disk-full incident, see lessons-learned.md).

## Services

| Container | Role | Port |
|---|---|---|
| wazuh.manager | manager + API | 1514/1515 (agents), 55000 (API) |
| wazuh.indexer | OpenSearch | 9200 |
| wazuh.dashboard | Kibana-based UI | 443 |

## Key configuration decisions

- **Vulnerability-detection is disabled** in
  `config/wazuh_cluster/wazuh_manager.conf` (`<enabled>no</enabled>`).
  The scanner's feed download is multi-GB and filled the disk on first
  install. That makes it the single most important hardening choice on a
  small lab.
- Docker images bundle a supported Ubuntu, so the host running 26.04
  (unsupported by native Wazuh packages) is irrelevant.
- The stock `docker-compose.yml` already ships `restart: always` for all
  three services; json-file log rotation blocks (`max-size: 50m`,
  `max-file: 3`) were added on top.
- Daily health checks and the weekly restart habit live in
  [ops-runbook.md](./ops-runbook.md).

## Verification commands

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
curl -k -s -m 60 -u admin:<password> https://localhost:9200/_cluster/health
docker exec single-node-wazuh.manager-1 curl -sk -u wazuh-wui:<password> \
  https://localhost:55000/security/user/authenticate | head -c 80
```
