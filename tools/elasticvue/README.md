# Elasticvue over the Wazuh indexer

Splunk-style open-source (MIT) web UI for browsing `wazuh-archives-*` / `wazuh-alerts-*`.

## Run (on u1)

```bash
docker run -d --name es-proxy --restart always --network host \
  -v /home/u1/es-proxy/nginx.conf:/etc/nginx/conf.d/default.conf:ro nginx:alpine
docker run -d --name elasticvue --restart always -p 8082:8080 cars10/elasticvue
```

es-proxy exposes the indexer over plain HTTP on :9210 and adds CORS for the
Elasticvue origin (self-signed indexer cert breaks browser fetch otherwise).

## Use

- UI: http://192.168.100.22:8082
- Cluster URL: `http://192.168.100.22:9210` (reachable from the browser, not localhost)
- Auth: `admin` / `SecretPassword` (single-node defaults from the docker compose)
- Search indices: `wazuh-archives-*` (everything, incl. non-alerting) or `wazuh-alerts-4.x-*`
