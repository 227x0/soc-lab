#!/usr/bin/env python3
"""wzread — human-readable Wazuh archives/alerts from the indexer.
No deps (urllib only). Indexer creds from the single-node docker compose.

Usage:
  wzread                last 60 min of archives, 30 lines
  wzread 15             last 15 min
  wzread -a             alerts index instead of archives
  wzread -n 50          50 lines
  wzread -s ssh         only events whose text matches "ssh"
  wzread -j 5           pretty-print full JSON of 5 newest events
  wzread -r             raw JSON output (pipe to jq/grep)
"""
import json, sys, urllib.request, base64, datetime

IDX = "https://localhost:9200"
AUTH = base64.b64encode(b"admin:SecretPassword").decode()

def parse():
    a = sys.argv[1:]
    o = {"min": 60, "n": 30, "alerts": False, "json": 0, "raw": False, "search": None}
    i = 0
    while i < len(a):
        if a[i] == "-a": o["alerts"] = True
        elif a[i] == "-j": o["json"] = int(a[i+1]); i += 1
        elif a[i] == "-n": o["n"] = int(a[i+1]); i += 1
        elif a[i] == "-r": o["raw"] = True
        elif a[i] == "-s": o["search"] = a[i+1].lower(); i += 1
        else:
            try: o["min"] = int(a[i])
            except ValueError: print("unknown arg:", a[i]); sys.exit(2)
        i += 1
    return o

def q(o):
    index = "wazuh-alerts-4.x-*" if o["alerts"] else "wazuh-archives-*"
    body = {
        "size": o["json"] or o["n"],
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"timestamp": {"gte": "now-%dm" % o["min"]}}},
        "_source": False if (o["json"] or o["raw"]) else
            ["timestamp", "agent.name", "rule.id", "rule.level", "rule.description",
             "data.srcip", "data.dstip", "data.srcport", "data.dstport",
             "data.srcuser", "data.dstuser",
             "data.command", "data.full_log", "full_log", "decoder.name", "location"]
    }
    if o["search"]:
        body["query"] = {"bool": {"must": [
            body["query"],
            {"query_string": {"query": "*" + o["search"] + "*"}}]}}
    req = urllib.request.Request(IDX + "/" + index + "/_search",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Basic " + AUTH})
    import ssl
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return json.load(urllib.request.urlopen(req, context=ctx, timeout=20))

def short(s, n):
    s = str(s).replace("\n", " ")
    return s if len(s) <= n else s[:n-1] + "…"

def line(h):
    ts = h.get("timestamp", "?")[0:19].replace("T", " ")
    agent = h.get("agent", {}).get("name", "?")
    rule = h.get("rule", {})
    rid, lvl = rule.get("id", "?"), rule.get("level", "?")
    d = h.get("data", {})
    ips = " ".join(x for x in [d.get("srcip"), "→" if d.get("srcip") and d.get("dstip") else None, d.get("dstip")] if x)
    users = " ".join(x for x in [d.get("srcuser"), d.get("dstuser")] if x)
    ports = " ".join(x for x in [":" + str(d["srcport"]) if d.get("srcport") else None, ":" + str(d["dstport"]) if d.get("dstport") else None] if x)
    who = " ".join(x for x in [ips, users, ports] if x) or (h.get("location", "") or "")
    raw = d.get("full_log") or h.get("full_log") or ""
    desc = rule.get("description") or (h.get("decoder") or {}).get("name") or raw
    extra = ""
    if d.get("command") and d.get("command") != desc: extra = d.get("command")
    elif raw and raw != desc and not rule.get("description"): extra = ""
    return "%s | %-4s | r%-7s L%-2s | %-22s | %s%s" % (
        ts, agent, rid, lvl, short(who, 22), short(desc, 68), " | " + short(extra, 50) if extra else "")

def main():
    o = parse()
    r = q(o)
    hits = r.get("hits", {}).get("hits", [])
    if not hits:
        print("no events in last %d min (%s)" % (o["min"], "alerts" if o["alerts"] else "archives")); return
    if o["raw"]:
        print(json.dumps(r, indent=2, ensure_ascii=False)); return
    for h in hits:
        src = h.get("_source", {})
        if o["json"]:
            print("=" * 78)
            print(json.dumps(src, indent=2, ensure_ascii=False))
        else:
            print(line(src))
    print("-" * 78)
    print("%d events (last %d min, %s)" % (len(hits), o["min"], "alerts index" if o["alerts"] else "archives"))

main()
