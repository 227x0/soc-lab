/* wzweb — Splunk-style web viewer for Wazuh archives/alerts.
 * Zero-dependency Node server (same pattern as the salary calculator API).
 * Serves a search page + proxies queries to the Wazuh indexer on localhost:9200.
 * Bind: host-only lab interface. Run: node wzweb-server.js   (port 8081)
 */
"use strict";
const http = require("http");
const https = require("https");

const HOST = process.env.HOST || "192.168.100.22";
const PORT = Number(process.env.PORT || 8081);
const IDX = { host: "127.0.0.1", port: 9200, user: "admin", pass: "SecretPassword" };

const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>wzweb — lab log search</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#c9d1d9;--dim:#8b949e;--acc:#58a6ff;--hi:#f85149;--ok:#3fb950}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
header{padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;gap:8px;flex-wrap:wrap;align-items:center}
h1{font-size:15px;margin:0 12px 0 0;color:var(--acc);white-space:nowrap}
input,select,button{background:#0d1117;border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:7px 10px;font:inherit}
input[type=text]{flex:1;min-width:220px}
input:focus,select:focus{outline:1px solid var(--acc)}
button{background:#1f6feb;border-color:#1f6feb;color:#fff;cursor:pointer;font-weight:600}
button:disabled{opacity:.5}
main{padding:10px 16px}
table{border-collapse:collapse;width:100%;font:12.5px/1.35 ui-monospace,Consolas,monospace}
th{position:sticky;top:0;background:var(--panel);text-align:left;padding:6px 8px;border-bottom:2px solid var(--line);color:var(--dim);font-weight:600}
td{padding:4px 8px;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap;max-width:420px;overflow:hidden;text-overflow:ellipsis}
tr:hover td{background:#161b22}
tr.open td{background:#1c2128}
.ts{color:var(--dim)}.lv{font-weight:700}.l7{color:var(--hi)}.l4,.l5,.l6{color:#d29922}.rule{color:var(--acc)}
#meta{color:var(--dim);padding:8px 16px;font-size:12px}
pre{display:none;margin:4px 0 8px;padding:10px;background:#010409;border:1px solid var(--line);border-radius:6px;font:12px ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all;max-width:none}
tr.open pre{display:block}
.empty{color:var(--dim);padding:30px;text-align:center}
</style></head><body>
<header>
<h1>wzweb</h1>
<input type="text" id="q" placeholder='search: ssh, rule.id:100200, data.srcip:192.168.100.20 ... (empty = everything)' autofocus>
<select id="idx"><option value="wazuh-archives-*">archives (all events)</option><option value="wazuh-alerts-4.x-*">alerts only</option></select>
<select id="range"><option value="15">15 min</option><option value="60" selected>1 h</option><option value="240">4 h</option><option value="1440">24 h</option><option value="10080">7 days</option></select>
<select id="size"><option value="50">50 rows</option><option value="200" selected>200 rows</option><option value="500">500 rows</option></select>
<button id="go">Search</button>
</header>
<div id="meta">ready</div>
<main><table id="t"><thead><tr>
<th>timestamp</th><th>agent</th><th>rule</th><th>lvl</th><th>src → dst</th><th>user</th><th>description</th>
</tr></thead><tbody id="rows"></tbody></table><div class="empty" id="empty">run a search — results stream here</div></main>
<script>
const $=id=>document.getElementById(id);
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function tr(k,o){return o&&o[k]!==undefined?o[k]:""}
async function search(){
  $("go").disabled=true;$("meta").textContent="searching…";
  $("rows").innerHTML="";$("empty").style.display="none";
  try{
    const r=await fetch("/api/search",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({q:$("q").value.trim(),index:$("idx").value,minutes:+$("range").value,size:+$("size").value})});
    const d=await r.json();
    if(!r.ok){$("meta").textContent="error: "+esc(d.error||r.status);return}
    $("meta").textContent=d.total.toLocaleString()+" events found — showing "+d.hits.length+" (newest first)";
    const tb=$("rows");
    if(!d.hits.length){$("empty").textContent="no events in this window";$("empty").style.display="block";return}
    for(const h of d.hits){
      const s=h._source||{},ru=s.rule||{},da=s.data||{},ag=s.agent||{};
      const ips=[tr("srcip",da),tr("dstip",da)].filter(Boolean).join(" → ");
      const us=[tr("srcuser",da),tr("dstuser",da)].filter(Boolean).join(" ");
      const trEl=document.createElement("tr");
      trEl.innerHTML="<td class=ts>"+esc((s.timestamp||"").replace("T"," ").slice(0,19))+"</td>"
        +"<td>"+esc(ag.name||"")+"</td>"
        +"<td class=rule>"+esc(ru.id||"—")+"</td>"
        +"<td class=lv "+(ru.level>=7?"class=l7":"")+">"+esc(ru.level||"—")+"</td>"
        +"<td>"+esc(ips)+"</td><td>"+esc(us)+"</td>"
        +"<td title='"+esc(ru.description||da.full_log||"")+"'>"+esc(ru.description||da.command||(da.full_log||"").slice(0,120))+"</td>";
      const pre=document.createElement("pre");
      pre.textContent=JSON.stringify(s,null,2);
      const td=document.createElement("td");td.colSpan=7;td.appendChild(pre);
      const row2=document.createElement("tr");row2.appendChild(td);row2.style.display="none";
      trEl.addEventListener("click",()=>{trEl.classList.toggle("open");row2.style.display=trEl.classList.contains("open")?"table-row":"none"});
      tb.appendChild(trEl);tb.appendChild(row2);
    }
  }catch(e){$("meta").textContent="error: "+esc(e.message)}
  $("go").disabled=false;
}
$("go").onclick=search;
$("q").addEventListener("keydown",e=>{if(e.key==="Enter")search()});
</script></body></html>`;

function idxSearch(body, cb) {
  const req = https.request({
    host: IDX.host, port: IDX.port, path: "/_search", method: "POST",
    rejectUnauthorized: false,
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Basic " + Buffer.from(IDX.user + ":" + IDX.pass).toString("base64")
    }, timeout: 20000
  }, (res) => {
    let buf = "";
    res.on("data", (c) => buf += c);
    res.on("end", () => {
      try { cb(null, res.statusCode, JSON.parse(buf)); } catch (e) { cb(e); }
    });
  });
  req.on("timeout", () => req.destroy(new Error("indexer timeout")));
  req.on("error", cb);
  req.end(JSON.stringify(body));
}

const server = http.createServer((req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      return res.end(PAGE);
    }
    if (req.method === "POST" && req.url === "/api/search") {
      let body = "";
      req.on("data", (c) => { body += c; if (body.length > 10e3) req.destroy(); });
      req.on("end", () => {
        let p;
        try { p = JSON.parse(body || "{}"); } catch (e) { return send(res, 400, { error: "bad JSON" }); }
        const minutes = Math.min(Math.max(+p.minutes || 60, 1), 60 * 24 * 30);
        const size = Math.min(Math.max(+p.size || 200, 1), 1000);
        const q = {
          size, sort: [{ timestamp: { order: "desc" } }],
          query: { bool: { must: [{ range: { timestamp: { gte: "now-" + minutes + "m" } } }] } }
        };
        if (p.q) q.query.bool.must.push({ query_string: { query: p.q } });
        idxSearch(q, (err, code, data) => {
          if (err) return send(res, 502, { error: "indexer: " + err.message });
          if (code !== 200) return send(res, 502, { error: "indexer answered " + code });
          const hits = (data.hits && data.hits.hits) || [];
          send(res, 200, { total: data.hits.total.value, hits });
        });
      });
      return;
    }
    send(res, 404, { error: "not found" });
  } catch (e) { send(res, 500, { error: "internal" }); }
  function send(r, c, o) { r.writeHead(c, { "Content-Type": "application/json" }); r.end(JSON.stringify(o)); }
});

server.listen(PORT, HOST, () => console.log("wzweb: http://" + HOST + ":" + PORT + "/"));
