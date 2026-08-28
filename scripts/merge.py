import base64, json, os, re, socket, time
import urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read()

def b64(t):
    return base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", "ignore")

def to_lines(raw):
    text = raw.decode("utf-8", "ignore").strip()
    if not text:
        return []
    if "://" not in text and re.fullmatch(r"[A-Za-z0-9+/\n=\s]+", text):
        try:
            dec = b64(text)
            if "://" in dec:
                text = dec
        except Exception:
            pass
    return [l.strip() for l in text.splitlines() if l.strip() and "://" in l]

def parse(line, source):
    try:
        m = re.match(r"^(vless|trojan|vmess|ss)://", line)
        if not m:
            return None
        proto = m.group(1)
        name = urllib.parse.unquote(line.split("#", 1)[1]) if "#" in line else ""
        body = line.split("#", 1)[0]
        s = {"proto": proto, "sni": "", "transport": "tcp", "name": name,
             "source": source, "link": line, "alive": False, "ms": None}
        if proto == "vmess":
            j = json.loads(b64(body[8:]))
            s["host"] = j.get("add")
            s["port"] = j.get("port")
            s["sni"] = j.get("sni") or j.get("host", "")
            s["transport"] = j.get("net", "tcp")
            s["name"] = j.get("ps") or name
        elif proto == "ss":
            rawb = body[5:]
            if "@" not in rawb:
                inner = urllib.parse.urlsplit("ss://" + b64(rawb))
                s["host"], s["port"] = inner.hostname, inner.port or 8388
            else:
                u = urllib.parse.urlsplit(body)
                s["host"], s["port"] = u.hostname, u.port or 8388
        else:
            u = urllib.parse.urlsplit(body)
            q = dict(urllib.parse.parse_qsl(u.query))
            s["host"] = u.hostname
            s["port"] = u.port or 443
            s["sni"] = q.get("sni") or q.get("serverName") or q.get("host") or ""
            s["transport"] = q.get("type") or q.get("net") or "tcp"
        if not s.get("host"):
            return None
        s["port"] = int(s["port"])
        return s
    except Exception:
        return None

def check(s):
    try:
        t = time.time()
        socket.create_connection((s["host"], s["port"]), timeout=3).close()
        s["alive"] = True
        s["ms"] = int((time.time() - t) * 1000)
    except Exception:
        s["alive"] = False

sources = json.load(open("sources.json"))["sources"]
seen, servers = set(), []
for src in sources:
    try:
        lines = to_lines(fetch(src["url"]))
        print("fetched", src["name"], len(lines))
    except Exception as e:
        print("SKIP", src["name"], e)
        continue
    for l in lines:
        p = parse(l, src["name"])
        if not p:
            continue
        k = (p["proto"], p["host"], p["port"])
        if k in seen:
            continue
        seen.add(k)
        servers.append(p)
        if len(servers) >= 800:
            break

with ThreadPoolExecutor(40) as ex:
    list(ex.map(check, servers))

os.makedirs("docs", exist_ok=True)
servers.sort(key=lambda x: (not x["alive"], x["ms"] if x["ms"] is not None else 9999))
json.dump({"updated": datetime.now(timezone.utc).isoformat(),
           "count": len(servers), "servers": servers},
          open("docs/servers.json", "w"), ensure_ascii=False, indent=2)

links = [s["link"] for s in servers if s["alive"]]
raw_b64 = base64.b64encode("\n".join(links).encode()).decode()
with open("docs/sub.txt", "w") as f:
    f.write(raw_b64)

alive = sum(1 for s in servers if s["alive"])
print(f"Done! Total: {len(servers)}, Alive: {alive}")
