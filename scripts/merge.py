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

# Сохраняем сырую base64 подписку для импорта в клиенты
links = [s["link"] for s in servers if s["alive"]]
raw_b64 = base64.b64encode("\n".join(links).encode()).decode()
with open("docs/sub.txt", "w") as f:
    f.write(raw_b64)

alive = sum(1 for s in servers if s["alive"])
print(f"Done! Total: {len(servers)}, Alive: {alive}")
