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
            s.update(host=j.get("add"), port=j.get("port"),
                     sni=j.get("sni") or j.get("host", ""),
                     transport=j.get("net", "tcp"), name=j.get("ps") or name)
        elif proto == "ss":
            rawb = body[5:]
            if
