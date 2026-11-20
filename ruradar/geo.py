"""Страна IP: батчи ip-api.com + дисковый кеш (лимит free-тарифа 15 батчей/мин)."""
from __future__ import annotations
import json, socket, time, urllib.request
from pathlib import Path

FIELDS = "status,countryCode,query"


def resolve(host: str) -> str | None:
    try:
        return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]
    except OSError:
        return None


def country_map(ips, cache_path=None) -> dict[str, str]:
    cache: dict[str, str] = {}
    p = Path(cache_path) if cache_path else None
    if p and p.exists():
        try:
            cache = json.loads(p.read_text())
        except Exception:
            cache = {}

    todo = [ip for ip in dict.fromkeys(ips) if ip and ip not in cache]
    for i in range(0, len(todo), 100):
        chunk = todo[i:i + 100]
        req = urllib.request.Request(
            f"http://ip-api.com/batch?fields={FIELDS}",
            data=json.dumps(chunk).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "ru-proxy-radar/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                for item in json.load(r):
                    q = item.get("query")
                    if not q:
                        continue
                    cache[q] = item.get("countryCode") if item.get("status") == "success" else "??"
        except Exception:
            pass
        time.sleep(4.2)          # не упираться в rate-limit

    if p:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(cache, indent=0))
    return cache
