"""SOCKS5-клиент без зависимостей + пул проверенных RU-прокси."""
from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import socket
import struct
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_SOURCES = ",".join([
    # только RU-списки
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/RU/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/RU/data.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/proxies/countries/RU/socks5.txt",
    "https://www.proxy-list.download/api/v1/get?type=socks5&country=RU",
    # общие списки: оттуда выживут только те, у кого реальный exit == RU
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
])
PROXY_SOURCES = [s.strip() for s in os.getenv("RU_PROXY_SOURCES", DEFAULT_SOURCES).split(",") if s.strip()]

UA = "ru-proxy-radar/1.0"
GEO_URL = "http://ip-api.com/json/?fields=status,countryCode,query"

IP_PORT = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})(?![\d])")
AUTH_IP_PORT = re.compile(r"([^\s:@/]+):([^\s:@/]+)@((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})")


class SocksError(Exception):
    pass


def _recv(s, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise SocksError("eof")
        buf += chunk
    return buf


def handshake(s, host: str, port: int, auth=None) -> None:
    s.sendall(b"\x05\x02\x00\x02" if auth else b"\x05\x01\x00")
    ver, method = _recv(s, 2)
    if ver != 5:
        raise SocksError("not socks5")
    if method == 2:
        if not auth:
            raise SocksError("auth required")
        u, p = auth
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if _recv(s, 2)[1] != 0:
            raise SocksError("auth rejected")
    elif method != 0:
        raise SocksError(f"method {method}")

    try:
        ip = ipaddress.ip_address(host)
        atyp, addr = (b"\x01", ip.packed) if ip.version == 4 else (b"\x04", ip.packed)
    except ValueError:
        hb = host.encode()
        atyp, addr = b"\x03", bytes([len(hb)]) + hb

    s.sendall(b"\x05\x01\x00" + atyp + addr + struct.pack(">H", port))
    _, rep, _, at = _recv(s, 4)
    if rep != 0:
        raise SocksError(f"rep={rep}")
    if at == 1:
        _recv(s, 6)
    elif at == 4:
        _recv(s, 18)
    elif at == 3:
        _recv(s, _recv(s, 1)[0] + 2)


@dataclass
class Proxy:
    host: str
    port: int
    user: str | None = None
    pw: str | None = None
    country: str | None = None
    latency: float = 99.0
    ok: int = 0
    fails: int = 0
    cooldown: float = 0.0
    inflight: int = 0

    @property
    def auth(self):
        return (self.user.encode(), (self.pw or "").encode()) if self.user else None

    @property
    def url(self) -> str:
        cred = f"{self.user}:{self.pw}@" if self.user else ""
        return f"socks5://{cred}{self.host}:{self.port}"


def open_tunnel(p: Proxy, host: str, port: int, timeout: float = 8.0):
    t0 = time.monotonic()
    s = socket.create_connection((p.host, p.port), timeout)
    s.settimeout(timeout)
    try:
        handshake(s, host, port, p.auth)
    except Exception:
        s.close()
        raise
    return s, time.monotonic() - t0


def http_get_via(p: Proxy, url: str, timeout: float = 10.0) -> str:
    u = urlsplit(url)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    s, _ = open_tunnel(p, u.hostname, u.port or 80, timeout)
    try:
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {u.hostname}\r\n"
            f"User-Agent: {UA}\r\nConnection: close\r\n\r\n".encode()
        )
        data = b""
        while len(data) < 65536:
            try:
                chunk = s.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", "ignore")
    finally:
        s.close()


def _from_json(text: str) -> list[tuple[str, int]]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    items = data.get("data") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        ip = it.get("ip") or it.get("host")
        port = it.get("port")
        if ip and port:
            try:
                out.append((str(ip).strip(), int(port)))
            except (TypeError, ValueError):
                pass
    return out


def _parse(text: str) -> list[tuple[str, int, str | None, str | None]]:
    """ip:port | user:pass@ip:port | JSON со списком."""
    found: list[tuple[str, int, str | None, str | None]] = []
    for user, pw, host, port in AUTH_IP_PORT.findall(text):
        found.append((host, int(port), user, pw))
    for host, port in IP_PORT.findall(text):
        found.append((host, int(port), None, None))
    for host, port in _from_json(text):
        found.append((host, port, None, None))
    return [f for f in found if 0 < f[1] < 65536]


def load_candidates(sources=None, limit: int = 4000) -> list[Proxy]:
    sources = sources or PROXY_SOURCES
    out, seen = [], set()
    for url in sources:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=30) as r:
                text = r.read(8 << 20).decode("utf-8", "ignore")
        except Exception as e:
            print(f"[pool] источник недоступен: {url} ({e})")
            continue
        got = 0
        for host, port, user, pw in _parse(text):
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            out.append(Proxy(host, port, user, pw))
            got += 1
        print(f"[pool] {got:5d} из {url}")
        if len(out) >= limit:
            break
    return out[:limit]


def validate(proxies: list[Proxy], workers: int = 64, timeout: float = 8.0) -> list[Proxy]:
    """Оставляем только те, у кого реальный exit-country == RU."""
    def one(p: Proxy) -> Proxy | None:
        try:
            body = http_get_via(p, GEO_URL, timeout)
            j = json.loads(body[body.find("{"):body.rfind("}") + 1])
            if j.get("status") == "success":
                p.country = j.get("countryCode") or "??"
                if p.country == "RU":
                    p.latency = 1.0
                    return p
        except Exception:
            pass
        return None

    good = []
    with ThreadPoolExecutor(workers) as ex:
        for i, p in enumerate(ex.map(one, proxies), 1):
            if p:
                good.append(p)
            if i % 500 == 0:
                print(f"[pool] проверено {i}/{len(proxies)}, RU: {len(good)}")
    return good


class RuPool:
    def __init__(self, proxies, per_proxy: int = 3, cooldown: float = 60.0):
        self._lock = threading.Lock()
        self.proxies = list(proxies)
        self.per_proxy = per_proxy
        self.cooldown = cooldown

    def __len__(self) -> int:
        return len(self.proxies)

    def _acquire(self) -> Proxy | None:
        now = time.monotonic()
        with self._lock:
            live = [p for p in self.proxies if p.cooldown < now and p.inflight < self.per_proxy]
            if not live:
                return None
            p = min(live, key=lambda x: (x.inflight, random.random()))
            p.inflight += 1
            return p

    def _release(self, p: Proxy, ok: bool) -> None:
        with self._lock:
            p.inflight -= 1
            if ok:
                p.ok += 1
                p.fails = 0
            else:
                p.fails += 1
                if p.fails >= 3:
                    p.cooldown = time.monotonic() + self.cooldown * min(p.fails, 6)

    def probe(self, host: str, port: int, attempts: int = 3, timeout: float = 8.0):
        for _ in range(attempts):
            p = self._acquire()
            if p is None:
                time.sleep(0.15)
                continue
            ok = False
            try:
                s, lat = open_tunnel(p, host, port, timeout)
                s.close()
                ok = True
                return lat, p
            except Exception:
                pass
            finally:
                self._release(p, ok)
        return None
