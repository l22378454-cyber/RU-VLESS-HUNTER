"""SOCKS5-клиент без зависимостей + пул проверенных RU-прокси."""
from __future__ import annotations
import ipaddress, json, random, re, socket, struct, threading, time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlsplit

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
]
IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})(?![\d])")


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
            f"User-Agent: ru-proxy-radar\r\nConnection: close\r\n\r\n".encode()
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


def load_candidates(sources=PROXY_SOURCES, limit: int = 4000) -> list[Proxy]:
    import urllib.request
    out, seen = [], set()
    for url in sources:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ru-proxy-radar/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                text = r.read(8 << 20).decode("utf-8", "ignore")
        except Exception:
            continue
        for host, port in IP_RE.findall(text):
            key = (host, int(port))
            if key not in seen and 0 < int(port) < 65536:
                seen.add(key)
                out.append(Proxy(host, int(port)))
        if len(out) >= limit:
            break
    return out[:limit]


def validate(proxies: list[Proxy], workers: int = 64, timeout: float = 8.0) -> list[Proxy]:
    """Оставляем только те, у кого реальный exit-country == RU."""
    def one(p: Proxy) -> Proxy | None:
        try:
            body = http_get_via(p, "http://ip-api.com/json/?fields=status,countryCode,query", timeout)
            j = json.loads(body[body.find("{"):body.rfind("}") + 1])
            if j.get("status") == "success":
                p.country = j.get("countryCode") or "??"
                if p.country == "RU":
                    p.latency = 1.0
                    return p
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(workers) as ex:
        return [p for p in ex.map(one, proxies) if p]


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
