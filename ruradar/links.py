"""Разбор share-ссылок в (scheme, host, port) + канонизация для дедупа."""
from __future__ import annotations
import base64, hashlib, json
from dataclasses import dataclass
from urllib.parse import urlsplit

SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"}


@dataclass(frozen=True, slots=True)
class Node:
    scheme: str
    host: str
    port: int
    link: str

    @property
    def endpoint(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{h}:{self.port}"

    @property
    def key(self) -> str:
        return hashlib.sha1(canonical(self.link).encode()).hexdigest()


def b64d(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return b""


def canonical(link: str) -> str:
    base, _, _ = link.strip().partition("#")
    scheme, _, rest = base.partition("://")
    return f"{scheme.lower()}://{rest}"


def _hp(host, port):
    if not host:
        return None
    try:
        p = int(str(port).strip())
    except (TypeError, ValueError):
        return None
    return (host.strip().strip("[]"), p) if 0 < p < 65536 else None


def parse(link: str) -> Node | None:
    link = link.strip()
    if "://" not in link:
        return None
    scheme = link.split("://", 1)[0].lower()
    if scheme not in SCHEMES:
        return None
    hp = None
    try:
        if scheme == "vmess":
            raw = b64d(link[8:].split("#", 1)[0]).decode("utf-8", "ignore")
            j = json.loads(raw)
            hp = _hp(j.get("add"), j.get("port"))
        elif scheme == "ss":
            body = link[5:].split("#", 1)[0].split("?", 1)[0]
            if "@" in body:                       # SIP002
                hp = _hp(*body.rsplit("@", 1)[1].rsplit(":", 1))
            else:                                 # legacy base64
                dec = b64d(body).decode("utf-8", "ignore")
                hp = _hp(*dec.rsplit("@", 1)[-1].rsplit(":", 1))
        else:
            u = urlsplit(link)
            hp = _hp(u.hostname, u.port)
    except Exception:
        return None
    if not hp:
        return None
    return Node(scheme, hp[0], hp[1], link)
