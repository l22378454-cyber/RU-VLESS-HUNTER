"""Сбор ссылок из внешних репозиториев и подписок."""
from __future__ import annotations
import json, os, re, urllib.request
from concurrent.futures import ThreadPoolExecutor
from .links import Node, b64d, parse

UA = "ru-proxy-radar/1.0"
LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s\"'<>\\,]+", re.I)
EXTS = (".txt", ".json", ".yaml", ".yml", ".conf", ".list", ".csv", ".md")
MAX_BYTES = 16 << 20
MAX_FILES = 40


def _req(url):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if tok := os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {tok}"
    return urllib.request.Request(url, headers=h)


def _get(url, timeout=30) -> str:
    with urllib.request.urlopen(_req(url), timeout=timeout) as r:
        return r.read(MAX_BYTES).decode("utf-8", "ignore")


def _gh_files(owner: str, repo: str, prefix: str) -> list[str]:
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    with urllib.request.urlopen(_req(url), timeout=30) as r:
        tree = json.load(r).get("tree", [])
    paths = [t["path"] for t in tree
             if t.get("type") == "blob"
             and t["path"].lower().endswith(EXTS)
             and t["path"].startswith(prefix)]
    return [f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{p}" for p in paths[:MAX_FILES]]


def expand(spec: str) -> list[str]:
    """gh:owner/repo  |  gh:owner/repo:path/prefix  |  https://..."""
    if not spec.startswith("gh:"):
        return [spec]
    body = spec[3:]
    prefix = ""
    if ":" in body:
        body, prefix = body.split(":", 1)
    owner, repo = body.split("/", 1)
    return _gh_files(owner, repo, prefix)


def extract(text: str) -> list[str]:
    found = LINK_RE.findall(text)
    if found:
        return found
    try:                                          # бывает вся подписка в base64
        return LINK_RE.findall(b64d(text.strip()).decode("utf-8", "ignore"))
    except Exception:
        return []


def collect(specs: list[str], workers: int = 8):
    stats = {"sources": 0, "failed": [], "raw_links": 0}
    urls: list[str] = []
    for s in specs:
        try:
            urls += expand(s)
        except Exception as e:
            stats["failed"].append(f"{s}: {e}")

    def one(u):
        try:
            return extract(_get(u))
        except Exception as e:
            stats["failed"].append(f"{u}: {e}")
            return []

    raw: list[str] = []
    with ThreadPoolExecutor(workers) as ex:
        for chunk in ex.map(one, urls):
            raw += chunk
    stats["sources"] = len(urls)
    stats["raw_links"] = len(raw)

    seen, nodes = set(), []
    for link in raw:
        n = parse(link)
        if n and n.key not in seen:
            seen.add(n.key)
            nodes.append(n)
    return nodes, stats
