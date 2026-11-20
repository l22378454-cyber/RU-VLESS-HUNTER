from __future__ import annotations
import argparse, json, sys
from pathlib import Path

from . import geo, knife, links, ruproxy, sources, tcpcheck

DATA = Path("data")


def _read_nodes() -> list[links.Node]:
    raw = json.loads((DATA / "nodes.json").read_text())
    return [links.Node(**n) for n in raw]


def _save_nodes(nodes, name="nodes.json"):
    DATA.mkdir(exist_ok=True)
    (DATA / name).write_text(json.dumps([n.__dict__ for n in nodes], ensure_ascii=False, indent=0))


def cmd_collect(a):
    specs = [l.strip() for l in Path(a.sources).read_text().splitlines()
             if l.strip() and not l.strip().startswith("#")]
    nodes, stats = sources.collect(specs, a.workers)
    _save_nodes(nodes)
    print(f"[collect] источников={stats['sources']} ссылок={stats['raw_links']} "
          f"уникальных={len(nodes)} ошибок={len(stats['failed'])}")
    for f in stats["failed"][:5]:
        print("   !", f)


def cmd_geo(a):
    nodes = _read_nodes()
    ip_of = {n.key: geo.resolve(n.host) for n in nodes}
    cmap = geo.country_map(ip_of.values(), DATA / "geo_cache.json")
    kept = [n for n in nodes if cmap.get(ip_of.get(n.key), "??") == "RU"]
    _save_nodes(kept)
    print(f"[geo] было {len(nodes)} → RU-серверов {len(kept)}")


def cmd_pool(a):
    cands = ruproxy.load_candidates(limit=a.pool_size)
    print(f"[pool] кандидатов {len(cands)}, проверяю...")
    good = ruproxy.validate(cands, a.workers)
    DATA.mkdir(exist_ok=True)
    (DATA / "ru_pool.json").write_text(json.dumps([p.url for p in good], indent=0))
    print(f"[pool] живых RU-прокси: {len(good)}")
    if not good:
        sys.exit("нет RU-прокси — стадия TCP невозможна")


def _load_pool(a) -> ruproxy.RuPool:
    urls = json.loads((DATA / "ru_pool.json").read_text())
    ps = []
    for u in urls:
        hp = u.split("://", 1)[1].rsplit("@", 1)
        cred, hostport = (hp[0].split(":", 1), hp[1]) if len(hp) == 2 else (None, hp[0])
        host, port = hostport.rsplit(":", 1)
        ps.append(ruproxy.Proxy(host, int(port),
                                cred[0] if cred else None,
                                cred[1] if cred else None, country="RU"))
    return ruproxy.RuPool(ps, per_proxy=a.per_proxy)


def cmd_tcp(a):
    nodes = _read_nodes()
    pool = _load_pool(a)
    passed, lat = tcpcheck.run(nodes, pool, a.workers, a.attempts, a.timeout)
    Path(a.out).write_text("\n".join(n.link for n in passed) + ("\n" if passed else ""))
    (DATA / "tcp_latency.json").write_text(json.dumps(lat, indent=0))
    print(f"[tcp] {len(nodes)} → {len(passed)} живых  → {a.out}")


def cmd_knife(a):
    res = knife.run(a.infile, a.out, a.knife_threads, not a.no_insecure,
                    not a.no_ru_exit, workdir=".")
    print("[knife]", res)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ruradar", description="RU proxy radar")
    ap.add_argument("-w", "--workers", type=int, default=64)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect"); c.add_argument("--sources", default="sources.txt"); c.set_defaults(fn=cmd_collect)
    sub.add_parser("geo").set_defaults(fn=cmd_geo)
    p = sub.add_parser("pool"); p.add_argument("--pool-size", type=int, default=4000); p.set_defaults(fn=cmd_pool)
    t = sub.add_parser("tcp"); t.add_argument("--out", default="TCP_config.txt")
    t.add_argument("--per-proxy", type=int, default=3)
    t.add_argument("--attempts", type=int, default=3)
    t.add_argument("--timeout", type=float, default=8.0); t.set_defaults(fn=cmd_tcp)
    k = sub.add_parser("knife"); k.add_argument("--infile", default="TCP_config.txt")
    k.add_argument("--out", default="Knife_config.txt")
    k.add_argument("--knife-threads", type=int, default=48)
    k.add_argument("--no-insecure", action="store_true")
    k.add_argument("--no-ru-exit", action="store_true"); k.set_defaults(fn=cmd_knife)

    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
