"""Стадия TCP: коннект к серверу конфига глазами RU-прокси."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from .ruproxy import RuPool


def run(nodes, pool: RuPool, workers: int = 64, attempts: int = 3, timeout: float = 8.0):
    if not pool:
        raise RuntimeError("пул RU-прокси пуст — проверять нечем")

    by_ep: dict[tuple[str, int], list] = {}
    for n in nodes:
        by_ep.setdefault((n.host, n.port), []).append(n)

    def one(ep):
        return ep, pool.probe(ep[0], ep[1], attempts, timeout)

    alive, lat_map = {}, {}
    with ThreadPoolExecutor(workers) as ex:
        for ep, best in ex.map(one, by_ep):
            if best:
                lat_map[ep] = round(best[0], 3)
                alive[ep] = best

    passed = [(lat_map[ep], n) for ep in alive for n in by_ep[ep]]
    passed.sort(key=lambda x: x[0])
    return [n for _, n in passed], {f"{h}:{p}": v for (h, p), v in lat_map.items()}
