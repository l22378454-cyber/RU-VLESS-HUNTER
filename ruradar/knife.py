"""Стадия E: реальный хендшейк через xray-knife (v11, CSV-режим)."""
from __future__ import annotations

import csv
import subprocess
from pathlib import Path

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://",
           "hysteria2://", "hy2://", "tuic://", "wireguard://")
PASSED = {"passed", "semi-passed"}
RU_TOKENS = {"RU", "RUS", "RUSSIA", "РОССИЯ", "РОССИЙСКАЯ ФЕДЕРАЦИЯ"}


def _country(value: str) -> str:
    v = (value or "").strip().upper()
    if not v or v == "NULL":
        return ""
    if v in RU_TOKENS or "RUSSIA" in v or "РОССИ" in v:
        return "RU"
    return v


def _rows(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))


def run(infile: str, outfile: str, threads: int = 48, insecure: bool = True,
        require_ru_exit: bool = True, test_url: str = "https://cloudflare.com/cdn-cgi/trace",
        retries: int = 2, workdir: str = ".", keep_on_empty: bool = True,
        binary: str = "xray-knife") -> dict:
    wd = Path(workdir)
    (wd / "data").mkdir(exist_ok=True)
    csv_path = (wd / "data" / "knife.csv").resolve()

    cmd = [binary, "http",
           "-f", str(Path(infile).resolve()),
           "-o", str(csv_path),
           "-x", "csv",
           "-t", str(threads),
           "--rip",
           "-u", test_url,
           "--retries", str(retries)]
    if insecure:
        cmd.append("-e")

    proc = subprocess.run(cmd, cwd=wd, capture_output=True, text=True)
    (wd / "data" / "knife.log").write_text(
        (proc.stdout or "") + "\n--- stderr ---\n" + (proc.stderr or ""), encoding="utf-8")

    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return {"ok": False, "error": "xray-knife не создал CSV", "rc": proc.returncode, "kept": 0}

    rows = _rows(csv_path)
    good: list[tuple[float, str]] = []
    passed = dropped = no_geo = 0

    for row in rows:
        if (row.get("status") or "").strip().lower() not in PASSED:
            continue
        link = (row.get("link") or "").strip()
        if not link.startswith(SCHEMES):
            continue
        passed += 1
        if require_ru_exit:
            loc = _country(row.get("location", ""))
            if not loc:
                no_geo += 1                       # гео не пришло — не наказываем
            elif loc != "RU":
                dropped += 1
                continue
        try:
            delay = float(row.get("delay") or 1e9)
        except ValueError:
            delay = 1e9
        good.append((delay, link))

    good.sort(key=lambda x: x[0])
    links = [l for _, l in good]
    out = Path(outfile)

    if not links and keep_on_empty and out.exists() and "://" in out.read_text(errors="ignore"):
        return {"ok": True, "kept": 0, "note": "0 результатов — оставил прошлый файл",
                "passed": passed, "dropped_country": dropped, "no_geo": no_geo,
                "rc": proc.returncode}

    out.write_text("\n".join(links) + ("\n" if links else ""), encoding="utf-8")
    return {"ok": True, "kept": len(links), "passed": passed,
            "dropped_country": dropped, "no_geo": no_geo,
            "note": f"exit=RU отфильтровано {dropped}, без гео {no_geo}", "rc": proc.returncode}
