"""Стадия E: реальный хендшейк через xray-knife + фильтр по exit-стране."""
from __future__ import annotations
import csv, os, shutil, subprocess
from pathlib import Path

COUNTRY_COLS = {"country", "country_code", "countrycode", "cc", "geo", "location"}
RU_VALUES = {"RU", "RUS", "RUSSIA", "РОССИЯ"}


def _newest_csv(workdir: Path) -> Path | None:
    files = sorted(workdir.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _ru_subset(csv_path: Path, links: list[str]) -> set[str] | None:
    """None = не смогли распознать формат (тогда не фильтруем)."""
    try:
        with csv_path.open(newline="", encoding="utf-8", errors="ignore") as f:
            rows = list(csv.reader(f))
    except Exception:
        return None
    if len(rows) < 2:
        return None
    header = [c.strip().lower().lstrip("# ") for c in rows[0]]
    ci = next((i for i, h in enumerate(header) if h in COUNTRY_COLS), None)
    li = next((i for i, h in enumerate(header)
               if h in ("config", "link", "url", "config_link", "remark")), None)
    if ci is None or li is None:
        return None
    keep = {r[li].strip() for r in rows[1:]
            if len(r) > max(ci, li) and r[ci].strip().upper() in RU_VALUES}
    matched = {l for l in links if l.strip() in keep}
    return matched or None


def run(infile: str, outfile: str, threads: int = 48, insecure: bool = True,
        require_ru_exit: bool = True, workdir: str = ".") -> dict:
    wd = Path(workdir)
    cmd = ["xray-knife", "http", "-f", infile, "-t", str(threads)]
    if insecure:
        cmd.append("--insecure")
    proc = subprocess.run(cmd, cwd=wd, capture_output=True, text=True)
    (wd / "data").mkdir(exist_ok=True)
    (wd / "data" / "knife.log").write_text(proc.stdout + "\n--- stderr ---\n" + proc.stderr)

    valid = wd / "valid.txt"
    if not valid.exists():
        return {"ok": False, "error": "valid.txt не появился", "rc": proc.returncode, "kept": 0}

    links = [l.strip() for l in valid.read_text().splitlines() if l.strip().startswith(tuple(
        ["vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://"]))]

    note = "exit-гео не проверялось"
    if require_ru_exit:
        csv_path = _newest_csv(wd)
        subset = _ru_subset(csv_path, links) if csv_path else None
        if subset is None:
            note = "CSV без страны — оставил всех, кто прошёл хендшейк"
        else:
            links = [l for l in links if l in subset]
            note = f"оставлены только exit=RU ({len(links)})"

    Path(outfile).write_text("\n".join(links) + ("\n" if links else ""))
    return {"ok": True, "kept": len(links), "note": note, "rc": proc.returncode}
