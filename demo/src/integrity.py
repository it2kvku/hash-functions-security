"""Tru 1 — TOAN VEN (Integrity): baseline SHA-256 + phat hien thay doi.

Nguyen ly giong AIDE/Tripwire: chup "van tay" thu muc mot lan (baseline),
lan sau so sanh hash tung file de phat hien MODIFIED / ADDED / DELETED.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

CHUNK = 1 << 20  # doc file theo khoi 1 MiB — ho tro file lon ma khong do bo nho


def file_hash(path: Path, algo: str = "sha256") -> str:
    """Bam toan bo noi dung file theo khoi."""
    h = hashlib.new(algo)
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def scan_directory(root: Path, algo: str = "sha256") -> dict[str, str]:
    """Quet thu muc, tra ve {ten_file_tuong_doi: hash}."""
    root = Path(root)
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.name.endswith(".manifest.json"):
            manifest[path.relative_to(root).as_posix()] = file_hash(path, algo)
    return manifest


def save_baseline(root: Path, out: Path | None = None) -> Path:
    """Ghi baseline vao file JSON."""
    out = Path(out) if out else Path(root) / "integrity.manifest.json"
    payload = {"algo": "sha256", "files": scan_directory(root)}
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


def verify(root: Path, manifest_path: Path) -> dict[str, list[str]]:
    """So sanh trang thai hien tai voi baseline."""
    data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    algo = data.get("algo", "sha256")
    baseline: dict[str, str] = data["files"]
    current = scan_directory(Path(root), algo)
    report: dict[str, list[str]] = {"modified": [], "deleted": [], "added": [], "ok": []}
    for name, digest in baseline.items():
        if name not in current:
            report["deleted"].append(name)
        elif current[name] != digest:
            report["modified"].append(name)
        else:
            report["ok"].append(name)
    report["added"] = sorted(set(current) - set(baseline))
    return report


def tamper(file_path: Path) -> str:
    """Gia lap hanh vi ke tan cong: noi them dong sua doi vao file."""
    file_path = Path(file_path)
    with file_path.open("a", encoding="utf-8") as f:
        f.write("\n[PHU LUC SUA DOI] Gia tri hop dong: 12.000.000 VND -> 98.000.000 VND\n")
    return str(file_path)


def format_report(report: dict[str, list[str]]) -> str:
    """Chuyen bao cao verify thanh text de in ra console."""
    lines: list[str] = []
    for status, icon in (("modified", "[!]"), ("deleted", "[-]"),
                         ("added", "[+]"), ("ok", "[ok]")):
        items = report.get(status, [])
        if items:
            lines.append(f"{icon} {status.upper()} ({len(items)}):")
            lines.extend(f"    {name}" for name in items)
    if not lines:
        lines.append("[ok] moi file khop baseline")
    return "\n".join(lines)
