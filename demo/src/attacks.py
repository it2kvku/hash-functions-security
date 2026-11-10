"""Mo phong tan cong: nghich ly sinh nhat (birthday) + do toc do bam.

Birthday: tim 2 input co n bit dau trung nhau. Do kho ky vong ~2^(n/2) lan thu
— cung quy luat voi va cham that, chi khac do phong. n=20 -> ~1024 lan thu,
chay tuc thi; n=256 (SHA-256) -> ~2^128 — khong bao gio trong vat ly.
"""
from __future__ import annotations

import hashlib
import secrets
import time


def truncated_collision(bits: int = 20, algo: str = "sha256",
                        max_trials: int = 2_000_000) -> dict:
    """Tim hai input co `bits` bit dau trung nhau trong digest.

    Tra ve dict co 'found': True/False de CLI kiem tra.
    """
    nbytes = (bits + 7) // 8
    shift = 8 * nbytes - bits
    seen: dict[int, bytes] = {}
    start = time.perf_counter()
    for trial in range(1, max_trials + 1):
        data = secrets.token_bytes(8)
        digest = hashlib.new(algo, data).digest()
        prefix = int.from_bytes(digest[:nbytes], "big") >> shift
        if prefix in seen:
            return {
                "bits": bits,
                "trials": trial,
                "expected": 2 ** (bits // 2),
                "seconds": round(time.perf_counter() - start, 3),
                "a": seen[prefix].hex(),
                "b": data.hex(),
                "found": True,
            }
        seen[prefix] = data
    return {"bits": bits, "trials": max_trials, "found": False}


def speed_compare(size_mb: int = 16) -> list[dict]:
    """Do toc do bam MB/s cua cac thuat toan — hash nhanh cung nghia la
    ke tan cong do tu dien nhanh (ly do can KDF cham cho mat khau)."""
    data = b"A" * (1 << 20) * size_mb
    rows: list[dict] = []
    for algo in ("md5", "sha1", "sha256", "sha3_256"):
        t0 = time.perf_counter()
        hashlib.new(algo, data).digest()
        dt = time.perf_counter() - t0
        rows.append({"algo": algo, "seconds": round(dt, 4),
                     "mb_per_s": round(size_mb / dt, 1) if dt > 0 else float("inf")})
    return rows
