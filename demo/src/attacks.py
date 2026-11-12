"""Mo phong tan cong: birthday, length-extension, do toc do bam.

- Birthday: tim 2 input co n bit dau trung nhau. Do kho ky vong ~2^(n/2) lan thu
  — cung quy luat voi va cham that, chi khac do phong. n=20 -> ~1024 lan thu.
- Length-extension (§2.2 ly thuyet): hash Merkle–Damgard de lo trang thai noi bo
  — biet tag = md5(key || msg) va do dai key||msg, ke tan cong nhom them du lieu
  va tinh lai tag HOP LE ma khong can biet key. Day la ly do phai dung HMAC.
  De lam dieu nay can mot loi MD5 thuần Python (de dieu khien trang thai).
"""
from __future__ import annotations

import hashlib
import math
import secrets
import struct
import time

# ---------------------------------------------------------------------------
# Loi MD5 thuần Python — chi dung cho length-extension demo
# ---------------------------------------------------------------------------

_MD5_K = [int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64)]
_MD5_S = ([7, 12, 17, 22] * 4) + ([5, 9, 14, 20] * 4) + ([4, 11, 16, 23] * 4) \
    + ([6, 10, 15, 21] * 4)
_MD5_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)


def _left_rotate(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _md5_block(state: tuple[int, int, int, int], block: bytes) -> tuple:
    """Xu ly mot khoi 64 byte — 64 vong chuan cua MD5 (RFC 1321)."""
    a0, b0, c0, d0 = state
    M = struct.unpack("<16I", block)
    A, B, C, D = a0, b0, c0, d0
    for i in range(64):
        if i < 16:
            F = (B & C) | (~B & D)
            g = i
        elif i < 32:
            F = (D & B) | (~D & C)
            g = (5 * i + 1) % 16
        elif i < 48:
            F = B ^ C ^ D
            g = (3 * i + 5) % 16
        else:
            F = C ^ (B | (~D & 0xFFFFFFFF))
            g = (7 * i) % 16
        F = (F + A + _MD5_K[i] + M[g]) & 0xFFFFFFFF
        A, D, C = D, C, B
        B = (B + _left_rotate(F, _MD5_S[i])) & 0xFFFFFFFF
    return ((a0 + A) & 0xFFFFFFFF, (b0 + B) & 0xFFFFFFFF,
            (c0 + C) & 0xFFFFFFFF, (d0 + D) & 0xFFFFFFFF)


def md5_length_extend(orig_digest_hex: str, orig_msg_len: int,
                      suffix: bytes) -> tuple[str, bytes]:
    """Forge tag cho key||msg||glue||suffix tu tag cu va do dai — khong can key.

    orig_digest_hex : tag cua key||msg (chinh la trang thai noi bo cuoi cung)
    orig_msg_len    : do dai byte cua key||msg
    suffix          : du lieu ke tan cong muon noi them
    Tra ve (tag_gia, glue + suffix) — message moi de gui la msg + glue + suffix.
    """
    state = struct.unpack("<4I", bytes.fromhex(orig_digest_hex))
    glue = (b"\x80" + b"\x00" * ((55 - orig_msg_len) % 64)
            + struct.pack("<Q", orig_msg_len * 8))
    # Trang thai da luu DA HAP THU ca glue padding cua key||msg (digest = trang
    # thai sau padding). Tu day chi can bam tiep suffix + padding cuoi cho tong
    # do dai moi — glue chi xuat hien trong message gia de server bam lai khop.
    total = orig_msg_len + len(glue) + len(suffix)
    tail = (b"\x80" + b"\x00" * ((55 - total) % 64)
            + struct.pack("<Q", total * 8))
    data = suffix + tail
    for i in range(0, len(data), 64):
        state = _md5_block(state, data[i:i + 64])
    return struct.pack("<4I", *state).hex(), glue + suffix


def length_extension_demo() -> dict:
    """Kich ban: server ky tham so bang md5(key||message) — CACH SAI.

    Ke trom khong biet key, chi thay message va tag. Noi them vao tin
    chuyen khoan de bien admin=false thanh admin=true — server van chap nhan.
    """
    key = secrets.token_bytes(16)
    message = b"chuyen khoan 12.000.000 VND; admin=false"
    suffix = b"; admin=true; them 98.000.000 VND"
    naive_tag = hashlib.md5(key + message).hexdigest()
    forged_tag, appended = md5_length_extend(naive_tag, len(key) + len(message), suffix)
    server_expected = hashlib.md5(key + message + appended).hexdigest()
    return {
        "message": message.decode("ascii"),
        "suffix": suffix.decode("ascii"),
        "naive_tag": naive_tag,
        "forged_message_display": repr(message + appended),
        "forged_tag": forged_tag,
        "server_expected": server_expected,
        "forge_valid": forged_tag == server_expected,
    }


# ---------------------------------------------------------------------------
# Birthday + benchmark
# ---------------------------------------------------------------------------

def truncated_collision(bits: int = 20, algo: str = "sha256",
                        max_trials: int = 2_000_000) -> dict:
    """Tim hai input co `bits` bit dau trung nhau trong digest."""
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
    """Do toc do bam MB/s — hash nhanh cung nghia la ke tan cong do tu dien nhanh."""
    data = b"A" * (1 << 20) * size_mb
    rows: list[dict] = []
    for algo in ("md5", "sha1", "sha256", "sha3_256"):
        t0 = time.perf_counter()
        hashlib.new(algo, data).digest()
        dt = time.perf_counter() - t0
        rows.append({"algo": algo, "seconds": round(dt, 4),
                     "mb_per_s": round(size_mb / dt, 1) if dt > 0 else float("inf")})
    return rows
