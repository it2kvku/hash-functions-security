"""Tru 2 — XAC THUC tin nhan bang HMAC (RFC 2104) + OTP (RFC 4226/6238).

HMAC = H(K xor opad || H(K xor ipad || m)) — hai lop bam voi 2 khoa phai sinh.
Giup Bob vua xac nguoi gui (co khoa moi ky duoc) vua xac noi dung (doi 1 bit
la tag khong con khop). So sanh tag luon dung compare_digest (thoi gian hang).

HOTP/TOTP la ung dung xac thuc kinh dien cua HMAC: ma 6 so tren
Google Authenticator = HMAC cua counter/thoi gian, cat lay 31 bit.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time

# Kich ban demo dung cung mot cau chuyen voi integrity.tamper():
# 12.000.000 VND bi sua thanh 98.000.000 VND giua duong truyen.
MESSAGE = "chuyen khoan 12.000.000 VND vao tai khoan ACB 123456789"
TAMPERED = MESSAGE.replace("12.000.000", "98.000.000")

# Khoa demo cho TOTP — trong he thong that: khoa rieng tung nguoi dung,
# luu trong database ben canh hash mat khau (secret cua authenticator app).
TOTP_DEMO_SECRET = b"HashGuard-demo-secret-2026"


def sign(key: bytes, message: str) -> str:
    """Alice ky tin nhan bang khoa chia se."""
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(key: bytes, message: str, tag: str) -> bool:
    """Bob kiem tra tag — so sanh thoi gian hang."""
    return hmac.compare_digest(sign(key, message), tag)


def exchange_demo() -> list[dict]:
    """Ba kich ban gui tin Alice -> Bob qua kenh co ke nghe trom.

    1. Tin that + tag dung          -> Bob chap nhan (VERIFIED)
    2. Khe trom sua so tien         -> tag khong con khop (FAILED)
    3. Khe trom ky lai bang sai khoa -> Bob tu choi (FAILED)
    """
    key = secrets.token_bytes(32)
    honest_tag = sign(key, MESSAGE)
    impostor_tag = sign(b"wrong-key-attempt", MESSAGE)
    return [
        {"name": "1. Gui tin that, tag dung", "message": MESSAGE,
         "tag": honest_tag, "verified": verify(key, MESSAGE, honest_tag)},
        {"name": "2. Tin bi sua tren duong truyen (12tr -> 98tr)", "message": TAMPERED,
         "tag": honest_tag, "verified": verify(key, TAMPERED, honest_tag)},
        {"name": "3. Ke trom ky lai bang sai khoa", "message": MESSAGE,
         "tag": impostor_tag, "verified": verify(key, MESSAGE, impostor_tag)},
    ]


# ---------------------------------------------------------------------------
# HOTP (RFC 4226) / TOTP (RFC 6238) — ma OTP mot lan dua tren HMAC
# ---------------------------------------------------------------------------

def hotp(secret: bytes, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    """HOTP = truncate(HMAC(secret, counter)) — RFC 4226.

    Cat 31 bit tu digest theo dynamic truncation (offset = 4 bit cuoi),
    chia du cho 10^digits de ra ma so.
    """
    digest = hmac.new(secret, struct.pack(">Q", counter), algo).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret: bytes, time_step: int = 30, digits: int = 6,
         now: float | None = None, algo: str = "sha1") -> str:
    """TOTP = HOTP voi counter la thoi gian chia cho cua so (RFC 6238)."""
    counter = int((time.time() if now is None else now) // time_step)
    return hotp(secret, counter, digits, algo)


def totp_remaining(time_step: int = 30, now: float | None = None) -> int:
    """So giay con lai cua cua so thoi gian hien tai."""
    now = time.time() if now is None else now
    return time_step - int(now) % time_step
