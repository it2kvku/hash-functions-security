"""Tru 2 — XAC THUC tin nhan bang HMAC (RFC 2104).

HMAC = H(K xor opad || H(K xor ipad || m)) — hai lop bam voi 2 khoa phai sinh.
Giup Bob vua xac nguoi gui (co khoa moi ky duoc) vua xac noi dung (doi 1 bit
la tag khong con khop). So sanh tag luon dung compare_digest (thoi gian hang).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

# Kich ban demo dung cung mot cau chuyen voi integrity.tamper():
# 12.000.000 VND bi sua thanh 98.000.000 VND giua duong truyen.
MESSAGE = "chuyen khoan 12.000.000 VND vao tai khoan ACB 123456789"
TAMPERED = MESSAGE.replace("12.000.000", "98.000.000")


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
