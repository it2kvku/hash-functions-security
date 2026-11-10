"""Tru 2 — XAC THUC (Authentication): luu mat khau bang PBKDF2 + salt.

Dinh dang luu tru kieu Django: pbkdf2_sha256$iterations$salt_hex$hash_hex
Khong luu mat khau, khong luu hash tran — moi nguoi dung mot salt rieng.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path

# 200_000 vong cho demo chay nhanh (~0.1s/hash tren laptop thong thuong).
# OWASP khuyen dung PBKDF2-HMAC-SHA256 >= 600_000 vong trong he thong that;
# hoac chuyen sang Argon2id (m=19MiB, t=2, p=1) neu co the cai them thu vien.
ITERATIONS = 200_000


def hash_password(password: str, iterations: int = ITERATIONS,
                  salt: bytes | None = None) -> str:
    """Bam mat khau: PBKDF2-HMAC-SHA256 + salt ngau nhien 16 byte."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Xac minh mat khau — so sanh thoi gian hang (chong do thoi gian)."""
    try:
        _, iterations, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


def insecure_md5(password: str) -> str:
    """Chuoi xau CU de doi chieu trong demo: MD5 khong salt."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def weak_dictionary_demo() -> None:
    """Minh hoa vi sao MD5 khong salt la 'chet': tu dien 5 tu la boc duoc."""
    target = insecure_md5("123456")
    print(f"MD5 khong salt cua '123456': {target}")
    t0 = time.perf_counter()
    for guess in ("123456", "password", "qwerty", "111111", "abc123"):
        if insecure_md5(guess) == target:
            ms = (time.perf_counter() - t0) * 1000
            print(f"[x] boc trong {ms:.1f} ms voi tu dien 5 tu -> mat khau la '{guess}'")
            break


class UserStore:
    """Co so du lieu nguoi dung mini (JSON) cho demo dang ky / dang nhap."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.users: dict[str, str] = {}
        if self.path.exists():
            self.users = json.loads(self.path.read_text(encoding="utf-8"))

    def register(self, username: str, password: str) -> str:
        if not username or not password:
            raise ValueError("ten dang nhap va mat khau phai khac rong")
        if username in self.users:
            raise ValueError(f"ten dang nhap da ton tai: {username}")
        self.users[username] = hash_password(password)
        self._save()
        return self.users[username]

    def login(self, username: str, password: str) -> bool:
        stored = self.users.get(username)
        return bool(stored) and verify_password(password, stored)

    def _save(self) -> None:
        self.path.write_text(json.dumps(self.users, indent=2), encoding="utf-8")
