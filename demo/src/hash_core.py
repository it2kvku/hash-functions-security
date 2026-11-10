"""Loi bam: bam van ban, so sanh thuat toan, hieu ung tuyet lo (avalanche).

Ghi chu: chi dung hashlib thu vien chuan. Moi ham tra ket qua de in ra CLI.
"""
from __future__ import annotations

import hashlib

# Bay thuat toan dai dien 4 the he: MD5/SHA-1 (da chet) -> SHA-2 -> SHA-3 -> BLAKE2
ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b")


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    """Bam mot mang byte, tra ve hexdigest."""
    return hashlib.new(algo, data).hexdigest()


def hash_text(text: str, algo: str = "sha256") -> str:
    """Bam chuoi UTF-8."""
    return hash_bytes(text.encode("utf-8"), algo)


def compare(text: str, algorithms: tuple[str, ...] = ALGORITHMS) -> list[dict]:
    """Bam cung mot chuoi voi nhieu thuat toan — cho thay do dai va dinh dang khac nhau."""
    return [{"algo": a, "digest": hash_text(text, a)} for a in algorithms]


def flip_last_bit(text: str) -> str:
    """Lay bien the input chi khac 1 bit o ky tu cuoi (de demo avalanche)."""
    if not text:
        return "x"
    return text[:-1] + chr(ord(text[-1]) ^ 0x01)


def leading_same_hex_chars(a: str, b: str) -> int:
    """Dem so ky tu hex giong nhau tu dau — chi so 'trung ngau nhien' cua 2 digest."""
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def avalanche(text: str) -> dict:
    """Do hieu ung tuyet lo: input khac 1 bit -> digest hoan toan khac."""
    variant = flip_last_bit(text)
    original, variant_digest = hash_text(text), hash_text(variant)
    return {
        "original_input": text,
        "variant_input": variant,
        "original": original,
        "variant": variant_digest,
        "same_prefix_bits": leading_same_hex_chars(original, variant_digest),
    }
