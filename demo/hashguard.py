#!/usr/bin/env python3
"""HashGuard — demo ba tru cot ung dung ham bam (Xac thuc & Toan ven).

Cac lenh:
    python hashguard.py hash <text> [--avalanche]      # bam 6 thuat toan
    python hashguard.py integrity baseline|verify|tamper
    python hashguard.py password register|login|inspect|weak-demo
    python hashguard.py hmac demo
    python hashguard.py attacks birthday|speed
    python hashguard.py full-demo                      # chay ca kich ban 5 phut

Chi dung thu vien chuan Python — khong can cai gi.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from src import attacks, hash_core, hmac_channel, integrity, password_auth  # noqa: E402

DATA = BASE / "data"
FILES = DATA / "files"
STORE = DATA / "users.json"
MANIFEST = DATA / "integrity.manifest.json"


def banner(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(0, 58 - len(title)))


def cmd_hash(args: argparse.Namespace) -> None:
    rows = hash_core.compare(args.text)
    print(f"text : {args.text!r}")
    for row in rows:
        print(f"{row['algo']:>9}: {row['digest']}")
    if args.avalanche:
        r = hash_core.avalanche(args.text)
        print(f"\n[avalanche] doi 1 bit cuoi: {r['variant_input']!r}")
        print(f"{'sha256 goc':>11}: {r['original']}")
        print(f"{'doi-1-bit':>11}: {r['variant']}")
        print(f"so ky tu hex giong nhau o dau: {r['same_prefix_bits']} (ky vong ~0)")


def cmd_integrity(args: argparse.Namespace) -> None:
    if args.action == "baseline":
        path = integrity.save_baseline(FILES, MANIFEST)
        n = len(json.loads(path.read_text(encoding="utf-8"))["files"])
        print(f"[ok] baseline {n} file (SHA-256) -> {path}")
    elif args.action == "verify":
        report = integrity.verify(FILES, MANIFEST)
        print(integrity.format_report(report))
    elif args.action == "tamper":
        target = FILES / "hop_dong.txt"
        integrity.tamper(target)
        print(f"[x] ke tan cong da sua: {target.name}")


def cmd_password(args: argparse.Namespace) -> None:
    if args.action in ("register", "login") and (not args.username or not args.password):
        sys.exit("can: python hashguard.py password register <ten> <matkhau>")
    store = password_auth.UserStore(STORE)
    if args.action == "register":
        stored = store.register(args.username, args.password)
        print(f"[ok] da luu {args.username}: {stored}")
    elif args.action == "login":
        ok = store.login(args.username, args.password)
        print("[ok] DANG NHAP THANH CONG" if ok else "[x] sai ten hoac mat khau")
    elif args.action == "inspect":
        print(STORE.read_text(encoding="utf-8") if STORE.exists() else "{} (store trong)")
    elif args.action == "weak-demo":
        password_auth.weak_dictionary_demo()


def cmd_hmac(args: argparse.Namespace) -> None:
    for s in hmac_channel.exchange_demo():
        verdict = "VERIFIED" if s["verified"] else "FAILED"
        print(f"\n{s['name']} -> {verdict}")
        print(f"  message : {s['message']}")
        print(f"  tag     : {s['tag'][:40]}...")


def cmd_attacks(args: argparse.Namespace) -> None:
    if args.kind == "birthday":
        r = attacks.truncated_collision(bits=args.bits)
        if r.get("found") is False:
            print(f"[!] khong tim thay trong {r['trials']} lan thu (thu --bits nho hon)")
        else:
            print(f"trung {r['bits']} bit dau sau {r['trials']} lan thu "
                  f"(ky vong ~{r['expected']}) trong {r['seconds']} giay")
            print(f"  input A : {r['a']}")
            print(f"  input B : {r['b']}")
    elif args.kind == "speed":
        for row in attacks.speed_compare():
            print(f"{row['algo']:>9}: {row['mb_per_s']:>9} MB/s")


def cmd_full_demo(args: argparse.Namespace) -> None:
    banner("BUOC 1/5 - TOAN VINH: ghi baseline SHA-256")
    cmd_integrity(argparse.Namespace(action="baseline"))
    banner("BUOC 2/5 - TOAN VINH: ke tan cong sua file, he thong phat hien")
    cmd_integrity(argparse.Namespace(action="tamper"))
    cmd_integrity(argparse.Namespace(action="verify"))
    banner("BUOC 3/5 - XAC THUC: dang ky + dang nhap (PBKDF2 + salt)")
    cmd_password(argparse.Namespace(action="register", username="sinhvien",
                                    password="Mk!Manh2026"))
    cmd_password(argparse.Namespace(action="inspect"))
    cmd_password(argparse.Namespace(action="login", username="sinhvien",
                                    password="Mk!Manh2026"))
    cmd_password(argparse.Namespace(action="login", username="sinhvien",
                                    password="sai roi"))
    banner("BUOC 4/5 - MAT KHAU YEU: MD5 khong salt bi boc bang tu dien")
    cmd_password(argparse.Namespace(action="weak-demo"))
    banner("BUOC 5/5 - HMAC: 3 kich ban Alice-Bob + nghich ly sinh nhat")
    cmd_hmac(argparse.Namespace())
    r = attacks.truncated_collision(bits=20)
    if r.get("found") is not False:
        print(f"\ntrung {r['bits']} bit dau sau {r['trials']} lan thu "
              f"(ky vong ~{r['expected']}) trong {r['seconds']} giay")
    print("\n[het demo] cam on thay va cac ban.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hashguard", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("hash", help="bam mot chuoi voi 6 thuat toan")
    p.add_argument("text")
    p.add_argument("--avalanche", action="store_true",
                   help="hien them digests cua bien the doi 1 bit")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("integrity", help="kiem tra toan ven thu muc data/files")
    p.add_argument("action", choices=["baseline", "verify", "tamper"])
    p.set_defaults(func=cmd_integrity)

    p = sub.add_parser("password", help="luu mat khau PBKDF2 + salt")
    p.add_argument("action", choices=["register", "login", "inspect", "weak-demo"])
    p.add_argument("username", nargs="?")
    p.add_argument("password", nargs="?")
    p.set_defaults(func=cmd_password)

    p = sub.add_parser("hmac", help="ky xac thuc tin nhan Alice-Bob")
    p.add_argument("action", choices=["demo"], nargs="?", default="demo")
    p.set_defaults(func=cmd_hmac)

    p = sub.add_parser("attacks", help="mo phong tan cong")
    p.add_argument("kind", choices=["birthday", "speed"])
    p.add_argument("--bits", type=int, default=20,
                   help="so bit dau de tim va cham (mac dinh 20)")
    p.set_defaults(func=cmd_attacks)

    p = sub.add_parser("full-demo", help="chay ca kich ban 5 phut theo thu tu")
    p.set_defaults(func=cmd_full_demo)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
