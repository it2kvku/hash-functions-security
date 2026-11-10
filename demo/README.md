# HashGuard — Demo "Applying Hash Functions in Security"

Dự án demo 5 phút cho bài thuyết trình môn **Bảo mật và an toàn hệ thống thông tin**.
Ba trụ cột lý thuyết biến thành ba module chạy được:

| Trụ cột | Module | Vai trong demo |
|---|---|---|
| **Toàn vẹn (Integrity)** | `src/integrity.py` | Baseline SHA-256 thư mục → phát hiện file bị sửa/xóa/thêm |
| **Xác thực (Authentication)** | `src/password_auth.py` | Lưu mật khẩu PBKDF2-HMAC-SHA256 + salt từng người dùng |
| **Xác thực tin nhắn** | `src/hmac_channel.py` | HMAC (RFC 2104) — chặn tin bị sửa và ký sai khóa |
| Minh họa tấn công | `src/attacks.py` | Birthday collision trên hash rút gọn + đo tốc độ băm |

**Yêu cầu:** Python 3.10+. **Không cần cài thư viện nào** — toàn bộ dùng `hashlib`,
`hmac`, `secrets`, `json` của thư viện chuẩn (chọn cách này để demo không phụ thuộc
mạng Wi-Fi hay pip trên máy lớp).

## Cài đặt & chạy

```bash
cd demo
python hashguard.py full-demo          # chạy cả kịch bản 5 phút
```

Mọi lệnh chạy từ thư mục `demo/` (tệp `users.json` và `integrity.manifest.json`
được tạo tại `demo/data/`).

## Lệnh chi tiết

```bash
# === Toàn vẹn ===
python hashguard.py integrity baseline   # ghi baseline SHA-256 cho data/files
python hashguard.py integrity tamper     # GIẢ LẬP kẻ tấn công sửa hop_dong.txt
python hashguard.py integrity verify     # báo cáo MODIFIED/ADDED/DELETED/OK

# === Xác thực mật khẩu ===
python hashguard.py password register sinhvien Mk!Manh2026
python hashguard.py password inspect     # xem JSON: salt + hash, không có mật khẩu
python hashguard.py password login sinhvien Mk!Manh2026
python hashguard.py password weak-demo   # MD5 không salt bị bóc bằng 5 từ

# === HMAC ===
python hashguard.py hmac demo            # 3 kịch bản Alice-Bob (thật/sửa tin/sai khóa)

# === Tấn công ===
python hashguard.py attacks birthday --bits 20   # nghịch lý sinh nhật, kỳ vọng ~1024 lần thử
python hashguard.py attacks speed                # MD5 vs SHA-256: MB/s

# === Khác ===
python hashguard.py hash "abc" --avalanche  # hiệu ứng tuyết lở: đổi 1 bit → hash khác hẳn
```

## Kiểm thử

```bash
python -m unittest discover -s tests -t . -v
```

## Cấu trúc

```
demo/
├── hashguard.py            # CLI tổng — entry point của demo
├── src/
│   ├── hash_core.py        # băm chuỗi, so sánh 6 thuật toán, avalanche
│   ├── integrity.py        # baseline + verify (trụ TOÀN VỆN)
│   ├── password_auth.py    # PBKDF2 + salt + UserStore (trụ XÁC THỰC)
│   ├── hmac_channel.py     # HMAC Alice-Bob, 3 kịch bản (RFC 2104)
│   └── attacks.py          # birthday simulation + speed benchmark
├── tests/                  # unittest cho từng module
├── data/
│   ├── files/              # thư mục được giám sát (bao_cao.txt, hop_dong.txt)
│   ├── users.json          # tạo khi chạy password register
│   └── integrity.manifest.json  # tạo khi chạy integrity baseline
└── README.md
```

## Ghi chú kỹ thuật (cho phần Q&A)

- **PBKDF2 200.000 vòng** là mức *demo chạy nhanh*; OWASP khuyến nghị
  ≥ 600.000 vòng cho hệ thống thật, hoặc ưu tiên Argon2id (`m=19MiB, t=2, p=1`).
- **So sánh hằng thời gian** (`hmac.compare_digest`) ở mọi nơi kiểm tra
  hash/tag — chặn timing attack; tuyệt đối không dùng `==` trên secret.
- **Đọc file theo khối 1 MiB** — hash được file dung lượng lớn mà không
  chiếm bộ nhớ tương đương.
- Output CLI viết **không dấu** chủ ý: chạy được trên mọi codepage Windows
  khi trình chiếu, không lo lỗi font.
- Muốn nâng cấp nâng cao: thêm `bcrypt`/`argon2-cffi` vào `requirements.txt`
  và đổi hàm `hash_password` — phần còn lại của demo không đổi.

## Phục hồi trạng thái demo (nếu lộn kịch bản)

```bash
del data\users.json data\integrity.manifest.json   # PowerShell/cmd
rm data/users.json data/integrity.manifest.json    # bash
git -C .. checkout -- demo/data/files              # khôi phục file mẫu nếu đã bị tamper
```
