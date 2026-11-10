# BmhtAttt — Applying Hash Functions in Security

Gói bài tập môn **Bảo mật và an toàn hệ thống thông tin**: chủ đề *Applying Hash
Functions in Security* (Xác thực — Authentication & Toàn vẹn — Integrity).

## Nội dung gói

| Đường dẫn | Nội dung |
|---|---|
| [PLAN.md](PLAN.md) | Kế hoạch trình bày: phân công 4 thành viên, kịch bản 12 slide / 10 phút, kịch bản demo 5 phút, checklist, dự phòng, Q&A |
| [docs/LY_THUYET.md](docs/LY_THUYET.md) | Phần lý thuyết đầy đủ: nền tảng, thuật toán + tấn công, ứng dụng Xác thực, ứng dụng Toàn vẹn, best practices, case study, tài liệu tham khảo |
| [demo/](demo/) | Dự án **HashGuard** — CLI demo 5 phút (Python 3.10+, chỉ thư viện chuẩn, không cần cài gì) |

## Chạy demo trong 30 giây

```bash
cd demo
python hashguard.py full-demo     # toàn bộ kịch bản 5 phút
python -m unittest discover -s tests -t .   # 19 bài test
```

## Cấu trúc thư mục

```
BmhtAttt/
├── PLAN.md                 # kế hoạch 10p slide + 5p demo
├── README.md               # file này
├── docs/
│   └── LY_THUYET.md        # lý thuyết đầy đủ (bản gốc để rút vào slide)
└── demo/
    ├── hashguard.py        # CLI entry point
    ├── src/                # hash_core / integrity / password_auth / hmac_channel / attacks
    ├── tests/              # 19 unittest
    ├── data/files/         # file mẫu cho demo toàn vẹn (bao_cao.txt, hop_dong.txt)
    └── README.md           # hướng dẫn chạy chi tiết + ghi chú kỹ thuật
```
