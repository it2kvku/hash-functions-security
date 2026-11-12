# PLAN — Nhóm bài tập: "Applying Hash Functions in Security"

**Môn học:** Bảo mật và an toàn hệ thống thông tin
**Chủ đề:** Ứng dụng hàm băm trong bảo mật — Xác thực (Authentication) và Toàn vẹn (Integrity)
**Hình thức:** 10 phút trình bày slide (4 thành viên) + 5 phút demo dự án
**Tổng thời lượng:** 15 phút

**Tài liệu đính kèm:**
- Lý thuyết đầy đủ: [docs/LY_THUYET.md](docs/LY_THUYET.md)
- Dự án demo: [demo/](demo/) — HashGuard (Python, chỉ dùng thư viện chuẩn, không cần cài gì)
- Kịch bản demo chi tiết: [demo/README.md](demo/README.md)

---

## 1. Mục tiêu buổi trình bày

1. Giải thích được hàm băm là gì và vì sao nó là "viên gạch nền" của bảo mật.
2. Nêu được 2 trụ cột ứng dụng gắn với đề bài: **Xác thực** (đúng người) và **Toàn vẹn** (đúng nội dung).
3. Chỉ ra được thuật toán nào đã chết (MD5, SHA-1), thuật toán nào dùng được (SHA-2, SHA-3, BLAKE2).
4. Demo chạy live: phát hiện file bị sửa, bóc mật khẩu MD5 yếu, HMAC chặn tin bị giả mạo.

---

## 2. Phân công 4 thành viên + timeline 10 phút

| Thành viên | Vai | Slide | Thời gian | Nội dung chính |
|---|---|---|---|---|
| **TV1** | Mở bài + nền tảng | 1–3 | 3'00" | Định nghĩa, 6 tính chất, sơ đồ Merkle–Damgård |
| **TV2** | Thuật toán + tấn công | 4–5 | 2'30" | Bảng MD5/SHA-1/SHA-2/SHA-3, birthday, collision, length-extension |
| **TV3** | Ứng dụng — XÁC THỰC | 6–8 | 2'30" | Lưu mật khẩu (salt + KDF), HMAC, chữ ký số, OTP |
| **TV4** | Ứng dụng — TOÀN VẸN + dẫn demo | 9–12 | 2'00" | Kiểm tra toàn vẹn file, Merkle tree, case study, chuyển demo |

**Tổng: 600 giây = đúng 10 phút.** Bấm giờ riêng từng người, ai quá giờ thì người sau lấn tới.

### Việc ngoài sân khấu (off-stage)

| Thành viên | Trách nhiệm xây dựng |
|---|---|
| TV1 | Tổng hợp lý thuyết (docs/LY_THUYET.md mục 1–3), slide 1–3, thiết kế template slide chung |
| TV2 | Slide 4–5, tìm hình minh họa SHAttered/Flame, demo phần attacks (birthday + speed) |
| TV3 | Slide 6–8, code `password_auth.py` + `hmac_channel.py`, soạn Q&A |
| TV4 | Slide 9–12, code `integrity.py` + kịch bản demo, quản lý repo + video backup |

---

## 3. Kịch bản slide chi tiết (12 slides)

> Quy ước: mỗi slide ≤ 6 dòng bullet, ưu tiên sơ đồ/bảng, không nhồi đoạn văn.
> Nhãn [TVx] = người nói. Số giây ghi trong ngoặc.

### Slide 1 — Trang bìa (30s) [TV1]
- Tên chủ đề + tên môn + danh sách 4 thành viên.
- Câu mở: *"Bảo mật có 3 câu hỏi: đúng người? đúng nội dung? đúng thời điểm? Hôm nay trả lời 2 câu đầu bằng một công cụ duy nhất: hàm băm."*
- Hình gợi ý: sơ đồ CIA triad, tô đậm 2 chữ A và I.

### Slide 2 — Hàm băm là gì? 6 tính chất bắt buộc (90s) [TV1]
- Định nghĩa 1 dòng: h(x) → chuỗi bit cố định chiều dài, chiều ngược không khả thi.
- 6 tính chất: (1) tất định, (2) đầu ra cố định, (3) nhanh, (4) kháng tiền ảnh (preimage), (5) kháng tiền ảnh thứ hai, (6) kháng va chạm (collision).
- Hiệu ứng tuyết lở (avalanche): đổi 1 bit → ~50% bit đầu ra lật. Có thể chạy live `python hashguard.py hash "abc" --avalanche`.
- Con số mấu chốt: kháng va chạm chỉ mạnh ~n/2 bit (nghịch lý sinh nhật), kháng tiền ảnh ~n bit.

### Slide 3 — Vận hành bên trong (60s) [TV1]
- Sơ đồ Merkle–Damgård: chia khối → nén tuần hoàn → IV → đầu ra; padded length.
- Hệ quả: đầu ra đủ dài là "vân tay" của dữ liệu — cùng input luôn ra cùng output, khác 1 bit ra hoàn toàn khác.
- Điểm sang slide sau: *"cấu trúc đó quyết định cả điểm mạnh lẫn điểm yếu."*

### Slide 4 — Các họ thuật toán: ai sống, ai chết (80s) [TV2]
Bảng (đưa nguyên vào slide):

| Thuật toán | Bit | Năm | Cấu trúc | Trạng thái |
|---|---|---|---|---|
| MD5 | 128 | 1991 | Merkle–Damgård | CHẾT — va chạm từ 2004, chọn tiền tố giờ laptop |
| SHA-1 | 160 | 1995 | Merkle–Damgård | CHẾT — SHAttered 2017, ~2^63.1 |
| SHA-2 (256/512) | 224–512 | 2001 | Merkle–Damgård | DÙNG ĐƯỢC — chuẩn hiện hành |
| SHA-3 (Keccak) | 224–512 | 2015 | Sponge | DÙNG ĐƯỢC — cấu trúc khác, dự phòng nếu SHA-2 gãy |
| BLAKE2/3 | đến 512 | 2012/2020 | HAIFA/sponge | Nhanh hơn MD5, an toàn |

- Nhấn: "chết" nghĩa là gì — tìm cặp file khác nhau cùng hash được thực tế.

### Slide 5 — Tấn công hàm băm: 3 mũi dao chính (70s) [TV2]
- **Birthday/collision:** độ khó 2^(n/2); minh họa live `python hashguard.py attacks birthday --bits 20` → trùng 20 bit sau ~1.024 lần thử.
- **Length-extension:** Merkle–Damgård cho phép nối thêm dữ liệu vào hash có biết secret-prefix → lý do phải dùng HMAC thay vì tự chế hash(key||msg).
- **Brute force GPU:** hash nhanh = kẻ tấn công nhanh; dẫn sang ứng dụng mật khẩu.
- Case 10 giây: Flame (2012) giả chữ ký Microsoft bằng va chạm MD5.

### Slide 6 — Hai trụ cột ứng dụng (30s) [TV3]
- Sơ đồ 2 nhánh từ chữ "HASH":
  - **XÁC THỰC (Authentication):** mật khẩu, HMAC, chữ ký số, OTP.
  - **TOÀN VẸN (Integrity):** checksum file, kiểm chứng bản tải, Merkle tree, Git.
- Nhấn: một primitive, hàng loạt cơ chế trong đời thực — từ đăng nhập Facebook đến apt-get.

### Slide 7 — XÁC THỰC ①: lưu mật khẩu (70s) [TV3]
- Không bao giờ lưu plaintext, cũng không lưu "mật khẩu đã mã hóa" — chỉ lưu hash của (salt + mật khẩu).
- Salt ngẫu nhiên từng người dùng → hạ gục rainbow table; KDF chậm có chủ đích (PBKDF2/bcrypt/scrypt/Argon2id) → hạ gục brute-force GPU.
- Con số OWASP: PBKDF2-HMAC-SHA256 ≥ 600.000 vòng; ưu tiên Argon2id.
- Case: LinkedIn 2012 — 164 triệu hash SHA-1 **không salt** bị bóc.
- Demo trước mắt: `python hashguard.py password register` + `inspect` xem JSON có salt.

### Slide 8 — XÁC THỰC ②: HMAC, chữ ký số, OTP (50s) [TV3]
- HMAC = H(K⊕opad ‖ H(K⊕ipad ‖ m)): hai bên chia sẻ khóa → vừa xác nguồn vừa xác nội dung; chống length-extension.
- Chữ ký số = hash-then-sign: ký trên hash (ngắn, cố định) thay vì cả tài liệu → RSA-PSS, ECDSA, Ed25519; thêm non-repudiation.
- OTP HOTP/TOTP (RFC 4226/6238): HMAC counter/thời gian → mã 6 số.
- Demo trước mắt: `python hashguard.py hmac demo` — tin bị sửa bị chặn.

### Slide 9 — TOÀN VẸN ①: kiểm tra dữ liệu hằng ngày (40s) [TV4]
- Checksum khi tải phần mềm: trang chủ đưa SHA-256, máy bạn tự băm so khớp.
- Trình quản lý gói (apt, pip --require-hashes), SRI của trình duyệt, code signing.
- Giám sát file hệ thống: AIDE/Tripwire — baseline ↔ kiểm tra định kỳ.
- Demo trước mắt: `python hashguard.py integrity baseline/verify` — sửa hợp đồng 12 triệu → 98 triệu bị phát hiện ngay.

### Slide 10 — TOÀN VẸN ②: Merkle tree + Git (40s) [TV4]
- Merkle tree: lá = hash khối dữ liệu, cha = hash con; sửa 1 lá → gốc đổi → chỉ cần so gốc là biết dữ liệu gãy ở đâu; nền của blockchain, Certificate Transparency, BitTorrent v2, dm-verity.
- Git: mọi commit được định địa chỉ bằng SHA-1 (đang chuyển SHA-256) — nội dung sửa là lịch sử gãy.

### Slide 11 — Case study gộp (20s) [TV4]
- 3 dòng: SHAttered 2017 (2 file PDF cùng hash SHA-1), Flame 2012 (MD5 giả chữ ký), LinkedIn 2012 (SHA-1 không salt).
- Thông điệp: thuật toán chết chưa lập tức làm bạn mất cắp, nhưng là quả bom nổ chậm.

### Slide 12 — Kết luận + chuyển demo (20s) [TV4]
- 3 câu chốt: (1) Dùng SHA-256/SHA-3/BLAKE2, không MD5/SHA-1; (2) Mật khẩu thì salt + KDF chậm (Argon2id); (3) Tin nhắn/API thì HMAC — đừng tự bịa hash(key||msg).
- *"Lý thuyết 10 phút vậy là đủ. Bây giờ chứng minh bằng code — 5 phút."* → sang demo.

---

## 4. Kịch bản demo 5 phút (dự án HashGuard)

**Người chạy:** TV4 (mở máy, gõ lệnh). **Người hỗ trợ:** TV3 (cầm kịch bản, chịu trách nhiệm Q&A phần demo). Cả nhóm đứng sẵn để trả lời.

> Chuẩn bị TRƯỚC buổi: mở sẵn terminal, `cd` vào `demo/`, chạy sẵn `python hashguard.py full-demo` một lần để khởi động + xác nhận chạy được (không đợi load trước hội đồng).

| # | Thời gian | Việc | Lệnh | Kết quả kỳ vọng | Lời thoại gợi ý |
|---|---|---|---|---|---|
| D01 | 0:00–0:30 | Giới thiệu tool | — (chỉ treo slide kiến trúc) | Cây thư mục 3 module: integrity / password / hmac | "3 trụ cột lý thuyết vừa nói — giờ biến thành 3 module chạy được, không thư viện ngoài nào." |
| D02 | 0:30–1:30 | Toàn vẹn | ① `python hashguard.py integrity baseline`<br>② `python hashguard.py integrity tamper`<br>③ `python hashguard.py integrity verify` | ① baseline N file<br>② "kẻ tấn công đã sửa hop_dong.txt"<br>③ `[!] MODIFIED: hop_dong.txt` | "Sửa đúng 1 dòng tiền trong hợp đồng — SHA-256 bắt được ngay. Đây là nguyên lý của AIDE, Tripwire." |
| D03 | 1:30–3:00 | Mật khẩu | ① `python hashguard.py password register sinhvien Mk!Manh2026`<br>② `inspect`<br>③ `login` đúng + sai<br>④ `password weak-demo` | ① chuỗi `pbkdf2_sha256$200000$salt$hash`<br>② thấy salt hex + hash hex<br>③ THÀNH CÔNG / sai khau<br>④ MD5 "123456" bóc trong vài ms | "Không lưu mật khẩu, không lưu cả hash trần — salt riêng từng người + 200.000 vòng PBKDF2. Còn nếu dại dột dùng MD5 không salt thì từ điển 5 từ đã bóc." |
| D04 | 3:00–4:15 | HMAC | `python hashguard.py hmac demo` | Kịch bản 1: VERIFIED; 2 (tin bị sửa 12tr→98tr): FAILED; 3 (sai khóa): FAILED | "Cùng một tin chuyển khoản — chỉ đổi 2 chữ số, chữ ký hết hiệu lực. Kẻ nghe trộm không có khóa thì ký gì cũng bị từ chối." |
| D05 | 4:15–4:50 | Tấn công | ① `python hashguard.py attacks birthday --bits 20`<br>② `python hashguard.py attacks speed` | ① trùng sau ~1.024 lần thử, tức thì<br>② MD5 nhanh hơn SHA-256 vài lần | "20 bit đầu chỉ cần ~2^10 lần thử — đó chính là 2^(n/2) lý thuyết vừa trình bày. Nên hash dài là điều kiện sống còn." |
| D06 | 4:50–5:00 | Chốt | — | — | "Baseline–verify là Integrity. Salt+KDF và HMAC là Authentication. Một primitive — hai trụ cột. Hết phần của nhóm chúng em." |

### Chạy một lần cả kịch bản (để quay video backup / tổng rehearsal)
```
python hashguard.py full-demo
```

### Bonus demo — chỉ mở khi Q&A hoặc dư giờ (không nằm trong 5 phút chính)

| Lệnh | Chứng minh điều gì | Câu chốt |
|---|---|---|
| `python hashguard.py attacks lengthext` | Kẻ trộm không biết khóa, nối `; admin=true; them 98.000.000 VND` vào tin ký kiểu `md5(key‖msg)` — server **chấp nhận** tag giả | "Đây chính là lỗ hổng length-extension — lý do bắt buộc dùng HMAC" |
| `python hashguard.py hmac totp` | Mã 6 số đang đếm ngược 30 giây kiểu Google Authenticator = HMAC của thời gian (RFC 6238) | "Ứng dụng xác thực của HMAC đang nằm trong túi bạn" |

---

## 5. Checklist trước khi lên

- [ ] **D-3:** Rehearsal lần 1 — cả nhóm, bấm giờ từng TV, dồn 12 slide trong 10:00.
- [ ] **D-2:** Chốt slide → xuất PDF backup (đề phòng máy chiếu mất font/chay PowerPoint).
- [ ] **D-1:** Rehearsal lần 2 (đúng thứ tự lên người, không chỉnh giữa buổi) + quay video `full-demo` 2–3 phút làm phương án dự phòng.
- [ ] **D-0 (trước giờ G):** laptop demo sạc đầy + second-screen test; terminal font ≥ 20pt; mở sẵn 2 tab terminal (1 chạy, 1 dự phòng).
- [ ] **D-0:** chạy thử `python hashguard.py full-demo` trước khi lớp bắt đầu để "hâm máy".
- [ ] In 1 tờ kịch bản bảng D01–D06 cho TV3 cầm.

## 6. Phương án dự phòng

| Rủi ro | Phương án |
|---|---|
| Máy chiếu không chạy được terminal | Phát video `full-demo` đã quay (có phụ đề gạch đầu dòng) |
| Python lỗi font tiếng Việt trên máy lớp | Mọi output CLI đã viết không dấu ASCII — chạy được ở mọi codepage |
| Quá giờ phần slide | Cắt Slide 10 (Merkle/Git) — TV4 nhảy thẳng sang Slide 11–12 |
| Demo quá giờ | Duyệt thẳng D02 → D04 (2 màn chính), bỏ D05 |
| Hội đồng hỏi sâu | Xem sẵn mục Q&A bên dưới |

## 7. Q&A dự phòng — câu hỏi giảng viên hay hỏi

1. **Vì sao không mã hóa mật khẩu mà phải băm?** Mã hóa thì phải có khóa và có thể giải ngược; ai có khóa đọc được toàn bộ. Băm là một chiều — kể cả DBA cũng không đọc lại được.
2. **Salt có cần giữ bí mật không?** Không. Salt chỉ cần ngẫu nhiên và khác nhau từng người; nhiệm vụ của nó là triệt tiêu rainbow table và bảng băm dựng sẵn, không phải giấu.
3. **Vì sao HMAC an toàn hơn hash(key ‖ message)?** Merkle–Damgård cho phép length-extension: biết H(k‖m) có thể tính H(k‖m‖padding‖tail) mà không cần k. HMAC băm hai lớp với 2 khóa phái sinh (ipad/opad) → đóng mọi đường nối dài.
4. **SHA-3 khác gì SHA-2 khi SHA-2 chưa gãy?** Cấu trúc khác hẳn (sponge thay vì Merkle–Damgård) — là phương án dự phòng cấu trúc; nếu một ngày SHA-2 gãy kiểu va chạm thì cả hệ sinh thái còn lối lui.
5. **Vì sao ký hash thay vì ký cả tài liệu?** Kết quả ký chỉ dài bằng khối khóa (256–512 bit), nhanh hơn gấp nhiều lần với tài liệu lớn, và tránh phải xử lý dữ liệu khổng lồ trong thuật toán ký chậm.
6. **Demo birthday 20 bit có ý nghĩa gì với 256 bit thật?** Cùng một quy luật xác suất: 20 bit cần ~2^10 lần thử, 256 bit cần ~2^128 — tức "về mặt vật lý không bao giờ". Quy luật cũ, độ phóng khác nhau.
