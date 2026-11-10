# LÝ THUYẾT — Applying Hash Functions in Security

**Chủ đề:** Ứng dụng hàm băm trong bảo mật — **Xác thực (Authentication)** và **Toàn vẹn (Integrity)**
**Môn học:** Bảo mật và an toàn hệ thống thông tin

> Tài liệu này là bản gốc đầy đủ để nhóm rút nội dung vào 12 slide (xem map slide ↔ mục ở cuối mỗi phần và file [../PLAN.md](../PLAN.md)). Các số liệu mấu chốt đã kiểm chứng qua nguồn ở mục 8.

---

## 1. [TV1] Nền tảng: hàm băm là gì?

### 1.1 Định nghĩa

Hàm băm mã hóa học là hàm `H` nhận đầu vào dữ liệu **bất kỳ độ dài nào** và trả về chuỗi bit **cố định độ dài n**:

```
        đầu vào (bất kỳ độ dài)                 đầu ra cố định n bit
   ┌──────────────────────────────┐            ┌──────────────────┐
   │ "HOP DONG SO 2026/HD-117..." │ ────H────► │ ba7816bf8f01cfea │  (SHA-256: n = 256 bit)
   │ 1 byte, 1 GB, 1 video...     │            │ ...414140de5dae22│
   └──────────────────────────────┘            └──────────────────┘
```

Đầu ra được gọi là **digest** (bản băm) hay "vân tay số" của dữ liệu: cùng một input **luôn** cho cùng một output, và không ai biết cách đi ngược từ output về input.

### 1.2 Sáu tính chất bắt buộc

| # | Tính chất | Ý nghĩa |
|---|---|---|
| 1 | **Tất định** (deterministic) | Cùng input → cùng output, trên mọi máy, mọi thời điểm |
| 2 | **Đầu ra cố định** | Dù input 1 byte hay 1 GB, output luôn n bit |
| 3 | **Nhanh** | Tính được hàng trăm MB/giây trở lên (dùng được trong pipeline thực) |
| 4 | **Kháng tiền ảnh** (preimage resistance) | Cho `y`, không tìm được `x` nào để `H(x) = y` |
| 5 | **Kháng tiền ảnh thứ hai** (second-preimage) | Cho `x`, không tìm được `x' ≠ x` để `H(x') = H(x)` |
| 6 | **Kháng va chạm** (collision resistance) | Không tìm được *cặp* bất kỳ `x ≠ x'` với `H(x) = H(x')` |

Ba tính chất cuối là "**bảo mật**"; ba đầu là "**vận hành**". Thiếu 4/5/6 thì hàm chỉ còn là checksum thông thường.

### 1.3 Mức an toàn đo bằng bit — nghịch lý sinh nhật

| Mục tiêu | Độ khó kỳ vọng | Với digest n bit |
|---|---|---|
| Tìm tiền ảnh (tấn công 1 chiều) | ~2^n phép băm | SHA-256 → 2^256 |
| Tìm va chạm (cặp bất kỳ) | ~2^(n/2) phép băm | SHA-256 → 2^128 |

Vì sao va chạm chỉ tốn **nửa** số bit? Nghịch lý sinh nhật: trong nhóm 23 người, xác suất có 2 người cùng ngày sinh vượt 50% — dù năm có 365 ngày. Tương tự, chọn ~2^(n/2) đầu vào ngẫu nhiên là xác suất "va" một cặp cùng hash vượt 50%.

> **Demo tức thì:** `python hashguard.py attacks birthday --bits 20` → tìm 2 input trùng 20 bit đầu chỉ sau ~1.000 lần thử (kỳ vọng 2^10 = 1.024). Phóng to n = 256 → 2^128 phép băm, vượt khả năng vật lý của mọi máy tính.

### 1.4 Nguyên lý bồ nhị (pigeonhole) — va chạm tồn tại tất yếu

Đầu vào vô hạn, đầu ra chỉ 2^n giá trị ⇒ **chắc chắn tồn tại** vô số cặp va chạm. Tính chất 6 không phải "không có va chạm" mà là "**không tìm được** va chạm một cách khả thi". Đây là điểm phân biệt lớn giữa "tồn tại" và "tìm được" trong mật mã.

### 1.5 Hiệu ứng tuyết lở (avalanche)

Đổi **1 bit** đầu vào, trung bình ~**50%** bit đầu ra lật vị trí — hai digest trông hoàn toàn không liên quan:

```
sha256("abc")   = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
sha256("abb")   = 715edf8ba8729420cd4d1ce85ed61954a9f531f8c548df728c407effe839296d
```

> **Demo:** `python hashguard.py hash "abc" --avalanche`

Ý nghĩa bảo mật: không ai suy ra nội dung đã thay đổi ở đâu từ việc so sánh hai digest — chỉ biết "đã đổi".

### 1.6 Vận hành bên trong: Merkle–Damgård và Sponge

**Merkle–Damgård** (dùng trong MD5, SHA-1, SHA-2):

```
input ──► pad ──► chia khối 512-bit ──► nén tuần hoàn
                                         ┌──────┐ IV   ┌──────┐       ┌──────┐
        m1 ────────────────────────────► │  f   │────► │  f   │─────► │  f   │ ──► H(m)
                                         └──────┘  m1  └──────┘  m2   └──────┘  mn
```

Mỗi khối được "trộn" vào trạng thái trước bằng hàm nén `f`; khối cuối chứa độ dài tin (padding Merkle–Damgård) chống mở rộng ngây thơ tầm thường.

**Hệ quả quan trọng (lát nước cho mục 2.3):** trạng thái nội bộ cuối cùng **chính là** digest ⇒ biết `H(m)` là biết trạng thái trung gian → có thể "tiếp tục băm" thêm dữ liệu mà không cần biết nội dung trước đó — đây là **length-extension attack**.

**Sponge** (dùng trong SHA-3/Keccak): trạng thái bị "vắt" và "hút" xen kẽ, cấu trúc khác hẳn — được thiết kế để không có lối length-extension, là phương án dự phòng cấu trúc cho SHA-2.

**Map slide:** 1.1–1.2 → Slide 2; 1.3–1.4 → Slide 2; 1.5–1.6 → Slide 3.

---

## 2. [TV2] Các thuật toán: ai sống, ai chết — và ba mũi dao tấn công

### 2.1 Bảng thuật toán

| Thuật toán | Bit | Năm | Cấu trúc | Trạng thái | Dùng điển hình |
|---|---|---|---|---|---|
| **MD5** | 128 | 1991 (RFC 1321, 1992) | Merkle–Damgård | ☠ **CHẾT** — va chạm toàn phần từ 2004 (Wang và cộng sự), chọn tiền tố khả thi từ 2007 | Không dùng cho bảo mật; chỉ checksum không đối thủ |
| **SHA-1** | 160 | 1995 (FIPS 180-1) | Merkle–Damgård | ☠ **CHẾT** — SHAttered 2017, ~2^63.1 | Vẫn gặp trong Git cũ, HMAC (an toàn hơn nhưng nên bỏ) |
| **SHA-2** (224/256/384/512) | 224–512 | 2002 (FIPS 180-2, hiện hành 180-4) | Merkle–Damgård | ✅ DÙNG ĐƯỢC | TLS, chữ ký số, Bitcoin, checksum chuẩn |
| **SHA-3** (Keccak) | 224–512 | 2015 (FIPS 202) | Sponge | ✅ DÙNG ĐƯỢC | Dự phòng cấu trúc, chuẩn mới |
| **BLAKE2 / BLAKE3** | đến 512 / 256+ | 2015 (RFC 7693) / 2020 | HAIFA / Merkle tree | ✅ DÙNG ĐƯỢC | BLAKE2b nhanh 4–8× MD5 trên CPU 64-bit, có chế độ MAC tích hợp |
| **RIPEMD-160** | 160 | 1996 | Merkle–Damgård (hai nhánh) | ⚠ Cũ nhưng chưa gãy | Bitcoin địa chỉ cổ điển |

**Quy tắc sống còn:** mật mã mới — SHA-256, SHA-3-256 hoặc BLAKE2; **cấm** MD5 và SHA-1 trong mọi thiết kế mới. Tính 1.3: 128 bit (MD5) cho va chạm chỉ còn "64 bit sức mạnh" → ~2^64 phép băm, GPU hiện đại xử lý được.

### 2.2 Ba mũi dao tấn công

#### ① Birthday / collision — "chọn cặp bất kỳ"
Như mục 1.3: tốn ~2^(n/2). Không cần biết nội dung gì đặc biệt — chỉ cần *một cặp* trùng nhau là đủ phá tính chất 6.

#### ② Chosen-prefix collision — "bóp méo nội dung theo ý muốn"
Attacker tự thiết kế **hai thông điệp khác nhau về ý nghĩa** nhưng cùng hash. Ba vụ án kinh điển:

| Năm | Vụ | Thuật toán | Tác hại |
|---|---|---|---|
| 2008 | **Rogue CA** (Sotirov, Stevens và cộng sự, 25C3) — lợi dụng CA còn ký MD5 lấy chứng chỉ RapidSSL gian lận, tự phong làm CA giả; cụm **~200 PlayStation 3** + ~700 USD chứng chỉ thật | MD5 | Chứng chỉ CA giả được mọi trình duyệt tin → nghe lén toàn bộ HTTPS |
| 2012 | **Flame** — mã độc gián điệp giả chữ ký số Microsoft bằng va chạm MD5 chọn tiền tố | MD5 | Malware có "giấy thông hành" chính chủ |
| 2017 | **SHAttered** (Google + CWI, 23/2/2017) — 2 file PDF nội dung hoàn toàn khác, cùng SHA-1; ~2^63.1 phép nén ≈ 6.500 năm CPU + 110 năm GPU, nhanh hơn brute-force birthday ~100.000 lần | SHA-1 | Chứng minh SHA-1 chết thực nghiệm; tiếp theo "SHA-1 is a Shambles" (2020) đưa chọn tiền tố về ~2^63.4 — thuê GPU khoảng 45.000 USD |

#### ③ Length-extension — "trộm đuôi bài toán"
Với hash Merkle–Damgård, biết `H(k ‖ m)` (k là khóa bí mật đằng trước) có thể tính tiếp `H(k ‖ m ‖ padding ‖ dữ-liệu-thêm)` **mà không cần biết k** — vì digest chính là trạng thái nội bộ.

Ví dụ thực tế: web API cũ ký tham số bằng `hash(secret ‖ params)`; attacker biết `params` và hash của nó, thêm `&admin=1` vào rồi tính lại hash — server nhận là hợp lệ. Bài học: **đừng tự chế MAC bằng `hash(key ‖ msg)` — dùng HMAC** (mục 3.2).

#### ④ (Đi kèm) Brute-force + rainbow table
- Hash càng nhanh thì đoán càng nhanh: benchmark hashcat trên RTX 4090 (ước lượng, tùy kernel) — **MD5 164,1 tỷ lần/giây, SHA-1 50,6 tỷ/giây, SHA-256 22,0 tỷ/giây**; trong khi bcrypt cost 10 hay Argon2id 64+ MiB tụt xuống còn **hàng trăm–nghìn lần/giây** — chênh ~10 triệu lần. Một card 4090 vét gần trọn không gian va chạm 2^64 của MD5 trong ~3,5 năm, và bóc mật khẩu NTLM 8 ký tự chữ-số trong **~13 phút**. Đây là lý do "chọn KDF chậm" là quyết định bảo mật, không phải sở thích (xem `python hashguard.py attacks speed`).
- **Rainbow table**: bảng tra hash ↔ mật khẩu dựng sẵn cho mật khẩu không salt — một lần dựng, dùng khét cho mọi máy trên thế giới. **Salt** (muối ngẫu nhiên từng người dùng) triệt tiêu loại này hoàn toàn (mục 3.1).

### 2.3 Trạng thái chuẩn hóa (NIST timeline)

- **FIPS 180-4** (2012, cập nhật 2015): chuẩn hiện hành cho SHA-1 + SHA-2.
- **FIPS 202** (8/2015): chuẩn SHA-3 — sponge, trạng thái 1600 bit (SHA3-256: r=1088, c=512), kèm thêm SHAKE128/256 — hàm băm đầu ra co giãn được.
- NIST: cấm SHA-1 **tạo** chữ ký số từ sau 31/12/2013 (SP 800-131A); ngày 15/12/2022 công bố nghỉ hưu đầy đủ — **SHA-1 bị cấm hoàn toàn sau 31/12/2030**. **NIST IR 8547** (chính thức 10/2026) khẳng định SHA-1 không được dùng tạo **hoặc xác minh** chữ ký sau 2030; dự thảo SP 800-131A Rev.3 cấm cả HMAC-SHA-1 sau 2030.
- CA/Browser Forum: chứng chỉ TLS mới phát hành cấm SHA-1 từ 1/1/2016. Còn chấp nhận tạm thời: HMAC-SHA-1 trong một số bộ mật mã cũ (cấu trúc HMAC làm tê liệt tấn công va chạm) — nhưng thiết kế mới dùng SHA-256/SHA-3.
- SP 800-107 (hướng dẫn dùng hash trong ứng dụng) đã bị rút khỏi hiện hành — thông điệp: chuẩn băm cũng có vòng đời, phải theo dõi.

**Map slide:** 2.1 → Slide 4; 2.2 → Slide 5 (Flame nhắc gọn ở Slide 5, chi tiết ở Slide 11).

---

## 3. [TV3] Ứng dụng trụ 1 — XÁC THỰC (Authentication)

Trả lời câu hỏi: **"Đúng người, đúng nguồn, đúng quyền?"**

### 3.1 Lưu mật khẩu: salt + KDF chậm có chủ đích

**Sai lầm từng được tha thứ... và không:**

| Cách lưu | Vấn đề | Vụ án |
|---|---|---|
| Plaintext | Đọc là có | RockYou 2009 — 32 triệu mật khẩu lộ nguyên văn |
| Mật khẩu mã hóa | Phải có khóa; khóa lộ là mất hết | Adobe 2013 — mã hóa kém, dễ khôi phục |
| Hash nhanh không salt (MD5/SHA-1) | Rainbow table + GPU brute-force | LinkedIn 2012/2016 — ~164 triệu hash SHA-1 không salt bị bóc hàng loạt |
| Hash nhanh có salt | GPU vẫn đoán hàng tỷ lần/giây | — (chưa đủ tốt) |
| **KDF chậm + salt riêng từng người** ✅ | Chi phí đoán bị nhân lên hàng triệu lần | — chuẩn hiện hành |

**Công thức đúng:**

```
stored = KDF(password, salt_ngẫu_nhiên_16_byte, tham_số_độ_tốn_kem)
```

- **Salt** ngẫu nhiên, khác nhau từng người, **không cần giữ bí mật** (nhiệm vụ của nó là tiêu diệt rainbow table và bảng dựng sẵn, không phải giấu). NIST SP 800-63B: salt ít nhất 32 bit, băm bằng KDF một chiều bắt buộc với mật khẩu ghi nhớ.
- **Pepper** (tùy nâng cao): một bí mật **toàn cục** nằm ngoài DB (secrets vault/HSM), áp dạng "post-hashing" — HMAC thêm một lớp trên đầu ra KDF với pepper làm khóa. Nếu DB rò mà pepper chưa rò thì hash còn giữ được.
- **KDF chậm** (Key Derivation Function) — đánh đổi chủ đích: hợp pháp đăng nhập 1 lần/giây phải chịu, kẻ tấn công đoán hàng triệu lần/giây phải trả gấp triệu lần:

| KDF | Tham số khuyến nghị (OWASP Password Storage Cheat Sheet) | Ghi chú |
|---|---|---|
| **Argon2id** ✅ ưu tiên | bộ nhớ 19 MiB, t=2, p=1 | Tối thượng vùng GPU/ASIC vì ngốn cả bộ nhớ; thắng Password Hashing Competition 2015, chuẩn hóa RFC 9106 |
| scrypt | N=2^17, r=8, p=1 | Tương tự, chống GPU bằng bộ nhớ |
| bcrypt | cost ≥ 10 | Cổ điển, ổn; giới hạn 72 byte |
| **PBKDF2-HMAC-SHA256** | ≥ 600.000 vòng | Chuẩn nhiều hệ thống cũ, chuẩn FIPS; dùng trong demo |

> **Demo:** `python hashguard.py password register sinhvien Mk!Manh2026` rồi `inspect` — file JSON chỉ có `pbkdf2_sha256$200000$salt_hex$hash_hex`; hai lần đăng ký cùng một mật khẩu cho hai chuỗi khác nhau (salt khác). `weak-demo` cho thấy MD5 "123456" bị bóc bằng 5 từ từ điển trong chưa đầy 1 ms.

### 3.2 HMAC — xác thực tin nhắn bằng khóa chia sẻ

**Vấn đề:** chỉ dùng hash không đủ xác nguồn — ai cũng tính được hash. Cần **khóa**: chỉ hai bên mới tạo được tag đúng.

**HMAC** (RFC 2104, 1997) — cấu trúc hai lớp với hai khóa phái sinh từ khóa chính K:

```
HMAC(K, m) = H( (K ⊕ opad) ‖ H( (K ⊕ ipad) ‖ m) )

ipad = 0x36 lặp đủ khối (đệm trong)      opad = 0x5c lặp đủ khối (đệm ngoài)
```

Ba điều HMAC mua được:
1. **Xác nguồn:** tag chỉ tạo được khi biết K (Bob tin tin nhắn là từ Alice).
2. **Toàn vẹn:** đổi 1 bit trong tin → tag sai ngay (`compare_digest` trả FAILED).
3. **Chống length-extension:** hai lớp ipad/opad phá được đường nối dài của Merkle–Damgård — không thể "đuổi" tag cũ thành tag của tin dài hơn.

**Đang chạy trong đời thực:**
- **JWT (HS256)** — token phiên đăng nhập là HMAC-SHA256 của header.payload.
- **AWS Signature V4** — mọi request API AWS được ký HMAC.
- **TLS 1.3** — message `Finished` là HMAC của transcript.
- **HOTP/TOTP** (RFC 4226/6238) — mã OTP 6 số trên điện thoại là HMAC của counter/thời gian.

**Chuẩn so sánh tag:** luôn dùng so sánh **thời gian hằng** (`hmac.compare_digest` trong Python) — so `==` trả False ngay từ byte đầu khác nhau, thời gian phản hồi rò rỉ "trùng được mấy byte" và cho phép kẻ tấn công đoán tag từng byte.

> **Demo:** `python hashguard.py hmac demo` — 3 kịch bản: tin thật VERIFIED; tin bị sửa 12.000.000 → 98.000.000 trên đường truyền FAILED; kẻ trộm ký bằng sai khóa FAILED.

### 3.3 Chữ ký số — hash-then-sign

Ký toàn bộ tài liệu thì chậm và cồng kềnh; thế giới ký trên **hash của tài liệu**:

```
Alice: signature = Sign(SK, H(tài liệu))        ── gửi (tài liệu, signature) ──►
Bob:   kiểm tra Verify(PK_alice, H(tài liệu nhận được), signature)
```

- Hash phải kháng va chạm: nếu tìm được cặp tài-liệu-xấu/tài-liệu-tốt cùng hash, Alice ký bản tốt nhưng bị gán cho bản xấu — chính là kỹ thuật của vụ **Rogue CA 2008** và **Flame 2012**.
- Họ chữ ký hiện hành: **RSA-PSS** (RFC 8017), **ECDSA** (FIPS 186-5), **Ed25519** (RFC 8032).
- Chi tiết sâu: ký RSA "thô" không băm cho phép kẻ tấn công ghép chữ ký của tin mới từ chữ ký có sẵn (kiểu Desmedt–Odlyzko) — băm trước phá cấu trúc đại số đó. ECDSA còn có vết thương riêng: tái sử dụng nonce k là lộ khóa riêng — đúng cách Sony PS3 mất khóa ký firmware năm 2010; Ed25519 sinh nonce tất định từ (khóa, tin) nên chặn tận gốc.
- Chữ ký số mang thêm **non-repudiation** (không chối bỏ) — điều HMAC không có, vì cả hai bên cùng giữ khóa K.
- Lưu ý: chữ ký số **không** mã hóa — xác thực + toàn vẹn, không bảo mật nội dung.
- Hệ sinh thái chứng chỉ: TLS certificate kèm chữ ký CA; trình duyệt kiểm tra chuỗi bằng hash-then-sign ở từng mắt xích; **Certificate Transparency** ghi toàn bộ chứng chỉ vào log Merkle (mục 4.3).

> Câu kiểm tra nhanh: "Vì sao ký hash thay vì ký cả tài liệu?" — kết quả ký chỉ dài đúng khối khóa (256–512 bit), nhanh hơn nhiều lần với tài liệu lớn, và chuỗi chữ ký gọn để truyền trong chứng chỉ.

**Map slide:** 3.1 → Slide 7; 3.2–3.3 → Slide 8.

---

## 4. [TV4] Ứng dụng trụ 2 — TOÀN VẸN (Integrity)

Trả lời câu hỏi: **"Dữ liệu còn nguyên vẹn từ lúc tạo đến lúc dùng?"**

### 4.1 Kiểm tra toàn vẹn file — hằng ngày, quanh ta

| Ứng dụng | Cách hoạt động |
|---|---|
| Tải phần mềm (Ubuntu ISO, Apache release) | Trang chủ công bố SHA-256; máy bạn tự băm và so khớp: `sha256sum -c SHA256SUMS` |
| Trình quản lý gói | **apt**: manifest `InRelease` chứa danh sách checksum *được ký GPG* — mirror không thể thay file; **pip** `--require-hashes`: mọi dependency phải khớp hash trong requirements.txt |
| Trình duyệt — **SRI** | `<script integrity="sha384-...">`: CDN bị phá → hash không khớp → script bị từ chối thực thi |
| Giám sát host — **AIDE/Tripwire** | Baseline hash toàn bộ file hệ thống + quét định kỳ → báo cáo thêm/sửa/xóa — đúng nguyên lý demo HashGuard |
| Ngành pháp y số | Hash ảnh đĩa chứng cứ tại hiện trường + xác minh lại khi phân tích = bằng chứng "chứng cứ không bị can thiệp" (chuỗi giám hộ); bộ hash NSRL của NIST lọc file "sạch" |

> **Demo:** `python hashguard.py integrity baseline` → `tamper` (kẻ tấn công sửa hợp đồng 12 triệu thành 98 triệu) → `verify` báo `[!] MODIFIED: hop_dong.txt`. Đây chính là AIDE thu nhỏ.

### 4.2 Ký mã nguồn (code signing) — toàn vẹn + xác thực gộp

- **Authenticode** (Windows): hash file được ký bằng chứng chỉ nhà phát hành; hệ điều hành kiểm tra trước khi chạy. Sửa 1 byte sau khi ký → chữ ký gãy.
- **Apple notarization**: app ký Developer ID gửi Apple quét → trả về ticket ký, ghim vào app.
- Phân biệt quan trọng: checksum **trần** chỉ phát hiện lỗi ngẫu nhiên/mirror xấu; nếu chính server phát checksum bị chiếm thì phải có **chữ ký** (khóa riêng bên thứ ba tin cậy).

### 4.3 Merkle tree — toàn vẹn ở quy mô triệu đối tượng

```
                    root = H(H01 ‖ H23)            ← chỉ cần tin ROOT
                   /            \
            H01 = H(H0 ‖ H1)    H23 = H(H2 ‖ H3)
             /      \            /      \
        H0=H(d0) H1=H(d1)  H2=H(d2)  H3=H(d3)     ← lá = hash từng khối dữ liệu
```

- Sửa 1 lá → mọi tổ tiên đến gốc đổi → **chỉ cần so 1 gốc 32 byte** là biết cả tỷ file có nguyên vẹn hay không.
- Kẻ chạy nhẹ (SPV wallet, trình duyệt) chỉ cần đường dẫn hash (Merkle proof) để xác minh một lá mà không tải toàn bộ.
- **Ở đâu đó đang chạy:** Bitcoin (block header nhúng hash khối trước + Merkle root giao dịch; băm đôi SHA256(SHA256)); **Certificate Transparency** (RFC 6962 — log chứng chỉ chỉ-ghi-được, bắt CA phải công khai chứng chỉ đã cấp); **dm-verity** (Android Verified Boot — mỗi block đọc được xác minh theo Merkle tree); **BitTorrent v2**.

**Git — hash làm địa chỉ:** mỗi object của Git được đặt tên bằng hash nội dung ("hash-as-address = integrity miễn phí"). Sửa 1 byte → hash commit đổi → lịch sử gãy hiển nhiên. Sau SHAttered 2017, Git đã bật SHA-1 "cứng hóa" (sha1dc — phát hiện va chạm khi ghi object) và có lộ trình chuyển chính thức sang SHA-256 (`git init --object-format=sha256` chạy được ngay hôm nay).

### 4.4 Các ứng dụng phụ nhưng hay hỏi

- **Deduplication** (Git, backup): nội dung trùng → hash trùng → lưu 1 bản; dựa hoàn toàn vào kháng va chạm.
- **VirusTotal**: tra file theo SHA-256 không cần upload.
- **Bất đồng bộ dữ liệu**: so hash từng khối thay vì truyền lại toàn bộ (rsync, API ETag).

**Map slide:** 4.1 → Slide 9; 4.3 (Merkle + Git) → Slide 10; case study → Slide 11.

---

## 5. Best practices — 10 điều bỏ túi

1. Hash mới: **SHA-256 / SHA-3-256 / BLAKE2**. Cấm MD5, SHA-1 trong thiết kế mới.
2. Mật khẩu: **không băm nhanh** — dùng **Argon2id** (ưu tiên) hoặc PBKDF2 ≥ 600.000 vòng (chuẩn FIPS).
3. Mỗi người dùng **một salt ngẫu nhiên riêng** (`secrets.token_bytes(16)`); salt không cần bí mật.
4. MAC tin nhắn/API: dùng **HMAC**, đừng tự bịa `hash(key ‖ msg)` — length-extension sẽ gắp bạn.
5. So sánh hash/tag bằng **so sánh thời gian hằng** (`hmac.compare_digest`), không dùng `==`.
6. Khóa HMAC ≥ 128 bit, sinh bằng CSPRNG (không dùng `random` thường).
7. Đọc file **theo khối** khi băm (1 MiB) — không đọc nguyên file vào RAM.
8. Kiểm tra tải xuống bằng **checksum + chữ ký**; checksum trần không cứu khi server gãy.
9. Theo dõi vòng đời chuẩn: những gì NIST cấm tạo chữ ký hôm nay sẽ bị cấm cả xác minh sau 2030.
10. Hiểu đúng phạm vi: hash **không mã hóa**, chữ ký **không bảo mật nội dung** — mỗi primitive một việc.

---

## 6. Case study tóm tắt (Slide 11)

| Vụ | Năm | Gốc rễ | Bài học |
|---|---|---|---|
| **RockYou** | 2009 | Lưu plaintext | Không băm = không có gì cản |
| **LinkedIn** | 2012 → 2016 | SHA-1 không salt, hash nhanh | Có băm mà không salt + KDF chậm vẫn bị bóc hàng loạt |
| **Rogue CA** | 2008 | Va chạm MD5 chọn tiền tố | Thuật toán chết = chữ ký giả được |
| **Flame** | 2012 | Va chạm MD5 giả chữ ký Microsoft | Code signing chỉ mạnh khi hash còn sống |
| **SHAttered** | 2017 | Va chạm SHA-1 thực nghiệm 2^63.1 | "Chưa gãy" ≠ "an toàn" — phải rời SHA-1 trước |

---

## 7. Liên hệ demo HashGuard — map lý thuyết ↔ code

| Lệnh demo | Lý thuyết tương ứng |
|---|---|
| `hash "abc" --avalanche` | §1.5 hiệu ứng tuyết lở; §2.1 so sánh 6 thuật toán |
| `attacks birthday --bits 20` | §1.3 nghịch lý sinh nhật 2^(n/2) |
| `attacks speed` | §2.2④ hash nhanh = đoán nhanh |
| `integrity baseline/verify/tamper` | §4.1 AIDE/Tripwire thu nhỏ |
| `password register/inspect/login` | §3.1 salt + PBKDF2 (chuỗi kiểu Django) |
| `password weak-demo` | §2.2④ + §3.1 — MD5 không salt bị bóc |
| `hmac demo` | §3.2 HMAC — chặn sửa tin và sai khóa |
| `src/hmac_channel.py` | so sánh `compare_digest` thời gian hằng |
| `src/integrity.py` | đọc file theo khối 1 MiB (§5.7) |

---

## 8. Tài liệu tham khảo

1. NIST — FIPS 180-4 *Secure Hash Standard*: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
2. NIST — FIPS 202 *SHA-3 Standard*: https://csrc.nist.gov/pubs/fips/202/final
3. NIST — SP 800-131A (quản lý thuật toán mật mã, SHA-1 bị cấm tạo chữ ký): https://csrc.nist.gov/pubs/sp/800/131a/r2/final
4. NIST IR 8547 (chính thức 10/2026 — SHA-1 cấm tạo/xác minh chữ ký sau 2030): https://csrc.nist.gov/pubs/ir/8547/final
5. RFC 1321 — MD5: https://datatracker.ietf.org/doc/html/rfc1321
6. RFC 2104 — HMAC: https://datatracker.ietf.org/doc/html/rfc2104
7. RFC 8018 — PBKDF2: https://datatracker.ietf.org/doc/html/rfc8018
8. RFC 4226 (HOTP) / RFC 6238 (TOTP): https://datatracker.ietf.org/doc/html/rfc6238
9. RFC 9106 — Argon2: https://www.rfc-editor.org/info/rfc9106
10. RFC 8446 — TLS 1.3 (bỏ MD5/SHA-1 khỏi bảng chữ ký): https://www.rfc-editor.org/info/rfc8446
11. NIST SP 800-63B — Digital Identity Guidelines (Authentication): https://pages.nist.gov/800-63-4/sp800-63b.html
12. OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
13. SHAttered (Google/CWI, 2017): https://shattered.io
14. Rogue CA MD5 (25C3, 2008): https://marc-stevens.nl/research/hashclash/rogue-ca/index.html
15. Phân tích va chạm MD5 của Flame (Marc Stevens, Counter-cryptanalysis): https://eprint.iacr.org/2012/309
16. Python hashlib/hmac/secrets docs: https://docs.python.org/3/library/hashlib.html
17. Git hash function transition: https://git-scm.com/docs/hash-function-transition
18. Certificate Transparency RFC 6962 / 9162: https://datatracker.ietf.org/doc/html/rfc6962
19. Debian SecureApt: https://wiki.debian.org/SecureApt
20. Subresource Integrity (W3C): https://www.w3.org/TR/sri-2
21. dm-verity (cryptsetup wiki): https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity
22. Bitcoin block chain reference: https://developer.bitcoin.org/reference/block_chain.html
23. NIST NSRL (pháp y số): https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl
24. Benchmark GPU hashcat (ước lượng): https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd
25. Wang, Feng, Lai, Yu — va chạm MD5 toàn phần (CRYPTO 2004): https://eprint.iacr.org/2004/199
26. RFC 7693 — BLAKE2: https://www.rfc-editor.org/info/rfc7693
27. "SHA-1 is a Shambles" (Leurent & Peyrin, 2020): https://eprint.iacr.org/2020/014
28. NIST retires SHA-1 (15/12/2022): https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm
29. Microsoft MSRC — Flame collision attack explained (2012): https://www.microsoft.com/en-us/msrc/blog/2012/06/flame-malware-collision-attack-explained/
30. Google Security Blog — Announcing the first SHA-1 collision (2017): https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html
