# Chương TH2 — Phục hồi cluster đầu trong directory entry

**Phụ trách:** Thành viên C (bổ sung họ tên/MSSV khi đóng gói). **Mã nguồn:** `case2.py`, được gọi từ `BaiLam.case2()`. Chương này dùng lại lõi FAT32 của Thành viên A.

**Trạng thái minh chứng (26/11/2026):** đã chạy bộ mẫu FAT32 trong `Sample_Image.zip` và ảnh TH2 trong `12345.rar` do người dùng cung cấp từ giảng viên. Bộ mẫu có đáp án SHA-256 và đạt 3/3 mục tiêu TH2. Ảnh `12345` đã ghép được ba entry, kiểm chứng định dạng độc lập thành công; gói này không có hash gốc để đối chiếu tuyệt đối. Các số ở mục 5 lấy từ nhật ký thật của hai bộ này.

## 1. Chẩn đoán hư hỏng

TH2 làm sai cluster đầu của ba tập tin trong thư mục `DATA`, trong khi tên, kích thước, bảng FAT và nội dung vẫn còn nguyên. Mỗi short entry dài 32 byte; hai trường nhiều byte được đọc theo little-endian:

| Vị trí tính từ đầu entry E | Độ dài | Trường | Vai trò |
| --- | --- | --- | --- |
| `E + 0x14` | 2 byte | `DIR_FstClusHI` | 16 bit cao của cluster đầu |
| `E + 0x1A` | 2 byte | `DIR_FstClusLO` | 16 bit thấp của cluster đầu |
| `E + 0x1C` | 4 byte | `DIR_FileSize` | Kích thước thật, dùng tính số cluster và cắt dữ liệu |

`cluster_dau = (HI << 16) | LO`. Chương trình giữ nguyên giá trị thô để nhận ra cả lỗi khác 0, không tự sửa entry nguồn. Tên tập tin lấy từ `doc_thu_muc()` của A, gồm LFN hợp lệ hoặc tên 8.3 có áp dụng cờ viết thường; đường dẫn giữ dạng `DATA/TEN.EXT`.

Một entry có dữ liệu bị nghi ngờ nếu cluster đầu ngoài phạm vi, trỏ vào cluster trống/thư mục, không phải đầu chuỗi nguyên vẹn, độ dài chuỗi khác `ceil(size / cluster_size)`, nội dung không khớp loại tập tin, hoặc có nhiều entry trỏ vào cùng cluster đầu. Việc nhận dạng không phụ thuộc số thứ tự hoặc tên cố định của tập tin mẫu.

Nhật ký lưu offset entry, offset HI/LO, giá trị đọc được, hexdump 32 byte và lý do nghi ngờ. Tập tin rỗng được xử lý riêng, không cần chuỗi dữ liệu.

## 2. Cơ sở lý thuyết và nguồn dư thừa

Directory entry chỉ giữ điểm bắt đầu. Bảng FAT giữ liên kết giữa các cluster, vì vậy khi con trỏ đầu bị sai nhưng FAT còn nguyên, chuỗi dữ liệu vẫn tồn tại. Một chuỗi mồ côi được cấp phát nhưng không được entry hợp lệ tham chiếu tới.

Chương trình đọc FAT một lần qua `doc_fat()` của A; các mục đã được mask `0x0FFFFFFF`. Đầu chuỗi là cluster đã cấp phát không có mục FAT nào trỏ tới nó. Theo chuỗi bằng `chuoi()`, chỉ giữ chuỗi kết thúc bằng EOC; loại chuỗi chạm cluster thư mục hoặc bị nối chéo. Thư mục gốc và mọi cluster của thư mục con được đánh dấu riêng, kể cả thư mục nhiều cluster.

Chuỗi một cluster vẫn là một ứng viên: chính mục FAT của cluster đó chứa EOC và không có cluster trước nó. Không yêu cầu một chuỗi phải có ít nhất một liên kết sang cluster khác.

Các entry hiện tại hợp lệ và không trùng con trỏ giữ chuỗi đang dùng. Những chuỗi còn lại được ghép với các entry nghi ngờ. Trong trường hợp nhiều entry cùng trỏ một chuỗi, các entry đó được đối chiếu lại cùng nhau để tránh chiếm nhầm dữ liệu.

## 3. Tiêu chí ghép và thuật toán

Với entry kích thước `S` và cluster có `C` byte, số cluster cần là `(S + C - 1) // C`. Đây là điều kiện bắt buộc. Khi đọc ứng viên, chương trình nối theo thứ tự FAT và cắt đúng `S` byte.

| Tiêu chí | Cách kiểm tra | Điểm |
| --- | --- | --- |
| Độ dài chuỗi | Bằng số cluster cần và đọc đủ `S` byte | 10, bắt buộc |
| JPEG | Đầu `FF D8 FF`, cuối đúng `S-2` là `FF D9` | 50 cho cả hai điều kiện, bắt buộc nếu đuôi JPG/JPEG |
| PNG | Đầu đủ 8 byte chữ ký, cuối là chunk IEND rỗng và CRC chuẩn | 50 cho cả hai điều kiện, bắt buộc nếu đuôi PNG |
| PDF | Đầu `%PDF-`, phần cuối trong 1024 byte kết thúc bằng `%%EOF` sau khi bỏ khoảng trắng/NUL cuối | 50 cho cả hai điều kiện, bắt buộc nếu đuôi PDF |
| TXT | Giải mã UTF-8, hoặc UTF-16 có BOM; chỉ có ký tự in được và tab/xuống dòng/form feed | 40, bắt buộc nếu đuôi TXT |
| Slack | Phần dư sau `S` trong cluster cuối toàn 0 | Thêm 1; không loại nếu khác 0 |

Với định dạng chưa hỗ trợ, chỉ có điểm độ dài và slack; không tuyên bố đã kiểm tra nội dung của chúng. Slack là dấu hiệu phụ, không phải bằng chứng chắc chắn.

Sau khi lập các cặp phù hợp, tìm phép ghép một-một có tổng điểm cao nhất bằng tìm kiếm nhánh-cận: xét entry ít ứng viên trước, không dùng lại một chuỗi cho hai entry. Không chọn tham lam từng cặp riêng rẽ. Nếu không có phép ghép đầy đủ hoặc có nhiều nghiệm tối ưu cùng điểm, chương trình ghi cảnh báo rồi dừng trước khi lưu tập tin.

```text
đọc BPB -> ThamSo; đọc FAT và mask 28 bit
duyệt cây bằng lõi A; thu tập tin và tập cluster thư mục
tìm các đầu chuỗi; loại chuỗi không EOC, thư mục và nối chéo
chẩn đoán từng entry; giữ ánh xạ đang phù hợp, gom entry nghi ngờ
ứng viên = các chuỗi còn lại sau khi loại chuỗi đang dùng hợp lệ
với mỗi entry nghi ngờ:
    lọc chuỗi theo số cluster, chữ ký và dấu kết thúc
    ghi tiêu chí, tính điểm từng cặp
tìm phép ghép một-một tốt nhất
nếu thiếu nghiệm hoặc mơ hồ: ghi cảnh báo và dừng
với từng tập tin:
    nối các cluster của chuỗi được chọn; cắt đúng size
    ghi quyết định cluster cũ/đúng, runs, offset và SHA-256
    lưu đúng đường dẫn qua out.luu()
```

FAT được quét tuyến tính. Chi phí ghép phụ thuộc số entry nghi ngờ và số cặp còn lại; bài toán TH2 thông thường chỉ có ba entry hỏng. Thuật toán không giả định dữ liệu liên tục; các chuỗi phân mảnh vẫn được đọc theo FAT.

## 4. Bảo toàn ảnh và ghi nhật ký

Chương trình chỉ mở ảnh nguồn qua `AnhDia` ở chế độ đọc. Cluster đúng được giữ trong ánh xạ bộ nhớ, không ghi vào directory entry trên ảnh. Dữ liệu phục hồi được lưu ở thư mục đầu ra; khung tạo `SHA256SUMS`.

Mỗi quyết định phục hồi có đường dẫn, cluster cũ/đúng, các run, kích thước, tiêu chí và điểm, offset entry, offset mục FAT của cluster đầu, offset dữ liệu đầu và SHA-256. Hash được tính từ nội dung vừa trích xuất; tính hash riêng lẻ không chứng minh phục hồi đúng, cần đối chiếu hash bản gốc bằng `selftest.py`.

## 5. Minh chứng trên ảnh giảng viên cung cấp

### 5.1. Nguồn và cách kiểm chứng

- `Sample_Image.zip`: ảnh sạch, ba ảnh tình huống và JSON đáp án công khai. Chỉ giải nén nhánh FAT32 vào `test_teacher_20261126/sample/mau/fat32/`.
- `12345.rar`: ba ảnh tình huống FAT32, không kèm ảnh sạch hoặc JSON đáp án; giải nén vào `test_teacher_20261126/group/12345/fat32/`.
- Nhật ký và kết quả thật nằm trong `test_teacher_20261126/results/`; tổng hợp ở `tong_hop.json`. Các tệp ảnh đầu vào được tính SHA-256 trước/sau, xác nhận không thay đổi.
- `recover.py`, `binio.py`, `tienich.py`, `selftest.py` hiện có khớp nội dung khung trong `Skeleton_Codes-20261126T061138Z-1-001.zip` sau chuẩn hóa xuống dòng.

### 5.2. Bộ mẫu công khai FAT32

`selftest.py` gốc báo `--info`: cluster_size đúng, tập tin đúng 5/5; TH2: nội dung đúng 3/3, tên/đường dẫn đúng 3/3. Kiểm tra riêng toàn bộ đầu ra TH2 khớp SHA-256 5/5 tập tin với `case2.json`, gồm cả hai tập tin còn nguyên. JSON đáp án chỉ được dùng ở bước chấm sau phục hồi.

| Mục tiêu mẫu | Cluster cũ → phục hồi | Runs | Size | Đối chiếu SHA-256 gốc |
| --- | --- | --- | --- | --- |
| `DATA/J12.JPG` | 0 → 4 | `[[4,28]]` | 113319 | Khớp |
| `DATA/D44.PDF` | 0 → 113 | `[[113,27]]` | 110400 | Khớp |
| `DATA/V77.TXT` | 0 → 140 | `[[140,1]]` | 220 | Khớp |

Nhật ký: `results/sample_C/nhat_ky.jsonl`. Thời gian phục hồi đo qua API ở lần kiểm chứng này khoảng 0,0191 giây, không bao gồm băm toàn ảnh trước/sau. Phần A trên `clean.img` cũng liệt kê đúng 5/5 và trích xuất khớp SHA-256 5/5.

### 5.3. Ảnh TH2 trong gói 12345

Ảnh dung lượng 512 MiB, cluster 4096 byte. Tham số đọc được: `bps=512`, `sc=8`, `sb=32`, `nf=2`, `sf=1024`. `FAT_offset = 32×512 = 0x4000`; `DataOffset = (32 + 2×1024)×512 = 0x104000`.

| Tập tin | Offset entry | HI / LO cũ | Cluster phục hồi | Runs | Size | Điểm |
| --- | --- | --- | --- | --- | --- | --- |
| `DATA/G81.JPG` | `0x105040` | 0 / 0 | 4 | `[[4,15]]` | 60452 | 61 |
| `DATA/U08.PNG` | `0x105060` | 0 / 0 | 19 | `[[19,47]]` | 190946 | 61 |
| `DATA/Z83.TXT` | `0x1050A0` | 0 / 0 | 114 | `[[114,1]]` | 268 | 51 |

Ví dụ với `G81.JPG`:

- HI tại `0x105040 + 0x14 = 0x105054`; LO tại `0x105040 + 0x1A = 0x10505A`. Hai trường bằng 0 nhưng `size=60452 > 0`, nên con trỏ hiện tại không hợp lệ.
- Cần `(60452 + 4096 - 1) // 4096 = 15` cluster. Chuỗi mồ côi bắt đầu tại 4 gồm cluster 4–18, kết thúc EOC.
- `FAT[4]` ở `0x4000 + 4×4 = 0x4010`; dữ liệu đầu ở `0x104000 + (4-2)×4096 = 0x106000`.
- EOI nằm ở byte `60450–60451` tính từ đầu nội dung; offset tuyệt đối bắt đầu EOI là `0x106000 + 60450 = 0x114C22`.
- Điểm 61 = 10 (độ dài) + 50 (chữ ký đầu/cuối) + 1 (slack toàn 0).

Hex đầu dữ liệu trích trực tiếp trong nhật ký:

```text
00106000  FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01  ......JFIF......
00115000  89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52  .PNG........IHDR
00174000  47 68 69 20 63 68 75 3A 20 6B 69 65 6D 20 74 72  Ghi chu: kiem tr
```

SHA-256 tính từ kết quả phục hồi (chưa có hash bản gốc của gói 12345 để đối chiếu):

| Tập tin | SHA-256 |
| --- | --- |
| `G81.JPG` | `cfa15d9f23fed93d245facfc1691da3e2a034a4bd8f06e293e1a7fdc31fd0dab` |
| `U08.PNG` | `cf86799d897cd80501e2a799352ee0e357e1e7c17fc1950c6832ef5525d8de3c` |
| `Z83.TXT` | `e5e735764b39f6f155f146a32ab67401662902228d86b6e4e087d7534f424c15` |

Kiểm chứng độc lập sau phục hồi: PyMuPDF giải mã được JPEG 299×299 và PNG 252×252; mã kiểm chứng dùng `zlib` xác nhận CRC mọi chunk PNG và giải nén IDAT thành công; TXT giải mã UTF-8 đủ 268 byte. PyMuPDF chỉ được dùng bởi công cụ kiểm chứng bên ngoài, không được import hay gọi từ chương trình phục hồi. Kết quả lưu ở `results/group_C/kiem_tra_dinh_dang.json`.

TH2 đã lưu 5 tập tin, gán lại ba entry trên, chạy khoảng 0,017 giây qua API, không gồm thời gian băm toàn ảnh. Nhật ký: `results/group_C/nhat_ky.jsonl`; dữ liệu: `results/group_C/recovered/`. Ảnh nguồn không thay đổi. Kiểm tra định dạng không thay thế phép đối chiếu SHA-256 với bản gốc.

### 5.4. Kiểm thử bổ sung

11 bài kiểm thử tự tạo vẫn dùng để kiểm tra lỗi khác 0, con trỏ hoán đổi, LFN, phần HI khác 0, chuỗi một cluster và phép ghép mơ hồ. Các bộ tự tạo được phân biệt với hai bộ giảng viên cung cấp; không dùng số của chúng làm minh chứng ảnh nhóm.

## 6. Hạn chế và việc cần hoàn thiện trước khi nộp

Thuật toán áp dụng giả thiết TH2: BPB, FAT, thư mục và dữ liệu còn nguyên, chỉ cluster đầu của tập tin bị sai. Nếu cây thư mục hoặc FAT cũng hỏng, chương trình có thể từ chối. Không khôi phục entry đã xóa vì lõi A bỏ qua chúng.

Chữ ký và dấu kết thúc là bộ lọc, không xác minh CRC mọi chunk PNG, cấu trúc đối tượng PDF hay giải mã JPEG. TXT hiện hỗ trợ UTF-8 và UTF-16 có BOM; văn bản theo bảng mã khác có thể bị từ chối. Nếu hai nội dung cùng loại/kích thước cho điểm giống nhau, không đủ cơ sở khẳng định tên nào thuộc dữ liệu nào. Tương tự, hai con trỏ bị hoán đổi giữa các tập tin không thể phân biệt bằng tiêu chí hiện tại có thể không bị nhận ra; cần thêm thông tin hoặc bộ kiểm tra nội dung mạnh hơn.

Đã kiểm chứng bộ mẫu công khai và chạy ảnh 12345; chưa có ảnh ẩn hoặc hash gốc của ảnh 12345. Khi nhận được hash/bản gốc, bổ sung đối chiếu thay vì chỉ dựa vào kiểm tra định dạng. Chương này là nguồn để biên tập vào báo cáo PDF chung tối đa 20 trang; mang theo nhật ký và kết quả khi đóng gói, bổ sung họ tên/MSSV người thực hiện.
