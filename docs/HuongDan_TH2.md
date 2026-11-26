# Bàn giao phần Thành viên C — Tình huống 2

## Phạm vi đã thực hiện

| Tệp | Vai trò |
| --- | --- |
| `case2.py` | Chẩn đoán entry, tìm chuỗi mồ côi, nhận dạng nội dung, ghép một-một, xuất tập tin và ghi nhật ký |
| `bai_lam.py` | `case2()` gọi `phuc_hoi_case2(img, out, log)` |
| `tests/test_case2.py` | Kiểm thử tích hợp và hàm sinh ảnh kiểm thử |
| `docs/BaoCao_ThanhVienC_TH2.md` | Chương TH2 để C biên tập vào báo cáo chung |

Phần TH2 dùng các hàm A đã cung cấp, không thay đổi `fat32.py` hoặc các tệp khung. Không đăng ký thêm `--repair` và không sửa phần TH1/TH3. Chương trình lưu cả tập tin khôi phục và tập tin còn nguyên để kiểm tra toàn bộ cây; bộ chấm vẫn đối chiếu các mục tiêu TH2.

## Chạy trên ảnh được giảng viên cung cấp

Đứng tại thư mục dự án. Trong PowerShell trên Windows, bật UTF-8 để `selftest.py` đọc được nhật ký tiếng Việt:

```powershell
$env:PYTHONUTF8 = '1'
python recover.py --image test_teacher_20261126\group\12345\fat32\case2.img --case 2 --out recovered_th2 --log nhat_ky_th2.jsonl
python selftest.py --mau test_teacher_20261126\sample\mau\fat32
```

Các đường dẫn trên là nơi đã giải nén hai gói giảng viên trong dự án. Nên dùng thư mục kết quả mới và tên nhật ký mới cho mỗi lần kiểm chứng, vì khung mở nhật ký ở chế độ nối thêm và không xóa kết quả cũ. Đầu ra gồm `DATA/...` và `SHA256SUMS`. Bộ mẫu chính thức đạt TH2 đúng nội dung 3/3 và tên/đường dẫn 3/3. `selftest.py` còn chạy TH1 và TH3; hai phần đó nằm ngoài phạm vi A/C trong tài liệu này.

`case2()` chỉ dùng BPB, FAT và dữ liệu từ ảnh đầu vào. Chỉ `selftest.py` được đọc JSON đáp án để chấm; không lấy SHA-256 hay cluster đúng từ đáp án làm đầu vào thuật toán.

## Kết quả trên dữ liệu giảng viên (26/11/2026)

| Kiểm tra | Kết quả | Nơi lưu |
| --- | --- | --- |
| A trên `clean.img` mẫu | `--info` đúng 5/5; trích xuất SHA-256 khớp 5/5 | `test_teacher_20261126/results/sample_A/` |
| C trên `case2.img` mẫu | Đúng 3/3 mục tiêu; toàn bộ 5 tập tin khớp hash gốc | `test_teacher_20261126/results/sample_C/` |
| C trên `12345/fat32/case2.img` | G81.JPG: 0→4, U08.PNG: 0→19, Z83.TXT: 0→114; giải mã định dạng thành công | `test_teacher_20261126/results/group_C/` |

Các thư mục kết quả có `nhat_ky.jsonl`, `ket_qua.json` và `recovered/SHA256SUMS`. `group_C/kiem_tra_dinh_dang.json` ghi kiểm chứng độc lập JPEG, PNG và TXT. Gói 12345 không có đáp án hoặc bản gốc nên chưa xác nhận hash khớp bản gốc. SHA-256 toàn ảnh đầu vào trước/sau không đổi. Các tệp khung bảo vệ khớp bản giảng viên gửi, chỉ khác kiểu xuống dòng của tệp trên đĩa.

## Kiểm thử hiện có

```powershell
$env:PYTHONUTF8 = '1'
python -m unittest discover -s tests -v
```

11 bài kiểm thử bao gồm nhiều trường hợp con: cluster sai bằng 0, giá trị khác 0, ngoài phạm vi, trỏ vào thư mục/cluster trống/giữa chuỗi/tập tin khác, hoán đổi con trỏ, chuỗi một cluster, chuỗi phân mảnh, tên dài LFN, cờ viết thường, tập tin rỗng, thay đổi hình học volume, cluster có phần HI khác 0, FAT có bit cao, chuỗi lỗi và phép ghép mơ hồ. Các ca thành công đối chiếu toàn bộ byte tập tin và SHA-256 ảnh nguồn trước/sau. Ca mơ hồ kiểm tra không lưu tập tin.

Để tạo lại bộ minh chứng cục bộ và chạy đúng giao diện chấm:

```powershell
python -c "import sys; sys.path.insert(0, 'tests'); from test_case2 import tao_bo_kiem_thu; tao_bo_kiem_thu('test_case2_generated')"
python selftest.py --mau test_case2_generated
python recover.py --image test_case2_generated\case2.img --case 2 --out test_case2_generated\recovered --log test_case2_generated\nhat_ky_case2.jsonl
```

Kết quả đã kiểm chứng: `--info` đúng kích thước cluster và 6/6 tập tin; TH2 đúng nội dung 3/3 và đúng tên/đường dẫn 3/3. Bộ này là volume nhỏ mô phỏng bố cục FAT32, payload chỉ phục vụ kiểm chữ ký/biên, không dùng để khẳng định khả năng mở ảnh JPEG/PNG/PDF bằng phần mềm xem. Các ảnh và kết quả tự tạo nằm trong thư mục `test_case2_generated/` được `.gitignore` bỏ qua.

## Đọc nhật ký để viết báo cáo

- `TH2: entry ...`: offset entry, giá trị HI/LO cũ, offset từng trường, size và hexdump.
- `TH2: chẩn đoán ...`: lý do entry bị nghi ngờ.
- `TH2: các chuỗi mồ côi/...`: các run của từng chuỗi chưa gán.
- `TH2: cặp ứng viên ...`: điểm và từng tiêu chí kiểm chứng.
- `TH2: ghép ...` (loại `quyet_dinh`): cluster cũ/đúng, runs, offset FAT/data, SHA-256 và lý do chọn.
- `TH2: hoàn tất phục hồi`: số tập tin đã lưu và số entry được gán lại.

`phuc_hoi_case2()` còn trả danh sách kết quả, mỗi phần tử có `path`, `cluster_dau_cu`, `cluster_dau_dung`, `size`, `runs`, `sha256`, `da_phuc_hoi`. Đây là dữ liệu hỗ trợ kiểm thử; giao diện CLI gốc không cần thay đổi.

## Phần cần cập nhật trước khi nộp

Minh chứng chương TH2 đã cập nhật theo bộ mẫu và ảnh 12345. Cần mang theo thư mục kết quả/nhật ký khi đóng gói, bổ sung hash gốc của ảnh 12345 khi có, ghi tên/MSSV người thực hiện và bàn giao chương cho người ghép báo cáo PDF chung tối đa 20 trang. Bộ ảnh ẩn chưa có nên không tuyên bố đã kiểm thử ảnh ẩn. Các thư mục `test_*/` được Git bỏ qua; phải chủ động đưa kết quả cần nộp vào gói nộp, không chỉ gửi mã nguồn trên Git.
