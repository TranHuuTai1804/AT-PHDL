# Khung chương trình — Đồ án phục hồi dữ liệu

Khung chỉ lo phần "ống nước": dòng lệnh, đọc byte, nhật ký, lưu kết quả, checksum exFAT, tự kiểm tra. **Toàn bộ việc giải mã hệ thống tập tin và phục hồi là phần của nhóm**, viết trong `bai_lam.py` (có thể tách thêm tệp và import).

| Tệp | Nội dung | Được sửa? |
| --- | --- | --- |
| `bai_lam.py` | Lớp `BaiLam`: `info`, `case1`, `case2`, `case3`, `case_ext`, `repair`, `corrupt` | **Có — phần làm bài** |
| `nhom.json` | Mã nhóm, hệ thống, thành viên, phần cộng điểm đăng ký | **Có** |
| `recover.py` | Giao diện dòng lệnh thống nhất | Không |
| `binio.py` | `AnhDia`: đọc u8/u16/u32/u64 (LE/BE), tìm chuỗi byte, hexdump, sao chép để ghi | Không |
| `tienich.py` | `NhatKy`, `ThuMucKetQua`, checksum exFAT | Không |
| `selftest.py` | Chạy chương trình trên bộ ảnh mẫu và so với đáp án mẫu | Không |

Yêu cầu: Python 3.9 trở lên, **chỉ thư viện chuẩn**. Cấm thư viện phân tích hệ thống tập tin (pytsk3, dfvfs, pyfatfs, libfsntfs…) và cấm gọi công cụ ngoài (`subprocess`, `os.system`).

## Dòng lệnh

```
python recover.py --image anh.img --info              # in tham số và danh sách tập tin
python recover.py --image anh.img --info --json       # dạng JSON (giảng viên dùng khi chấm)
python recover.py --image case2.img --case 2 --out ket_qua/
python recover.py --image case1.img --case 1 --out ket_qua/ --repair da_sua.img
python recover.py --image clean.img --corrupt mo_rong.json --out anh_hong.img
python recover.py ... --log nhat_ky.jsonl             # lưu thêm nhật ký ra tệp
```

* `--info --json` phải trả về `{"fs": ..., "cluster_size": ..., "files": [{"path": "DATA/A12.JPG", "size": 123}]}` (chỉ tập tin, không thư mục; đường dẫn tính từ gốc volume, dùng `/`).
* `--case` lưu tập tin bằng `out.luu("DATA/A12.JPG", data)` — giữ đúng đường dẫn gốc; đường dẫn đúng được tính điểm riêng.
* Nhật ký (stderr) là căn cứ đối chiếu với báo cáo: ghi mọi bước quan trọng bằng `self.log.buoc(...)`, mọi lựa chọn bằng `self.log.quyet_dinh(...)`.
* Không bao giờ ghi lên ảnh đầu vào: `--repair` và `--corrupt` phải dùng `img.sao_chep(duong_dan_moi)`.

## Tự kiểm tra

Bộ ảnh mẫu (`mau/<he_thong>/`) được phát kèm đáp án. Chạy:

```
python selftest.py --mau duong_dan/mau/ntfs
```

Kết quả cho biết số tập tin khôi phục đúng nội dung và đúng đường dẫn ở từng tình huống. Giảng viên chấm đúng theo cách này, nhưng trên **ảnh của nhóm và một bộ ảnh ẩn** — vì vậy không được cố định offset, số cluster hay tên tập tin của ảnh mẫu/ảnh nhóm trong mã.

## Phần cộng điểm

Khai báo trong `nhom.json`:

```json
"cong_diem": {"repair": [1, 2], "mo_rong": {"tinh_huong": "ext-size", "dac_ta": "mo_rong.json"}}
```

* `repair`: danh sách tình huống có cài `--repair`. Ảnh sửa được kiểm tra bằng cách đọc lại toàn bộ tập tin và chạy `fsck` chế độ chỉ đọc.
* `mo_rong`: một trong `ext-root`, `ext-size`, `ext-mbr`. `corrupt()` phải trả về danh sách vùng đã sửa, ví dụ `[{"offset": 61468, "length": 4, "cau_truc": "DIR_FileSize của A12.JPG"}]`; `recover.py` tự ghi danh sách này ra `<ảnh hỏng>.changes.json`. Mọi byte thay đổi phải nằm trong các vùng đã khai và không được chạm vùng dữ liệu tập tin. Sau đó `--case ext` sẽ được chạy trên ảnh nhóm tự làm hỏng và trên ảnh ẩn cùng tình huống.

## Phân công mã nguồn (nhóm)

| Tệp / hàm | Người viết | Nội dung |
| --- | --- | --- |
| `fat32.py`, `BaiLam.info()` | A | Lõi giải mã FAT32 dùng chung, `--info` |
| `BaiLam.case_ext()`, `BaiLam.corrupt()`, `mo_rong.json` | A | Cộng điểm `ext-root` |
| `case1.py`, `BaiLam.case1()` | B (Trần Đăng Khoa) | TH1 — suy ra SC/SB/SF từ chữ ký FAT, so khớp 2 bản FAT, '.'/'..' và độ dài chuỗi |
| `case2.py`, `BaiLam.case2()` | C | TH2 — ghép tên ↔ dữ liệu cho entry mất cluster đầu |
| `jpeg.py`, `case3.py`, `BaiLam.case3()` | D | TH3 — ghép hai mảnh, kiểm chứng entropy JPEG baseline |

Sản phẩm chạy trên ảnh nhóm: `recovered/case<N>/` (kèm `SHA256SUMS`) và nhật ký `logs/case<N>.log.jsonl`, tạo bằng:

```
python recover.py --image case1.img --case 1 --out recovered/case1 --log logs/case1.log.jsonl
```

## Phần Thành viên C — TH2

`BaiLam.case2()` đã nối với `case2.py`: chẩn đoán cluster đầu sai, tìm chuỗi mồ côi, ghép một-một theo độ dài/chữ ký/dấu kết thúc và lưu tập tin kèm nhật ký. Lõi `fat32.py` của A được dùng lại. Hàm chỉ sửa ánh xạ trong bộ nhớ, giữ nguyên ảnh đầu vào.

```powershell
$env:PYTHONUTF8 = '1'
python recover.py --image 'DUONG_DAN\case2.img' --case 2 --out ket_qua_th2 --log nhat_ky_th2.jsonl
python -m unittest discover -s tests -v
```

- Hướng dẫn chạy, kiểm chứng và bàn giao: [docs/HuongDan_TH2.md](docs/HuongDan_TH2.md).
- Chương báo cáo TH2 và giới hạn: [docs/BaoCao_ThanhVienC_TH2.md](docs/BaoCao_ThanhVienC_TH2.md).
- Kiểm thử: 11 bài trong `tests/test_case2.py`; bộ mẫu FAT32 của giảng viên đạt `--info` 5/5, TH2 3/3 nội dung và đường dẫn. Ảnh TH2 trong `12345.rar` đã phục hồi ba entry, kiểm chứng định dạng thành công; chưa có hash gốc của gói 12345 để đối chiếu. Kết quả và nhật ký ở `test_teacher_20261126/results/`.
- Chức năng TH2 không đọc các JSON đáp án. Tên thật và MSSV của thành viên C cần được nhóm điền vào `nhom.json` khi đóng gói.

## Phần Thành viên D — TH3

`BaiLam.case3()` gọi `case3.phuc_hoi_case3()`. Chương trình đọc cluster đầu và kích thước từ entry, thử vị trí chia run đầu, tìm run thứ hai sau khe 1–64 cluster, loại vùng đã cấp phát và kiểm tra JPEG bằng `jpeg.py`. Chỉ xuất khi có duy nhất một cách ghép hợp lệ. Không đọc đáp án JSON, không sửa ảnh đầu vào, chỉ dùng thư viện chuẩn.

```powershell
$env:PYTHONUTF8 = '1'
python recover.py --image 'DUONG_DAN\case3.img' --case 3 --out recovered/case3 --log logs/case3.log.jsonl
python -m unittest discover -s tests -v
```

- Hướng dẫn và giới hạn: [docs/HuongDan_TH3.md](docs/HuongDan_TH3.md).
- Chương báo cáo để ghép vào báo cáo chung: [docs/BaoCao_ThanhVienD_TH3.md](docs/BaoCao_ThanhVienD_TH3.md).
- JPEG hỗ trợ: baseline 8-bit Huffman, grayscale/color, sampling, restart marker; giải mã toàn bộ luồng hệ số DC/AC, kiểm tra đủ MCU và EOI. Chưa hỗ trợ progressive/arithmetic và không tạo raster qua IDCT.
- Kiểm thử TH3 dùng JPEG thật đã tạo sẵn trong `tests/fixtures/`; chạy test không cần Pillow. Pillow chỉ được dùng ngoài chương trình để sinh/kiểm chứng fixture.
- Đã kiểm chứng TH3 trên bộ mẫu chính thức ngày 28/11/2026: mục tiêu `DATA/K09.JPG` đúng hash và đường dẫn (1/1); toàn bộ 5 tệp đúng hash, hai run `[[172, 33], [226, 38]]` khớp đáp án, thời gian 28,169 giây, ảnh nguồn không đổi. Minh chứng ở `test_teacher_th3_20261128/` (Git bỏ qua).
- Đã chạy ảnh nhóm 12345: phục hồi `DATA/T01.JPG`, runs `[[168, 65], [254, 35]]`, 74,241 giây; JPEG giải mã được 791 x 791, ảnh nguồn không đổi. Gói nhóm không có hash gốc nên chưa khẳng định khớp bản gốc. Bộ bàn giao phần D ở `handoff/TH3_12345/`; chưa kiểm chứng ảnh ẩn.
