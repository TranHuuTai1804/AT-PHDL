# Bàn giao phần D - TH3 nhóm 12345

## Nội dung

- `code/`: `case3.py`, `jpeg.py` và `bai_lam.py` đã nối TH3.
- `BaoCao_TH3.md`: chương báo cáo có số liệu ảnh nhóm và minh chứng hex; ghép vào PDF chung tối đa 20 trang.
- `hex/`, `hex_details.json`: byte/offset trích trực tiếp từ ảnh nguồn, hình hex dựng từ byte (không phải ảnh chụp hex editor).
- `recovered/`: 5 tập tin trích xuất, có `SHA256SUMS`.
- `run.jsonl`: nhật ký chạy ảnh nhóm, có chuỗi cluster cuối cùng.
- `verification.json`: hash ảnh nguồn, thời gian, hash các tệp phục hồi và kết quả giải mã độc lập.

## Tích hợp

Dự án nhóm đã có lõi `fat32.py` và khung `binio.py`, `tienich.py`, `recover.py`. Chép thêm `case3.py`, `jpeg.py`; đối chiếu `bai_lam.py` và tích hợp phần `case3()` để không ghi đè thay đổi mới của thành viên khác. Không dùng riêng thư mục `code/` như một dự án độc lập.

```python
def case3(self, img, out):
    from case3 import phuc_hoi_case3
    return phuc_hoi_case3(img, out, self.log)
```

Chạy từ thư mục dự án nhóm, tạo thư mục `logs` trước nếu chưa có:

```powershell
$env:PYTHONUTF8 = '1'
python recover.py --image 'DUONG_DAN\12345\fat32\case3.img' --case 3 --out recovered/case3 --log logs/case3.log.jsonl
```

## Kết quả và giới hạn

Bộ mẫu chính thức: JPEG mục tiêu khớp hash/đường dẫn, hai run trùng đáp án; cả 5 tệp khớp hash, chạy 28,169 giây.

Ảnh nhóm: phục hồi JPEG `DATA/T01.JPG` trong 74,241 giây, hai run `[[168, 65], [254, 35]]`, giải mã JPEG 791 x 791 thành công, ảnh nguồn không đổi. Gói nhóm không có hash gốc/JSON đáp án; chưa thể xác nhận hash khớp bản gốc. Chưa có ảnh ẩn để kiểm chứng.

Chỉ dùng thư viện chuẩn trong phục hồi. Pillow được dùng ngoài chương trình để kiểm chứng giải mã ảnh. Hỗ trợ JPEG baseline Huffman, chưa hỗ trợ progressive/arithmetic.

Nhóm cần điền họ tên/MSSV thành viên D, ghép chương báo cáo và chuẩn bị vấn đáp. Ảnh đĩa 512 MiB không kèm bộ bàn giao nhẹ này; lấy lại từ `12345.rar` của giảng viên.
