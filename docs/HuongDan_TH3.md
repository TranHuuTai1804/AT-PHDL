# Bàn giao Thành viên D - Tình huống 3

## Phạm vi

- `case3.py`: chẩn đoán JPEG bị xóa FAT, tìm hai run, xuất dữ liệu và nhật ký.
- `jpeg.py`: kiểm tra cấu trúc và giải mã entropy JPEG baseline bằng thư viện chuẩn.
- `BaiLam.case3()`: tích hợp với giao diện dòng lệnh gốc.
- `tests/test_case3.py`, `tests/fixtures/`: kiểm thử với JPEG thật.
- `docs/BaoCao_ThanhVienD_TH3.md`: chương báo cáo, cần bổ sung minh chứng ảnh nhóm.

Các tệp khung `recover.py`, `binio.py`, `tienich.py`, `selftest.py` được giữ nguyên. Không sửa lõi FAT32, TH1, TH2 hay đăng ký `repair`.

## Chạy

Đứng tại thư mục `AT-PHDL`:

```powershell
$env:PYTHONUTF8 = '1'
python recover.py --image 'DUONG_DAN\case3.img' --case 3 --out recovered/case3 --log logs/case3.log.jsonl
python -m unittest discover -s tests -v
```

Tạo thư mục chứa log nếu chưa có. Dùng thư mục kết quả mới và tên nhật ký mới cho mỗi lần kiểm chứng vì khung không xóa kết quả cũ và mở log ở chế độ nối thêm.

Kết quả giữ đường dẫn `DATA/<tên gốc>`, chứa cả JPEG mục tiêu và các tệp nguyên vẹn. CLI tạo `SHA256SUMS`. Không có thao tác ghi lên ảnh nguồn.

Khi có đủ bộ mẫu `.img` và `.json`:

```powershell
python selftest.py --mau mau/fat32 --timeout 600
```

## Cách đọc nhật ký

- `TH3: chẩn đoán chuỗi FAT bị xóa`: entry, hexdump, cluster đầu, size, số cluster cần, offset/giá trị ở các bản FAT.
- `TH3: loại ứng viên JPEG`: vị trí chia, cluster đầu run thứ hai, khe và lỗi JPEG cụ thể.
- `TH3: ứng viên giải mã entropy đầy đủ`: hai run, kích thước ảnh, số MCU/block đã kiểm tra.
- `TH3: tổng kết tìm kiếm`: số cặp được xét, số qua lọc EOI, số nghiệm.
- `TH3: chọn duy nhất hai mảnh JPEG`: toàn bộ chuỗi cluster, runs, offset dữ liệu, SHA-256 và lý do chọn.

## Giới hạn cần trình bày

Chỉ nhận đúng một JPEG mất toàn bộ chuỗi FAT trên mọi bản FAT, vẫn giữ cluster đầu/kích thước, phân mảnh thành hai run liên tục với khe từ 1 đến 64 cluster. Hai run phải không giao thư mục/tệp khác và có FAT bằng 0 trên mọi bản.

`jpeg.py` nhận baseline sequential 8-bit Huffman, grayscale hoặc màu, sampling và restart marker. Bộ kiểm tra giải mã các mã DC/AC và tiêu thụ bit hệ số, kiểm đủ block/MCU, byte stuffing, padding, restart, EOI. Không tính IDCT/chuyển màu ra raster. JPEG progressive/arithmetic bị từ chối rõ ràng; không tự coi chúng hợp lệ chỉ nhờ SOI/EOI. Cần kiểm tra chế độ của JPEG thực tế trước khi kết luận hỗ trợ ảnh nhóm.

Không có nghiệm hoặc nhiều nghiệm đều là lỗi; không xuất tệp khi ghép mảnh chưa chắc chắn. Nội dung đúng theo đề vẫn phải được xác nhận bằng SHA-256 bản gốc. Một JPEG giải mã được chưa đảm bảo đó là nội dung gốc.

## Kết quả trên ảnh nhóm và bàn giao

Đã chạy ảnh nhóm 12345 từ `12345.rar`: JPEG `DATA/T01.JPG`, 408.430 byte, runs `[[168, 65], [254, 35]]`, thời gian 74,241 giây. Pillow giải mã JPEG 791 x 791 thành công; hash ảnh nguồn trước/sau không đổi. Không có hash gốc/đáp án trong gói nhóm nên chưa xác nhận khớp nội dung gốc. Chương báo cáo đã bổ sung offset, byte, hình hex thật. Bộ bàn giao ở `handoff/TH3_12345/`. Hình hex được dựng từ byte nguồn, không phải ảnh chụp ứng dụng hex editor. Các bước dưới là hướng dẫn tái kiểm chứng và hoàn thiện bộ nộp chung.

Đã kiểm chứng bộ mẫu chính thức tại `C:\Users\ADMIN\OneDrive\Máy tính\Sample_Image\mau\fat32`: TH3 mục tiêu `DATA/K09.JPG` khớp hash/đường dẫn, hai run `[[172, 33], [226, 38]]` khớp đáp án, cả 5 tệp khớp hash, ảnh nguồn không đổi. Thời gian 28,169 giây; Pillow giải mã JPEG 661 x 661 thành công. Minh chứng: `test_teacher_th3_20261128/recovered/`, `run.jsonl`, `verification.json`. Đây là bộ mẫu công khai, chưa phải ảnh riêng của nhóm.

Kết quả kiểm chứng ngày 28/11/2026: toàn bộ 19 bài kiểm thử TH2/TH3 đạt. Chạy CLI riêng trên volume mô phỏng với JPEG màu 650 x 500, 296.848 byte, 73 cluster (run đầu 33, run sau 40, khe 21 cluster) hoàn tất trong 18,22 giây; mã thoát 0, hash của cả ba tệp khớp, ảnh nguồn không đổi, Pillow giải mã ảnh phục hồi thành pixel thành công. Kết quả tự tạo tại `test_case3_generated/verification.json` được Git bỏ qua và không phải minh chứng ảnh giảng viên. Lần chạy trên dữ liệu khác có thể có thời gian khác.

1. Chạy CLI trên ảnh nhóm; lưu nhật ký và kết quả vào gói nộp.
2. Đối chiếu SHA-256 với bản gốc/đáp án nếu có. Nếu không có, chỉ ghi mức kiểm chứng thực tế.
3. Dùng phần mềm xem ảnh độc lập để mở JPEG; công cụ kiểm chứng không tham gia thuật toán phục hồi.
4. Lấy offset/giá trị/runs thật từ log, bổ sung ảnh chụp hex vào chương báo cáo; không dùng fixture thay cho ảnh nhóm.
5. Điền tên và MSSV D; ghép chương vào PDF chung tối đa 20 trang.
