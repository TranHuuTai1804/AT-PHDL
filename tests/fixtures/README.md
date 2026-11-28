# JPEG fixtures

Ba ảnh JPEG được tạo từ byte pixel giả ngẫu nhiên với seed `28112026`, bằng Pillow 12.2.0 (chỉ dùng để sinh fixture và kiểm chứng ngoài chương trình phục hồi).

- `baseline_color.jpg`: RGB, 97 x 89, quality 85, sampling mặc định.
- `baseline_gray.jpg`: grayscale, 97 x 89, quality 85.
- `baseline_restart.jpg`: RGB, 97 x 89, quality 85, `restart_marker_blocks=3`.

Các ảnh được sinh liên tiếp từ cùng `random.Random(28112026)`, mỗi byte lấy bằng `randrange(256)`. Chạy kiểm thử chỉ cần các file JPEG đã có và thư viện chuẩn Python; không cần cài Pillow. Không có dữ liệu ảnh nhóm hay đáp án giảng viên trong fixture.
