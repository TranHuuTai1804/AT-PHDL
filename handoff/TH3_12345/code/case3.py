"""TH3: tìm hai run JPEG khi FAT của tập tin bị xóa, không ghi ảnh nguồn."""
import hashlib
import time

from fat32 import (FAT_MASK, chuoi, chuoi_thanh_runs, doc_bpb, doc_du_lieu,
                   doc_fat, doc_thu_muc, la_eoc)
from jpeg import LoiJPEG, kiem_tra_jpeg


def _cay(img, ts, fat, log):
    files, used, visited, todo = [], set(), set(), [(ts.root_clus, '')]
    while todo:
        start, prefix = todo.pop()
        if start in visited:
            raise RuntimeError('TH3: cây thư mục lặp')
        visited.add(start)
        clusters = chuoi(fat, start)
        if not clusters or not la_eoc(fat[clusters[-1]]) or used.intersection(clusters):
            raise RuntimeError('TH3: chuỗi thư mục hỏng')
        used.update(clusters)
        log.buoc('TH3: đọc thư mục ' + (prefix or '/'), offset=ts.off_cluster(start),
                 gia_tri={'clusters': clusters})
        for e in doc_thu_muc(img, ts, clusters):
            path = prefix + '/' + e.ten if prefix else e.ten
            if e.la_thu_muc:
                todo.append((e.cluster_dau & FAT_MASK, path))
            else:
                files.append((path, e))
    return files, used


def _tim_hai_manh(img, ts, fats, entry, used, log, deadline):
    start, size, cs = entry.cluster_dau & FAT_MASK, entry.kich_thuoc, ts.cluster_size
    n = (size + cs - 1) // cs
    if n < 2 or start < 2 or start + n > len(fats[0]):
        raise RuntimeError('TH3: cluster đầu/kích thước không phù hợp hai mảnh')
    if not img.doc(ts.off_cluster(start), 2) == b'\xff\xd8':
        raise RuntimeError('TH3: cluster đầu không chứa SOI JPEG')

    def free(c):
        return c not in used and all(c < len(f) and f[c] == 0 for f in fats)

    log.buoc('TH3: chẩn đoán chuỗi FAT bị xóa', offset=entry.offset_entry,
             gia_tri={'start': start, 'size': size, 'cluster_size': cs,
                      'so_cluster_can': n, 'so_cluster_sau_dau': n - 1,
                      'FAT_offsets': [ts.off_fat(k) + start*4 for k in range(ts.nf)],
                      'FAT_values': [f[start] for f in fats],
                      'entry_hex': img.hexdump(entry.offset_entry, 32)})
    valid = []
    tested = filtered = 0
    for first_len in range(1, n):
        if time.monotonic() > deadline:
            raise RuntimeError('TH3: vượt ngân sách thời gian tìm kiếm')
        if not free(start + first_len - 1):
            break
        rest = n - first_len
        prefix = img.doc(ts.off_cluster(start), first_len * cs)
        # Gap = số cluster nằm giữa hai run, từ 1 đến 64 theo phạm vi đề.
        for gap in range(1, 65):
            if time.monotonic() > deadline:
                raise RuntimeError('TH3: vượt ngân sách thời gian tìm kiếm')
            second = start + first_len + gap
            if second + rest > len(fats[0]):
                continue
            if not all(free(c) for c in range(second, second + rest)):
                continue
            tested += 1
            remaining = size - len(prefix)
            end = ts.off_cluster(second) + remaining
            if end > img.kich_thuoc or img.doc(end - 2, 2) != b'\xff\xd9':
                continue
            filtered += 1
            candidate = prefix + img.doc(ts.off_cluster(second), remaining)
            try:
                metadata = kiem_tra_jpeg(candidate, deadline=deadline)
            except LoiJPEG as exc:
                log.buoc('TH3: loại ứng viên JPEG', offset=ts.off_cluster(second),
                         gia_tri={'first_len': first_len, 'second': second, 'gap': gap,
                                  'ly_do': str(exc)})
                continue
            clusters = list(range(start, start + first_len)) + list(range(second, second + rest))
            log.buoc('TH3: ứng viên giải mã entropy đầy đủ', offset=ts.off_cluster(second),
                     gia_tri={'runs': chuoi_thanh_runs(clusters), 'jpeg': metadata})
            valid.append((clusters, candidate, metadata))
            if len(valid) > 1:
                raise RuntimeError('TH3: ghép mảnh mơ hồ, nhiều ứng viên JPEG hợp lệ; không xuất dữ liệu')
    log.buoc('TH3: tổng kết tìm kiếm', gia_tri={'so_cap': tested, 'qua_loc_EOI': filtered,
                                               'so_nghiem': len(valid)})
    if not valid:
        raise RuntimeError('TH3: không tìm được hai mảnh JPEG baseline hợp lệ trong phạm vi 64 cluster')
    return valid[0]


def phuc_hoi_case3(img, out, log):
    deadline = time.monotonic() + 570
    ts = doc_bpb(img, log)
    fats = [doc_fat(img, ts, k=k, log=log) for k in range(ts.nf)]
    fat = fats[0]
    files, used = _cay(img, ts, fat, log)
    healthy, targets = [], []
    for path, e in files:
        start = e.cluster_dau & FAT_MASK
        n = (e.kich_thuoc + ts.cluster_size - 1) // ts.cluster_size
        if n and 2 <= start < len(fat) and all(f[start] == 0 for f in fats):
            if not path.lower().endswith(('.jpg', '.jpeg')):
                raise RuntimeError('TH3: tập tin ngoài JPEG có FAT bị xóa')
            targets.append((path, e))
            continue
        clusters = chuoi(fat, start) if n else []
        if len(clusters) != n or (n and not la_eoc(fat[clusters[-1]])) or used.intersection(clusters):
            raise RuntimeError('TH3: tập tin còn lại không có chuỗi nguyên vẹn: ' + path)
        if any(f[c] != fat[c] for f in fats for c in clusters):
            raise RuntimeError('TH3: các bản FAT không nhất quán: ' + path)
        used.update(clusters)
        healthy.append((path, e, clusters))
    if len(targets) != 1:
        raise RuntimeError(f'TH3: cần đúng một JPEG bị xóa FAT, tìm thấy {len(targets)}')
    path, entry = targets[0]
    clusters, data, jpeg = _tim_hai_manh(img, ts, fats, entry, used, log, deadline)
    rec = {'path': path, 'size': len(data), 'clusters': clusters,
           'runs': chuoi_thanh_runs(clusters), 'sha256': hashlib.sha256(data).hexdigest(),
           'jpeg': jpeg, 'data_offsets': [ts.off_cluster(c) for c in clusters]}
    log.quyet_dinh('TH3: chọn duy nhất hai mảnh JPEG', offset=entry.offset_entry,
                  **rec, ly_do='Đủ kích thước, FAT=0 trên mọi bản, không đè tập tin/thư mục, giải mã đủ MCU và EOI đúng cuối')
    # Chỉ xuất sau khi đã xác định nghiệm duy nhất; giữ cả các tập tin nguyên vẹn.
    for healthy_path, e, chain in healthy:
        payload = doc_du_lieu(img, ts, chain, e.kich_thuoc)
        if len(payload) != e.kich_thuoc:
            raise RuntimeError('TH3: đọc thiếu dữ liệu: ' + healthy_path)
        out.luu(healthy_path, payload)
    out.luu(path, data)
    log.quyet_dinh('TH3: hoàn tất phục hồi', so_tap_tin=len(files), **rec)
    return rec
