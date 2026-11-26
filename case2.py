"""TH2 (Thành viên C): phục hồi cluster đầu bị sai, không sửa ảnh nguồn.

Chỉ dùng thư viện chuẩn và lõi FAT32 của A. Không đọc đáp án JSON khi phục hồi.
"""
import hashlib
from collections import Counter

from fat32 import (
    chuoi, chuoi_thanh_runs, doc_bpb, doc_du_lieu, doc_fat,
    doc_thu_muc, la_eoc, tim_cac_dau_chuoi,
)


def nhan_dang(data, ten):
    """Trả (hợp lệ, điểm, tiêu chí) theo phần mở rộng và biên tập tin.

    Chữ ký là bộ lọc TH2, không phải bộ giải mã đầy đủ JPEG/PNG/PDF.
    Định dạng chưa hỗ trợ chỉ được đánh giá theo độ dài chuỗi ở bước gọi.
    """
    ext = ten.rsplit('.', 1)[-1].lower() if '.' in ten else ''
    if ext in ('jpg', 'jpeg'):
        dau = data.startswith(b'\xff\xd8\xff')
        cuoi = data.endswith(b'\xff\xd9')
    elif ext == 'png':
        dau = data.startswith(b'\x89PNG\r\n\x1a\n')
        cuoi = data.endswith(b'\x00\x00\x00\x00IEND\xaeB`\x82')
    elif ext == 'pdf':
        dau = data.startswith(b'%PDF-')
        cuoi = data[-1024:].rstrip(b' \t\r\n\x0c\x00').endswith(b'%%EOF')
    elif ext == 'txt':
        try:
            encoding = 'utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
            van_ban = data.decode(encoding)
            dau = bool(van_ban) and all(c.isprintable() or c in '\t\r\n\f' for c in van_ban)
        except UnicodeError:
            dau = False
        return dau, 40 if dau else 0, {'van_ban_hop_le': dau}
    else:
        return True, 0, {'dinh_dang': 'chua_ho_tro', 'chi_kiem_tra_do_dai': True}
    return dau and cuoi, 50 if dau and cuoi else 0, {'chu_ky_dau': dau, 'dau_ket_thuc': cuoi}


def _doc_cay(img, ts, fat, log):
    """Lấy tập tin và đánh dấu TOÀN BỘ cluster thư mục, kể cả thư mục nhiều cluster."""
    tep, thu_muc = [], set()
    cho_doc = [(ts.root_clus, '')]
    da_doc = set()
    while cho_doc:
        dau, tien_to = cho_doc.pop()
        if dau in da_doc:
            raise RuntimeError('Cây thư mục lặp hoặc nhiều thư mục dùng chung cluster')
        da_doc.add(dau)
        cac = chuoi(fat, dau)
        if not cac or not la_eoc(fat[cac[-1]]) or thu_muc.intersection(cac):
            raise RuntimeError('Chuỗi thư mục không nguyên vẹn; nằm ngoài phạm vi TH2')
        thu_muc.update(cac)
        log.buoc(f"TH2: đọc thư mục '{tien_to or '/'}'", offset=ts.off_cluster(dau),
                 gia_tri={'runs': chuoi_thanh_runs(cac)})
        for e in doc_thu_muc(img, ts, cac):
            path = f'{tien_to}/{e.ten}' if tien_to else e.ten
            if e.la_thu_muc:
                cho_doc.append((e.cluster_dau, path))
            else:
                tep.append((path, e))
                log.buoc(f'TH2: entry {path}', offset=e.offset_entry,
                         gia_tri={'size': e.kich_thuoc, 'cluster_dau_tho': e.cluster_dau,
                                  'HI_offset': e.offset_entry + 0x14,
                                  'HI': img.u16(e.offset_entry + 0x14),
                                  'LO_offset': e.offset_entry + 0x1A,
                                  'LO': img.u16(e.offset_entry + 0x1A),
                                  'hexdump': img.hexdump(e.offset_entry, 32)})
    return tep, thu_muc


def _cham_diem(img, ts, e, cac):
    can = (e.kich_thuoc + ts.cluster_size - 1) // ts.cluster_size
    if len(cac) != can or not cac:
        return None
    data = doc_du_lieu(img, ts, cac, e.kich_thuoc)
    if len(data) != e.kich_thuoc:
        return None
    ok, diem, tieu_chi = nhan_dang(data, e.ten)
    if not ok:
        return None
    du = e.kich_thuoc % ts.cluster_size
    slack_zero = None
    if du:
        slack = img.doc(ts.off_cluster(cac[-1]) + du, ts.cluster_size - du)
        slack_zero = not any(slack)
    tieu_chi = dict(tieu_chi, so_cluster=len(cac), size=e.kich_thuoc,
                    slack_toan_0=slack_zero)
    return 10 + diem + int(slack_zero is True), tieu_chi


def chon_phep_ghep(cac_cap):
    """Ghép một-một có tổng điểm lớn nhất; từ chối nếu có nhiều nghiệm tối ưu.

    cac_cap[i] = {cluster_đầu: (điểm, tiêu_chí)}. TH2 có ít entry hỏng,
    dùng tìm kiếm nhánh-cận, ưu tiên entry ít ứng viên, không chọn tham lam.
    """
    thu_tu = sorted(cac_cap, key=lambda i: len(cac_cap[i]))
    if any(not cac_cap[i] for i in thu_tu):
        raise RuntimeError('TH2: có entry không có chuỗi ứng viên phù hợp')
    tran = [0] * (len(thu_tu) + 1)
    for p in range(len(thu_tu) - 1, -1, -1):
        tran[p] = tran[p + 1] + max(v[0] for v in cac_cap[thu_tu[p]].values())
    diem_tot, so_nghiem, tot = -1, 0, None

    def thu(p, da_dung, diem, gan):
        nonlocal diem_tot, so_nghiem, tot
        if so_nghiem >= 2 and diem_tot == tran[0]:
            return
        if diem + tran[p] < diem_tot:
            return
        if p == len(thu_tu):
            if diem > diem_tot:
                diem_tot, so_nghiem, tot = diem, 1, dict(gan)
            elif diem == diem_tot:
                so_nghiem = min(2, so_nghiem + 1)
            return
        i = thu_tu[p]
        for dau, (diem_cap, _) in sorted(cac_cap[i].items(), key=lambda kv: -kv[1][0]):
            if dau not in da_dung:
                gan[i] = dau
                thu(p + 1, da_dung | {dau}, diem + diem_cap, gan)
                del gan[i]

    thu(0, set(), 0, {})
    if tot is None:
        raise RuntimeError('TH2: không có phép ghép một-một đầy đủ')
    if so_nghiem != 1:
        raise RuntimeError('TH2: phép ghép còn mơ hồ (nhiều nghiệm cùng điểm); cần thêm minh chứng nội dung')
    return tot


def phuc_hoi_case2(img, out, log):
    ts = doc_bpb(img, log)
    fat = doc_fat(img, ts, log=log)
    tep, thu_muc = _doc_cay(img, ts, fat, log)
    dau_chuoi = tim_cac_dau_chuoi(fat)
    cac_chuoi = {}
    for dau in dau_chuoi:
        cac = chuoi(fat, dau)
        if cac and la_eoc(fat[cac[-1]]) and not thu_muc.intersection(cac):
            cac_chuoi[dau] = cac
    # Loại chuỗi bị nối chéo: khác giả thiết 'chỉ hỏng directory entry'.
    tan_suat = Counter(c for cac in cac_chuoi.values() for c in cac)
    cac_chuoi = {dau: cac for dau, cac in cac_chuoi.items()
                 if all(tan_suat[c] == 1 for c in cac)}
    log.buoc('TH2: tìm đầu chuỗi FAT, giữ chuỗi kết thúc EOC, loại thư mục/nối chéo',
             offset=ts.off_fat(), gia_tri={'so_dau_chuoi': len(dau_chuoi),
                                         'ung_vien': list(cac_chuoi)})

    so_tham_chieu = Counter(e.cluster_dau for _, e in tep if e.kich_thuoc > 0)
    gan, nghi_ngo, da_dung = {}, [], set()
    for i, (path, e) in enumerate(tep):
        ly_do = []
        if e.kich_thuoc == 0:
            if e.cluster_dau != 0:
                ly_do.append('tập tin rỗng nhưng cluster đầu khác 0')
            gan[i] = None
        else:
            cac = cac_chuoi.get(e.cluster_dau)
            if not 2 <= e.cluster_dau < len(fat):
                ly_do.append('cluster đầu bằng 0/1 hoặc nằm ngoài vùng dữ liệu')
            elif e.cluster_dau in thu_muc:
                ly_do.append('cluster đầu trỏ vào một thư mục')
            elif fat[e.cluster_dau] == 0:
                ly_do.append('cluster đầu trỏ vào cluster trống (FAT = 0)')
            elif cac is None:
                ly_do.append('cluster đầu không phải đầu chuỗi tập tin nguyên vẹn')
            elif len(cac) != (e.kich_thuoc + ts.cluster_size - 1) // ts.cluster_size:
                ly_do.append('độ dài chuỗi không khớp kích thước')
            elif _cham_diem(img, ts, e, cac) is None:
                ly_do.append('chữ ký đầu hoặc dấu kết thúc không khớp định dạng')
            if e.cluster_dau >= 2 and so_tham_chieu[e.cluster_dau] > 1:
                ly_do.append('nhiều entry tham chiếu cùng cluster đầu')
            if ly_do:
                nghi_ngo.append(i)
            else:
                gan[i] = e.cluster_dau
                da_dung.add(e.cluster_dau)
        log.buoc(f'TH2: chẩn đoán {path}', offset=e.offset_entry + 0x1A,
                 gia_tri={'cluster_dau_cu': e.cluster_dau, 'nghi_ngo': bool(ly_do),
                          'ly_do': ly_do or ['entry và nội dung hiện tại phù hợp']})

    mo_coi = {dau: cac for dau, cac in cac_chuoi.items() if dau not in da_dung}
    log.buoc('TH2: các chuỗi mồ côi/chuỗi cần đối chiếu lại', offset=ts.off_fat(),
             gia_tri=[{'dau': dau, 'runs': chuoi_thanh_runs(cac)} for dau, cac in mo_coi.items()])
    cac_cap = {}
    for i in nghi_ngo:
        path, e = tep[i]
        cac_cap[i] = {}
        for dau, cac in mo_coi.items():
            kq = _cham_diem(img, ts, e, cac)
            if kq is not None:
                cac_cap[i][dau] = kq
                log.buoc(f'TH2: cặp ứng viên cho {path}', offset=ts.off_cluster(dau),
                         gia_tri={'cluster_dau': dau, 'diem': kq[0], 'tieu_chi': kq[1]})
    try:
        phuc_hoi = chon_phep_ghep(cac_cap)
    except RuntimeError as exc:
        log.canh_bao(str(exc), so_entry_nghi_ngo=len(nghi_ngo))
        raise
    gan.update(phuc_hoi)
    # Chỉ lưu sau khi đã xác định được phép ghép đầy đủ, duy nhất.
    ket_qua = []
    for i, (path, e) in enumerate(tep):
        dau = gan[i]
        cac = cac_chuoi[dau] if dau is not None else []
        data = doc_du_lieu(img, ts, cac, e.kich_thuoc)
        if len(data) != e.kich_thuoc:
            raise RuntimeError(f'TH2: đọc thiếu dữ liệu của {path}')
        rec = {'path': path, 'cluster_dau_cu': e.cluster_dau,
               'cluster_dau_dung': dau or 0, 'size': len(data),
               'runs': chuoi_thanh_runs(cac), 'sha256': hashlib.sha256(data).hexdigest(),
               'da_phuc_hoi': i in phuc_hoi}
        if i in phuc_hoi:
            diem, tieu_chi = cac_cap[i][dau]
            log.quyet_dinh(f'TH2: ghép {path} với chuỗi bắt đầu tại {dau}',
                          offset=e.offset_entry, **rec, diem=diem, tieu_chi=tieu_chi,
                          FAT_offset=ts.off_fat() + dau * 4,
                          data_offset=ts.off_cluster(dau),
                          hexdump_dau=img.hexdump(ts.off_cluster(dau), min(32, ts.cluster_size)))
        out.luu(path, data)
        log.buoc(f'TH2: đã lưu {path}', offset=e.offset_entry, gia_tri=rec)
        ket_qua.append(rec)
    log.quyet_dinh('TH2: hoàn tất phục hồi', so_tap_tin=len(tep),
                  so_entry_phuc_hoi=len(phuc_hoi))
    return ket_qua
