"""Tình huống 1 — Sai tham số boot sector (Thành viên B).

Ba trường BPB_SecPerClus (0x0D), BPB_RsvdSecCnt (0x0E), BPB_FATSz32 (0x24) bị ghi giá trị sai
(nhưng hợp lệ về hình thức) ở cả sector 0 lẫn Backup Boot Sector. Mọi cấu trúc khác còn nguyên.

Không tin ba trường đó; suy ra lại từ các cấu trúc còn nguyên:
  1. SB (RsvdSecCnt): sector đầu tiên của FAT#0 = sector đầu tiên có chữ ký FAT[0]/FAT[1]
     (FAT[0] = 0x0FFFFF00 | BPB_Media, FAT[1] là EOC, có thể mang cờ dirty ở bit 27/26).
  2. SF (FATSz32): khoảng cách tới bản FAT kế tiếp có cùng chữ ký, sao cho NumFATs bản FAT
     giống hệt nhau từng byte (FAT là dư thừa của nhau).
  3. SC (SecPerClus): thử mọi luỹ thừa của 2; giá trị đúng khi thư mục con đọc từ thư mục gốc
     bắt đầu bằng '.' (cluster = chính nó) và '..', và độ dài chuỗi FAT của mọi tập tin
     khớp ceil(size / (BytsPerSec*SC)).
Chỉ đọc ảnh đầu vào; không cố định offset hay giá trị nào của ảnh nhóm.
"""
import struct
from dataclasses import replace
from typing import Dict, List, Optional, Tuple

from fat32 import (
    BOOT_SIGNATURE,
    FAT_MASK,
    ThamSo,
    chuoi,
    doc_dot_dotdot,
    doc_fat,
    doc_thu_muc,
    trich_xuat_tat_ca,
)

SC_UNG_VIEN = [1, 2, 4, 8, 16, 32, 64, 128]
MAX_UNG_VIEN_FAT = 256  # giới hạn số vị trí có chữ ký FAT được xét (tránh quét quá lâu)


# ----------------------------------------------------------------------------- bước 0: đọc BPB thô
def _doc_bpb_tho(img, log) -> Tuple[ThamSo, int]:
    """Đọc BPB ở sector 0 mà không kiểm tra hợp lệ (vì 3 trường có thể sai). Trả về (ts_goc, media)."""
    chu_ky = img.u16(0x1FE)
    log.buoc("Đọc chữ ký Boot Sector", offset=0x1FE, gia_tri=f"{chu_ky:#06x}")
    if chu_ky != BOOT_SIGNATURE:
        log.canh_bao("Chữ ký Boot Sector khác 0xAA55", offset=0x1FE, gia_tri=f"{chu_ky:#06x}")

    bps = img.u16(0x0B)
    sc = img.u8(0x0D)
    sb = img.u16(0x0E)
    nf = img.u8(0x10)
    media = img.u8(0x15)
    tot16 = img.u16(0x13)
    tot32 = img.u32(0x20)
    sf = img.u32(0x24)
    root = img.u32(0x2C) & FAT_MASK
    fsinfo = img.u16(0x30)
    bk = img.u16(0x32)
    tot = tot32 if tot32 else tot16

    for ten, off, v in [
        ("BPB_BytsPerSec", 0x0B, bps), ("BPB_SecPerClus (SC, nghi sai)", 0x0D, sc),
        ("BPB_RsvdSecCnt (SB, nghi sai)", 0x0E, sb), ("BPB_NumFATs", 0x10, nf),
        ("BPB_Media", 0x15, f"{media:#04x}"), ("BPB_TotSec32", 0x20, tot32),
        ("BPB_FATSz32 (SF, nghi sai)", 0x24, sf), ("BPB_RootClus", 0x2C, root),
        ("BPB_FSInfo", 0x30, fsinfo), ("BPB_BkBootSec", 0x32, bk),
    ]:
        log.buoc(f"Đọc {ten}", offset=off, gia_tri=v)

    if bps not in (512, 1024, 2048, 4096):
        raise ValueError(f"BPB_BytsPerSec không hợp lệ ({bps}); TH1 giả định trường này còn nguyên")
    if nf < 1:
        raise ValueError(f"BPB_NumFATs không hợp lệ ({nf})")

    # So sánh với Backup Boot Sector: đề cho biết bản sao cũng bị sửa nên không dùng để khôi phục được.
    if 0 < bk and (bk + 1) * bps <= img.kich_thuoc:
        off_bk = bk * bps
        giong = img.doc(0, bps) == img.doc(off_bk, bps)
        log.buoc(
            f"So sánh sector 0 với Backup Boot Sector (sector {bk})",
            offset=off_bk,
            gia_tri={"giong_het": giong, "SC": img.u8(off_bk + 0x0D),
                     "SB": img.u16(off_bk + 0x0E), "SF": img.u32(off_bk + 0x24)},
        )
        if giong:
            log.quyet_dinh("Bản sao giống hệt bản chính nên không dùng để sửa được; "
                           "phải suy ra SC/SB/SF từ cấu trúc khác")

    ts = ThamSo(bps=bps, sc=sc, sb=sb, nf=nf, sf=sf, root_clus=root, tot_sec=tot,
                fsinfo_sec=fsinfo, bkboot_sec=bk)
    return ts, media


# ----------------------------------------------------------------------------- bước 1: tìm SB
def _la_chu_ky_fat(img, off: int, media: Optional[int]) -> bool:
    """FAT[0] = 0x0FFFFF00 | media; FAT[1] = EOC (bit 27 = clean shutdown, bit 26 = hard error có thể bị xoá)."""
    if off + 8 > img.kich_thuoc:
        return False
    f0, f1 = struct.unpack("<II", img.doc(off, 8))
    f0 &= FAT_MASK
    f1 &= FAT_MASK
    if (f0 & 0x0FFFFF00) != 0x0FFFFF00:
        return False
    b = f0 & 0xFF
    if media is not None and b != media:
        return False
    if b != 0xF0 and b < 0xF8:
        return False
    return (f1 | 0x0C000000) == FAT_MASK


def _tim_cac_sector_chu_ky(img, ts: ThamSo, media: int, log) -> List[int]:
    """Quét các sector (bỏ sector 0, FSInfo, Backup Boot + bản sao FSInfo) có chữ ký FAT ở đầu."""
    bps = ts.bps
    bo_qua = {0, ts.fsinfo_sec, ts.bkboot_sec, ts.bkboot_sec + 1}
    ket_thuc = min(img.kich_thuoc, ts.tot_sec * bps if ts.tot_sec else img.kich_thuoc)

    def quet(media_loc):
        mau = bytes([media_loc]) + b"\xff\xff"
        ds = []
        o = bps
        while len(ds) < MAX_UNG_VIEN_FAT:
            o = img.tim(mau, o, ket_thuc, buoc=bps)
            if o < 0:
                break
            s = o // bps
            if s not in bo_qua and _la_chu_ky_fat(img, o, media_loc):
                ds.append(s)
            o += bps
        return ds

    ds = quet(media)
    if not ds:
        log.canh_bao("Không thấy chữ ký FAT khớp BPB_Media, thử mọi giá trị media hợp lệ")
        for m in [0xF8, 0xF0] + list(range(0xF9, 0x100)):
            ds = quet(m)
            if ds:
                break
    log.buoc("Quét các sector bắt đầu bằng chữ ký FAT[0]/FAT[1]",
             gia_tri={"so_vi_tri": len(ds), "sector": ds[:16],
                      "offset": [f"{s * bps:#x}" for s in ds[:16]]})
    return ds


# ----------------------------------------------------------------------------- bước 2: tìm SF
def _tim_sb_sf(img, ts: ThamSo, ung_vien: List[int], log) -> Tuple[int, int]:
    """Chọn (SB, SF) sao cho NumFATs bản FAT bắt đầu tại SB, SB+SF, ... giống hệt nhau."""
    bps, nf = ts.bps, ts.nf
    tap = set(ung_vien)
    for i, sb in enumerate(ung_vien):
        if nf == 1:
            # Không có bản FAT thứ hai để đối chiếu: SF = số sector tới hết vùng FAT không xác định được
            raise RuntimeError("NumFATs = 1: không đủ dư thừa để suy ra BPB_FATSz32 bằng so sánh bản FAT")
        for sb2 in ung_vien[i + 1:]:
            sf = sb2 - sb
            if any((sb + k * sf) not in tap for k in range(1, nf)):
                continue
            if (sb + nf * sf) * bps > img.kich_thuoc:
                break
            ban0 = img.doc(sb * bps, sf * bps)
            if all(img.doc((sb + k * sf) * bps, sf * bps) == ban0 for k in range(1, nf)):
                log.buoc(f"Hai bản FAT giống hệt nhau từng byte với SB={sb}, SF={sf}",
                         offset=sb * bps,
                         gia_tri={"fat0_offset": f"{sb * bps:#x}",
                                  "fat1_offset": f"{(sb + sf) * bps:#x}", "so_byte": sf * bps})
                return sb, sf
            log.buoc(f"Loại cặp SB={sb}, SF={sf}: các bản FAT không giống nhau", offset=(sb + sf) * bps)
    raise RuntimeError("Không tìm được cặp vị trí FAT nào có các bản sao giống hệt nhau")


# ----------------------------------------------------------------------------- bước 3: tìm SC
def _danh_gia_sc(img, ts: ThamSo, fat: List[int]) -> Tuple[int, Dict]:
    """Chấm điểm một giá trị SC: kiểm tra '.'/'..' của thư mục con và độ dài chuỗi của các tập tin."""
    cs = ts.cluster_size
    bang_chung = {"thu_muc_khop": [], "thu_muc_sai": [], "tap_tin_khop": 0, "tap_tin_sai": 0}
    if ts.so_cluster < 1 or ts.data_offset + cs > img.kich_thuoc:
        return -1, bang_chung
    if ts.so_cluster + 2 > ts.sf * ts.bps // 4:
        return -1, bang_chung  # FAT không đủ chỗ cho số cluster này -> SC quá nhỏ

    def kiem_tap_tin(entries):
        for e in entries:
            if e.la_thu_muc or e.kich_thuoc == 0:
                continue
            can = (e.kich_thuoc + cs - 1) // cs
            if len(chuoi(fat, e.cluster_dau & FAT_MASK)) == can:
                bang_chung["tap_tin_khop"] += 1
            else:
                bang_chung["tap_tin_sai"] += 1

    hang_doi = [(ts.root_clus, 0)]
    da_tham = set()
    while hang_doi and len(da_tham) < 64:
        clus, cha = hang_doi.pop(0)
        if clus in da_tham or not ts.cluster_hop_le(clus):
            continue
        da_tham.add(clus)
        cac = chuoi(fat, clus)
        if not cac:
            continue
        try:
            entries = doc_thu_muc(img, ts, cac)
        except ValueError:
            return -1, bang_chung
        kiem_tap_tin(entries)
        for e in entries:
            if not e.la_thu_muc:
                continue
            c = e.cluster_dau & FAT_MASK
            if not ts.cluster_hop_le(c):
                bang_chung["thu_muc_sai"].append(c)
                continue
            dd = doc_dot_dotdot(img, ts.off_cluster(c))
            # '..' của thư mục con trực tiếp của gốc = 0 theo đặc tả (một số công cụ ghi RootClus)
            if dd is not None and dd[0] == c and dd[1] in (cha, ts.root_clus if cha == 0 else cha):
                bang_chung["thu_muc_khop"].append({"cluster": c, "offset_dot": f"{ts.off_cluster(c):#x}"})
                hang_doi.append((c, c))
            else:
                bang_chung["thu_muc_sai"].append(c)

    diem = (100 * len(bang_chung["thu_muc_khop"]) - 100 * len(bang_chung["thu_muc_sai"])
            + 10 * bang_chung["tap_tin_khop"] - 10 * bang_chung["tap_tin_sai"])
    return diem, bang_chung


def _tim_sc(img, ts: ThamSo, log) -> int:
    fat = doc_fat(img, replace(ts, sc=1), k=0)  # đọc đủ mọi mục FAT (SC=1 cho giới hạn rộng nhất)
    ket_qua = []
    for sc in SC_UNG_VIEN:
        if sc * ts.bps > 32 * 1024 * 2:  # cluster > 64 KiB không hợp lệ theo đặc tả
            continue
        t = replace(ts, sc=sc)
        diem, bc = _danh_gia_sc(img, t, fat[: t.max_cluster + 1])
        log.buoc(f"Thử SC={sc}: dữ liệu bắt đầu {t.data_offset:#x}, cluster {t.cluster_size} B",
                 offset=t.data_offset, gia_tri={"diem": diem, **bc})
        ket_qua.append((diem, sc, bc))
    ket_qua.sort(key=lambda x: (x[0], -x[1]), reverse=True)
    diem, sc, bc = ket_qua[0]
    if diem <= 0:
        raise RuntimeError("Không giá trị SC nào cho cấu trúc thư mục nhất quán")
    if len(ket_qua) > 1 and ket_qua[1][0] == diem:
        log.canh_bao("Có nhiều SC cùng điểm cao nhất, chọn giá trị nhỏ nhất",
                     gia_tri=[k[1] for k in ket_qua if k[0] == diem])
    return sc


# ----------------------------------------------------------------------------- chương trình chính TH1
def phuc_hoi_case1(img, out, log):
    ts_goc, media = _doc_bpb_tho(img, log)

    # SB, SF
    ung_vien = _tim_cac_sector_chu_ky(img, ts_goc, media, log)
    if not ung_vien:
        raise RuntimeError("Không tìm thấy bảng FAT nào trên ảnh")
    sb, sf = _tim_sb_sf(img, ts_goc, ung_vien, log)
    log.quyet_dinh(f"BPB_RsvdSecCnt đúng = {sb}: FAT#0 bắt đầu tại sector {sb} (offset {sb * ts_goc.bps:#x})",
                   offset=0x0E, gia_tri_ghi=ts_goc.sb, gia_tri_dung=sb)
    log.quyet_dinh(f"BPB_FATSz32 đúng = {sf}: FAT#1 bắt đầu tại sector {sb + sf} = {sb} + {sf}",
                   offset=0x24, gia_tri_ghi=ts_goc.sf, gia_tri_dung=sf)

    # SC
    ts_sb_sf = replace(ts_goc, sb=sb, sf=sf)
    sc = _tim_sc(img, ts_sb_sf, log)
    ts = replace(ts_sb_sf, sc=sc)
    log.quyet_dinh(
        f"BPB_SecPerClus đúng = {sc}: thư mục con có '.'/'..' đúng vị trí và độ dài chuỗi FAT khớp kích thước",
        offset=0x0D, gia_tri_ghi=ts_goc.sc, gia_tri_dung=sc)

    # Kiểm tra chéo
    can_sf = -(-((ts.so_cluster + 2) * 4) // ts.bps)
    log.buoc("Kiểm tra chéo: FAT đủ chỗ cho mọi cluster",
             gia_tri={"so_cluster": ts.so_cluster, "sf_toi_thieu": can_sf, "sf": sf, "hop_le": can_sf <= sf})
    if can_sf > sf:
        log.canh_bao("SF nhỏ hơn mức tối thiểu tính từ TotSec32 và SC")

    sai = {k: (getattr(ts_goc, k), getattr(ts, k)) for k in ("sc", "sb", "sf") if getattr(ts_goc, k) != getattr(ts, k)}
    log.quyet_dinh("Tổng kết TH1: các trường bị sai (giá trị ghi -> giá trị đúng)",
                   sai={k: f"{a} -> {b}" for k, (a, b) in sai.items()},
                   data_offset=f"{ts.data_offset:#x}", cluster_size=ts.cluster_size)

    fat = doc_fat(img, ts, k=0, log=log)
    trich_xuat_tat_ca(img, ts, fat, out, log=log)
    return ts
