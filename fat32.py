"""Lõi giải mã hệ thống tập tin FAT32 dùng chung cho toàn nhóm (Thành viên A).

Chỉ sử dụng thư viện chuẩn của Python và khung chương trình (binio, tienich).
Mọi hàm đọc dữ liệu đều đi qua đối tượng ThamSo (không tự đọc cứng lại BPB),
nhằm tái sử dụng trực tiếp cho --info, TH1, TH2, TH3 và phần mở rộng.
"""
from dataclasses import dataclass
import struct
from typing import List, Optional, Set, Tuple

# Các hằng số đặc tả Microsoft FAT32 (fatgen103)
FAT_MASK = 0x0FFFFFFF
FAT_FREE = 0x00000000
FAT_MAX_VALID = 0x0FFFFFEF
FAT_BAD = 0x0FFFFFF7
FAT_EOC_MIN = 0x0FFFFFF8
FAT_EOC_MAX = 0x0FFFFFFF

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LONG_NAME = 0x0F
ATTR_LONG_NAME_MASK = 0x3F

NTRES_LOWER_BASE = 0x08
NTRES_LOWER_EXT = 0x10

BOOT_SIGNATURE = 0xAA55

# Tập ký tự bị cấm trong tên ngắn 8.3 theo đặc tả FAT
_SHORT_FORBIDDEN = set(b'"*+,./:;<=>?[\\]|')


def la_eoc(gia_tri: int) -> bool:
    """Kiểm tra giá trị mục FAT (đã hoặc chưa mask) có phải dấu kết thúc chuỗi (EOC)."""
    return (gia_tri & FAT_MASK) >= FAT_EOC_MIN


def la_cluster_trong(gia_tri: int) -> bool:
    """Kiểm tra mục FAT có biểu diễn cluster trống hay không."""
    return (gia_tri & FAT_MASK) == FAT_FREE


def tinh_lfn_checksum(short_name_11: bytes) -> int:
    """Tính checksum 1 byte của 11 byte tên ngắn 8.3 để đối chiếu với entry LFN."""
    if len(short_name_11) != 11:
        raise ValueError("Tên ngắn 8.3 phải đúng 11 byte")
    s = 0
    for b in short_name_11:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def chuoi_thanh_runs(cac_cluster: List[int]) -> List[List[int]]:
    """Gom danh sách các cluster thành danh sách các đoạn liên tiếp [[cluster_dau, so_luong], ...]."""
    if not cac_cluster:
        return []
    runs: List[List[int]] = []
    bat_dau = cac_cluster[0]
    do_dai = 1
    for c in cac_cluster[1:]:
        if c == bat_dau + do_dai:
            do_dai += 1
        else:
            runs.append([bat_dau, do_dai])
            bat_dau = c
            do_dai = 1
    runs.append([bat_dau, do_dai])
    return runs


@dataclass
class ThamSo:
    """Tham số bố cục của một volume FAT32.

    Thứ tự 7 trường đầu giữ đúng hợp đồng giao diện nhóm:
    (bps, sc, sb, nf, sf, root_clus, tot_sec).
    """
    bps: int
    sc: int
    sb: int
    nf: int
    sf: int
    root_clus: int
    tot_sec: int
    base_offset: int = 0
    fsinfo_sec: int = 1
    bkboot_sec: int = 6

    @property
    def cluster_size(self) -> int:
        return self.bps * self.sc

    @property
    def first_data_sector(self) -> int:
        return self.sb + self.nf * self.sf

    @property
    def data_offset(self) -> int:
        return self.base_offset + self.first_data_sector * self.bps

    @property
    def unit_base(self) -> int:
        return self.data_offset - 2 * self.cluster_size

    @property
    def so_cluster(self) -> int:
        if self.sc <= 0 or self.tot_sec <= self.first_data_sector:
            return 0
        return (self.tot_sec - self.first_data_sector) // self.sc

    @property
    def max_cluster(self) -> int:
        return self.so_cluster + 1

    def off_sector(self, sector: int) -> int:
        """Offset byte tuyệt đối của một sector tính từ đầu volume."""
        if sector < 0:
            raise ValueError(f"Chỉ số sector không hợp lệ: {sector}")
        return self.base_offset + sector * self.bps

    def off_fat(self, k: int = 0) -> int:
        """Offset byte tuyệt đối của bảng FAT thứ k (0 <= k < nf)."""
        if k < 0 or k >= self.nf:
            raise ValueError(f"Chỉ số bảng FAT ngoài phạm vi: {k} (nf={self.nf})")
        return self.base_offset + (self.sb + k * self.sf) * self.bps

    def off_cluster(self, n: int) -> int:
        """Offset byte tuyệt đối của cluster thứ n (cluster đánh số từ 2)."""
        if n < 2:
            raise ValueError(f"Chỉ số cluster không hợp lệ (phải >= 2): {n}")
        return self.base_offset + (self.first_data_sector + (n - 2) * self.sc) * self.bps

    def cluster_hop_le(self, n: int) -> bool:
        """Kiểm tra chỉ số cluster n có nằm trong vùng Data hợp lệ của volume."""
        return 2 <= n <= self.max_cluster


@dataclass
class Entry:
    """Biểu diễn một mục thư mục (directory entry) của tập tin hoặc thư mục con."""
    ten: str
    thuoc_tinh: int
    cluster_dau: int
    kich_thuoc: int
    offset_entry: int
    la_thu_muc: bool
    ten_ngan_raw: bytes = b""
    nt_res: int = 0
    co_lfn: bool = False

    @property
    def la_tap_tin(self) -> bool:
        return not self.la_thu_muc


def doc_bpb(img, log=None, base_offset: int = 0) -> ThamSo:
    """Đọc Boot Sector / BPB tại base_offset và tạo đối tượng ThamSo."""
    chu_ky = img.u16(base_offset + 0x1FE)
    if log:
        log.buoc("Đọc chữ ký Boot Sector (0x1FE)", offset=base_offset + 0x1FE, gia_tri=f"{chu_ky:#06x}")
        if chu_ky != BOOT_SIGNATURE:
            log.canh_bao("Chữ ký Boot Sector khác 0xAA55", offset=base_offset + 0x1FE, gia_tri=f"{chu_ky:#06x}")

    bps = img.u16(base_offset + 0x0B)
    sc = img.u8(base_offset + 0x0D)
    sb = img.u16(base_offset + 0x0E)
    nf = img.u8(base_offset + 0x10)
    tot16 = img.u16(base_offset + 0x13)
    tot32 = img.u32(base_offset + 0x20)
    sf = img.u32(base_offset + 0x24)
    root_clus = img.u32(base_offset + 0x2C) & FAT_MASK
    fsinfo_sec = img.u16(base_offset + 0x30)
    bkboot_sec = img.u16(base_offset + 0x32)

    tot_sec = tot32 if tot32 != 0 else tot16

    if log:
        log.buoc("Đọc BPB_BytsPerSec", offset=base_offset + 0x0B, gia_tri=bps)
        log.buoc("Đọc BPB_SecPerClus (SC)", offset=base_offset + 0x0D, gia_tri=sc)
        log.buoc("Đọc BPB_RsvdSecCnt (SB)", offset=base_offset + 0x0E, gia_tri=sb)
        log.buoc("Đọc BPB_NumFATs (NF)", offset=base_offset + 0x10, gia_tri=nf)
        if tot32 != 0:
            log.buoc("Đọc BPB_TotSec32 (SV)", offset=base_offset + 0x20, gia_tri=tot32)
        else:
            log.buoc("Đọc BPB_TotSec16 (SV)", offset=base_offset + 0x13, gia_tri=tot16)
        log.buoc("Đọc BPB_FATSz32 (SF)", offset=base_offset + 0x24, gia_tri=sf)
        log.buoc("Đọc BPB_RootClus", offset=base_offset + 0x2C, gia_tri=root_clus)
        log.buoc("Đọc BPB_FSInfo", offset=base_offset + 0x30, gia_tri=fsinfo_sec)
        log.buoc("Đọc BPB_BkBootSec", offset=base_offset + 0x32, gia_tri=bkboot_sec)

    if bps <= 0 or (bps & (bps - 1)) != 0:
        raise ValueError(f"BPB_BytsPerSec không hợp lệ: {bps}")
    if sc <= 0 or (sc & (sc - 1)) != 0:
        raise ValueError(f"BPB_SecPerClus không hợp lệ: {sc}")
    if nf <= 0:
        raise ValueError(f"BPB_NumFATs không hợp lệ: {nf}")

    ts = ThamSo(
        bps=bps,
        sc=sc,
        sb=sb,
        nf=nf,
        sf=sf,
        root_clus=root_clus,
        tot_sec=tot_sec,
        base_offset=base_offset,
        fsinfo_sec=fsinfo_sec,
        bkboot_sec=bkboot_sec,
    )

    if log:
        log.buoc(
            "Tính bố cục volume từ BPB",
            offset=ts.data_offset,
            gia_tri={
                "cluster_size": ts.cluster_size,
                "fat0_offset": f"{ts.off_fat(0):#x}",
                "data_offset": f"{ts.data_offset:#x}",
                "so_cluster": ts.so_cluster,
            },
        )
    return ts


def doc_fat(img, ts: ThamSo, k: int = 0, log=None) -> List[int]:
    """Đọc toàn bộ bảng FAT thứ k một lần và áp mặt nạ 28-bit (0x0FFFFFFF).

    Mảng trả về được giới hạn đúng tới chỉ số max_cluster hợp lệ của vùng Data
    (nhưng vẫn giữ FAT[0] và FAT[1]), đảm bảo mọi chỉ số 2 <= c < len(fat) đều
    nằm trong vùng dữ liệu hợp lệ trên đĩa.
    """
    off = ts.off_fat(k)
    n_bytes = ts.sf * ts.bps
    if off + n_bytes > img.kich_thuoc:
        n_bytes = max(0, img.kich_thuoc - off)
    n_slots = n_bytes // 4
    raw_bytes = img.doc(off, n_slots * 4)
    raw_vals = struct.unpack(f"<{n_slots}I", raw_bytes)

    # Giới hạn theo số cluster thực sự tồn tại trên volume và trong phạm vi file ảnh
    if ts.cluster_size > 0 and img.kich_thuoc > ts.data_offset:
        max_by_img = 1 + (img.kich_thuoc - ts.data_offset) // ts.cluster_size
    else:
        max_by_img = 1
    gioi_han = min(n_slots, ts.max_cluster + 1, max_by_img + 1)
    gioi_han = max(gioi_han, min(2, n_slots))

    fat = [v & FAT_MASK for v in raw_vals[:gioi_han]]
    if log:
        fat0 = f"{fat[0]:#010x}" if len(fat) > 0 else None
        fat1 = f"{fat[1]:#010x}" if len(fat) > 1 else None
        log.buoc(
            f"Đọc bảng FAT{k}",
            offset=off,
            gia_tri={"so_muc": len(fat), "FAT0": fat0, "FAT1": fat1},
        )
    return fat


def chuoi(fat: List[int], dau: int) -> List[int]:
    """Lần theo chuỗi cluster trong bảng FAT bắt đầu từ `dau`.

    Dừng khi gặp EOC (>= 0x0FFFFFF8), cluster trống (0), cluster hỏng (0x0FFFFFF7),
    chỉ số ngoài phạm vi hoặc phát hiện vòng lặp.
    """
    if dau < 2 or dau >= len(fat):
        return []

    ket_qua: List[int] = []
    da_tham: Set[int] = set()
    hien_tai = dau

    while 2 <= hien_tai < len(fat) and hien_tai not in da_tham:
        muc_tiep = fat[hien_tai] & FAT_MASK
        if muc_tiep == FAT_FREE or muc_tiep == FAT_BAD:
            break
        ket_qua.append(hien_tai)
        da_tham.add(hien_tai)
        if muc_tiep >= FAT_EOC_MIN:
            break
        if muc_tiep < 2 or muc_tiep > FAT_MAX_VALID or muc_tiep >= len(fat):
            break
        hien_tai = muc_tiep

    return ket_qua


def _trich_doan_lfn(raw_entry: bytes) -> str:
    """Trích tối đa 13 ký tự UTF-16LE từ một entry LFN 32 byte."""
    manh_bytes = raw_entry[0x01:0x0B] + raw_entry[0x0E:0x1A] + raw_entry[0x1C:0x20]
    code_units = struct.unpack("<13H", manh_bytes)
    hop_le: List[int] = []
    for cu in code_units:
        if cu == 0x0000 or cu == 0xFFFF:
            break
        hop_le.append(cu)
    if not hop_le:
        return ""
    return struct.pack(f"<{len(hop_le)}H", *hop_le).decode("utf-16-le", errors="replace")


def _giai_ma_ten_ngan(raw_11: bytes, nt_res: int) -> str:
    """Giải mã tên ngắn 8.3 kèm xử lý byte 0x05 và cờ viết thường ở DIR_NTRes (0x0C)."""
    raw_base = (b"\xE5" + raw_11[1:8]) if raw_11[0] == 0x05 else raw_11[0:8]
    raw_ext = raw_11[8:11]

    base = raw_base.rstrip(b" ").decode("latin-1")
    ext = raw_ext.rstrip(b" ").decode("latin-1")

    if nt_res & NTRES_LOWER_BASE:
        base = base.lower()
    if nt_res & NTRES_LOWER_EXT:
        ext = ext.lower()

    return f"{base}.{ext}" if ext else base


def doc_dot_dotdot(img, offset_cluster: int) -> Optional[Tuple[int, int]]:
    """Kiểm tra 2 entry đầu tại `offset_cluster` có phải `.` và `..` của thư mục con không.

    Trả về `(cluster_dot, cluster_dotdot)` nếu khớp, ngược lại trả về `None`.
    Hữu ích cho TH1 (tìm thư mục con DATA) và phần mở rộng `ext-root`.
    """
    if offset_cluster < 0 or offset_cluster + 64 > img.kich_thuoc:
        return None
    buf = img.doc(offset_cluster, 64)
    e1, e2 = buf[0:32], buf[32:64]
    if e1[0:11] != b".          " or (e1[0x0B] & ATTR_DIRECTORY) == 0:
        return None
    if e2[0:11] != b"..         " or (e2[0x0B] & ATTR_DIRECTORY) == 0:
        return None
    c_dot = (struct.unpack_from("<H", e1, 0x14)[0] << 16) | struct.unpack_from("<H", e1, 0x1A)[0]
    c_dotdot = (struct.unpack_from("<H", e2, 0x14)[0] << 16) | struct.unpack_from("<H", e2, 0x1A)[0]
    return c_dot & FAT_MASK, c_dotdot & FAT_MASK


def doc_thu_muc(img, ts: ThamSo, cac_cluster: List[int]) -> List[Entry]:
    """Đọc toàn bộ các entry hợp lệ từ danh sách cluster của một thư mục.

    - Ghép tên dài LFN (có đối chiếu checksum và thứ tự mảnh, hỗ trợ LFN vắt qua 2 cluster).
    - Giải mã tên ngắn 8.3 và cờ viết thường DIR_NTRes (0x0C).
    - Bỏ qua entry đã xóa (0xE5), nhãn volume (0x08), `.` và `..`.
    - Dừng ngay khi gặp byte đầu 0x00 (hết bảng thư mục).
    - Giữ nguyên `cluster_dau` thô đọc từ (HI << 16) | LO để phục vụ chẩn đoán TH2.
    """
    ket_qua: List[Entry] = []
    cs = ts.cluster_size

    # Trạng thái gom các mảnh LFN đứng trước short entry
    lfn_parts: Optional[List[str]] = None
    lfn_chksum: int = -1
    lfn_next_seq: int = 0

    for c in cac_cluster:
        off_c = ts.off_cluster(c)
        if off_c + cs > img.kich_thuoc:
            break
        data_c = img.doc(off_c, cs)

        for pos in range(0, cs, 32):
            raw = data_c[pos:pos + 32]
            slot_off = off_c + pos
            b0 = raw[0]

            # 0x00: kết thúc bảng thư mục
            if b0 == 0x00:
                return ket_qua

            # 0xE5: entry đã xóa -> bỏ qua và hủy chuỗi LFN dở dang
            if b0 == 0xE5:
                lfn_parts = None
                lfn_chksum = -1
                lfn_next_seq = 0
                continue

            attr = raw[0x0B]

            # Entry phụ LFN (0x0F)
            if (attr & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME:
                ldir_type = raw[0x0C]
                chksum = raw[0x0D]
                fst_lo = struct.unpack_from("<H", raw, 0x1A)[0]
                seq = b0 & 0x3F
                la_manh_cuoi = (b0 & 0x40) != 0

                if ldir_type != 0 or fst_lo != 0 or seq == 0:
                    lfn_parts = None
                    continue

                doan = _trich_doan_lfn(raw)
                if la_manh_cuoi:
                    lfn_parts = [doan]
                    lfn_chksum = chksum
                    lfn_next_seq = seq - 1
                elif lfn_parts is not None and seq == lfn_next_seq and chksum == lfn_chksum:
                    lfn_parts.append(doan)
                    lfn_next_seq -= 1
                else:
                    lfn_parts = None
                continue

            # Short entry (8.3): lấy và reset trạng thái LFN trước khi lọc
            cur_lfn_parts = lfn_parts if (lfn_parts is not None and lfn_next_seq == 0) else None
            cur_lfn_chksum = lfn_chksum
            lfn_parts = None
            lfn_chksum = -1
            lfn_next_seq = 0

            # Bỏ qua nhãn volume (Volume ID)
            if attr & ATTR_VOLUME_ID:
                continue

            ten_ngan_11 = raw[0:11]
            # Bỏ qua mục `.` và `..`
            if ten_ngan_11 in (b".          ", b"..         "):
                continue

            nt_res = raw[0x0C]
            if cur_lfn_parts is not None and tinh_lfn_checksum(ten_ngan_11) == cur_lfn_chksum:
                ten = "".join(reversed(cur_lfn_parts))
                co_lfn = True
            else:
                ten = _giai_ma_ten_ngan(ten_ngan_11, nt_res)
                co_lfn = False

            hi = struct.unpack_from("<H", raw, 0x14)[0]
            lo = struct.unpack_from("<H", raw, 0x1A)[0]
            cluster_dau = (hi << 16) | lo
            kich_thuoc = struct.unpack_from("<I", raw, 0x1C)[0]
            la_thu_muc = (attr & ATTR_DIRECTORY) != 0

            ket_qua.append(
                Entry(
                    ten=ten,
                    thuoc_tinh=attr,
                    cluster_dau=cluster_dau,
                    kich_thuoc=kich_thuoc,
                    offset_entry=slot_off,
                    la_thu_muc=la_thu_muc,
                    ten_ngan_raw=ten_ngan_11,
                    nt_res=nt_res,
                    co_lfn=co_lfn,
                )
            )

    return ket_qua


def duyet_cay(img, ts: ThamSo, fat: List[int], log=None) -> List[Tuple[str, Entry]]:
    """Duyệt đệ quy cây thư mục từ `ts.root_clus` và trả về danh sách `(duong_dan, Entry)` của mọi tập tin.

    Đường dẫn tính từ gốc volume, phân tách bằng `/` (ví dụ `"DATA/A12.JPG"`).
    Có chống vòng lặp thư mục qua tập các cluster đầu thư mục đã thăm.
    """
    tap_tin: List[Tuple[str, Entry]] = []
    da_tham_dir: Set[int] = set()

    def _duyet(clus_dau: int, tien_to: str) -> None:
        clus_sach = clus_dau & FAT_MASK
        if clus_sach < 2 or clus_sach in da_tham_dir or not ts.cluster_hop_le(clus_sach):
            if log and clus_sach not in da_tham_dir:
                log.canh_bao(
                    f"Cluster đầu thư mục không hợp lệ khi duyệt '{tien_to or '/'}'",
                    gia_tri=clus_dau,
                )
            return

        da_tham_dir.add(clus_sach)
        cac_clus = chuoi(fat, clus_sach)
        if not cac_clus:
            if log:
                log.canh_bao(
                    f"Chuỗi FAT của thư mục '{tien_to or '/'}' rỗng",
                    offset=ts.off_cluster(clus_sach),
                    gia_tri=clus_sach,
                )
            return

        if log:
            log.buoc(
                f"Đọc thư mục '{tien_to or '/'}'",
                offset=ts.off_cluster(cac_clus[0]),
                gia_tri={"cluster_dau": clus_sach, "runs": chuoi_thanh_runs(cac_clus)},
            )

        muc_con = doc_thu_muc(img, ts, cac_clus)
        for e in muc_con:
            duong_dan = f"{tien_to}/{e.ten}" if tien_to else e.ten
            if e.la_thu_muc:
                if log:
                    log.buoc(
                        f"Phát hiện thư mục con '{duong_dan}'",
                        offset=e.offset_entry,
                        gia_tri={"cluster_dau": e.cluster_dau},
                    )
                _duyet(e.cluster_dau, duong_dan)
            else:
                if log:
                    runs_f = chuoi_thanh_runs(chuoi(fat, e.cluster_dau & FAT_MASK)) if e.kich_thuoc > 0 else []
                    log.buoc(
                        f"Phát hiện tập tin '{duong_dan}'",
                        offset=e.offset_entry,
                        gia_tri={
                            "size": e.kich_thuoc,
                            "cluster_dau": e.cluster_dau,
                            "runs": runs_f,
                        },
                    )
                tap_tin.append((duong_dan, e))

    _duyet(ts.root_clus, "")
    return tap_tin


def doc_du_lieu(img, ts: ThamSo, cac_cluster: List[int], kich_thuoc: int) -> bytes:
    """Đọc và nối dữ liệu từ danh sách cluster, cắt chính xác `kich_thuoc` byte.

    Tự động gộp các cluster liên tiếp thành một lần đọc để tối ưu tốc độ trên tập tin lớn.
    """
    if kich_thuoc <= 0 or not cac_cluster:
        return b""

    cs = ts.cluster_size
    con_lai = kich_thuoc
    cac_manh: List[bytes] = []

    for clus_bat_dau, so_luong in chuoi_thanh_runs(cac_cluster):
        if con_lai <= 0:
            break
        off = ts.off_cluster(clus_bat_dau)
        so_byte_run = min(so_luong * cs, con_lai)
        if off + so_byte_run > img.kich_thuoc:
            so_byte_run = max(0, img.kich_thuoc - off)
        if so_byte_run > 0:
            cac_manh.append(img.doc(off, so_byte_run))
            con_lai -= so_byte_run

    return b"".join(cac_manh)


def trich_xuat_tat_ca(img, ts: ThamSo, fat: List[int], out, log=None) -> List[Tuple[str, Entry]]:
    """Duyệt toàn bộ cây thư mục từ `ts` + `fat` và lưu mọi tập tin vào `out`."""
    danh_sach = duyet_cay(img, ts, fat, log)
    for duong_dan, e in danh_sach:
        if e.kich_thuoc == 0:
            data = b""
        else:
            cac_clus = chuoi(fat, e.cluster_dau & FAT_MASK)
            data = doc_du_lieu(img, ts, cac_clus, e.kich_thuoc)
        out.luu(duong_dan, data)
        if log:
            log.buoc(
                f"Đã trích xuất '{duong_dan}'",
                offset=e.offset_entry,
                gia_tri={"bytes_written": len(data)},
            )
    return danh_sach


def kiem_tra_ung_vien_root(img, ts: ThamSo, fat: List[int], clus_ung_vien: int, tap_dau_chuoi: Set[int]) -> Tuple[bool, int, str]:
    """Đánh giá một cluster đầu chuỗi có phải thư mục gốc (Root Directory) của FAT32 không.

    Trả về `(hop_le, diem, ly_do)` phục vụ chẩn đoán và khôi phục `ext-root` (BPB_RootClus).
    """
    if not ts.cluster_hop_le(clus_ung_vien):
        return False, -1, "ngoài phạm vi cluster hợp lệ"

    cac_clus = chuoi(fat, clus_ung_vien)
    if not cac_clus:
        return False, -1, "chuỗi FAT rỗng"

    off_dau = ts.off_cluster(cac_clus[0])
    # Thư mục gốc KHÔNG được bắt đầu bằng entry `.` và `..` (đặc trưng của thư mục con)
    if doc_dot_dotdot(img, off_dau) is not None:
        return False, -1, "bắt đầu bằng entry '.' và '..' (là thư mục con, không phải thư mục gốc)"

    cs = ts.cluster_size
    diem = 0
    so_entry_thuc = 0
    so_thu_muc_con_goc = 0
    so_tap_tin_khop = 0
    da_gap_ket_thuc = False

    for c in cac_clus:
        off_c = ts.off_cluster(c)
        if off_c + cs > img.kich_thuoc:
            return False, -1, "vượt kích thước ảnh đĩa"
        buf = img.doc(off_c, cs)

        for pos in range(0, cs, 32):
            raw = buf[pos:pos + 32]
            b0 = raw[0]

            if b0 == 0x00:
                da_gap_ket_thuc = True
                if not any(buf[pos:]):
                    diem += 5
                break

            if b0 == 0xE5:
                continue

            attr = raw[0x0B]
            # Kiểm tra cấu trúc entry LFN
            if (attr & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME:
                seq = b0 & 0x3F
                fst_lo = struct.unpack_from("<H", raw, 0x1A)[0]
                if raw[0x0C] != 0 or fst_lo != 0 or not (1 <= seq <= 20):
                    return False, -1, "entry LFN sai cấu trúc"
                continue

            # Hai bit cao của DIR_Attr trong short entry FAT32 được dự trữ = 0
            if (attr & 0xC0) != 0:
                return False, -1, f"DIR_Attr={attr:#04x} có bit cao dự trữ khác 0"

            # Kiểm tra 11 byte tên ngắn chứa ký tự hợp lệ
            ten_11 = raw[0:11]
            for idx, ch in enumerate(ten_11):
                if idx == 0 and ch == 0x05:
                    continue
                if ch < 0x20 or ch in _SHORT_FORBIDDEN:
                    return False, -1, "DIR_Name chứa byte không hợp lệ cho tên ngắn 8.3"

            hi = struct.unpack_from("<H", raw, 0x14)[0]
            lo = struct.unpack_from("<H", raw, 0x1A)[0]
            fclus = ((hi << 16) | lo) & FAT_MASK
            fsize = struct.unpack_from("<I", raw, 0x1C)[0]

            # Nhãn volume (Volume Label)
            if attr & ATTR_VOLUME_ID:
                if (attr & ATTR_DIRECTORY) != 0 or fclus != 0 or fsize != 0:
                    return False, -1, "entry Volume Label có cluster/size khác 0"
                diem += 10
                continue

            if ten_11 in (b".          ", b"..         "):
                return False, -1, "chứa entry '.' hoặc '..' bên trong thư mục gốc"

            so_entry_thuc += 1
            if attr & ATTR_DIRECTORY:
                if fsize != 0 or fclus not in tap_dau_chuoi or not ts.cluster_hop_le(fclus):
                    return False, -1, "entry thư mục con có size != 0 hoặc cluster đầu không hợp lệ"
                dot_info = doc_dot_dotdot(img, ts.off_cluster(fclus))
                if dot_info is None:
                    return False, -1, "thư mục con không bắt đầu bằng '.' và '..'"
                c_dot, c_dotdot = dot_info
                # Theo chuẩn Microsoft FAT32: thư mục con trực tiếp của gốc có '.' = fclus và '..' = 0
                if c_dot != fclus or c_dotdot != 0:
                    return False, -1, f"thư mục con có '.'={c_dot}, '..'={c_dotdot} (không trỏ về gốc)"
                so_thu_muc_con_goc += 1
                diem += 50
            else:
                if fsize == 0:
                    if fclus != 0:
                        return False, -1, "tập tin rỗng nhưng cluster đầu khác 0"
                    so_tap_tin_khop += 1
                    diem += 15
                else:
                    if fclus not in tap_dau_chuoi or not ts.cluster_hop_le(fclus):
                        return False, -1, "tập tin trỏ tới cluster không phải đầu chuỗi hợp lệ"
                    so_clus_can = (fsize + cs - 1) // cs
                    if len(chuoi(fat, fclus)) != so_clus_can:
                        return False, -1, "độ dài chuỗi FAT của tập tin không khớp kích thước"
                    so_tap_tin_khop += 1
                    diem += 25

        if da_gap_ket_thuc:
            break

    if so_entry_thuc == 0:
        return False, -1, "không chứa tập tin hay thư mục con nào"

    ly_do = (
        f"cấu trúc bảng thư mục hợp lệ, không có '.'/'..', "
        f"gồm {so_thu_muc_con_goc} thư mục con trực tiếp (có '..'=0) và {so_tap_tin_khop} tập tin khớp chuỗi FAT"
    )
    return True, diem, ly_do


def tim_cac_dau_chuoi(fat: List[int]) -> List[int]:
    """Tìm tất cả các cluster đầu chuỗi đã cấp phát trong bảng FAT (FAT[c] != 0 và không ai trỏ tới c)."""
    duoc_tro_toi: Set[int] = set()
    n = len(fat)
    for c in range(2, n):
        nxt = fat[c] & FAT_MASK
        if 2 <= nxt < n and nxt <= FAT_MAX_VALID:
            duoc_tro_toi.add(nxt)

    return [
        c for c in range(2, n)
        if (fat[c] & FAT_MASK) not in (FAT_FREE, FAT_BAD) and c not in duoc_tro_toi
    ]
