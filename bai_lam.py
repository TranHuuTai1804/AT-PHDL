"""PHẦN LÀM BÀI CỦA NHÓM (Hệ thống tập tin: FAT32).

Quy tắc:
  * Tự giải mã mọi cấu trúc từ byte (dùng binio.AnhDia). Cấm thư viện phân tích hệ thống tập tin
    (pytsk3, dfvfs, pyfatfs, libntfs, libext2fs...) và cấm gọi công cụ ngoài (subprocess, os.system).
  * Không cố định offset / số cluster / giá trị của ảnh nhóm: chương trình sẽ chạy trên ảnh ẩn.
  * Không ghi lên ảnh đầu vào; muốn sửa thì img.sao_chep(...).
  * Ghi nhật ký mọi bước quan trọng: self.log.buoc(...), self.log.quyet_dinh(...).
  * Tách lõi dùng chung trong fat32.py (Thành viên A).
"""
from dataclasses import replace

from case2 import phuc_hoi_case2

from fat32 import (
    BOOT_SIGNATURE,
    FAT_MASK,
    doc_bpb,
    doc_fat,
    duyet_cay,
    kiem_tra_ung_vien_root,
    tim_cac_dau_chuoi,
    trich_xuat_tat_ca,
)


class BaiLam:
    def __init__(self, log):
        self.log = log

    # ------------------------------------------------------------------ --info (Thành viên A)
    def info(self, img):
        """Đọc ảnh FAT32 nguyên vẹn, ghi nhật ký từng bước và trả về thông tin volume + danh sách tập tin."""
        ts = doc_bpb(img, self.log)
        fat = doc_fat(img, ts, k=0, log=self.log)
        danh_sach_tap_tin = duyet_cay(img, ts, fat, log=self.log)

        self.log.quyet_dinh(
            f"Hoàn tất đọc thông tin volume FAT32: cluster_size={ts.cluster_size}, tìm thấy {len(danh_sach_tap_tin)} tập tin",
            cluster_size=ts.cluster_size,
            so_tap_tin=len(danh_sach_tap_tin),
        )

        return {
            "fs": "fat32",
            "bytes_per_sector": ts.bps,
            "sectors_per_cluster": ts.sc,
            "cluster_size": ts.cluster_size,
            "reserved_sectors": ts.sb,
            "fat_count": ts.nf,
            "fat_size_sectors": ts.sf,
            "total_sectors": ts.tot_sec,
            "total_clusters": ts.so_cluster,
            "root_cluster": ts.root_clus,
            "fat_offset": ts.off_fat(0),
            "data_offset": ts.data_offset,
            "files": [
                {"path": duong_dan, "size": entry.kich_thuoc}
                for duong_dan, entry in danh_sach_tap_tin
            ],
        }

    # ------------------------------------------------------------- tình huống (B, C, D)
    def case1(self, img, out):
        """Tình huống 1 (Thành viên B) — sai tham số boot sector (SC, SB, SF).
        Suy ra giá trị đúng, tạo ThamSo rồi gọi trich_xuat_tat_ca(img, ts, fat, out, self.log).
        Cài đặt chi tiết trong case1.py."""
        from case1 import phuc_hoi_case1
        phuc_hoi_case1(img, out, self.log)

    def case2(self, img, out):
        """Tình huống 2 (Thành viên C) — sai directory entry.
        Tìm chuỗi mồ côi trong bảng FAT, ghép đúng tên với dữ liệu và lưu các tập tin."""
        return phuc_hoi_case2(img, out, self.log)

    def case3(self, img, out):
        """Tình huống 3 (Thành viên D) — sai chuỗi vị trí.
        Ghép mảnh tập tin JPEG theo nội dung và lưu tập tin mục tiêu."""
        raise NotImplementedError("case3")

    # --------------------------------------------------------------- cộng điểm (Thành viên A: ext-root)
    def case_ext(self, img, out):
        """Tình huống mở rộng `ext-root` — phục hồi khi trường BPB_RootClus (0x2C) bị làm sai."""
        ts = doc_bpb(img, self.log)
        fat = doc_fat(img, ts, k=0, log=self.log)

        # Kiểm tra bản sao Backup Boot Sector (nếu có) để ghi nhận đối chiếu, không tin mù quáng
        root_bk = None
        if ts.bkboot_sec > 0:
            off_bk_sec = ts.off_sector(ts.bkboot_sec)
            if off_bk_sec + ts.bps <= img.kich_thuoc and img.u16(off_bk_sec + 0x1FE) == BOOT_SIGNATURE:
                root_bk = img.u32(off_bk_sec + 0x2C) & FAT_MASK
                self.log.buoc(
                    f"Đọc BPB_RootClus tại Backup Boot Sector (sector {ts.bkboot_sec})",
                    offset=off_bk_sec + 0x2C,
                    gia_tri=root_bk,
                )

        cac_dau_chuoi = tim_cac_dau_chuoi(fat)
        tap_dau_chuoi = set(cac_dau_chuoi)
        self.log.buoc(
            "Quét bảng FAT tìm các cluster đầu chuỗi đã cấp phát",
            offset=ts.off_fat(0),
            gia_tri={"so_dau_chuoi": len(cac_dau_chuoi), "danh_sach": cac_dau_chuoi[:32]},
        )

        # Chẩn đoán giá trị BPB_RootClus hiện tại ở sector 0
        hop_le_hien_tai, _, ly_do_hien_tai = kiem_tra_ung_vien_root(
            img, ts, fat, ts.root_clus, tap_dau_chuoi
        )
        if not hop_le_hien_tai:
            self.log.buoc(
                f"Chẩn đoán BPB_RootClus={ts.root_clus} tại 0x2C bị hỏng: {ly_do_hien_tai}",
                offset=ts.base_offset + 0x2C,
                gia_tri=ts.root_clus,
            )

        # Đánh giá mọi ứng viên đầu chuỗi để tìm thư mục gốc thật sự
        ung_vien_tot = []
        for c in cac_dau_chuoi:
            ok, diem, ly_do = kiem_tra_ung_vien_root(img, ts, fat, c, tap_dau_chuoi)
            if ok:
                if root_bk is not None and c == root_bk:
                    diem += 5
                    ly_do += f"; khớp thêm Backup Boot Sector (sector {ts.bkboot_sec})"
                self.log.buoc(
                    f"Ứng viên thư mục gốc hợp lệ: cluster {c}",
                    offset=ts.off_cluster(c),
                    gia_tri={"cluster": c, "diem": diem, "ly_do": ly_do},
                )
                ung_vien_tot.append((diem, -c, c, ly_do))

        if not ung_vien_tot:
            raise RuntimeError("Không tìm được ứng viên thư mục gốc FAT32 hợp lệ nào trên ảnh đĩa")

        ung_vien_tot.sort(reverse=True)
        diem_cao_nhat, _, root_dung, ly_do_chon = ung_vien_tot[0]

        self.log.quyet_dinh(
            f"Khôi phục BPB_RootClus = {root_dung} (thay cho giá trị hỏng {ts.root_clus}): {ly_do_chon}",
            offset=ts.off_cluster(root_dung),
            root_clus_cu=ts.root_clus,
            root_clus_dung=root_dung,
            diem=diem_cao_nhat,
        )

        ts_dung = replace(ts, root_clus=root_dung)
        trich_xuat_tat_ca(img, ts_dung, fat, out, log=self.log)

    def repair(self, img, case, anh_moi):
        """--repair: sửa trên BẢN SAO và ghi ra anh_moi."""
        raise NotImplementedError("repair")

    def corrupt(self, img, dac_ta, anh_hong):
        """--corrupt (Thành viên A: `ext-root`): tạo ảnh hỏng từ ảnh sạch theo đặc tả JSON.

        Trả về danh sách vùng siêu dữ liệu đã sửa để giảng viên đối chiếu tự động.
        """
        tinh_huong = dac_ta.get("tinh_huong", "ext-root")
        if tinh_huong != "ext-root":
            raise ValueError(f"Chỉ hỗ trợ tình huống mở rộng 'ext-root', nhận được: {tinh_huong!r}")

        ts = doc_bpb(img, self.log)
        gia_tri_sai = int(dac_ta.get("gia_tri_sai", 0)) & FAT_MASK
        if gia_tri_sai == ts.root_clus:
            gia_tri_sai = 0 if ts.root_clus != 0 else (ts.max_cluster & FAT_MASK)

        sua_ban_sao = bool(dac_ta.get("sua_ban_sao", True))
        ban_sua = img.sao_chep(anh_hong)
        thay_doi = []
        try:
            off_chinh = ts.base_offset + 0x2C
            ban_sua.ghi_u32(off_chinh, gia_tri_sai)
            thay_doi.append(
                {
                    "offset": off_chinh,
                    "length": 4,
                    "cau_truc": "BPB_RootClus (Boot Sector chính, sector 0)",
                }
            )
            self.log.buoc(
                f"Ghi sai BPB_RootClus tại sector 0: {ts.root_clus} -> {gia_tri_sai}",
                offset=off_chinh,
                gia_tri=gia_tri_sai,
            )

            if sua_ban_sao and ts.bkboot_sec > 0:
                off_bk_sec = ts.off_sector(ts.bkboot_sec)
                if off_bk_sec + ts.bps <= ban_sua.kich_thuoc and ban_sua.u16(off_bk_sec + 0x1FE) == BOOT_SIGNATURE:
                    off_phu = off_bk_sec + 0x2C
                    cu_phu = ban_sua.u32(off_phu) & FAT_MASK
                    ban_sua.ghi_u32(off_phu, gia_tri_sai)
                    thay_doi.append(
                        {
                            "offset": off_phu,
                            "length": 4,
                            "cau_truc": f"BPB_RootClus (Backup Boot Sector, sector {ts.bkboot_sec})",
                        }
                    )
                    self.log.buoc(
                        f"Ghi sai BPB_RootClus tại Backup Boot Sector (sector {ts.bkboot_sec}): {cu_phu} -> {gia_tri_sai}",
                        offset=off_phu,
                        gia_tri=gia_tri_sai,
                    )
        finally:
            ban_sua.dong()

        self.log.quyet_dinh(
            f"Hoàn tất tạo ảnh hỏng '{tinh_huong}' tại '{anh_hong}' ({len(thay_doi)} vùng siêu dữ liệu)",
            so_vung=len(thay_doi),
            gia_tri_sai=gia_tri_sai,
        )
        return thay_doi
