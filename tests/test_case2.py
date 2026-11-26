"""Kiểm thử tích hợp TH2 bằng ảnh sinh tại chỗ, không phải bộ mẫu giảng viên.

Chạy: python -m unittest discover -s tests -v
"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from bai_lam import BaiLam
from binio import AnhDia
from case2 import chon_phep_ghep, nhan_dang
from fat32 import tinh_lfn_checksum
from tienich import NhatKy, ThuMucKetQua


def short_entry(name, start, size=0, attr=0x20, nt=0):
    raw = bytearray(32)
    if name in ('.', '..'):
        raw[:11] = name.encode().ljust(11, b' ')
    else:
        base, _, ext = name.partition('.')
        raw[:11] = base.encode().ljust(8, b' ') + ext.encode().ljust(3, b' ')
    raw[11], raw[12] = attr, nt
    struct.pack_into('<H', raw, 20, start >> 16)
    struct.pack_into('<H', raw, 26, start & 0xffff)
    struct.pack_into('<I', raw, 28, size)
    return bytes(raw)


def lfn_entries(name, short):
    units = list(struct.unpack('<%dH' % (len(name.encode('utf-16-le')) // 2), name.encode('utf-16-le')))
    units.append(0)
    while len(units) % 13:
        units.append(0xffff)
    result = []
    count = len(units) // 13
    for seq in range(count, 0, -1):
        raw = bytearray(32)
        raw[0] = seq | (0x40 if seq == count else 0)
        raw[11], raw[13] = 0x0f, tinh_lfn_checksum(short[:11])
        chars = struct.pack('<13H', *units[(seq - 1) * 13:seq * 13])
        raw[1:11], raw[14:26], raw[28:32] = chars[:10], chars[10:22], chars[22:]
        result.append(bytes(raw))
    return result


def tao_bo_kiem_thu(folder, sai=None, sc=1, sb=11, high=False, trung_loai=False):
    """Sinh volume giảm dung lượng; BPB/FAT/entry có bố cục FAT32.

    Payload chỉ phục vụ kiểm chữ ký/biên TH2, không kiểm giải mã ảnh.
    high=True sinh đủ cluster để HI của cluster đầu khác 0.
    """
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    bps, nf, root, data_dir = 512, 2, 9, 21
    clusters = 70000 if high else 400
    sf = ((clusters + 2) * 4 + bps - 1) // bps
    data_offset, cs = (sb + nf * sf) * bps, bps * sc
    total = sb + nf * sf + clusters * sc
    def offset(c):
        return data_offset + (c - 2) * cs

    chains = {'DATA/PHOTO.JPG': [40, 75], 'DATA/IMAGE.PNG': [120, 170],
              'DATA/DOC.PDF': [88, 99], 'DATA/Ghi chu.txt': [65540 if high else 41],
              'DATA/keep.txt': [44]}
    original = {
        'DATA/PHOTO.JPG': b'\xff\xd8\xff\xe0' + b'J' * (cs + 11) + b'\xff\xd9',
        'DATA/IMAGE.PNG': b'\x89PNG\r\n\x1a\n' + b'P' * (cs + 60) + b'\0\0\0\0IEND\xaeB`\x82',
        'DATA/DOC.PDF': b'%PDF-1.4\n' + b'%' * (cs + 14) + b'\n%%EOF\n',
        'DATA/Ghi chu.txt': 'Nội dung văn bản TH2\n'.encode(),
        'DATA/keep.txt': b'Healthy text file\n',
    }
    if trung_loai:
        original['DATA/SECOND.JPG'] = b'\xff\xd8\xff\xe0' + b'K' * (cs + 35) + b'\xff\xd9'
        chains['DATA/SECOND.JPG'] = [181, 191]
    fat = [0] * (sf * bps // 4)
    fat[0:2] = [0x0ffffff8, 0x0fffffff]
    for cac in [[root, 10], [data_dir]] + list(chains.values()):
        for a, b in zip(cac, cac[1:]):
            fat[a] = b
        fat[cac[-1]] = 0xafffffff  # bit cao phải được mask
    clean = folder / 'clean.img'
    with clean.open('w+b') as f:
        f.truncate(total * bps)
        boot = bytearray(bps)
        struct.pack_into('<H', boot, 11, bps)
        boot[13] = sc
        struct.pack_into('<H', boot, 14, sb)
        boot[16] = nf
        struct.pack_into('<I', boot, 32, total)
        struct.pack_into('<I', boot, 36, sf)
        struct.pack_into('<I', boot, 44, root)
        struct.pack_into('<H', boot, 48, 1)
        struct.pack_into('<H', boot, 50, 6)
        boot[82:90], boot[510:512] = b'FAT32   ', b'\x55\xaa'
        f.write(boot)
        for k in range(nf):
            f.seek((sb + k * sf) * bps)
            f.write(struct.pack('<%dI' % len(fat), *fat))
        f.seek(offset(root))
        f.write((b'\xe5' + b'\0' * 31) * (cs // 32))
        f.seek(offset(10))
        f.write(short_entry('DATA', data_dir, attr=0x10))
        entries = [short_entry('.', data_dir, attr=0x10), short_entry('..', 0, attr=0x10)]
        entry_offsets = {}
        for path, payload in original.items():
            name = path.split('/')[-1]
            if name == 'Ghi chu.txt':
                short = short_entry('GHICHU~1.TXT', chains[path][0], len(payload))
                entries.extend(lfn_entries(name, short))
            else:
                short = short_entry(name.upper(), chains[path][0], len(payload), nt=0x18 if name == 'keep.txt' else 0)
            entry_offsets[path] = offset(data_dir) + len(entries) * 32
            entries.append(short)
        entries.append(short_entry('EMPTY.TXT', 0))
        original['DATA/EMPTY.TXT'] = b''
        f.seek(offset(data_dir))
        f.write(b''.join(entries))
        for path, cac in chains.items():
            for n, c in enumerate(cac):
                f.seek(offset(c))
                f.write(original[path][n * cs:(n + 1) * cs])
    broken = folder / 'case2.img'
    broken.write_bytes(clean.read_bytes())
    if sai is None:
        sai = {'DATA/PHOTO.JPG': 0, 'DATA/DOC.PDF': 0, 'DATA/Ghi chu.txt': 0}
    with broken.open('r+b') as f:
        for path, value in sai.items():
            off = entry_offsets[path]
            f.seek(off + 20)
            f.write(struct.pack('<H', value >> 16))
            f.seek(off + 26)
            f.write(struct.pack('<H', value & 0xffff))
    files = [{'path': p, 'size': len(d), 'sha256': hashlib.sha256(d).hexdigest()} for p, d in original.items()]
    for name in ('clean', 'case2'):
        ans = {'fs': 'fat32', 'unit_size': cs, 'files': files, 'targets': list(sai)}
        (folder / (name + '.json')).write_text(json.dumps(ans, ensure_ascii=False, indent=2), encoding='utf-8')
    return broken, original, entry_offsets, offset, cs


class Case2Tests(unittest.TestCase):
    def run_fixture(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            image, want, _, _, _ = tao_bo_kiem_thu(tmp, **kwargs)
            before = hashlib.sha256(image.read_bytes()).hexdigest()
            dest = Path(tmp) / 'out'
            log_path = Path(tmp) / 'log.jsonl'
            with contextlib.redirect_stderr(io.StringIO()):
                log = NhatKy(str(log_path))
                try:
                    with AnhDia(str(image)) as img:
                        out = ThuMucKetQua(str(dest))
                        recs = BaiLam(log).case2(img, out)
                        out.ket_thuc()
                finally:
                    log.tep.close()
            got = {p.relative_to(dest).as_posix(): p.read_bytes() for p in dest.rglob('*') if p.is_file() and p.name != 'SHA256SUMS'}
            self.assertEqual(want, got)
            self.assertEqual(before, hashlib.sha256(image.read_bytes()).hexdigest())
            logs = [json.loads(s) for s in log_path.read_text(encoding='utf-8').splitlines()]
            self.assertTrue(any('HI_offset' in r.get('gia_tri', {}) for r in logs if isinstance(r.get('gia_tri'), dict)))
            decisions = [r for r in logs if r['loai'] == 'quyet_dinh' and 'cluster_dau_dung' in r]
            for rec in decisions:
                self.assertEqual(hashlib.sha256(want[rec['path']]).hexdigest(), rec['sha256'])
            self.assertTrue((dest / 'SHA256SUMS').exists())
            return recs

    def test_zero_lfn_lowercase_fragmented_one_cluster_and_empty(self):
        recs = self.run_fixture()
        self.assertEqual(3, sum(r['da_phuc_hoi'] for r in recs))

    def test_wrong_nonzero_free_middle_directory_out_of_range(self):
        for bad in (333, 75, 21, 0x12345678):
            with self.subTest(bad=bad):
                self.run_fixture(sai={'DATA/PHOTO.JPG': bad, 'DATA/DOC.PDF': 0, 'DATA/Ghi chu.txt': 0})

    def test_wrong_pointer_to_another_valid_file(self):
        self.run_fixture(sai={'DATA/PHOTO.JPG': 120, 'DATA/DOC.PDF': 0, 'DATA/Ghi chu.txt': 0})

    def test_swapped_nonzero_pointers(self):
        self.run_fixture(sai={'DATA/PHOTO.JPG': 88, 'DATA/DOC.PDF': 40, 'DATA/Ghi chu.txt': 0})

    def test_geometry_and_high_cluster_word(self):
        self.run_fixture(sc=2, sb=19, high=True)

    def test_same_type_same_cluster_count_different_size(self):
        self.run_fixture(trung_loai=True, sai={'DATA/PHOTO.JPG': 0, 'DATA/SECOND.JPG': 0, 'DATA/Ghi chu.txt': 0})

    def test_clean_image_needs_no_recovery(self):
        self.assertFalse(any(r['da_phuc_hoi'] for r in self.run_fixture(sai={})))

    def test_ambiguous_data_is_not_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            image, _, _, off, cs = tao_bo_kiem_thu(tmp)
            # Thêm một chuỗi mồ côi TXT có cùng nội dung và điểm với TXT mục tiêu.
            with image.open('r+b') as f:
                # Đọc hình học từ BPB, không phụ thuộc sf của fixture.
                f.seek(14)
                sb = struct.unpack('<H', f.read(2))[0]
                f.seek(36)
                sf = struct.unpack('<I', f.read(4))[0]
                for k in range(2):
                    f.seek((sb + k * sf) * 512 + 210 * 4)
                    f.write(struct.pack('<I', 0x0fffffff))
                f.seek(off(41))
                payload = f.read(cs)
                f.seek(off(210))
                f.write(payload)
            out = ThuMucKetQua(str(Path(tmp) / 'out'))
            with contextlib.redirect_stderr(io.StringIO()), AnhDia(str(image)) as img:
                with self.assertRaisesRegex(RuntimeError, 'mơ hồ'):
                    BaiLam(NhatKy()).case2(img, out)
            self.assertEqual([], list(Path(out.goc).rglob('*')))

    def test_loop_and_bad_cluster_are_rejected(self):
        for end in (40, 0x0ffffff7, 0x0ffffff2):
            with self.subTest(end=end), tempfile.TemporaryDirectory() as tmp:
                image, _, _, _, _ = tao_bo_kiem_thu(tmp)
                with image.open('r+b') as f:
                    f.seek(11 * 512 + 75 * 4)
                    f.write(struct.pack('<I', end))
                with contextlib.redirect_stderr(io.StringIO()), AnhDia(str(image)) as img:
                    with self.assertRaisesRegex(RuntimeError, 'không có chuỗi'):
                        BaiLam(NhatKy()).case2(img, ThuMucKetQua(str(Path(tmp) / 'out')))

    def test_assignment_uses_global_score(self):
        result = chon_phep_ghep({0: {4: (9, {}), 5: (8, {})}, 1: {4: (8, {}), 5: (1, {})}})
        self.assertEqual({0: 5, 1: 4}, result)
        with self.assertRaisesRegex(RuntimeError, 'mơ hồ'):
            chon_phep_ghep({0: {4: (1, {}), 5: (1, {})}})

    def test_signatures_and_text(self):
        for name, payload in [('a.jpg', b'\xff\xd8\xffX\xff\xd9'),
                              ('a.png', b'\x89PNG\r\n\x1a\n\0\0\0\0IEND\xaeB`\x82'),
                              ('a.pdf', b'%PDF-1.4\n%%EOF\n'),
                              ('a.txt', 'Xin chào\n'.encode()),
                              ('a.txt', 'Xin chào\n'.encode('utf-16'))]:
            self.assertTrue(nhan_dang(payload, name)[0])
        for name, payload in [('a.jpg', b'fake\xff\xd9'), ('a.png', b'\x89PNG\r\n\x1a\n'),
                              ('a.pdf', b'%PDF-1.4'), ('a.txt', b'\x00\x01garbage')]:
            self.assertFalse(nhan_dang(payload, name)[0])


if __name__ == '__main__':
    unittest.main()
