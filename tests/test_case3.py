"""Ảnh JPEG thật cố định; kiểm thử chỉ cần thư viện chuẩn.

Fixtures được sinh bằng Pillow, chỉ dùng ngoài chương trình để kiểm chứng.
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
from jpeg import LoiJPEG, kiem_tra_jpeg
from tienich import NhatKy, ThuMucKetQua
from test_case2 import short_entry


FIXTURES = Path(__file__).parent / 'fixtures'


def tao_anh(folder, name='baseline_color.jpg', sc=1, split=3, gap=21,
            duplicate=False, fake=False):
    """Volume bố cục FAT32 nhỏ; cả hai FAT của JPEG mục tiêu bằng 0."""
    payload = (FIXTURES / name).read_bytes()
    bps, sb, nf, sf, total_clusters = 512, 13, 2, 3, 300
    cs = sc*bps
    n = (len(payload) + cs - 1)//cs
    if split >= n:
        split = n - 1
    root, data_dir, first = 7, 12, 30
    second = first + split + gap
    data_offset = (sb + nf*sf)*bps
    def off(c):
        return data_offset + (c-2)*cs
    fat = [0]*(sf*bps//4)
    fat[:2] = [0x0ffffff8, 0x0fffffff]
    for c in (root, data_dir, 16):
        fat[c] = 0x0fffffff
    raw = bytearray(data_offset + total_clusters*cs)
    struct.pack_into('<H', raw, 11, bps)
    raw[13] = sc
    struct.pack_into('<H', raw, 14, sb)
    raw[16] = nf
    raw[21] = 248
    struct.pack_into('<I', raw, 32, sb + nf*sf + total_clusters*sc)
    struct.pack_into('<I', raw, 36, sf)
    struct.pack_into('<I', raw, 44, root)
    raw[510:512] = b'\x55\xaa'
    for k in range(nf):
        struct.pack_into('<%dI' % len(fat), raw, (sb + k*sf)*bps, *fat)
    raw[off(root):off(root)+32] = short_entry('DATA', data_dir, attr=16)
    entries = (short_entry('.', data_dir, attr=16) + short_entry('..', 0, attr=16)
               + short_entry('TARGET.JPG', first, len(payload))
               + short_entry('KEEP.TXT', 16, 11) + short_entry('EMPTY.TXT', 0, 0))
    raw[off(data_dir):off(data_dir)+len(entries)] = entries
    raw[off(16):off(16)+11] = b'keep bytes\n'
    prefix, tail = payload[:split*cs], payload[split*cs:]
    raw[off(first):off(first)+len(prefix)] = prefix
    # Nhiễu ở khe giữa hai run, không phải toàn số 0.
    raw[off(first+split):off(second)] = b'\x5a'*(gap*cs)
    raw[off(second):off(second)+len(tail)] = tail
    if fake:
        # Một đuôi giả có FF D9 đúng vị trí nhưng luồng entropy sai.
        fake_second = second + 2
        raw[off(fake_second):off(fake_second)+len(tail)] = b'\x55'*(len(tail)-2) + b'\xff\xd9'
        # Đặt lại đuôi thật ở vùng không giao nhau với đuôi giả.
        second = first + split + 50
        raw[off(second):off(second)+len(tail)] = tail
    if duplicate:
        duplicate_second = second + n + 3
        raw[off(duplicate_second):off(duplicate_second)+len(tail)] = tail
    image = Path(folder)/'case3.img'
    image.write_bytes(raw)
    chain = list(range(first, first+split)) + list(range(second, second+n-split))
    want = {'DATA/TARGET.JPG': payload, 'DATA/KEEP.TXT': b'keep bytes\n', 'DATA/EMPTY.TXT': b''}
    return image, want, chain, off, sb, sf


class JPEGTests(unittest.TestCase):
    def test_real_baseline_grayscale_color_and_restart(self):
        for name in ('baseline_color.jpg', 'baseline_gray.jpg', 'baseline_restart.jpg'):
            with self.subTest(name=name):
                meta = kiem_tra_jpeg((FIXTURES/name).read_bytes())
                self.assertEqual((97, 89), (meta['width'], meta['height']))
                self.assertTrue(meta['entropy_decoded'])

    def test_invalid_entropy_with_valid_soi_and_eoi(self):
        data = bytearray((FIXTURES/'baseline_color.jpg').read_bytes())
        pos = data.index(b'\xff\xda') + 2
        start = pos + int.from_bytes(data[pos:pos+2], 'big')
        data[start:start+12] = b'\xff\xd9' + b'\x00'*10
        with self.assertRaises(LoiJPEG):
            kiem_tra_jpeg(bytes(data))

    def test_decoder_respects_time_budget(self):
        with self.assertRaisesRegex(RuntimeError, 'thời gian'):
            kiem_tra_jpeg((FIXTURES/'baseline_color.jpg').read_bytes(), deadline=0)

    def test_truncation_trailing_bytes_and_progressive_rejected(self):
        data = (FIXTURES/'baseline_gray.jpg').read_bytes()
        for bad in (data[:-3] + b'\xff\xd9', data + b'garbage',
                    data.replace(b'\xff\xc0', b'\xff\xc2', 1), b'\xff\xd8\xff\xd9'):
            with self.subTest(size=len(bad)), self.assertRaises(LoiJPEG):
                kiem_tra_jpeg(bad)


class Case3Tests(unittest.TestCase):
    def run_fixture(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            image, want, chain, _, _, _ = tao_anh(tmp, **kwargs)
            before = hashlib.sha256(image.read_bytes()).hexdigest()
            dest, logfile = Path(tmp)/'out', Path(tmp)/'log.jsonl'
            with contextlib.redirect_stderr(io.StringIO()):
                log = NhatKy(str(logfile))
                try:
                    with AnhDia(str(image)) as img:
                        out = ThuMucKetQua(str(dest))
                        rec = BaiLam(log).case3(img, out)
                        out.ket_thuc()
                finally:
                    log.tep.close()
            self.assertEqual(chain, rec['clusters'])
            got = {p.relative_to(dest).as_posix(): p.read_bytes() for p in dest.rglob('*')
                   if p.is_file() and p.name != 'SHA256SUMS'}
            self.assertEqual(want, got)
            self.assertEqual(before, hashlib.sha256(image.read_bytes()).hexdigest())
            sums = (dest/'SHA256SUMS').read_text()
            for path, payload in want.items():
                self.assertIn(hashlib.sha256(payload).hexdigest() + '  ' + path, sums)
            logs = [json.loads(line) for line in logfile.read_text(encoding='utf-8').splitlines()]
            self.assertTrue(any(r.get('clusters') == chain for r in logs if r['loai'] == 'quyet_dinh'))

    def test_recovery_exact_bytes_and_source_unchanged(self):
        self.run_fixture()

    def test_geometry_split_and_gap_boundaries(self):
        for opts in ({'split': 1, 'gap': 1}, {'split': 14, 'gap': 64},
                     {'sc': 8, 'split': 1, 'gap': 17},
                     {'name': 'baseline_gray.jpg', 'split': 4},
                     {'name': 'baseline_restart.jpg', 'split': 5}):
            with self.subTest(opts=opts):
                self.run_fixture(**opts)

    def test_fake_eoi_candidate_is_rejected(self):
        self.run_fixture(fake=True)

    def test_ambiguous_no_match_and_inconsistent_fat_save_nothing(self):
        for mode in ('ambiguous', 'missing', 'fat'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                image, _, chain, off, sb, sf = tao_anh(tmp, duplicate=mode == 'ambiguous')
                with image.open('r+b') as f:
                    if mode == 'missing':
                        f.seek(off(chain[-1]))
                        f.write(b'\x00'*512)
                    elif mode == 'fat':
                        f.seek((sb+sf)*512 + chain[0]*4)
                        f.write(struct.pack('<I', 0x0fffffff))
                dest = Path(tmp)/'out'
                with contextlib.redirect_stderr(io.StringIO()), AnhDia(str(image)) as img:
                    with self.assertRaises(RuntimeError):
                        BaiLam(NhatKy()).case3(img, ThuMucKetQua(str(dest)))
                self.assertEqual([], list(dest.rglob('*')))


if __name__ == '__main__':
    unittest.main()
