"""Kiểm chứng JPEG baseline 8-bit bằng thư viện chuẩn (ITU-T T.81).

Giải mã Huffman toàn bộ hệ số DC/AC, kiểm tra số MCU, stuffing, padding,
restart và EOI. Không thực hiện IDCT/chuyển màu hay xuất ảnh raster.
Không nhận progressive/arithmetic: báo rõ thay vì chỉ kiểm tra FF D9.
"""
import math
import time


class LoiJPEG(ValueError):
    pass


class _Bits:
    def __init__(self, data, pos):
        self.data, self.pos = data, pos
        self.value = self.left = 0

    def read(self, n):
        value = 0
        for _ in range(n):
            if not self.left:
                if self.pos >= len(self.data):
                    raise LoiJPEG('Thiếu dữ liệu entropy')
                self.value = self.data[self.pos]
                self.pos += 1
                if self.value == 255:
                    if self.pos >= len(self.data) or self.data[self.pos] != 0:
                        raise LoiJPEG('Marker xuất hiện trước khi giải mã đủ MCU')
                    self.pos += 1
                self.left = 8
            self.left -= 1
            value = (value << 1) | ((self.value >> self.left) & 1)
        return value

    def align(self):
        if self.left and self.value & ((1 << self.left) - 1) != (1 << self.left) - 1:
            raise LoiJPEG('Bit padding entropy phải bằng 1')
        self.left = 0

    def symbol(self, table):
        code = 0
        for length in range(1, 17):
            code = (code << 1) | self.read(1)
            value = table.get((length, code))
            if value is not None:
                return value
        raise LoiJPEG('Mã Huffman không tồn tại')


def _marker(data, pos):
    if pos >= len(data) or data[pos] != 255:
        raise LoiJPEG('Thiếu marker JPEG')
    while pos < len(data) and data[pos] == 255:
        pos += 1
    if pos >= len(data) or data[pos] == 0:
        raise LoiJPEG('Marker JPEG không hợp lệ')
    return data[pos], pos + 1


def _tables(payload, tables):
    p = 0
    while p < len(payload):
        if p + 17 > len(payload):
            raise LoiJPEG('DHT bị cắt')
        selector = payload[p]
        counts = payload[p + 1:p + 17]
        p += 17
        count = sum(counts)
        if selector >> 4 > 1 or selector & 15 > 3 or not count or p + count > len(payload):
            raise LoiJPEG('DHT không hợp lệ')
        table, code, i = {}, 0, p
        for length, num in enumerate(counts, 1):
            if code + num >= 1 << length and num:
                raise LoiJPEG('Cây Huffman quá đầy hoặc chứa mã toàn bit 1')
            for _ in range(num):
                symbol = payload[i]
                if selector >> 4 == 0:
                    if symbol > 11:
                        raise LoiJPEG('DC category ngoài baseline')
                elif (symbol & 15) > 10 or ((symbol & 15) == 0 and symbol not in (0, 240)):
                    raise LoiJPEG('AC symbol ngoài baseline')
                table[length, code] = symbol
                code += 1
                i += 1
            code <<= 1
        tables[selector >> 4, selector & 15] = table
        p += count


def _block(bits, dc, ac):
    bits.read(bits.symbol(dc))
    k = 1
    while k < 64:
        symbol = bits.symbol(ac)
        run, size = symbol >> 4, symbol & 15
        if symbol == 0:
            return
        if symbol == 240:
            k += 16
            if k > 64:
                raise LoiJPEG('ZRL vượt 64 hệ số')
            continue
        k += run
        if k >= 64:
            raise LoiJPEG('AC run vượt 64 hệ số')
        bits.read(size)
        k += 1


def kiem_tra_jpeg(data, deadline=None):
    """Trả metadata nếu giải mã entropy baseline trọn vẹn; lỗi => LoiJPEG.

    Hỗ trợ grayscale/color, sampling, scan xen kẽ hoặc tách thành phần, DRI.
    Dấu EOI phải kết thúc đúng kích thước tập tin, không chấp nhận đuôi rác.
    """
    if not data.startswith(b'\xff\xd8'):
        raise LoiJPEG('Thiếu SOI')
    pos, tables, quant, frame, done = 2, {}, set(), None, set()
    restart, scans, blocks_total, mcus_total = 0, 0, 0, 0
    while pos < len(data):
        if deadline is not None and time.monotonic() > deadline:
            raise RuntimeError('TH3: vượt ngân sách thời gian giải mã JPEG')
        marker, pos = _marker(data, pos)
        if marker == 0xD9:
            if frame is None or done != set(frame) or pos != len(data):
                raise LoiJPEG('EOI sai vị trí hoặc thiếu thành phần ảnh')
            return {'width': width, 'height': height, 'components': len(frame),
                    'scans': scans, 'mcus': mcus_total, 'blocks': blocks_total,
                    'entropy_decoded': True, 'mode': 'baseline', 'eoi_offset': pos - 2}
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            raise LoiJPEG('Marker độc lập sai vị trí')
        if pos + 2 > len(data):
            raise LoiJPEG('Thiếu độ dài segment')
        length = int.from_bytes(data[pos:pos + 2], 'big')
        if length < 2 or pos + length > len(data):
            raise LoiJPEG('Segment vượt kích thước tập tin')
        payload = data[pos + 2:pos + length]
        pos += length
        if marker == 0xC0:
            if frame is not None or len(payload) < 6 or payload[0] != 8:
                raise LoiJPEG('SOF0 không hợp lệ')
            height, width = int.from_bytes(payload[1:3], 'big'), int.from_bytes(payload[3:5], 'big')
            count = payload[5]
            if not width or not height or count not in (1, 3, 4) or len(payload) != 6 + 3 * count:
                raise LoiJPEG('Kích thước/thành phần SOF0 không hợp lệ')
            frame = {}
            for i in range(count):
                cid, sampling, qt = payload[6 + 3*i:9 + 3*i]
                h, v = sampling >> 4, sampling & 15
                if cid in frame or not 1 <= h <= 4 or not 1 <= v <= 4 or qt > 3:
                    raise LoiJPEG('Thành phần SOF0 không hợp lệ')
                frame[cid] = (h, v, qt)
            if sum(h*v for h, v, _ in frame.values()) > 10:
                raise LoiJPEG('Quá nhiều block mỗi MCU')
        elif marker == 0xC4:
            _tables(payload, tables)
        elif marker == 0xDB:
            p = 0
            while p < len(payload):
                selector = payload[p]
                p += 1
                if selector >> 4 != 0 or selector & 15 > 3 or p + 64 > len(payload):
                    raise LoiJPEG('Chỉ hỗ trợ DQT 8-bit baseline')
                if 0 in payload[p:p + 64]:
                    raise LoiJPEG('Hệ số lượng tử bằng 0')
                quant.add(selector & 15)
                p += 64
        elif marker == 0xDD:
            if len(payload) != 2:
                raise LoiJPEG('DRI sai độ dài')
            restart = int.from_bytes(payload, 'big')
        elif marker == 0xDA:
            if frame is None or not payload:
                raise LoiJPEG('SOS trước SOF0')
            ns = payload[0]
            if not 1 <= ns <= len(frame) or len(payload) != 1 + 2*ns + 3 or payload[-3:] != b'\x00\x3f\x00':
                raise LoiJPEG('SOS không phải baseline sequential')
            scan, seen = [], set()
            for i in range(ns):
                cid, selector = payload[1 + 2*i:3 + 2*i]
                if cid not in frame or cid in done or cid in seen:
                    raise LoiJPEG('Thành phần SOS trùng hoặc không tồn tại')
                h, v, qt = frame[cid]
                dc, ac = tables.get((0, selector >> 4)), tables.get((1, selector & 15))
                if dc is None or ac is None or qt not in quant:
                    raise LoiJPEG('Thiếu DHT/DQT được tham chiếu')
                scan.append((h*v if ns > 1 else 1, dc, ac))
                seen.add(cid)
            hm, vm = max(v[0] for v in frame.values()), max(v[1] for v in frame.values())
            if ns > 1:
                mcus = math.ceil(width / (8*hm)) * math.ceil(height / (8*vm))
            else:
                h, v, _ = frame[next(iter(seen))]
                mcus = math.ceil(width*h / (8*hm)) * math.ceil(height*v / (8*vm))
            # Mỗi block cần ít nhất một mã DC và một mã AC; giới hạn cả ảnh giả mạo.
            block_count = mcus * sum(s[0] for s in scan)
            if block_count > len(data) * 4:
                raise LoiJPEG('Kích thước ảnh vượt lượng dữ liệu entropy có thể chứa')
            bits = _Bits(data, pos)
            rst = 0
            for mcu in range(mcus):
                if mcu % 256 == 0 and deadline is not None and time.monotonic() > deadline:
                    raise RuntimeError('TH3: vượt ngân sách thời gian giải mã JPEG')
                for num, dc, ac in scan:
                    for _ in range(num):
                        _block(bits, dc, ac)
                if restart and (mcu + 1) % restart == 0 and mcu + 1 < mcus:
                    bits.align()
                    mark, bits.pos = _marker(data, bits.pos)
                    if mark != 0xD0 + rst:
                        raise LoiJPEG('Sai thứ tự restart marker')
                    rst = (rst + 1) % 8
            bits.align()
            pos = bits.pos
            done.update(seen)
            scans += 1
            blocks_total += block_count
            mcus_total += mcus
        elif 0xE0 <= marker <= 0xEF or marker == 0xFE:
            pass  # APPn/COM có độ dài; không tìm marker trong payload.
        else:
            raise LoiJPEG(f'Chưa hỗ trợ marker FF{marker:02X}; cần JPEG baseline Huffman')
    raise LoiJPEG('Thiếu EOI')
