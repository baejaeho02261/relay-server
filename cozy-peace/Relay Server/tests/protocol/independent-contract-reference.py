#!/usr/bin/env python3
"""TEST ONLY: independent integer SHA-512, nine bitwise CRCs and PE64 reference.
No production module is imported. SHA constants are derived from prime roots;
this does not call hashlib/OpenSSL. Protocol JSON fixtures contain safe integers,
not floating-point serialization edge cases. This is not a replacement verifier.
"""
import base64
import decimal
import functools
import json
import struct
import sys

MASK = (1 << 64) - 1
PRIMES = []
n = 2
while len(PRIMES) < 80:
    if all(n % d for d in range(2, int(n ** .5) + 1)):
        PRIMES.append(n)
    n += 1
with decimal.localcontext() as ctx:
    ctx.prec = 180
    def fraction_root(p, degree):
        r = decimal.Decimal(p) ** (decimal.Decimal(1) / degree)
        return int((r - int(r)) * (1 << 64))
    IV = [fraction_root(p, 2) for p in PRIMES[:8]]
    ROUND = [fraction_root(p, 3) for p in PRIMES]
assert IV[0] == 0x6a09e667f3bcc908 and ROUND[0] == 0x428a2f98d728ae22

def rotr(x, amount):
    return ((x >> amount) | (x << (64 - amount))) & MASK

def sha512(data):
    length = len(data) * 8
    padded = data + b'\x80'
    padded += b'\x00' * ((112 - len(padded) % 128) % 128)
    padded += length.to_bytes(16, 'big')
    state = IV.copy()
    for offset in range(0, len(padded), 128):
        words = list(struct.unpack('>16Q', padded[offset:offset + 128]))
        for i in range(16, 80):
            x, y = words[i - 15], words[i - 2]
            s0 = rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
            s1 = rotr(y, 19) ^ rotr(y, 61) ^ (y >> 6)
            words.append((words[i - 16] + s0 + words[i - 7] + s1) & MASK)
        a, b, c, d, e, f, g, h = state
        for word, k in zip(words, ROUND):
            t1 = (h + (rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)) + ((e & f) ^ ((~e) & g)) + k + word) & MASK
            t2 = ((rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))) & MASK
            a, b, c, d, e, f, g, h = (t1 + t2) & MASK, a, b, c, (d + t1) & MASK, e, f, g
        state = [(x + y) & MASK for x, y in zip(state, [a, b, c, d, e, f, g, h])]
    return ''.join(f'{x:016x}' for x in state)

def crc64(data):
    value = 0
    for byte in data:
        value ^= byte << 56
        for _ in range(8):
            value = ((value << 1) ^ (0x42F0E1EBA9EA3693 if value & (1 << 63) else 0)) & MASK
    return f'{value:016X}'

# Rocksoft parameters in protocol order; these are constants, not values
# supplied by the system under test. CHECK values pin the named variants.
CRC = {
    'ecma182': ('CRC-64/ECMA-182', 64, 0x42F0E1EBA9EA3693, 0, False, 0, 0x6C40DF5F0B497347),
    'nvme': ('CRC-64/NVME', 64, 0xAD93D23594C93659, MASK, True, MASK, 0xAE8B14860A799888),
    'jones': ('CRC-64/JONES', 64, 0xAD93D23594C935A9, MASK, True, 0, 0xCAA717168609F281),
    'xz': ('CRC-64/XZ', 64, 0x42F0E1EBA9EA3693, MASK, True, MASK, 0x995DC9BBDF1939FA),
    'we': ('CRC-64/WE', 64, 0x42F0E1EBA9EA3693, MASK, False, MASK, 0x62EC59E3F1A4F00A),
    'iso': ('CRC-64/GO-ISO', 64, 0x1B, MASK, True, MASK, 0xB90956C775A41001),
    'crc32c': ('CRC-32/ISCSI', 32, 0x1EDC6F41, 0xFFFFFFFF, True, 0xFFFFFFFF, 0xE3069283),
    'crc16_arc': ('CRC-16/ARC', 16, 0x8005, 0, True, 0, 0xBB3D),
    'crc8_smbus': ('CRC-8/SMBUS', 8, 0x07, 0, False, 0, 0xF4),
}

def crc_value(kind, data, table_entry=False):
    _, width, polynomial, initial, reflected, final, _ = CRC[kind]
    mask, high = (1 << width) - 1, 1 << (width - 1)
    value = 0 if table_entry else initial
    # Always shift left using the canonical polynomial. Reflected variants
    # reverse each input octet and the final register, independently of the
    # production implementation's reflected lookup tables and split words.
    if reflected:
        value = int(f'{value:0{width}b}'[::-1], 2)
    for byte in data:
        if reflected:
            byte = int(f'{byte:08b}'[::-1], 2)
        value ^= byte << (width - 8)
        for _ in range(8):
            value = ((value << 1) ^ (polynomial if value & high else 0)) & mask
    if reflected:
        value = int(f'{value:0{width}b}'[::-1], 2)
    return value ^ (0 if table_entry else final)

def crc_hex(kind, data):
    return f'{crc_value(kind, data):0{CRC[kind][1] // 4}X}'

@functools.lru_cache(maxsize=9)
def crc_table(kind):
    return b''.join(struct.pack('<Q', crc_value(kind, bytes([i]), True)) for i in range(256))

def crc_parameters():
    return b''.join(struct.pack('<BBQQQQ', width, int(reflected), poly, initial, final, check)
                    for _, width, poly, initial, reflected, final, check in CRC.values())

def page_manifest(code):
    prefix = b'GAME-CODE-V1\0'
    require(len(prefix) + 4 <= len(code) <= 64 * 1024 * 1024 + 4096 and code.startswith(prefix))
    count = struct.unpack_from('<I', code, len(prefix))[0]
    require(1 <= count <= 96)
    at, previous, pages = len(prefix) + 4, 0, []
    for _ in range(count):
        require(at + 8 <= len(code))
        rva, length = struct.unpack_from('<II', code, at)
        at += 8
        require(length > 0 and at + length <= len(code) and previous <= rva and rva + length <= 0xFFFFFFFF)
        previous = rva + length
        while length:
            size = min(length, 4096 - rva % 4096)
            pages.append(struct.pack('<III', rva, size, crc_value('crc32c', code[at:at + size])))
            at, rva, length = at + size, rva + size, length - size
    require(at == len(code))
    return b'CRC-PAGES-V1\0' + struct.pack('<II', 4096, len(pages)) + b''.join(pages)

def require(condition):
    if not condition:
        raise ValueError('PE_REFERENCE_REJECTED')

def pe_code(data, details=False):
    """PE64-CODE-V1 including .pdata shape and protected relocations."""
    require(512 <= len(data) <= 64 * 1024 * 1024 and data[:2] == b'MZ')
    def u16(at):
        require(0 <= at <= len(data) - 2)
        return struct.unpack_from('<H', data, at)[0]
    def u32(at):
        require(0 <= at <= len(data) - 4)
        return struct.unpack_from('<I', data, at)[0]
    pe = u32(0x3c)
    require(64 <= pe <= len(data) - 24 and data[pe:pe+4] == b'PE\0\0' and u16(pe+4) == 0x8664)
    count, opt_size, opt = u16(pe+6), u16(pe+20), pe+24
    table = opt + opt_size
    require(1 <= count <= 96 and opt_size >= 160 and table + count*40 <= len(data) and u16(opt) == 0x20b)
    image, headers, directories = u32(opt+56), u32(opt+60), u32(opt+108)
    require(4096 <= image <= 128*1024*1024 and table+count*40 <= headers <= len(data) and directories <= 16 and 112+directories*8 <= opt_size)
    sections = []
    for i in range(count):
        entry = table+i*40
        virtual, rva, size, raw = struct.unpack_from('<4I', data, entry+8)
        flags = u32(entry+36)
        span = virtual or size
        mapped = max(span, size)
        require(span > 0 and rva >= headers and rva+mapped <= image and (not size or headers <= raw and raw+size <= len(data)))
        sections.append(dict(rva=rva, span=span, mapped=mapped, size=size, raw=raw, flags=flags))
    def nonoverlap(ranges):
        ranges = sorted(ranges)
        require(all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])))
    nonoverlap([(s['rva'], s['rva']+s['mapped']) for s in sections])
    nonoverlap([(s['raw'], s['raw']+s['size']) for s in sections if s['size']])
    protected = sorted([s.copy() for s in sections if s['flags'] & 0x20000000 and not s['flags'] & 0x80000000], key=lambda s:s['rva'])
    require(protected and sum(s['span'] for s in protected) <= 64*1024*1024)
    def locate(rva, length, virtual_limit=True):
        return next((s for s in sections if s['rva'] <= rva and rva+length <= s['rva']+(min(s['size'],s['span']) if virtual_limit else s['size'])), None)
    def directory(index):
        return (u32(opt+112+index*8), u32(opt+116+index*8)) if directories > index else (0,0)
    er, es = directory(3)
    if er or es:
        require(er > 0 and er % 4 == 0 and 0 < es <= 16*1024*1024 and es % 12 == 0)
        section = locate(er, es)
        require(section and not section['flags'] & 0xA0000000)
        at = section['raw'] + er-section['rva']
        last_end = 0
        for offset in range(at, at+es, 12):
            begin, end, unwind = struct.unpack_from('<3I', data, offset)
            require(end > begin and begin >= last_end and unwind % 4 == 0)
            code, meta = locate(begin, end-begin), locate(unwind, 4)
            require(code and code['flags'] & 0x20000000 and not code['flags'] & 0x80000000)
            require(meta and meta['flags'] & 0x40000000 and not meta['flags'] & 0x20000000)
            last_end = end
    for s in protected:
        s['content'] = bytearray(data[s['raw']:s['raw']+min(s['size'],s['span'])])
        s['content'] += bytes(s['span']-len(s['content']))
    rr, rs = directory(5)
    require(bool(rr) == bool(rs) and rs <= 16*1024*1024)
    relocations = []
    if rs:
        owner = locate(rr, rs, False)
        at = rr if rr < headers and rr+rs <= headers else (owner['raw'] + rr-owner['rva'] if owner else -1)
        require(at >= 0)
        end = at + rs
        while at < end:
            require(at+8 <= end)
            page, size = u32(at), u32(at+4)
            require(size >= 8 and size % 2 == 0 and at+size <= end and page < image)
            for offset in range(at+8, at+size, 2):
                entry = u16(offset)
                kind, target = entry >> 12, page+(entry & 4095)
                if kind == 0:
                    continue
                width = {10:8, 3:4}.get(kind, 1)
                code = next((s for s in protected if target < s['rva']+s['span'] and target+width > s['rva']), None)
                if code is not None:
                    require(kind in (10,3) and code['rva'] <= target and target+width <= code['rva']+code['span'])
                    code['content'][target-code['rva']:target-code['rva']+width] = bytes(width)
                    relocations.append((target,target+width))
                    require(len(relocations) <= 1000000)
            at += size
        nonoverlap(relocations)
    normalized = bytearray(b'GAME-CODE-V1\0') + struct.pack('<I', len(protected))
    for s in protected:
        normalized.extend(struct.pack('<II', s['rva'], s['span']))
        normalized.extend(s['content'])
    if details:
        return bytes(normalized), protected
    return dict(accepted=True, codeSha512=sha512(normalized), codeCrc64=crc64(normalized))

class PeLayout:
    """Bounded file/RVA reader; never load or execute an input image."""
    def __init__(self, data):
        self.data = data
        require(512 <= len(data) <= 64 * 1024 * 1024 and data[:2] == b'MZ')
        self.pe = self.u32(60)
        require(64 <= self.pe <= len(data) - 24 and data[self.pe:self.pe + 4] == b'PE\0\0')
        require(self.u16(self.pe + 4) == 0x8664)
        self.count, self.opt = self.u16(self.pe + 6), self.pe + 24
        self.opt_size = self.u16(self.pe + 20)
        self.table = self.opt + self.opt_size
        require(1 <= self.count <= 96 and self.opt_size >= 112 and self.table + self.count * 40 <= len(data))
        require(self.u16(self.opt) == 0x20B)
        self.image, self.headers, self.dirs = self.u32(self.opt + 56), self.u32(self.opt + 60), self.u32(self.opt + 108)
        require(4096 <= self.image <= 128 * 1024 * 1024 and self.table + self.count * 40 <= self.headers <= len(data))
        require(self.dirs <= 16 and 112 + self.dirs * 8 <= self.opt_size)
        self.sections = None

    def read(self, at, fmt):
        require(0 <= at <= len(self.data) - struct.calcsize(fmt))
        return struct.unpack_from(fmt, self.data, at)[0]

    def u16(self, at): return self.read(at, '<H')
    def u32(self, at): return self.read(at, '<I')
    def u64(self, at): return self.read(at, '<Q')

    def directory(self, index):
        return (self.u32(self.opt + 112 + index * 8), self.u32(self.opt + 116 + index * 8)) if index < self.dirs else (0, 0)

    def load_sections(self):
        sections = []
        for i in range(self.count):
            at = self.table + i * 40
            span, rva, size, raw = struct.unpack_from('<4I', self.data, at + 8)
            span = span or size
            mapped = max(span, size)
            require(mapped and rva >= self.headers and rva + mapped <= self.image)
            require(not size or self.headers <= raw and raw + size <= len(self.data))
            sections.append(dict(rva=rva, span=span, mapped=mapped, size=size, raw=raw, flags=self.u32(at + 36)))
        for field, extent in [('rva', 'mapped'), ('raw', 'size')]:
            intervals = sorted((s[field], s[field] + s[extent]) for s in sections if s[extent])
            require(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])))
        self.sections = sections

    def locate(self, rva, length, raw_only=False):
        require(length >= 0)
        return next((s for s in self.sections if s['rva'] <= rva and
                     rva + length <= s['rva'] + (s['size'] if raw_only else min(s['size'], s['span']))), None)

    def raw(self, rva, length, raw_only=False):
        section = self.locate(rva, length, raw_only)
        require(section is not None)
        return section['raw'] + rva - section['rva']

    def relocations(self, readonly=False):
        rva, size = self.directory(5)
        require(bool(rva) == bool(size) and size <= 16 * 1024 * 1024)
        if not size: return
        section = self.locate(rva, size, not readonly)
        require(section is not None and (not readonly or not section['flags'] & 0x80000000))
        at = section['raw'] + rva - section['rva']
        stop = at + size
        while at < stop:
            require(at + 8 <= stop)
            page, block = self.u32(at), self.u32(at + 4)
            require(page < self.image and block >= 8 and block % 2 == 0 and at + block <= stop)
            for offset in range(at + 8, at + block, 2):
                item = self.u16(offset)
                kind, target = item >> 12, page + (item & 4095)
                if kind: yield kind, target, {10: 8, 3: 4}.get(kind, 1)
            at += block

def export_reference(data):
    try:
        pe = PeLayout(data)
        rva, span = pe.directory(0)
        if not rva and not span:
            return dict(status='NO_EXPORTS', sha512='', crc64=''), b''
        require(rva > 0 and 40 <= span <= 8 * 1024 * 1024 and rva + span <= pe.image)
        pe.load_sections()
        section = pe.locate(rva, span)
        require(section is not None and not section['flags'] & 0x80000000)
        start, end = section['raw'] + rva - section['rva'], rva + span
        def inside(address, length):
            require(length >= 0 and rva <= address and address + length <= end)
            return start + address - rva
        def string(address, forwarder=False):
            at = inside(address, 1)
            for i in range(512):
                require(address + i < end)
                byte = data[at + i]
                if byte == 0:
                    require(i > 0)
                    return
                require(32 <= byte <= 126 and not (forwarder and byte == 32))
            require(False)
        functions, names = pe.u32(start + 20), pe.u32(start + 24)
        require(names <= functions <= 131072)
        string(pe.u32(start + 12))
        fa = inside(pe.u32(start + 28), functions * 4) if functions else 0
        na = inside(pe.u32(start + 32), names * 4) if names else 0
        oa = inside(pe.u32(start + 36), names * 2) if names else 0
        exported = code = forwarded = 0
        for i in range(functions):
            target = pe.u32(fa + i * 4)
            if not target: continue
            require(target < pe.image)
            exported += 1
            if rva <= target < end:
                string(target, True)
                forwarded += 1
            elif any(s['rva'] <= target < s['rva'] + s['span'] and
                     s['flags'] & 0x20000000 and not s['flags'] & 0x80000000 for s in pe.sections):
                code += 1
        for i in range(names):
            require(pe.u16(oa + i * 2) < functions)
            string(pe.u32(na + i * 4))
        for _, target, width in pe.relocations():
            require(not (target < end and target + width > rva))
        offset = pe.opt + 112
        stream = b'GAME-EXPORT-V1\0' + struct.pack('<I', offset) + data[offset:offset + 8] + data[start:start + span]
        return dict(status='MEASURED', sha512=sha512(stream), crc64=crc64(stream), directoryOffset=offset,
                    rva=rva, span=span, exportCount=exported, codeExportCount=code, forwardedExportCount=forwarded), stream
    except (ValueError, struct.error, IndexError):
        return dict(status='UNSUPPORTED_EXPORT_LAYOUT', sha512='', crc64=''), b''

def header_stream(pe):
    require(pe.headers <= pe.image)
    ranges = [(0, 2), (60, 4), (pe.pe, 8), (pe.pe + 20, 4), (pe.opt, 2),
              (pe.opt + 16, 8), (pe.opt + 32, 8), (pe.opt + 56, 8), (pe.opt + 108, 4)]
    if pe.dirs: ranges.append((pe.opt + 112, pe.dirs * 8))
    for i in range(pe.count): ranges.extend([(pe.table + i * 40 + 8, 16), (pe.table + i * 40 + 36, 4)])
    require(all(offset + size <= pe.headers for offset, size in ranges))
    return b''.join(struct.pack('<II', offset, size) + pe.data[offset:offset + size] for offset, size in ranges)

def checker_reference(pe, protected):
    marker = bytes.fromhex('47435243414e4348038d47912a60b5ec')
    metadata = lambda s: s['flags'] & 0x40000000 and not s['flags'] & 0x20000000
    executable = lambda s: s['flags'] & 0x20000000 and not s['flags'] & 0x80000000
    candidates = []
    for section in filter(metadata, pe.sections):
        chunk = pe.data[section['raw']:section['raw'] + min(section['size'], section['span'])]
        at = chunk.find(marker)
        while at >= 0:
            require(at + 72 <= len(chunk))
            candidates.append((section['raw'] + at, section['rva'] + at))
            require(len(candidates) == 1)
            at = chunk.find(marker, at + 1)
    if not candidates: return {}, 'unavailable'
    at, anchor = candidates[0]
    require(pe.u32(at + 16) == 1 and pe.u32(at + 20) == 6)
    base = pe.u64(pe.opt + 24)
    targets = [pe.u64(at + 24 + i * 8) - base for i in range(6)]
    for target in targets:
        section = pe.locate(target, 1)
        require(0 <= target < pe.image and section is not None and executable(section))
    require(all(pe.directory(5)))
    hits = []
    for kind, target, width in pe.relocations(True):
        if target < anchor + 72 and target + width > anchor + 24:
            require(kind == 10 and anchor + 24 <= target and target + 8 <= anchor + 72 and (target - anchor - 24) % 8 == 0)
            hits.append(target)
    require(len(hits) == 6 and len(set(hits)) == 6)
    rva, length = pe.directory(3)
    if not rva and not length: return {}, 'unavailable'
    require(rva > 0 and rva % 4 == 0 and 0 < length <= 16 * 1024 * 1024 and length % 12 == 0)
    section = pe.locate(rva, length)
    require(section is not None and not section['flags'] & 0xA0000000)
    start, previous, functions = pe.raw(rva, length), 0, []
    for offset in range(start, start + length, 12):
        begin, end, unwind = struct.unpack_from('<III', pe.data, offset)
        require(previous <= begin < end and unwind % 4 == 0)
        code, meta = pe.locate(begin, end - begin), pe.locate(unwind, 4)
        require(code is not None and executable(code) and meta is not None and metadata(meta))
        functions.append((begin, end))
        previous = end
    result = {}
    for role, indexes in [('nvme', [0]), ('jones', [1, 2]), ('iso', [3, 4, 5])]:
        spans = [next(((a, b) for a, b in functions if a <= targets[i] < b), None) for i in indexes]
        if None in spans: continue
        spans = sorted(set(spans))
        stream = b'CRC-CHECKERS-V1\0' + struct.pack('<I', len(spans))
        for begin, end in spans:
            section = next((s for s in protected if s['rva'] <= begin and end <= s['rva'] + s['span']), None)
            require(section is not None)
            stream += struct.pack('<II', begin, end - begin) + section['content'][begin - section['rva']:end - section['rva']]
        result[role] = stream
    return result, 'measured' if len(result) == 3 else 'partial'

def auxiliary_reference(data, code, protected):
    pe = PeLayout(data)
    pe.load_sections()
    headers = header_stream(pe)
    _, exports = export_reference(data)
    checkers, status = checker_reference(pe, protected)
    entries = []
    for section in protected:
        at = 0
        while at < section['span']:
            rva = section['rva'] + at
            size = min(section['span'] - at, 4096 - rva % 4096)
            entries.append(struct.pack('<III', rva, size, crc_value('crc32c', section['content'][at:at + size])))
            at += size
    pages = b'CRC-PAGES-V1\0' + struct.pack('<II', 4096, len(entries)) + b''.join(entries)
    params = crc_parameters()
    def measured(kind, role, value):
        return dict(algorithm=CRC[kind][0], role=role, status='measured', digest=crc_hex(kind, value), bytes=len(value))
    result = dict(version='CRC-LAYERS-V1', ecma182=measured('ecma182', 'normalized-code', code))
    result['nvme'] = measured('nvme', 'ecma-checker-and-table' if 'nvme' in checkers else 'ecma-lookup-table',
                              checkers.get('nvme', b'') + crc_table('ecma182'))
    if 'nvme' not in checkers: result['nvme'].update(status='partial', reason='CHECKER_RANGES_REQUIRED')
    for kind, role in [('jones', 'integrity-routine-code'), ('iso', 'auxiliary-checker-code')]:
        result[kind] = measured(kind, role, checkers[kind]) if kind in checkers else dict(
            algorithm=CRC[kind][0], role=role, status='unavailable', reason='CHECKER_RANGES_REQUIRED')
    result['xz'] = measured('xz', 'header-ranges-and-export', headers + exports)
    result['we'] = measured('we', 'crc-tables-parameters-and-baseline',
                            b''.join(crc_table(k) for k in CRC) + params + sha512(code).encode('ascii'))
    result['crc32c'] = dict(algorithm='CRC-32/ISCSI', role='rva-aligned-code-pages', status='measured', digest=sha512(pages),
                           digestAlgorithm='SHA-512-PAGE-MANIFEST', pageSize=4096, pages=len(entries), bytes=len(pages))
    result['crc16_arc'] = measured('crc16_arc', 'crc-parameters', params)
    result['crc8_smbus'] = measured('crc8_smbus', 'layout-state', struct.pack('<BQQQ', 1, len(code), len(headers), len(exports)))
    return result, status

def stable(value):
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k:k.encode('utf-16-be'))
        return '{'+','.join(json.dumps(k,ensure_ascii=False)+':'+stable(value[k]) for k in keys)+'}'
    if isinstance(value, list):
        return '['+','.join(stable(v) for v in value)+']'
    if isinstance(value, int) and not isinstance(value, bool):
        require(abs(value) <= (1<<53)-1)
    require(not isinstance(value, float))
    return json.dumps(value, ensure_ascii=False, separators=(',',':'))

def main():
    raw=sys.stdin.buffer.read(8*1024*1024+1)
    if len(raw)>8*1024*1024:
        raise ValueError('REFERENCE_INPUT_LIMIT')
    payload=json.loads(raw.decode('utf8'))
    hashes=[]
    for v in payload['hashes']:
        data=base64.b64decode(v,validate=True)
        hashes.append(dict(sha512=sha512(data),crc64=crc64(data),crcs={kind:crc_hex(kind,data) for kind in CRC}))
    pes=[]
    for v in payload['pe']:
        try:
            data=base64.b64decode(v,validate=True)
            code,protected=pe_code(data,True)
            layers,status=auxiliary_reference(data,code,protected)
            pes.append(dict(accepted=True,codeSha512=sha512(code),codeCrc64=crc64(code),crcLayers=layers,checkerStatus=status))
        except (ValueError,struct.error,IndexError):
            pes.append(dict(accepted=False))
    exports=[export_reference(base64.b64decode(v,validate=True))[0] for v in payload['pe']]
    constants=dict(parameters=crc_hex('we',crc_parameters()), tables=crc_hex('we',b''.join(crc_table(kind) for kind in CRC)))
    page_vectors=[page_manifest(base64.b64decode(v,validate=True)).hex().upper() for v in payload.get('crcPages',[])]
    protocols=[sha512(('GAME-REQUEST-RECEIPT-V1\n'+v['purpose']+'\n'+stable(v['body'])).encode('utf8')) for v in payload['protocols']]
    h=payload['handoff']; digest=sha512(h['claim'].encode('utf8'))
    canonical=lambda kind:'\n'.join(['GAME-HANDOFF-'+kind+'-V3',h['role'],digest,h['childKeyId'],h['nonce']])
    print(json.dumps(dict(hashes=hashes,pe=pes,exports=exports,crcConstants=constants,crcPageManifests=page_vectors,protocols=protocols,handoff=dict(claimSha512=digest,delegationCanonical=canonical('DELEGATION'),claimCanonical=canonical('CLAIM')))))

if __name__ == '__main__':
    main()
