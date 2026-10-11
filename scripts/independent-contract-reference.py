#!/usr/bin/env python3
"""TEST ONLY: separate integer SHA-512/CRC64 and bounded PE64 reference.
No production module is imported. SHA constants are derived from prime roots;
this does not call hashlib/OpenSSL. Protocol JSON fixtures contain safe integers,
not floating-point serialization edge cases. This is not a replacement verifier.
"""
import base64
import decimal
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

def require(condition):
    if not condition:
        raise ValueError('PE_REFERENCE_REJECTED')

def pe_code(data):
    """PE64-CODE-V1 reference, including .pdata shape and protected relocations.
    Export/auxiliary CRC layers are intentionally not compared by this function.
    """
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
    return dict(accepted=True, codeSha512=sha512(normalized), codeCrc64=crc64(normalized))

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
        hashes.append(dict(sha512=sha512(data),crc64=crc64(data)))
    pes=[]
    for v in payload['pe']:
        try:
            pes.append(pe_code(base64.b64decode(v,validate=True)))
        except (ValueError,struct.error,IndexError):
            pes.append(dict(accepted=False))
    protocols=[sha512(('GAME-REQUEST-RECEIPT-V1\n'+v['purpose']+'\n'+stable(v['body'])).encode('utf8')) for v in payload['protocols']]
    h=payload['handoff']; digest=sha512(h['claim'].encode('utf8'))
    canonical=lambda kind:'\n'.join(['GAME-HANDOFF-'+kind+'-V3',h['role'],digest,h['childKeyId'],h['nonce']])
    print(json.dumps(dict(hashes=hashes,pe=pes,protocols=protocols,handoff=dict(claimSha512=digest,delegationCanonical=canonical('DELEGATION'),claimCanonical=canonical('CLAIM')))))

if __name__ == '__main__':
    main()
