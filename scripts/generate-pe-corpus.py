#!/usr/bin/env python3
"""Independent byte fixtures / expected SHA512 + bitwise CRC; no production parser import.
No PE is loaded/executed. --write updates the pinned JSON, default checks drift.
"""
import base64,hashlib,json,pathlib,struct,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
def crc(data):
    v=0
    for c in data:
        v ^= c << 56
        for _ in range(8): v=((v<<1) ^ (0x42F0E1EBA9EA3693 if v>>63 else 0)) & ((1<<64)-1)
    return f'{v:016X}'
def pe():
    b=bytearray(3072)
    def put(o,fmt,*v): struct.pack_into('<'+fmt,b,o,*v)
    b[:2]=b'MZ';put(60,'I',128);b[128:132]=b'PE\0\0'
    put(132,'HH',0x8664,4);put(148,'H',240);put(152,'H',0x20b)
    put(176,'Q',0x140000000);put(184,'II',4096,512);put(208,'II',0x5000,1024);put(260,'I',16)
    # .text = 520 logical bytes, 512 file backed: 8 zero-filled bytes.
    for i,(name,rva,span,raw,flags) in enumerate([(b'.text',0x1000,520,1024,0x60000020),(b'.rdata',0x2000,512,1536,0x40000040),(b'.reloc',0x3000,512,2048,0x42000040),(b'.data',0x4000,512,2560,0xc0000040)]):
        o=392+40*i;b[o:o+len(name)]=name;put(o+8,'IIII',span,rva,512,raw);put(o+36,'I',flags)
    for i in range(512): b[1024+i]=(i*13+7)%256
    put(304,'II',0x3000,12);put(2048,'IIHH',0x1000,12,0xa018,0x3030)
    put(288,'II',0x2040,24);put(1600,'III',0x1000,0x1020,0x2080);put(1612,'III',0x1020,0x1040,0x2080)
    b[1664]=1
    return b
base=pe();rows=[]
def add(name,edit=lambda b:None,accepted=True,code_edit=None,note=''):
    b=bytearray(base);edit(b)
    row={'id':name,'accepted':accepted,'bytes':base64.b64encode(b).decode(),'note':note}
    if accepted:
        code=bytearray(b[1024:1536])+bytes(8);code[24:32]=bytes(8);code[48:52]=bytes(4)
        if code_edit: code_edit(code)
        stream=b'GAME-CODE-V1\0'+struct.pack('<III',1,0x1000,520)+code
        row.update(codeSha512=hashlib.sha512(stream).hexdigest(),codeCrc64=crc(stream),fileSha512=hashlib.sha512(b).hexdigest(),fileCrc64=crc(b))
    rows.append(row)
def p(o,fmt,v): return lambda b:struct.pack_into('<'+fmt,b,o,v)
add('normal-zero-fill-and-two-relocation-widths')
add('code-byte-changed',lambda b:b.__setitem__(1064,b[1064]^1))
add('relocation-operands-changed',lambda b:b.__setitem__(slice(1048,1056),b'12345678'))
add('mutable-data-changed',lambda b:b.__setitem__(2600,77))
add('missing-pdata',lambda b:b.__setitem__(slice(288,296),bytes(8)),note='Accepted code baseline; missing unwind coverage is not full CRC/checker verification.')
add('export-directory-unsupported',p(264,'I',0xFFFFFF00),note='Code hash remains measurable; export coverage must not claim MEASURED.')
add('bad-dos',p(0,'H',0),False)
add('bad-machine',p(132,'H',0x14c),False)
add('bad-pe-offset',p(60,'I',0xFFFFFFF0),False)
add('too-many-sections',p(134,'H',97),False)
add('optional-header-small',p(148,'H',100),False)
add('bad-image-size',p(208,'I',0xFFFFFFFF),False)
add('directory-count-overflow',p(260,'I',17),False)
add('raw-overlap',p(452,'I',1024),False)
add('virtual-overlap',p(444,'I',0x1000),False)
add('raw-out-of-file',p(412,'I',0xFFFFFFF0),False)
add('no-immutable-code',p(428,'I',0xE0000020),False)
add('relocation-half-directory',p(308,'I',0),False)
add('relocation-odd-block',p(2052,'I',11),False)
add('relocation-unknown-in-code',p(2056,'H',0x5018),False)
add('relocation-overlap',p(2058,'H',0x301c),False)
add('relocation-crosses-zero-fill-end',p(2056,'H',0xa204),False)
add('pdata-half-directory',p(292,'I',0),False)
add('pdata-unsorted',lambda b:b.__setitem__(slice(1600,1624),b[1612:1624]+b[1600:1612]),False)
add('pdata-overlap',p(1604,'I',0x1030),False)
add('pdata-misaligned',p(288,'I',0x2041),False)
add('pdata-unwind-in-code',p(1608,'I',0x1000),False)
add('pdata-code-range-outside',p(1604,'I',0x1800),False)
value={'version':1,'normalization':'PE64-CODE-V1','preflight':'PE64-PREFLIGHT-V1','oracle':'Python hashlib SHA512 + independent bitwise CRC64-ECMA, no production parsing/hash code','cases':rows}
text=json.dumps(value,ensure_ascii=False,indent=2)+'\n';dest=ROOT/'contracts/pe-corpus-v1.json'
if '--write' in sys.argv: dest.parent.mkdir(exist_ok=True);dest.write_text(text)
elif dest.read_text()!=text: raise SystemExit('PE_CORPUS_DRIFT')
print(f'PE_CORPUS_OK {len(rows)} cases')
