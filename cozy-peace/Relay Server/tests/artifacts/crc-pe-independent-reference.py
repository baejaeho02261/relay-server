#!/usr/bin/env python3
"""Test-only full PE CRC oracle. No production hashing/PE module is imported.

Shares only the existing independent Python struct/bitwise/integer reference.
Input files are read as bytes, never mapped/executed. SHA-512 is independently
implemented there rather than using the Delphi or Node digest implementation.
PE layout rules: https://learn.microsoft.com/windows/win32/debug/pe-format
"""
import importlib.util
import json
from pathlib import Path
import struct
import sys

spec = importlib.util.spec_from_file_location('independent_contract_reference',
    Path(__file__).resolve().parent.parent / 'protocol' / 'independent-contract-reference.py')
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)


def framed_ranges(stream, prefix=b''):
    at = len(prefix)
    if prefix:
        ref.require(stream.startswith(prefix))
        count = struct.unpack_from('<I', stream, at)[0]
        at += 4
    else:
        count = None
    result = []
    while at < len(stream) and (count is None or len(result) < count):
        rva, size = struct.unpack_from('<II', stream, at)
        at += 8
        ref.require(at + size <= len(stream))
        result.append(dict(rva=rva, span=size))
        at += size
    ref.require(at == len(stream) and (count is None or len(result) == count))
    return result


def snapshot(data):
    try:
        # The native constructor needs at least export/exception/reloc fields.
        pe = ref.PeLayout(data)
        ref.require(pe.opt_size >= 160)
        pe.load_sections()
        code, protected = ref.pe_code(data, True)
        layers, _ = ref.auxiliary_reference(data, code, protected)
        headers = ref.header_stream(pe)
        export, exports = ref.export_reference(data)
        checkers, _ = ref.checker_reference(pe, protected)
        parameters = ref.crc_parameters()
        inputs = {
            'ecma182': code,
            'nvme': checkers.get('nvme', b'') + ref.crc_table('ecma182'),
            'jones': checkers.get('jones', b''),
            'xz': headers + exports,
            'we': b''.join(ref.crc_table(k) for k in ref.CRC) + parameters + ref.sha512(code).encode('ascii'),
            'iso': checkers.get('iso', b''),
            'crc32c': ref.page_manifest(code),
            'crc16_arc': parameters,
            'crc8_smbus': struct.pack('<BQQQ', 1, len(code), len(headers), len(exports)),
        }
        relocations = []
        # pe_code already checked duplicates/straddles and normalized operands.
        rr, rs = pe.directory(5)
        if rs:
            # Header-backed relocs are valid for code. PeLayout.relocations is
            # intentionally section-only for export/anchor admission; use a
            # separately bounded reader for complete selected code operands.
            at = rr if rr < pe.headers and rr + rs <= pe.headers else pe.raw(rr, rs, True)
            stop = at + rs
            while at < stop:
                page, block = struct.unpack_from('<II', data, at)
                for offset in range(at + 8, at + block, 2):
                    entry = pe.u16(offset)
                    kind, rva = entry >> 12, page + (entry & 4095)
                    width = {10: 8, 3: 4}.get(kind, 1)
                    if kind and any(s['rva'] <= rva < s['rva'] + s['span'] for s in protected):
                        relocations.append(dict(rva=rva, span=width))
                at += block
        ranges = dict(
            code=[dict(rva=s['rva'], span=s['span']) for s in protected],
            headers=framed_ranges(headers),
            codeRelocations=sorted(relocations, key=lambda x:x['rva']),
            checkers={role:framed_ranges(checkers[role], b'CRC-CHECKERS-V1\0') if role in checkers else []
                      for role in ('nvme', 'jones', 'iso')})
        return dict(accepted=True, version=1, codeSha512=ref.sha512(code),
                    exportStatus=export['status'], layers=layers, ranges=ranges,
                    inputs={kind:dict(bytes=len(value), sha512=ref.sha512(value)) for kind,value in inputs.items()})
    except (ValueError, struct.error, IndexError, OverflowError):
        return dict(accepted=False)


def main():
    paths = json.load(sys.stdin)
    ref.require(isinstance(paths, list) and len(paths) <= 256)
    result = []
    for name in paths:
        path = Path(name)
        ref.require(path.is_file() and path.stat().st_size <= 64 * 1024 * 1024)
        result.append(snapshot(path.read_bytes()))
    json.dump(result, sys.stdout, separators=(',', ':'))


if __name__ == '__main__':
    main()
