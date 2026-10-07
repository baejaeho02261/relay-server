#!/usr/bin/env python3
"""Validate the real compiled Pascal HashProbe. Never substitutes another implementation.
SHA-512 is compared with Python/OpenSSL; XXH3-128 with upstream libxxhash;
BLAKE3 hash, keyed, derive, XOF and seek with official project vectors.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--extended-vectors', type=Path, default=here / 'fixtures/extended-hash-vectors.json')
    parser.add_argument('--blake3-vectors', type=Path,
                        default=here.parent.parent / 'GameConnect_Win64/tests/blake3-official-full-vectors.json')
    parser.add_argument('--xxhash-library', default=ctypes.util.find_library('xxhash'))
    args = parser.parse_args()
    probe = args.probe.resolve()
    if not probe.is_file(): parser.error('--probe must identify an actual compiled Pascal executable')
    if not args.xxhash_library: parser.error('Upstream libxxhash is required for an independent XXH3-128 reference')
    class Hash128(ctypes.Structure):
        _fields_ = [('low64', ctypes.c_uint64), ('high64', ctypes.c_uint64)]
    xx = ctypes.CDLL(args.xxhash_library)
    xx.XXH3_128bits.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    xx.XXH3_128bits.restype = Hash128
    vectors = json.loads(args.blake3_vectors.read_text())
    total = 0
    def check(path, data, update_size, mode, output_size, seek, expected_blake):
        nonlocal total
        digest = xx.XXH3_128bits(data, len(data))
        expected = [str(len(data)), f'{digest.high64:016x}{digest.low64:016x}',
                    expected_blake, hashlib.sha512(data).hexdigest()]
        result = subprocess.run([str(probe), str(path), str(update_size), mode, str(output_size), str(seek)],
                                check=True, capture_output=True, text=True)
        fields = result.stdout.strip().split('\t')
        if fields != expected:
            raise AssertionError(f'length={len(data)}, update={update_size}, mode={mode}, seek={seek}:\nexpected {expected}\ngot {fields}')
        total += 1
    with tempfile.TemporaryDirectory(prefix='game-hash-probe-') as temporary:
        path = Path(temporary) / 'input.bin'
        for case in vectors['cases']:
            size = case['input_len']
            data = (bytes(range(251)) * ((size + 250) // 251))[:size]
            path.write_bytes(data)
            for update in (1, 7, 31, 63, 64, 65, 127, 128, 129, 239, 240, 241, 255, 256, 257, 1023, 1024, 1025, 4093, 65536):
                if size > 102400 and update < 1023: continue
                for mode, field in (('hash', 'hash'), ('keyed', 'keyed_hash'), ('derive', 'derive_key')):
                    check(path, data, update, mode, 131, 0, case[field])
                    # XOF seek across an output-block boundary must be exact.
                    if update in (1, 1025): check(path, data, update, mode, 68, 63, case[field][126:262])
        extended = json.loads(args.extended_vectors.read_text())
        for case in extended['cases']:
            size = case['length']
            if case['pattern'] == 'repeat-0-250':
                data = (bytes(range(251)) * ((size + 250) // 251))[:size]
            elif case['pattern'] == 'ascii': data = case['ascii'].encode('ascii')
            else: raise ValueError(case['pattern'])
            assert len(data) == size
            path.write_bytes(data)
            updates = (1, 7, 31, 64, 127, 239, 240, 241, 255, 256, 257, 1023, 1024, 1025, 4093, 65536)
            if size > 102400: updates = (1023, 1025, 4093, 65536)
            if size > 1048577: updates = (4093, 65536, 1048576)
            for update in updates: check(path, data, update, 'hash', 32, 0, case['blake3'])
    print(f'PASS: {total} compiled Pascal vector/mode/update-size/XOF cases; XXH3-128 and SHA-512 independently compared in every case')

if __name__ == '__main__': main()
