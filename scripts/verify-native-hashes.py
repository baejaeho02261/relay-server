#!/usr/bin/env python3
"""Validate the actual compiled Pascal HashProbe against saved reference vectors.

This runner never substitutes a Python or JavaScript implementation for Pascal.
Supply --probe with a DCC64/FPC-built HashProbe executable. Compilation is a
separate explicit step, described in ../licenses/Hash_Provenance.txt.
"""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument(
        "--extended-vectors", type=Path,
        default=here / "fixtures/extended-hash-vectors.json",
        help="server reference fixtures, including the 64 MiB input",
    )
    args = parser.parse_args()
    probe = args.probe.resolve()
    if not probe.is_file():
        parser.error("--probe must identify the compiled Pascal executable")
    vectors = json.loads((here / "fixtures/blake3-official-vectors.json").read_text())
    cases = [dict(case, pattern="repeat-0-250", length=case["input_len"])
             for case in vectors["cases"]]
    known = {("repeat-0-250", case["length"]) for case in cases}
    extended = json.loads(args.extended_vectors.read_text())
    for case in extended["cases"]:
        key = (case["pattern"], case["length"])
        if key not in known:
            cases.append(case)
            known.add(key)
    total = 0
    with tempfile.TemporaryDirectory(prefix="game-hash-probe-") as temporary:
        path = Path(temporary) / "input.bin"
        for case in cases:
            size = case["length"]
            if case["pattern"] == "repeat-0-250":
                data = (bytes(range(251)) * ((size + 250) // 251))[:size]
            elif case["pattern"] == "ascii":
                data = case["ascii"].encode("ascii")
            else:
                raise ValueError(f"Unsupported input pattern: {case['pattern']}")
            assert len(data) == size
            path.write_bytes(data)
            # Deliberately cross XXH stripe, BLAKE block, and chunk boundaries.
            update_sizes = (1, 7, 31, 32, 33, 63, 64, 65, 1023,
                            1024, 1025, 4093, 65536)
            if size > 102400:
                update_sizes = (1023, 1024, 1025, 4093, 65536)
            if size > 1048577:
                update_sizes = (4093, 65536, 1048576)
            for update_size in update_sizes:
                result = subprocess.run(
                    [str(probe), str(path), str(update_size)],
                    check=True, capture_output=True, text=True,
                )
                fields = result.stdout.strip().split("\t")
                expected = [str(size), case["xxh64"], case["blake3"]]
                if fields != expected:
                    raise AssertionError(
                        f"size={size}, update_size={update_size}: "
                        f"expected {expected}, got {fields}"
                    )
                total += 1
    print(f"PASS: {total} compiled Pascal hash/vector/update-size cases")


if __name__ == "__main__":
    main()
