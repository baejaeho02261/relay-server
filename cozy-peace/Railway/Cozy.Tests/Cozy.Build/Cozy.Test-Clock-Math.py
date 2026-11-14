#!/usr/bin/env python3
"""Compare an already compiled Cozy.ClockMathProbe with Python exact integers.

Usage: python Cozy.Test-Clock-Math.py /absolute/path/to/Cozy.ClockMathProbe[.exe]
Tests the production Pascal arithmetic; it does not execute Windows timing APIs.
"""
import json
import random
import subprocess
import sys

MAX64 = (1 << 64) - 1
MAXI64 = (1 << 63) - 1
MAX32 = (1 << 32) - 1
rng = random.Random(0xC02C10C)
cases = []

def add(op, args, value):
    cases.append((op + ' ' + ' '.join(map(str, args)), 'ERR' if value is None else 'OK ' + str(value)))

def counter(c, f):
    v = None if c < 0 or f <= 0 else c * 1000 // f
    add('counter', (c, f), v if v is None or v <= MAX64 else None)

frequencies = [1, 2, 999, 1000, 1001, 10_000_000, MAX64 // 1000, MAXI64 - 1, MAXI64]
for f in frequencies:
    for c in [0, 1, f - 1, f, min(f + 1, MAXI64), MAXI64 - 1, MAXI64]:
        counter(c, f)
for c, f in [(-1, 1), (0, 0), (1, -1), (MAXI64, 0)]:
    counter(c, f)
# Forces the no-wide-intermediate fraction path, checks both rounding sides.
for _ in range(4000):
    counter(rng.randrange(MAXI64 + 1), rng.randrange(1, MAXI64 + 1))
for _ in range(1000):
    f = rng.randrange(1, 10001)
    counter(rng.randrange(MAXI64 + 1), f)
for a, d in [(0, 0), (MAX64, 0), (MAX64, 1), (MAX64 - 100, 100), (MAX64 - 100, 101)]:
    add('deadline', (a, d), a + d if a + d <= MAX64 else None)
for _ in range(1000):
    a, d = rng.randrange(MAX64 + 1), rng.randrange(MAX64 + 1)
    add('deadline', (a, d), a + d if a + d <= MAX64 else None)
for a, d, cap in [(0, 0, 100), (1, 0, 100), (0, MAX64, MAX32), (0, 1, 0), (99, 100, 100), (100, 100, 100)]:
    add('left', (a, d, cap), min(max(d - a, 0), cap))
for _ in range(1000):
    a, d, cap = rng.randrange(MAX64 + 1), rng.randrange(MAX64 + 1), rng.randrange(MAX32 + 1)
    add('left', (a, d, cap), min(max(d - a, 0), cap))
if len(sys.argv) != 2:
    raise SystemExit(__doc__)
result = subprocess.run([sys.argv[1]], input='\n'.join(x[0] for x in cases) + '\n', text=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
lines = result.stdout.splitlines()
if len(lines) != len(cases):
    raise SystemExit('FAIL result count mismatch: ' + str(len(lines)))
for index, ((entry, expected), actual) in enumerate(zip(cases, lines)):
    if actual != expected:
        raise SystemExit(f'FAIL vector {index}: {entry}; expected {expected}, got {actual}')
print(json.dumps({'status': 'PASS', 'productionPascalArithmeticVectors': len(cases),
                  'oracle': 'Python arbitrary precision integers',
                  'windowsQpcAndWaitExecution': 'NOT_RUN', 'delphiWindowsBuild': 'NOT_RUN'}))
