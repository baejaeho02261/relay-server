#!/usr/bin/env python3
"""TEST ONLY: exact rational binary64 conversion and shortest-decimal oracle.

No production code, host float conversion/formatting, Node, or third-party dtoa
is used for numeric expectations.
Decimal input is rounded with integer arithmetic; formatting searches decimal
integers inside the binary64 rounding interval. This follows Number::toString's
closest/even recommendation and decimal notation thresholds, independently of
V8's implementation. https://tc39.es/ecma262/#sec-numeric-types-number-tostring

The protocol admits finite binary64 values except unsafe integers. Thus the
1e21 exponent threshold and large finite doubles are formatter-only coverage,
explicitly rejected at the protocol boundary. This is a test oracle, not a new
wire canonicalization algorithm. SHA-512 uses the existing pure-integer Python
test reference, never a production digest as an expected value.
"""
from fractions import Fraction
from functools import lru_cache
import importlib.util
import json
from pathlib import Path
import re
import sys

SIGN = 1 << 63
INF = 0x7ff0000000000000
MAX = INF - 1
SAFE = (1 << 53) - 1
NUMBER = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z')
spec = importlib.util.spec_from_file_location('integer_hash_reference', Path(__file__).resolve().parent.parent / 'protocol' / 'independent-contract-reference.py')
hash_reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hash_reference)


@lru_cache(maxsize=None)
def scale(base, exponent):
    return Fraction(base ** exponent) if exponent >= 0 else Fraction(1, base ** -exponent)


def nearest_even(value):
    q, remainder = divmod(value.numerator, value.denominator)
    return q + (2 * remainder > value.denominator or
                (2 * remainder == value.denominator and q % 2 == 1))


def floor_log(value, base):
    if base == 2:
        exponent = value.numerator.bit_length() - value.denominator.bit_length()
    else:
        exponent = len(str(value.numerator)) - len(str(value.denominator))
    while value < scale(base, exponent):
        exponent -= 1
    while value >= scale(base, exponent + 1):
        exponent += 1
    return exponent


def decimal_bits(token):
    if not NUMBER.fullmatch(token):
        raise ValueError('JSON_NUMBER_SYNTAX')
    sign = SIGN if token.startswith('-') else 0
    mantissa, *exponent = re.split('[eE]', token.lstrip('-'))
    whole, _, fraction = mantissa.partition('.')
    coefficient = int(whole + fraction)
    exp = (int(exponent[0]) if exponent else 0) - len(fraction)
    if coefficient == 0:
        return sign
    # Bound hostile exponents before constructing giant powers. Corpus/input
    # limits are test-only and intentionally explicit.
    magnitude = len(str(coefficient)) + exp
    if magnitude > 310:
        return sign | INF
    if magnitude < -325:
        return sign
    value = coefficient * scale(10, exp)
    power = floor_log(value, 2)
    if power < -1022:
        return sign | nearest_even(value / scale(2, -1074))
    if power > 1023:
        return sign | INF
    significand = nearest_even(value / scale(2, power - 52))
    if significand == 1 << 53:
        significand >>= 1
        power += 1
    if power > 1023:
        return sign | INF
    return sign | ((power + 1023) << 52) | (significand - (1 << 52))


def rational(bits):
    magnitude = bits & (SIGN - 1)
    if magnitude >= INF:
        raise ValueError('NONFINITE_UNSUPPORTED')
    exponent, fraction = magnitude >> 52, magnitude & ((1 << 52) - 1)
    value = fraction * scale(2, -1074) if exponent == 0 else ((1 << 52) + fraction) * scale(2, exponent - 1075)
    return -value if bits & SIGN else value


def admitted(bits):
    if bits & (SIGN - 1) >= INF:
        return False
    value = rational(bits)
    return value.denominator != 1 or abs(value) <= SAFE


@lru_cache(maxsize=None)
def shortest(bits):
    negative = bool(bits & SIGN)
    magnitude = bits & (SIGN - 1)
    if magnitude >= INF:
        raise ValueError('NONFINITE_UNSUPPORTED')
    if magnitude == 0:
        return '0'
    value = rational(magnitude)
    lower = (value + rational(magnitude - 1)) / 2
    upper = (value + (scale(2, 1024) if magnitude == MAX else rational(magnitude + 1))) / 2
    closed = magnitude % 2 == 0
    order = floor_log(value, 10)
    chosen = None
    for digits in range(1, 18):
        candidates = []
        # The adjacent exponent covers intervals which cross a power of ten.
        for exponent in range(order - digits, order - digits + 3):
            unit = scale(10, exponent)
            lo, hi = lower / unit, upper / unit
            first = lo.numerator // lo.denominator + (lo.denominator != 1 or not closed)
            last = hi.numerator // hi.denominator - (hi.denominator == 1 and not closed)
            first, last = max(first, 10 ** (digits - 1)), min(last, 10 ** digits - 1)
            if first > last:
                continue
            coefficient = min(last, max(first, nearest_even(value / unit)))
            candidates.append((abs(coefficient * unit - value), coefficient % 2, coefficient, exponent))
        if candidates:
            _, _, coefficient, exponent = min(candidates)
            chosen = coefficient, exponent
            break
    if chosen is None:
        raise AssertionError('BINARY64_SHORTEST_NOT_FOUND')
    coefficient, exponent = chosen
    while coefficient % 10 == 0:
        coefficient //= 10
        exponent += 1
    text = str(coefficient)
    point = len(text) + exponent
    if -5 <= point <= 21:
        if point >= len(text):
            text += '0' * (point - len(text))
        elif point > 0:
            text = text[:point] + '.' + text[point:]
        else:
            text = '0.' + '0' * -point + text
    else:
        text = text[0] + ('.' + text[1:] if len(text) > 1 else '') + 'e' + ('+' if point > 0 else '-') + str(abs(point - 1))
    return ('-' if negative else '') + text


class Binary64:
    def __init__(self, token):
        self.bits = decimal_bits(token)
        if not admitted(self.bits):
            raise ValueError('JSON_NUMBER_RANGE')


def pairs(items):
    result = {}
    for key, value in items:
        if key in result or key in ('__proto__', 'constructor', 'prototype'):
            raise ValueError('JSON_FIELD_INVALID')
        result[key] = value
    return result


def invalid_constant(_):
    raise ValueError('JSON_NUMBER_SYNTAX')


def stable(value):
    if isinstance(value, Binary64):
        return shortest(value.bits)
    if isinstance(value, dict):
        return '{' + ','.join(stable(key) + ':' + stable(value[key]) for key in sorted(value, key=lambda key: key.encode('utf-16-be'))) + '}'
    if isinstance(value, list):
        return '[' + ','.join(stable(item) for item in value) + ']'
    if isinstance(value, str):
        value.encode('utf8', errors='strict')
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def evaluate(raw, purpose='bootstrap.begin'):
    try:
        body = json.loads(raw, parse_float=Binary64, parse_int=Binary64,
                          parse_constant=invalid_constant, object_pairs_hook=pairs)
        if not isinstance(body, dict):
            raise ValueError('OBJECT_REQUIRED')
        canonical = stable(body)
        wire = canonical.encode('utf8')
        result = dict(accepted=True, canonical=canonical, canonicalHex=wire.hex(),
                      wireSha512=hash_reference.sha512(raw.encode('utf8')),
                      canonicalSha512=hash_reference.sha512(wire),
                      fingerprint=hash_reference.sha512(('GAME-REQUEST-RECEIPT-V1\n' + purpose + '\n').encode('ascii') + wire))
        if isinstance(body.get('n'), Binary64):
            result['bits'] = format(body['n'].bits, '016x')
        return result
    except (ValueError, UnicodeError) as error:
        return dict(accepted=False, reason=str(error))


def exact_decimal(value):
    if value == 0:
        return '0'
    negative, value = value < 0, abs(value)
    denominator = value.denominator
    twos = fives = 0
    while denominator % 2 == 0:
        twos += 1
        denominator //= 2
    while denominator % 5 == 0:
        fives += 1
        denominator //= 5
    if denominator != 1:
        raise ValueError('NONTERMINATING_FIXTURE')
    places = max(twos, fives)
    digits = str(value.numerator * 2 ** (places - twos) * 5 ** (places - fives)).rjust(places + 1, '0')
    text = digits if places == 0 else (digits[:-places] + '.' + digits[-places:]).rstrip('0').rstrip('.')
    return ('-' if negative else '') + text


def corpus():
    rows = []
    def add(label, token, category):
        raw = '{"n":' + token + '}'
        row = dict(id=label, category=category, raw=raw, **evaluate(raw))
        if NUMBER.fullmatch(token):
            bits = decimal_bits(token)
            if bits & (SIGN - 1) < INF:
                row['formatBits'] = format(bits, '016x')
                row['numberText'] = shortest(bits)
                row['scope'] = 'PROTOCOL' if admitted(bits) else 'FORMAT_ONLY_PROTOCOL_REJECTED'
        rows.append(row)
    for label, token in [
        ('positive-zero', '0'), ('negative-zero', '-0'), ('negative-decimal-zero', '-0.000e-999'),
        ('fraction', '0.1'), ('fraction-long', '0.1000000000000000055511151231257827021181583404541015625'),
        ('fraction-trailing-zero', '1.23000'), ('uppercase-exponent', '123E-2'),
        ('exponent-leading-zero', '1e-007'), ('negative-tiny', '-1e-999'), ('positive-underflow', '1e-999'),
        ('min-subnormal', '5e-324'), ('long-min-subnormal', '4.9406564584124654e-324'),
        ('decimal-tie-candidate', '1424953923781206.25'), ('decimal-tie-even', '1000000000000000.25'),
        ('safe-limit', '9007199254740991'), ('safe-rounded-fraction', '9007199254740991.1'),
        ('unsafe-rounded-fraction', '9007199254740991.5'), ('unsafe-integer', '9007199254740992'),
        ('max-finite', '1.7976931348623157e308'), ('overflow', '1e309'), ('negative-overflow', '-1e999')
    ]:
        add(label, token, 'LEXEME')
    for token in ['NaN', 'Infinity', '-Infinity', '+Infinity', '+1', '.1', '1.', '01', '-01', '0x10', '1e', '1e+', '--1', '1_0']:
        add('invalid-' + token, token, 'INVALID')
    for exponent in [-324, -323, -308, -100, -7, -6, -5, -1, 0, 1, 14, 15, 16, 20, 21, 22, 100, 308]:
        add('decimal-power-' + str(exponent), '1e' + str(exponent), 'DECIMAL_POWER')
        bits = decimal_bits('1e' + str(exponent))
        for delta in [-1, 1]:
            neighbor = bits + delta
            if 0 < neighbor <= MAX:
                add('decimal-neighbor-' + str(exponent) + '-' + str(delta), exact_decimal(rational(neighbor)), 'DECIMAL_NEIGHBOR')
    bit_values = [1, 2, 3, (1 << 52) - 1, 1 << 52, (1 << 52) + 1,
                  0x3fd5555555555555, 0x3fefffffffffffff, 0x3ff0000000000000, 0x3ff0000000000001,
                  0x43143ff3c1cb0959, 0x4340000000000000, MAX]
    for exponent in [-1074, -1022, -1000, -53, -52, -1, 0, 1, 51, 52, 53, 1023]:
        bits = decimal_bits(exact_decimal(scale(2, exponent)))
        for delta in [-1, 0, 1]:
            if 0 < bits + delta <= MAX:
                bit_values.append(bits + delta)
    for index, bits in enumerate(dict.fromkeys(bit_values)):
        for negative in [False, True]:
            signed = bits | (SIGN if negative else 0)
            add('binary-boundary-' + str(index) + ('-negative' if negative else ''), exact_decimal(rational(signed)), 'BINARY_BOUNDARY')
    # Exactly representable decimal midpoints, including zero/subnormal and
    # normal exponent transitions. Both even and odd target significands occur.
    for index, bits in enumerate([0, 1, 2, (1 << 52) - 1, 1 << 52, 0x3fefffffffffffff,
                                  0x3ff0000000000000, 0x3ff0000000000001, 0x433fffffffffffff]):
        midpoint = (rational(bits) + rational(bits + 1)) / 2
        epsilon = scale(10, -1100)
        for delta in [-1, 0, 1]:
            add('rounding-midpoint-' + str(index) + '-' + str(delta), exact_decimal(midpoint + delta * epsilon), 'ROUNDING_TIE')
    # Reproducible bit corpus independent of any runtime's decimal printer.
    state = 0x9e3779b97f4a7c15
    for index in range(256):
        state ^= (state << 13) & ((1 << 64) - 1)
        state ^= state >> 7
        state ^= (state << 17) & ((1 << 64) - 1)
        bits = state & ((1 << 64) - 1)
        if bits & (SIGN - 1) >= INF:
            continue
        add('seeded-bits-' + str(index), exact_decimal(rational(bits)), 'SEEDED_BITS')
    mixed = '{"z":[0.1,-0,5e-324,{"n":1e-7}],"a":1e-6,"😀":1.25,"\\ue000":2.5,"2":1.5,"1":-2.25}'
    rows.append(dict(id='nested-utf16-order', category='NESTED', raw=mixed, **evaluate(mixed)))
    # Anchors catch errors in the independent reference itself before comparison.
    expected = {'positive-zero': '{"n":0}', 'negative-zero': '{"n":0}',
                'fraction': '{"n":0.1}', 'min-subnormal': '{"n":5e-324}',
                'decimal-power--6': '{"n":0.000001}', 'decimal-power--7': '{"n":1e-7}',
                'safe-limit': '{"n":9007199254740991}'}
    for row in rows:
        if row['id'] in expected:
            assert row['canonical'] == expected[row['id']], row['id']
        if 'formatBits' in row:
            original = int(row['formatBits'], 16)
            reparsed = decimal_bits(row['numberText'])
            assert reparsed == original or original == SIGN and reparsed == 0, row['id']
    return rows


def main():
    if sys.argv[1:] == ['--evaluate']:
        raw = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('REFERENCE_INPUT_LIMIT')
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) > 4096:
            raise ValueError('REFERENCE_CASE_LIMIT')
        result = [evaluate(value) for value in values]
    elif not sys.argv[1:]:
        result = dict(version=1, oracle='EXACT_RATIONAL_BINARY64_SHORTEST_INTERVAL',
                      hashOracle='PURE_PYTHON_INTEGER_SHA512', cases=corpus())
    else:
        raise ValueError('REFERENCE_ARGUMENT_INVALID')
    print(json.dumps(result, ensure_ascii=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
