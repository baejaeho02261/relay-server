'use strict';
// Portable contract/vector test, not a Delphi compilation or Windows execution.
// Mirrors documented loader relocation arithmetic and checks the mapped stream
// against the independently generated server baseline for the same fixture.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Fixture } = require('./test-desktop-code-integrity');
const { CodeImage, Crc64 } = require('../services/desktopIntegrity');
function relocated(value, preferred, actual, width) {
  return BigInt.asUintN(width * 8, value + actual - preferred);
}
function loadedMeasurement(file, preferred, actual, mutate) {
  const source = Buffer.from(file);
  source.writeBigUInt64LE(preferred, 152 + 24);
  const first = Buffer.alloc(520), second = Buffer.from(source.subarray(2048, 2112));
  source.copy(first, 0, 1024, 1536);
  const fixups = [
    { at: 24, width: 8, original: source.readBigUInt64LE(1048) },
    { at: 48, width: 4, original: BigInt(source.readUInt32LE(1072)) }
  ];
  for (const f of fixups) {
    f.expected = relocated(f.original, preferred, actual, f.width);
    if (f.width === 8) first.writeBigUInt64LE(f.expected, f.at);
    else first.writeUInt32LE(Number(f.expected), f.at);
  }
  if (mutate) mutate(first);
  for (const f of fixups) {
    const value = f.width === 8 ? first.readBigUInt64LE(f.at) : BigInt(first.readUInt32LE(f.at));
    if (value !== f.expected) throw Error('RELOCATION_OPERAND_CHANGED');
    first.fill(0, f.at, f.at + f.width);
  }
  const data = Buffer.concat([
    Buffer.from('47414d452d434f44452d56310002000000', 'hex'),
    Buffer.from('0010000008020000', 'hex'), first,
    Buffer.from('0030000040000000', 'hex'), second
  ]);
  return { sha256: crypto.createHash('sha256').update(data).digest('hex'), crc64: Crc64(data) };
}
const fixture = Fixture(), baseline = CodeImage(fixture);
for (const [preferred, actual] of [
  [0x140000000n, 0x180000000n], [0x180000000n, 0x140000000n],
  [0x140000000n, 0x140000000n], [0n, 0x7ffe12340000n]
]) {
  const result = loadedMeasurement(fixture, preferred, actual);
  assert.equal(result.sha256, baseline.sha256);
  assert.equal(result.crc64, baseline.crc64);
  for (const at of [24, 31, 48, 51]) {
    assert.throws(() => loadedMeasurement(fixture, preferred, actual, b => { b[at] ^= 1; }),
      /^Error: RELOCATION_OPERAND_CHANGED$/);
  }
  assert.notEqual(loadedMeasurement(fixture, preferred, actual, b => { b[40] ^= 1; }).sha256, baseline.sha256);
}
assert.equal(relocated(0xfffffffffffffff8n, 0n, 16n, 8), 8n);
assert.equal(relocated(0n, 16n, 0n, 8), 0xfffffffffffffff0n);
assert.equal(relocated(0xfffffff8n, 0n, 16n, 4), 8n);
assert.equal(relocated(0n, 16n, 0n, 4), 0xfffffff0n);
console.log('Native code contract vectors passed: ASLR positive/negative, modulo32/64, relocation operand tamper, code tamper');
