'use strict';
// Portable contract/vector test, not a Delphi compilation or Windows execution.
// Mirrors documented loader relocation arithmetic and checks the mapped stream
// against the independently generated server baseline for the same fixture.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Fixture } = require('./test-desktop-code-integrity');
const { CodeImage, Crc64 } = require('../services/desktopIntegrity');
const { Xxh3_128, Blake3 } = require('../services/extendedHashes');
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
  return { sha512: crypto.createHash('sha512').update(data).digest('hex'), crc64: Crc64(data), xxh3_128: Xxh3_128(data), blake3: Blake3(data) };
}
const fixture = Fixture(), baseline = CodeImage(fixture);
for (const [preferred, actual] of [
  [0x140000000n, 0x180000000n], [0x180000000n, 0x140000000n],
  [0x140000000n, 0x140000000n], [0n, 0x7ffe12340000n]
]) {
  const result = loadedMeasurement(fixture, preferred, actual);
  assert.equal(result.sha512, baseline.sha512);
  assert.equal(result.crc64, baseline.crc64);
  assert.equal(result.xxh3_128, baseline.xxh3_128);
  assert.equal(result.blake3, baseline.blake3);
  for (const at of [24, 31, 48, 51]) {
    assert.throws(() => loadedMeasurement(fixture, preferred, actual, b => { b[at] ^= 1; }),
      /^Error: RELOCATION_OPERAND_CHANGED$/);
  }
  const changedCode = loadedMeasurement(fixture, preferred, actual, b => { b[40] ^= 1; });
  for (const hash of ['sha512', 'crc64', 'xxh3_128', 'blake3']) assert.notEqual(changedCode[hash], baseline[hash]);
}
assert.equal(relocated(0xfffffffffffffff8n, 0n, 16n, 8), 8n);
assert.equal(relocated(0n, 16n, 0n, 8), 0xfffffffffffffff0n);
assert.equal(relocated(0xfffffff8n, 0n, 16n, 4), 8n);
assert.equal(relocated(0n, 16n, 0n, 4), 0xfffffff0n);
console.log('Native code contract vectors passed: four hashes on canonical ASLR positive/negative streams, modulo32/64, relocation operand tamper, code tamper');

// Export metadata uses the original, retained on-disk range plan. A changed
// live data-directory pointer must not choose a fresh (attacker supplied) range.
const { Fixture: ExportFixture } = require('./test-desktop-pe-exports');
const { ExportTable } = require('../services/desktopPeExports');
function loadedExportMeasurement(original, mutate) {
  const image = Buffer.alloc(0x3000);
  original.copy(image, 0, 0, 512);
  original.copy(image, 4096, 512, 1024);
  original.copy(image, 8192, 1024, 1536);
  if (mutate) mutate(image);
  const directoryOffset = 264, exportRva = 8192, exportBytes = 256;
  const offset = Buffer.alloc(4); offset.writeUInt32LE(directoryOffset);
  const canonical = Buffer.concat([
    Buffer.from('GAME-EXPORT-V1\0', 'ascii'), offset,
    image.subarray(directoryOffset, directoryOffset + 8),
    image.subarray(exportRva, exportRva + exportBytes)
  ]);
  return { sha512: crypto.createHash('sha512').update(canonical).digest('hex'), crc64: Crc64(canonical), xxh3_128: Xxh3_128(canonical), blake3: Blake3(canonical) };
}
const exportFile = ExportFixture(), exportBaseline = ExportTable(exportFile);
const exportMemory = loadedExportMeasurement(exportFile);
assert.equal(exportMemory.sha512, exportBaseline.sha512);
assert.equal(exportMemory.crc64, exportBaseline.crc64);
assert.equal(exportMemory.xxh3_128, exportBaseline.xxh3_128);
assert.equal(exportMemory.blake3, exportBaseline.blake3);
assert.equal(exportMemory.sha512, 'efb8f6127b4d419315375549cc391b6c2edcaab07729970f5c408bfb54c0ffde69add7c0f07b3a2da5f67c9eab560d224660d66b8866fd19064bfbb6313f07fb');
assert.equal(exportMemory.crc64, '57560B63C1315D58');
for (const change of [
  image => image.writeUInt32LE(4100, 8192 + 40), // Direct API address table redirect.
  image => { image[8192 + 104] ^= 1; },         // Forwarder DLL/API name changed.
  image => image.writeUInt32LE(8192 + 72, 264), // Header export pointer redirected.
  image => image.writeUInt16LE(1, 8192 + 56),   // Named export ordinal remapped.
  image => { image[8192 + 80] ^= 1; }          // Name lookup string changed.
]) {
  const changedExport = loadedExportMeasurement(exportFile, change);
  for (const hash of ['sha512', 'crc64', 'xxh3_128', 'blake3']) assert.notEqual(changedExport[hash], exportBaseline[hash]);
}
console.log('Native export contract vectors passed: four pristine server digests, direct/forwarded/named API table and live header-pointer tamper');
