'use strict';
// Run the compiled Pascal probe, then independently compare all three 3 MiB
// mode/XOF outputs with the pinned upstream BLAKE3 implementation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const { blake3 } = require("../../services/cryptography/vendor/noble-hashes-1.8.0/peace.blake3.js");
const executable = process.argv[2];
if (!executable || !fs.statSync(executable).isFile()) throw Error('COMPILED_PASCAL_PARALLEL_PROBE_REQUIRED');
const result = cp.spawnSync(path.resolve(executable), [], { encoding: 'utf8', timeout: 180000, maxBuffer: 1024 * 1024 });
if (result.error) throw result.error;
assert.equal(result.status, 0, result.stderr + result.stdout);
const data = Buffer.alloc(3146505);
for (let i = 0; i < data.length; i++) data[i] = i % 251;
const modes = [{}, { key: Buffer.from('whats the Elvish word for friend') },
  { context: 'BLAKE3 2019-12-27 16:29:52 test vectors context' }];
for (let mode = 0; mode < modes.length; mode++) {
  const line = result.stdout.split(/\r?\n/).find(value => value.startsWith(`VECTOR ${mode} `));
  assert.ok(line, `Mode ${mode} missing`);
  const expected = Buffer.from(blake3(data, { ...modes[mode], dkLen: 194 })).subarray(63).toString('hex');
  assert.equal(line.slice(`VECTOR ${mode} `.length), expected, `Independent mode ${mode} mismatch`);
}
assert.match(result.stdout, /PASS cases=351 batches=[1-9][0-9]* portableThreadStarts=[0-9]+/);
process.stdout.write(result.stdout);
console.log('PASS: native parallel hash/keyed/derive XOF independently compared; no Windows validation implied by a Linux probe.');
