'use strict';
// Storage-only fixtures are inert bytes. This suite never executes a PE image,
// imports signing keys, or changes the release approval policy.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-artifact-storage-'));
process.env.DATA_DIR = temp;
process.env.STORAGE_ENGINE = 'json';
process.env.HA_ENABLED = '0';
const storePath = require.resolve('../services/desktopBootstrapStore');
const store = require(storePath);
const CHUNK = 262144, HEADER = 96, TAG = 16;
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
let sequence = 0, checks = 0;
const nextId = () => (++sequence).toString(16).toUpperCase().padStart(24, '0');
const fileFor = row => row.plugin ? store.PluginPath(row.id) : store.ArtifactPath(row.id);
const read = row => store.ReadBytes(row.id, row.bytes.length, row.sha256, row.plugin);
const chunk = (row, offset, length) => store.ReadChunk(row.id, row.bytes.length, row.sha256, offset, length, row.plugin);
const reject = fn => assert.throws(fn);
const names = () => fs.readdirSync(store.DIR).sort();
function check(label, fn) { fn(); checks++; console.log('PASS ' + label); }
function fixture(size, label) {
  const bytes = Buffer.alloc(size);
  for (let i = 0; i < size; i++) bytes[i] = (i * 29 + Math.floor(i / 251)) & 255;
  const marker = Buffer.from('SERVER-PRIVATE-APPROVED-ARTIFACT:' + label + ':PLAINTEXT-MUST-NOT-BE-STORED');
  marker.copy(bytes, 0, 0, Math.min(size, marker.length));
  return bytes;
}
function publish(bytes, plugin = false, id = nextId()) {
  const row = { id, bytes: Buffer.from(bytes), sha256: sha(bytes), plugin };
  store.PublishBytes(id, bytes, plugin);
  return row;
}
function legacy(bytes, plugin = false) {
  const row = { id: nextId(), bytes: Buffer.from(bytes), sha256: sha(bytes), plugin };
  fs.writeFileSync(fileFor(row), bytes, { flag: 'wx', mode: 0o600 });
  return row;
}
function encrypted(row) {
  const bytes = fs.readFileSync(fileFor(row));
  assert.equal(bytes.subarray(0, 8).toString('ascii'), 'GACGCM01');
  assert.equal(bytes.length, HEADER + row.bytes.length + Math.ceil(row.bytes.length / CHUNK) * TAG);
  assert.notDeepEqual(bytes, row.bytes);
  if (row.bytes.length >= 80) assert.equal(bytes.indexOf(row.bytes.subarray(0, 80)), -1);
  if (process.platform !== 'win32') assert.equal(fs.statSync(fileFor(row)).mode & 0o777, 0o600);
  return bytes;
}
function withBytes(row, bytes, fn) {
  const previous = fs.readFileSync(fileFor(row));
  fs.writeFileSync(fileFor(row), bytes);
  try { fn(); } finally { fs.writeFileSync(fileFor(row), previous); }
}
function fsyncFailure(fn) {
  const original = fs.fsyncSync;
  fs.fsyncSync = () => { const error = new Error('INJECTED_STORAGE_FLUSH_FAILURE'); error.code = 'ENOSPC'; throw error; };
  try { fn(); } finally { fs.fsyncSync = original; }
}
function childRead(row, directory) {
  const program = `const crypto=require('node:crypto');const store=require(${JSON.stringify(storePath)});const data=store.ReadBytes(${JSON.stringify(row.id)},${row.bytes.length},${JSON.stringify(row.sha256)},${row.plugin});process.stdout.write(crypto.createHash('sha256').update(data).digest('hex'));`;
  return spawnSync(process.execPath, ['-e', program], {
    env: { ...process.env, DATA_DIR: directory }, encoding: 'utf8', timeout: 15000
  });
}

try {
  store.Load();
  check('A, B and O payloads are encrypted on disk and returned byte-for-byte', () => {
    for (const component of ['A', 'B', 'O']) {
      const bytes = fixture(4096, component), unchanged = Buffer.from(bytes);
      const row = publish(bytes, component === 'O');
      encrypted(row);
      assert.deepEqual(bytes, unchanged, 'publishing must not alter caller-owned approved bytes');
      assert.deepEqual(read(row), unchanged);
      const returned = read(row); returned.fill(0);
      assert.deepEqual(read(row), unchanged, 'returned bytes must not alias retained storage');
    }
    assert.equal(names().some(name => name.endsWith('.tmp')), false);
  });
  check('single-byte and exact chunk boundaries preserve full and partial reads', () => {
    for (const size of [1, CHUNK - 1, CHUNK, CHUNK + 1, 4 * CHUNK + 37]) {
      const row = publish(fixture(size, 'boundary-' + size), size % 2 === 1);
      encrypted(row);
      assert.deepEqual(read(row), row.bytes);
      for (let offset = 0; offset < size; offset += CHUNK) {
        const length = Math.min(CHUNK, size - offset);
        assert.deepEqual(chunk(row, offset, length), row.bytes.subarray(offset, offset + length));
      }
      assert.deepEqual(chunk(row, size - 1, 1), row.bytes.subarray(size - 1));
      if (size > CHUNK + 1) assert.deepEqual(chunk(row, CHUNK - 7, 19), row.bytes.subarray(CHUNK - 7, CHUNK + 12));
    }
  });
  check('independent publications randomize ciphertext and never overwrite an existing artifact', () => {
    const bytes = fixture(2048, 'same-approved-bytes');
    const first = publish(bytes), second = publish(bytes);
    const original = encrypted(first);
    const another = encrypted(second);
    assert.notDeepEqual(original, another);
    assert.notDeepEqual(original.subarray(16, 48), another.subarray(16, 48), 'each envelope uses a new key-derivation salt');
    assert.notDeepEqual(original.subarray(48, 56), another.subarray(48, 56), 'each envelope uses a new nonce prefix');
    const before = names();
    reject(() => store.PublishBytes(first.id, fixture(bytes.length, 'replacement')));
    assert.deepEqual(fs.readFileSync(fileFor(first)), original);
    assert.deepEqual(names(), before);
    assert.deepEqual(read(first), bytes);
  });
  check('encrypted payloads survive server restart under the existing authority secret', () => {
    const row = publish(fixture(CHUNK + 9, 'restart'), true), result = childRead(row, temp);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, row.sha256);
  });
  check('another authority secret cannot decrypt copied storage', () => {
    const row = publish(fixture(512, 'authority-binding'));
    const other = path.join(temp, 'other-authority'), target = path.join(other, 'desktop-bootstrap');
    fs.mkdirSync(target, { recursive: true });
    fs.copyFileSync(fileFor(row), path.join(target, path.basename(fileFor(row))));
    const result = childRead(row, other);
    assert.equal(result.error, undefined);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unsupported state|authenticate|ARTIFACT_STORAGE_INVALID/i);
    assert.equal(result.stdout, '');
  });
  check('header fields, ciphertext and authentication tags reject tampering', () => {
    const row = publish(fixture(CHUNK + 31, 'tamper'), true), original = encrypted(row);
    // This is the documented on-disk envelope, not a second crypto implementation.
    for (const position of [0, 8, 12, 16, 48, 56, 88, 89, HEADER, HEADER + CHUNK, original.length - 1]) {
      const damaged = Buffer.from(original); damaged[position] ^= 1;
      withBytes(row, damaged, () => {
        reject(() => read(row));
        const offset = position === original.length - 1 ? CHUNK : 0;
        reject(() => chunk(row, offset, Math.min(CHUNK, row.bytes.length - offset)));
      });
    }
    assert.deepEqual(read(row), row.bytes);
  });
  check('chunks cannot be reordered even when their sizes are equal', () => {
    const row = publish(fixture(2 * CHUNK, 'chunk-order'));
    const original = encrypted(row), reordered = Buffer.concat([
      original.subarray(0, HEADER), original.subarray(HEADER + CHUNK + TAG), original.subarray(HEADER, HEADER + CHUNK + TAG)
    ]);
    withBytes(row, reordered, () => {
      reject(() => read(row)); reject(() => chunk(row, 0, CHUNK)); reject(() => chunk(row, CHUNK, CHUNK));
    });
  });
  check('encrypted storage is bound to the artifact ID and A/B-versus-O domain', () => {
    const bytes = fixture(1024, 'substitution'), first = publish(bytes), second = publish(bytes);
    const plugin = publish(bytes, true, first.id);
    withBytes(second, encrypted(first), () => { reject(() => read(second)); reject(() => chunk(second, 0, 32)); });
    withBytes(plugin, encrypted(first), () => { reject(() => read(plugin)); reject(() => chunk(plugin, 0, 32)); });
    withBytes(first, encrypted(plugin), () => reject(() => read(first)));
  });
  check('approved size and digest must match encrypted metadata on every read', () => {
    const row = publish(fixture(700, 'metadata'));
    const wrongHash = '0'.repeat(64) === row.sha256 ? '1'.repeat(64) : '0'.repeat(64);
    reject(() => store.ReadBytes(row.id, row.bytes.length, wrongHash));
    reject(() => store.ReadBytes(row.id, row.bytes.length - 1, row.sha256));
    reject(() => store.ReadBytes(row.id, row.bytes.length + 1, row.sha256));
    reject(() => store.ReadChunk(row.id, row.bytes.length, wrongHash, 0, 10));
    reject(() => store.ReadChunk(row.id, row.bytes.length + 1, row.sha256, 0, 10));
  });
  check('truncated and oversized physical files are rejected before yielding bytes', () => {
    const row = publish(fixture(CHUNK + 17, 'physical-size')), original = encrypted(row);
    for (const damaged of [Buffer.alloc(0), original.subarray(0, 7), original.subarray(0, HEADER - 1), original.subarray(0, original.length - 1), Buffer.concat([original, Buffer.from([0])])]) {
      withBytes(row, damaged, () => { reject(() => read(row)); reject(() => chunk(row, 0, 1)); });
    }
  });
  check('valid legacy A/B/O files migrate atomically before full or chunk reads return', () => {
    for (const component of ['A', 'B', 'O']) for (const partial of [false, true]) {
      const row = legacy(fixture(CHUNK + 21, 'legacy-' + component + partial), component === 'O');
      if (partial) assert.deepEqual(chunk(row, CHUNK, 21), row.bytes.subarray(CHUNK));
      else assert.deepEqual(read(row), row.bytes);
      encrypted(row);
      assert.deepEqual(read(row), row.bytes);
    }
    assert.equal(names().some(name => name.endsWith('.tmp')), false);
  });
  check('invalid legacy size or digest is never accepted or migrated', () => {
    for (const plugin of [false, true]) {
      const row = legacy(fixture(300, 'bad-legacy'), plugin), changed = Buffer.from(row.bytes); changed[150] ^= 1;
      fs.writeFileSync(fileFor(row), changed);
      reject(() => read(row)); reject(() => chunk(row, 0, 10));
      assert.deepEqual(fs.readFileSync(fileFor(row)), changed);
      fs.writeFileSync(fileFor(row), row.bytes.subarray(0, row.bytes.length - 1));
      reject(() => read(row)); reject(() => chunk(row, 0, 10));
      assert.deepEqual(fs.readFileSync(fileFor(row)), row.bytes.subarray(0, row.bytes.length - 1));
    }
  });
  check('publication write failures remove incomplete files and preserve existing data', () => {
    const row = { id: nextId(), bytes: fixture(500, 'write-failure'), plugin: true }, before = names();
    fsyncFailure(() => reject(() => store.PublishBytes(row.id, row.bytes, row.plugin)));
    assert.equal(fs.existsSync(fileFor(row)), false);
    assert.deepEqual(names(), before);
    const valid = publish(row.bytes, row.plugin, row.id);
    assert.deepEqual(read(valid), row.bytes);
  });
  check('failed legacy encryption does not return bytes or damage the original file', () => {
    const row = legacy(fixture(CHUNK + 3, 'migration-failure'), true), before = names();
    fsyncFailure(() => { reject(() => read(row)); reject(() => chunk(row, 0, 1)); });
    assert.deepEqual(fs.readFileSync(fileFor(row)), row.bytes);
    assert.deepEqual(names(), before);
    assert.deepEqual(read(row), row.bytes); encrypted(row);
  });
  check('invalid metadata and out-of-range spans cannot access artifacts', () => {
    const row = publish(fixture(500, 'bounds'));
    for (const size of [0, -1, 0.5, NaN, Infinity, 64 * 1024 * 1024 + 1, Number.MAX_SAFE_INTEGER]) reject(() => store.ReadBytes(row.id, size, row.sha256));
    for (const digest of ['', 'f'.repeat(63), 'z'.repeat(64), null]) reject(() => store.ReadBytes(row.id, row.bytes.length, digest));
    for (const [offset, length] of [[-1, 1], [0.5, 1], [NaN, 1], [Infinity, 1], [0, 0], [0, -1], [0, 0.5], [0, NaN], [0, Infinity], [500, 1], [499, 2], [0, 501], [Number.MAX_SAFE_INTEGER, 2]]) reject(() => chunk(row, offset, length));
    const large = publish(fixture(CHUNK + 1, 'chunk-api-bound'));
    reject(() => chunk(large, 0, CHUNK + 1));
    reject(() => store.ReadBytes(large.id, 16 * 1024 * 1024 + 1, large.sha256, true));
    reject(() => store.PublishBytes(nextId(), Buffer.alloc(0)));
    for (const id of ['../authority', 'a'.repeat(24), '', null]) {
      reject(() => store.ReadBytes(id, row.bytes.length, row.sha256));
      reject(() => store.PublishBytes(id, row.bytes));
    }
  });
  check('missing, directory and symbolic-link artifact paths never expose target contents', () => {
    const row = { id: nextId(), bytes: fixture(500, 'unsafe-path'), plugin: true };
    row.sha256 = sha(row.bytes);
    reject(() => read(row));
    fs.mkdirSync(fileFor(row)); reject(() => read(row)); reject(() => chunk(row, 0, 1)); fs.rmdirSync(fileFor(row));
    if (process.platform !== 'win32') {
      const target = path.join(temp, 'symlink-target'); fs.writeFileSync(target, row.bytes);
      fs.symlinkSync(target, fileFor(row));
      reject(() => read(row)); reject(() => chunk(row, 0, 1));
      reject(() => store.PublishBytes(row.id, row.bytes, true));
      assert.equal(fs.lstatSync(fileFor(row)).isSymbolicLink(), true);
      assert.deepEqual(fs.readFileSync(target), row.bytes);
      fs.unlinkSync(fileFor(row));
    }
    assert.equal(names().some(name => name.endsWith('.tmp')), false);
  });
  check('symbolic-link artifact directory is rejected for reads and publication', () => {
    if (process.platform === 'win32') return;
    const row = publish(fixture(500, 'directory-binding'), true);
    const real = path.join(temp, 'authority-directory-real');
    fs.renameSync(store.DIR, real);
    try {
      fs.symlinkSync(real, store.DIR, 'dir');
      reject(() => read(row)); reject(() => chunk(row, 0, 1));
      reject(() => store.PublishBytes(nextId(), row.bytes, true));
    } finally {
      if (fs.existsSync(store.DIR)) fs.unlinkSync(store.DIR);
      fs.renameSync(real, store.DIR);
    }
    assert.deepEqual(read(row), row.bytes);
  });
  console.log('ARTIFACT STORAGE TESTS PASS (' + checks + ' groups)');
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
