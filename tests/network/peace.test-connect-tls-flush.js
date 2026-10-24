'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Focused TLS persistence regression, NOT a SQLite/Windows product test.
// Real temporary files, OpenSSL, X509/RSA checks and fsync are used. A scoped
// fs facade enforces the Windows writable-file-handle rule on every host.
// Only the key-purpose registry is an in-memory test double; production lock
// and database modules are never replaced in the application or preflight.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const { createRequire } = require('node:module');
const file = path.resolve(MODULE_RESOURCE_ROOT, "../services/network/peace.connect-tls.js");
const source = fs.readFileSync(file, 'utf8');
const realRequire = createRequire(file);
const fixedOpen = "const fd=fs.openSync(file,'r+');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}";
assert.ok(source.includes(fixedOpen), 'Generated TLS files must be flushed through a non-truncating writable handle.');
const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'game-tls-flush-'));
const sentinel = path.join(root, 'untouched.txt');
fs.writeFileSync(sentinel, 'outside generated TLS identity');
const digest = b => crypto.createHash('sha512').update(b).digest('hex');
let passed = 0;
function fault(code, syscall) { return Object.assign(Error(code + ': test-injected ' + syscall), { code, syscall }); }
function harness(options = {}) {
  const data = options.data || fs.mkdtempSync(path.join(root, 'case-'));
  const state = { open: new Map(), flushes: [], opens: [], generated: new Map(), generations: 0, reservations: 0 };
  const purposes = options.purposes || new Map();
  const fingerprint = key => digest((key.type === 'public' ? key : crypto.createPublicKey(key)).export({ type: 'spki', format: 'der' }));
  const purposeStore = {
    Fingerprint: fingerprint,
    Reserve(key, purpose) { const id = fingerprint(key); assert.ok(!purposes.has(id) || purposes.get(id) === purpose); purposes.set(id, purpose); state.reservations++; return id; },
    Assert(key, purpose) { const id = fingerprint(key); assert.ok(!purposes.has(id) || purposes.get(id) === purpose); return id; }
  };
  const api = Object.create(fs);
  api.openSync = function (p, flags, mode) {
    const name = typeof p === 'string' ? path.basename(p) : '';
    const target = name === 'private-key.pem' || name === 'certificate.pem';
    if (target && name === options.openFailure) throw fault('EACCES', 'open');
    const fd = fs.openSync(p, flags, mode);
    state.open.set(fd, { target, name, flags });
    if (target) state.opens.push({ name, flags });
    return fd;
  };
  api.closeSync = function (fd) { fs.closeSync(fd); state.open.delete(fd); };
  api.fsyncSync = function (fd) {
    const opened = state.open.get(fd);
    if (opened?.target) {
      // FlushFileBuffers requires GENERIC_WRITE even when OpenSSL has already
      // written and closed the file. Do not model directory-sync semantics.
      const writable = typeof opened.flags === 'string'
        ? /[wa+]/.test(opened.flags)
        : (opened.flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) !== 0;
      if (!writable) throw fault('EPERM', 'fsync');
      if (opened.name === options.flushFailure) throw fault(options.flushCode || 'EIO', 'fsync');
    }
    fs.fsyncSync(fd);
    if (opened?.target) state.flushes.push(opened.name);
  };
  const env = {};
  for (const k of ['PATH','Path','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','TMPDIR','HOME','USERPROFILE'])
    if (process.env[k]) env[k] = process.env[k];
  const childProcess = {
    execFileSync(command, args, opts) {
      if (options.noGenerate) throw Error('Unexpected identity regeneration');
      assert.equal(command, 'openssl');
      state.generations++;
      const result = cp.execFileSync(command, args, { ...opts, env });
      for (const flag of ['-keyout', '-out']) {
        const generatedPath = args[args.indexOf(flag) + 1];
        assert.ok(path.resolve(generatedPath).startsWith(path.resolve(data) + path.sep));
        state.generated.set(path.basename(generatedPath), digest(fs.readFileSync(generatedPath)));
      }
      if (options.badCertificate) fs.writeFileSync(args[args.indexOf('-out') + 1], 'invalid certificate');
      return result;
    }
  };
  const localRequire = request => {
    if (request === 'node:fs') return api;
    if (request === 'node:child_process') return childProcess;
    if (request === '../config/peace.runtime-configuration') return { DATA_DIR: data, HA_ENABLED: false };
    if (request === './peace.desktop-key-purposes') return purposeStore;
    return realRequire(request);
  };
  const mod = { exports: {} };
  // The exact shipped module is evaluated with scoped dependencies and an
  // isolated environment. No require.cache or process.env mutation is used.
  new Function('require','module','exports','__filename','__dirname','process', options.source || source)(
    localRequire, mod, mod.exports, file, path.dirname(file), { platform: process.platform, env: {} });
  return { tls: mod.exports, state, data, purposes };
}
function unpublished(h) {
  assert.equal(fs.existsSync(h.tls.MARKER), false, 'Failed generation must not publish a pin');
  assert.equal(h.state.open.size, 0, 'Every descriptor must close on failure');
  assert.equal(h.state.reservations, 0, 'No key-purpose reservation before successful flush and validation');
  if (fs.existsSync(h.tls.DIR)) assert.deepEqual(fs.readdirSync(h.tls.DIR), [], 'No pending/final identity left after failure');
}
function check(name, run) {
  run(); assert.equal(fs.readFileSync(sentinel, 'utf8'), 'outside generated TLS identity');
  passed++; console.log('PASS ' + name);
}
try {
  check('read-only pre-fix handle reproduces EPERM; failure is not converted to success', () => {
    const h = harness({ source: source.replace(fixedOpen, fixedOpen.replace("'r+'", "'r'")) });
    assert.throws(() => h.tls.Public(), e => e.code === 'EPERM' && e.syscall === 'fsync');
    unpublished(h);
  });
  let successful;
  check('new identity uses r+ for both files and preserves OpenSSL output bytes', () => {
    const h = successful = harness(); const output = h.tls.Public();
    assert.equal(h.state.generations, 1);
    assert.deepEqual(h.state.opens.slice(0,2).map(x => x.flags), ['r+', 'r+']);
    assert.deepEqual(h.state.flushes, ['private-key.pem', 'certificate.pem']);
    const persisted = h.tls.ReadIdentity();
    assert.equal(digest(persisted.cert), h.state.generated.get('certificate.pem'));
    assert.equal(digest(persisted.key), h.state.generated.get('private-key.pem'));
    const leaf = new crypto.X509Certificate(persisted.cert);
    assert.ok(leaf.checkPrivateKey(crypto.createPrivateKey(persisted.key)));
    assert.equal(leaf.publicKey.asymmetricKeyDetails.modulusLength, 3072);
    assert.equal(output.tlsCertificateSha256, crypto.createHash('sha256').update(leaf.raw).digest('hex'));
    assert.equal(h.state.open.size, 0);
  });
  check('existing persisted identity and pin are reused without regeneration', () => {
    const h = harness({ data: successful.data, purposes: successful.purposes, noGenerate: true });
    assert.deepEqual(h.tls.Public(), successful.tls.Public());
    assert.equal(h.state.generations, 0); assert.deepEqual(h.state.flushes, []);
    assert.equal(h.state.open.size, 0);
  });
  check('private-key flush failure aborts publication and closes the descriptor', () => {
    const h = harness({ flushFailure: 'private-key.pem', flushCode: 'EIO' });
    assert.throws(() => h.tls.Public(), e => e.code === 'EIO' && e.syscall === 'fsync'); unpublished(h);
  });
  check('certificate flush failure is not ignored even after key flush succeeds', () => {
    const h = harness({ flushFailure: 'certificate.pem', flushCode: 'EPERM' });
    assert.throws(() => h.tls.Public(), e => e.code === 'EPERM' && e.syscall === 'fsync');
    assert.deepEqual(h.state.flushes, ['private-key.pem']); unpublished(h);
  });
  check('write-access denial remains a hard failure, not a read-only fallback', () => {
    const h = harness({ openFailure: 'certificate.pem' });
    assert.throws(() => h.tls.Public(), e => e.code === 'EACCES' && e.syscall === 'open'); unpublished(h);
  });
  check('malformed certificate still fails validation after both durable flushes', () => {
    const h = harness({ badCertificate: true });
    assert.throws(() => h.tls.Public(), /CONNECT_TLS_IDENTITY_INVALID/); unpublished(h);
    assert.deepEqual(h.state.flushes, ['private-key.pem', 'certificate.pem']);
  });
  check('failed later generation leaves the existing pin and identity bytes unchanged', () => {
    const old = successful.tls.ReadIdentity();
    const pinBefore = fs.readFileSync(successful.tls.MARKER);
    const h = harness({ data: successful.data, purposes: successful.purposes, flushFailure: 'certificate.pem' });
    assert.throws(() => h.tls.Generate('rotation-test.invalid'), e => e.code === 'EIO');
    assert.deepEqual(fs.readFileSync(h.tls.MARKER), pinBefore);
    assert.deepEqual(fs.readFileSync(old.certFile), old.cert);
    assert.deepEqual(fs.readFileSync(old.keyFile), old.key);
    assert.equal(fs.readdirSync(h.tls.DIR).some(x => x.startsWith('.pending-')), false);
    assert.equal(h.state.open.size, 0);
  });
  console.log('TLS FILE FLUSH PASS: ' + passed + ' cases; real OpenSSL/files/crypto, modeled Windows file access, in-memory purpose registry. Not a SQLite integration or Windows product PASS.');
} finally {
  fs.rmSync(root, { recursive: true, force: false, maxRetries: 6, retryDelay: 100 });
}
