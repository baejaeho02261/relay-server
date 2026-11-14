'use strict';
// Independent format checks. Generated keys are isolated public test fixtures;
// no private key, executable, server state or network operation is written.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const crypto = require('node:crypto'), child = require('node:child_process');
const helperPath = path.resolve(__dirname, '../../Cozy.Build/Cozy.Prepare-LauncherResource.js');
const helper = require(helperPath);
const MAGIC = Buffer.from('COZYAISSUERKEY1!', 'ascii');
const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
const second = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
function Public(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' }), blob = Buffer.alloc(283);
  [0x31415352, 2048, 3, 256, 0, 0].forEach((value, index) => blob.writeUInt32LE(value, index * 4));
  Buffer.from(jwk.e, 'base64url').copy(blob, 24); Buffer.from(jwk.n, 'base64url').copy(blob, 27);
  return Buffer.concat([MAGIC, crypto.createHash('sha256').update(blob).digest(), blob]);
}
function Declaration(anchor) {
  return '\ufeff{ Public test fixture only. }\r\n{$J-}\r\nconst\r\n  CozyIssuedATrustAnchor: array[0..330] of Byte = (' +
    [...anchor].map(value => '$' + value.toString(16).padStart(2, '0')).join(', ') + ');\r\n';
}
function Fixture(t) {
  const owned = fs.mkdtempSync(path.join(os.tmpdir(), 'cozy-launcher-resource-'));
  t.after(() => fs.rmSync(owned, { recursive: true, force: true }));
  const root = path.join(owned, 'source with spaces 한글'), configuration = path.join(root, 'Cozy.Source', 'Cozy.Configuration');
  const project = path.join(root, 'Cozy.Projects', 'Cozy.Launcher');
  fs.mkdirSync(configuration, { recursive: true }); fs.mkdirSync(project, { recursive: true });
  const files = { include: path.join(configuration, 'Cozy.IssuedA.Trust.inc'), binary: path.join(configuration, 'Cozy.IssuedA.Trust.bin'),
    metadata: path.join(configuration, 'Cozy.ReleaseMetadata.json'), manifest: path.join(project, 'Cozy.Launcher.manifest'),
    output: path.join(project, 'Cozy.LauncherResources.res') };
  const anchor = Public(pair.publicKey), metadata = { schemaVersion: 1, version: '12.34.56.78', companyName: 'Cozy Test', productName: 'Cozy Peace',
    descriptions: { A: 'Cozy Launcher', B: 'Cozy Client', O: 'Cozy Overlay' } };
  const manifest = Buffer.from('\ufeff<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n' +
    '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\r\n' +
    '<!-- 실제 파일 바이트 보존 -->\r\n' +
    '<assemblyIdentity version="12.34.56.78" processorArchitecture="amd64" name="Cozy.Launcher.Windows" type="win32"/>\r\n' +
    '<description>Cozy Launcher</description><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">' +
    '<security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>' +
    '</trustInfo></assembly>\r\n', 'utf8');
  fs.writeFileSync(files.include, Declaration(anchor)); fs.writeFileSync(files.binary, anchor);
  fs.writeFileSync(files.metadata, JSON.stringify(metadata)); fs.writeFileSync(files.manifest, manifest);
  return { root, owned, project, files, anchor, metadata, manifest };
}
function Records(bytes) {
  const records = []; let at = 0;
  while (at < bytes.length) {
    assert.equal(at % 4, 0); assert.ok(at + 32 <= bytes.length);
    const size = bytes.readUInt32LE(at), header = bytes.readUInt32LE(at + 4);
    assert.equal(header, 32); assert.equal(bytes.readUInt16LE(at + 8), 0xffff); assert.equal(bytes.readUInt16LE(at + 12), 0xffff);
    const type = bytes.readUInt16LE(at + 10), name = bytes.readUInt16LE(at + 14), start = at + header, end = start + size;
    assert.ok(end <= bytes.length); const next = (end + 3) & ~3;
    assert.ok(next <= bytes.length); assert.ok(bytes.subarray(end, next).every(value => value === 0));
    records.push({ type, name, data: bytes.subarray(start, end), language: bytes.readUInt16LE(at + 22) }); at = next;
  }
  return records;
}
function VersionBlock(bytes, start = 0) {
  const length = bytes.readUInt16LE(start), valueLength = bytes.readUInt16LE(start + 2), type = bytes.readUInt16LE(start + 4);
  assert.ok(length >= 6 && start + length <= bytes.length);
  let at = start + 6; const keyStart = at;
  while (at + 2 <= start + length && bytes.readUInt16LE(at) !== 0) at += 2;
  assert.ok(at + 2 <= start + length);
  const key = bytes.subarray(keyStart, at).toString('utf16le'); at = (at + 2 + 3) & ~3;
  const valueBytes = valueLength * (type === 1 ? 2 : 1), value = bytes.subarray(at, at + valueBytes);
  assert.equal(value.length, valueBytes); at += valueBytes;
  const children = [];
  while (((at + 3) & ~3) < start + length) {
    at = (at + 3) & ~3; const next = VersionBlock(bytes, at); children.push(next); at += next.length;
  }
  return { key, length, type, valueLength, value, children };
}
function Rejection(fixture, mutate, pattern = /^COZY_LAUNCHER_RESOURCE_/) {
  const original = fs.readFileSync(fixture.files.output), restore = mutate();
  try {
    assert.throws(() => helper.Prepare(fixture.root), error => pattern.test(error.message));
    assert.deepEqual(fs.readFileSync(fixture.files.output), original);
  } finally { restore?.(); }
}
function Change(file, value) {
  const original = fs.readFileSync(file); fs.writeFileSync(file, value); return () => fs.writeFileSync(file, original);
}

test('CLI creates standard public RCDATA, exact manifest and complete version resources', t => {
  const fixture = Fixture(t), output = child.spawnSync(process.execPath, [helperPath, '--source-root', fixture.root], { encoding: 'utf8' });
  assert.equal(output.status, 0, output.stderr); assert.equal(output.stderr, '');
  const response = JSON.parse(output.stdout), bytes = fs.readFileSync(fixture.files.output), records = Records(bytes);
  assert.deepEqual(response, { ok: true, keyId: fixture.anchor.subarray(16, 48).toString('hex'), resourceBytes: bytes.length, publicOnly: true });
  assert.deepEqual(records.map(record => [record.type, record.name]), [[0, 0], [10, 311], [24, 1], [16, 1]]);
  assert.equal(records[0].data.length, 0); assert.equal(records[0].language, 0);
  assert.deepEqual(records[1].data, fixture.anchor); assert.deepEqual(records[2].data, fixture.manifest);
  assert.ok(records.slice(1).every(record => record.language === 0x0409));
  const version = VersionBlock(records[3].data);
  assert.equal(version.length, records[3].data.length); assert.equal(version.key, 'VS_VERSION_INFO'); assert.equal(version.type, 0); assert.equal(version.valueLength, 52);
  assert.deepEqual(Array.from({ length: 13 }, (_, index) => version.value.readUInt32LE(index * 4)),
    [0xfeef04bd, 0x10000, 12 * 65536 + 34, 56 * 65536 + 78, 12 * 65536 + 34, 56 * 65536 + 78, 0x3f, 0, 0x40004, 1, 0, 0, 0]);
  assert.deepEqual(version.children.map(block => block.key), ['StringFileInfo', 'VarFileInfo']);
  const table = version.children[0].children[0]; assert.equal(table.key, '040904E4');
  assert.deepEqual(Object.fromEntries(table.children.map(block => [block.key, block.value.toString('utf16le').replace(/\0$/, '')])),
    { CompanyName: 'Cozy Test', FileDescription: 'Cozy Launcher', FileVersion: '12.34.56.78', ProductName: 'Cozy Peace', ProductVersion: '12.34.56.78' });
  const translation = version.children[1].children[0]; assert.equal(translation.key, 'Translation');
  assert.deepEqual([...translation.value], [9, 4, 228, 4]);
  assert.equal(bytes.includes(Buffer.from('PRIVATE KEY')), false);
  const before = fs.statSync(fixture.files.output).mtimeMs;
  assert.deepEqual(helper.Prepare(fixture.root), response); assert.equal(fs.statSync(fixture.files.output).mtimeMs, before);
});

test('replacement uses the newly supplied public key and retains the exact manifest bytes', t => {
  const fixture = Fixture(t); helper.Prepare(fixture.root); const before = fs.readFileSync(fixture.files.output);
  const updated = Public(second.publicKey); fs.writeFileSync(fixture.files.include, Declaration(updated)); fs.writeFileSync(fixture.files.binary, updated);
  const result = helper.Prepare(fixture.root), bytes = fs.readFileSync(fixture.files.output), records = Records(bytes);
  assert.notDeepEqual(bytes, before); assert.deepEqual(records[1].data, updated); assert.equal(bytes.includes(fixture.anchor), false);
  assert.equal(result.keyId, updated.subarray(16, 48).toString('hex')); assert.deepEqual(records[2].data, fixture.manifest);
});

test('zero and maximum four-part versions retain unsigned DWORD and string values', t => {
  const fixture = Fixture(t);
  for (const [version, word] of [['0.0.0.0', 0], ['65535.65535.65535.65535', 0xffffffff]]) {
    fs.writeFileSync(fixture.files.metadata, JSON.stringify({ ...fixture.metadata, version }));
    fs.writeFileSync(fixture.files.manifest, fixture.manifest.toString('utf8').replace('12.34.56.78', version));
    helper.Prepare(fixture.root);
    const record = Records(fs.readFileSync(fixture.files.output)).find(value => value.type === 16);
    const resource = VersionBlock(record.data);
    assert.deepEqual([8, 12, 16, 20].map(offset => resource.value.readUInt32LE(offset)), [word, word, word, word]);
    const value = resource.children[0].children[0].children.find(block => block.key === 'FileVersion');
    assert.equal(value.value.toString('utf16le'), version + '\0');
  }
});

test('missing, unconfigured, mismatched and malformed public inputs preserve an existing resource', t => {
  const fixture = Fixture(t); helper.Prepare(fixture.root);
  Rejection(fixture, () => Change(fixture.files.include, "{$MESSAGE ERROR 'COZY_ISSUED_A_PUBLIC_KEY_SETUP_REQUIRED'}"), /PUBLIC_KEY_SETUP_REQUIRED$/);
  for (const file of [fixture.files.include, fixture.files.binary, fixture.files.metadata, fixture.files.manifest]) {
    Rejection(fixture, () => { const moved = file + '.keep'; fs.renameSync(file, moved); return () => fs.renameSync(moved, file); }, /INPUT_MISSING$/);
  }
  Rejection(fixture, () => Change(fixture.files.include, Declaration(fixture.anchor).replace('0..330', '0..331')), /PUBLIC_INCLUDE_INVALID$/);
  Rejection(fixture, () => Change(fixture.files.binary, Public(second.publicKey)), /PUBLIC_BINARY_MISMATCH$/);
  for (const offset of [0, 16, 48, 52, 56, 60, 64, 68, 72, 74, 75, 330]) {
    const changed = Buffer.from(fixture.anchor); changed[offset] ^= offset === 75 ? 128 : offset === 330 ? 1 : 2;
    Rejection(fixture, () => {
      const restoreInclude = Change(fixture.files.include, Declaration(changed)), restoreBinary = Change(fixture.files.binary, changed);
      return () => { restoreInclude(); restoreBinary(); };
    });
  }
});

test('bounded metadata, duplicate fields and manifest version errors leave the prior output intact', t => {
  const fixture = Fixture(t); helper.Prepare(fixture.root);
  for (const bytes of [Buffer.from('{'), Buffer.from('{"version":"1.2.3.4",' + JSON.stringify(fixture.metadata).slice(1)),
    Buffer.from(JSON.stringify({ ...fixture.metadata, schemaVersion: 2 })), Buffer.from(JSON.stringify({ ...fixture.metadata, version: '65536.0.0.0' })),
    Buffer.from(JSON.stringify({ ...fixture.metadata, companyName: 'bad\nname' })), Buffer.alloc(16385, 32)]) {
    Rejection(fixture, () => Change(fixture.files.metadata, bytes));
  }
  for (const bytes of [Buffer.from(fixture.manifest.toString('utf8').replace('12.34.56.78', '1.2.3.4')),
    Buffer.from('<assembly/>'), Buffer.from([255, 254, 1]), Buffer.alloc(65537, 32),
    Buffer.concat([Buffer.from('<!DOCTYPE assembly SYSTEM "file:///unused">'), fixture.manifest])]) {
    Rejection(fixture, () => Change(fixture.files.manifest, bytes));
  }
});

test('relative paths, symlink inputs, linked ancestors and linked outputs are rejected', t => {
  const fixture = Fixture(t); helper.Prepare(fixture.root);
  assert.throws(() => helper.Prepare('relative'), /ABSOLUTE_SOURCE_ROOT_REQUIRED$/);
  assert.throws(() => helper.Main(['--source-root', fixture.root, '--extra']), /ARGUMENTS_INVALID$/);
  for (const file of [fixture.files.include, fixture.files.binary, fixture.files.metadata, fixture.files.manifest]) {
    const kept = file + '.keep'; fs.renameSync(file, kept);
    try {
      fs.symlinkSync(kept, file); assert.throws(() => helper.Prepare(fixture.root), /SYMLINK_REJECTED$/);
      assert.deepEqual(fs.readFileSync(kept), fs.readFileSync(file));
    } finally { fs.unlinkSync(file); fs.renameSync(kept, file); }
  }
  const rootLink = path.join(fixture.owned, 'linked source'); fs.symlinkSync(fixture.root, rootLink, 'dir');
  assert.throws(() => helper.Prepare(rootLink), /SYMLINK_REJECTED$/);
  const sourceDirectory = path.join(fixture.root, 'Cozy.Source'), keptDirectory = sourceDirectory + '.keep';
  fs.renameSync(sourceDirectory, keptDirectory);
  try { fs.symlinkSync(keptDirectory, sourceDirectory, 'dir'); assert.throws(() => helper.Prepare(fixture.root), /SYMLINK_REJECTED$/); }
  finally { fs.unlinkSync(sourceDirectory); fs.renameSync(keptDirectory, sourceDirectory); }
  const kept = fixture.files.output + '.keep'; fs.renameSync(fixture.files.output, kept); fs.symlinkSync(kept, fixture.files.output);
  assert.throws(() => helper.Prepare(fixture.root), /SYMLINK_REJECTED$/); assert.deepEqual(fs.readFileSync(kept), fs.readFileSync(fixture.files.output));
});

test('a failed atomic replacement preserves the previous complete resource and cleans its own temporary file', t => {
  const fixture = Fixture(t); helper.Prepare(fixture.root); const previous = fs.readFileSync(fixture.files.output);
  const updated = Public(second.publicKey); fs.writeFileSync(fixture.files.include, Declaration(updated)); fs.writeFileSync(fixture.files.binary, updated);
  const rename = fs.renameSync;
  fs.renameSync = () => { throw Object.assign(Error('injected rename failure'), { code: 'EACCES' }); };
  try { assert.throws(() => helper.Prepare(fixture.root), /WRITE_FAILED$/); }
  finally { fs.renameSync = rename; }
  assert.deepEqual(fs.readFileSync(fixture.files.output), previous);
  assert.equal(fs.readdirSync(fixture.project).some(name => name.includes('.pending.res')), false);
});

test('source changes before the atomic commit are rejected without replacing the prior resource', t => {
  const fixture = Fixture(t); helper.Prepare(fixture.root); const previous = fs.readFileSync(fixture.files.output);
  const updated = Public(second.publicKey); fs.writeFileSync(fixture.files.include, Declaration(updated)); fs.writeFileSync(fixture.files.binary, updated);
  const sync = fs.fsyncSync;
  fs.fsyncSync = fd => { sync(fd); fs.appendFileSync(fixture.files.include, '\r\n{ changed during preparation }'); };
  try { assert.throws(() => helper.Prepare(fixture.root), /INPUT_CHANGED$/); }
  finally { fs.fsyncSync = sync; }
  assert.deepEqual(fs.readFileSync(fixture.files.output), previous);
  assert.equal(fs.readdirSync(fixture.project).some(name => name.includes('.pending.res')), false);
});
