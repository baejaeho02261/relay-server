'use strict';
// Execute the standalone BAT workers through stdin; synthetic PE data is never loaded.
const assert = require('node:assert/strict'), crypto = require('node:crypto');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { spawnSync } = require('node:child_process');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-approval-tools-'));
process.env.DATA_DIR = temp;
process.env.HA_ENABLED = '0';
const { PE } = require('./desktop-bootstrap-fixture');
const { SignRelease } = require('../tools/sign-release-approval');
const authority = require('../services/desktopSecurityAuthority');
const sources = {};
for (const name of ['Create_Approval', 'Check_Approval']) {
  const source = fs.readFileSync(path.join(__dirname, '../tools', name + '.bat'), 'utf8');
  assert.ok(!/(?<!\r)\n/.test(source), name + ' must retain CRLF');
  assert.ok(source.includes("@('A','B','O')"));
  assert.ok(source.includes('*.bin'));
  const worker = source.match(/\$script:Worker = @'\r\n([\s\S]*?)\r\n'@/);
  assert.ok(worker, name + ' worker exists');
  for (const match of worker[1].matchAll(/require\('([^']+)'\)/g)) assert.ok(['node:fs', 'node:path', 'node:crypto'].includes(match[1]), 'Worker stays standalone');
  sources[name] = worker[1];
}
const privateKey = crypto.generateKeyPairSync('ed25519').privateKey;
const key = path.join(temp, 'existing.pem');
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
fs.writeFileSync(key, pem, { mode: 0o600 });
let count = 0, sequence = 0;
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function test(name, fn) { fn(); count++; console.log('PASS ' + name); }
function run(name, values) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) if (name.startsWith('GC_APPROVAL_') || ['NODE_OPTIONS', 'NODE_PATH', 'NODE_REPL_EXTERNAL_MODULE'].includes(name)) delete env[name];
  return spawnSync(process.execPath, ['--input-type=commonjs', '-'], { input: sources[name], env: { ...env, ...values }, encoding: 'utf8', timeout: 30000 });
}
function create(component, bytes, version = '94.1.0') {
  const file = path.join(temp, `${++sequence}.${component === 'O' ? 'bin' : 'exe'}`);
  const output = file + '.approval.json';
  fs.writeFileSync(file, bytes);
  const result = run('Create_Approval', { GC_APPROVAL_ACTION: 'sign', GC_APPROVAL_COMPONENT: component, GC_APPROVAL_VERSION: version, GC_APPROVAL_EXE: file, GC_APPROVAL_KEY: key, GC_APPROVAL_OUTPUT: output });
  return { result, file, output, version, component, bytes };
}
function inspect(item, component = item.component, version = item.version) {
  return run('Check_Approval', { GC_APPROVAL_ACTION: 'inspect', GC_APPROVAL_COMPONENT: component, GC_APPROVAL_VERSION: version, GC_APPROVAL_EXE: item.file, GC_APPROVAL_JSON: item.output });
}
function ok(result) { assert.equal(result.status, 0, result.stderr); return JSON.parse(result.stdout); }
function denied(result, code) { assert.equal(result.status, 1, result.stdout); assert.equal(result.stderr.trim(), code); assert.equal(result.stdout, ''); }
function dll() {
  const b = Buffer.alloc(2048); PE('O', 'approval fixture').copy(b);
  const pe = b.readUInt32LE(0x3c), opt = pe + 24, section = opt + b.readUInt16LE(pe + 20) + 40;
  b.writeUInt16LE(2, pe + 6); b.writeUInt16LE(0x2022, pe + 22); b.writeUInt32LE(0x3000, opt + 56);
  b.write('.rdata', section);
  for (const [offset, value] of [[8, 1024], [12, 8192], [16, 1024], [20, 1024], [36, 0x40000040]]) b.writeUInt32LE(value, section + offset);
  b.writeUInt32LE(8192, opt + 112); b.writeUInt32LE(1024, opt + 116);
  for (const [offset, value] of [[12, 8292], [16, 1], [20, 1], [24, 1], [28, 8232], [32, 8236], [36, 8240]]) b.writeUInt32LE(value, 1024 + offset);
  b.writeUInt32LE(4096, 1064); b.writeUInt32LE(8320, 1068); b.writeUInt16LE(0, 1072);
  b.write('overlay.bin\0', 1124); b.write('GameOverlayRunV1\0', 1152);
  return b;
}
function signedInvalid(bytes) {
  const item = create('O', dll()); ok(item.result); fs.writeFileSync(item.file, bytes);
  const a = JSON.parse(fs.readFileSync(item.output)); a.sha256 = sha(bytes);
  a.approval.signature = crypto.sign(null, Buffer.from(authority.ReleaseCanonical('O', item.version, a.sha256)), privateKey).toString('base64');
  fs.writeFileSync(item.output, JSON.stringify(a));
  return item;
}
try {
  test('Existing A/B workers and Node signer produce identical public approvals', () => {
    for (const component of ['A', 'B']) {
      const item = create(component, PE(component, authority.DOMAIN)); ok(item.result); ok(inspect(item));
      const approval = JSON.parse(fs.readFileSync(item.output));
      assert.deepEqual(approval, SignRelease(component, item.version, item.file, key));
      assert.ok(!JSON.stringify(approval).includes('PRIVATE KEY'));
      assert.deepEqual(fs.readFileSync(item.file), item.bytes);
    }
  });
  test('O uses the same existing key and exact server O canonical scope', () => {
    const item = create('O', dll()); ok(item.result); const checked = ok(inspect(item));
    assert.equal(checked.component, 'O'); assert.equal(checked.serverTrustChecked, false); assert.equal(checked.serverPolicyChanged, false);
    const approval = JSON.parse(fs.readFileSync(item.output));
    assert.deepEqual(approval, SignRelease('O', item.version, item.file, key));
    const policy = { ...authority.Defaults(), requireReleaseSignature: true, trustedReleaseKeys: [approval.trustedKey] };
    assert.equal(authority.VerifyApproval({ ...approval, releaseApproval: approval.approval }, policy), true);
    for (const component of ['A', 'B']) assert.equal(authority.VerifyApproval({ ...approval, component, releaseApproval: approval.approval }, policy), false);
    denied(inspect(item, 'B'), 'UPLOAD_COMPONENT_MISMATCH');
    denied(inspect(item, 'O', '94.1.1'), 'UPLOAD_VERSION_MISMATCH');
  });
  test('Wrong DLL flags, architecture, missing/forwarded/writable/noncode ABI exports fail before approval', () => {
    const invalid = [];
    let b = dll(); b.writeUInt16LE(0x22, 0x80 + 22); invalid.push(b);
    b = dll(); b.writeUInt16LE(0x2000, 0x80 + 22); invalid.push(b);
    b = dll(); b.writeUInt16LE(0x14c, 0x80 + 4); invalid.push(b);
    b = dll(); b.write('OtherOverlayABI\0', 1152); invalid.push(b);
    b = dll(); b.writeUInt32LE(8320, 1064); invalid.push(b);
    b = dll(); b.writeUInt32LE(0xc0000040, 0x80 + 24 + 240 + 40 + 36); invalid.push(b);
    b = dll(); b.writeUInt32LE(8700, 1064); invalid.push(b);
    b = dll(); b.writeUInt32LE(0xffffffff, 1068); invalid.push(b);
    for (const bytes of invalid) {
      const item = create('O', bytes); denied(item.result, 'OVERLAY_PLUGIN_PE_INVALID'); assert.equal(fs.existsSync(item.output), false);
      denied(inspect(signedInvalid(bytes)), 'OVERLAY_PLUGIN_PE_INVALID');
      assert.throws(() => SignRelease('O', item.version, item.file, key));
    }
  });
  test('O allows the 16MiB boundary and rejects larger files; A/B retains its previous bound', () => {
    const bytes = Buffer.alloc(16 * 1024 * 1024); dll().copy(bytes);
    const item = create('O', bytes); ok(item.result); ok(inspect(item)); SignRelease('O', item.version, item.file, key);
    const larger = Buffer.alloc(bytes.length + 1); bytes.copy(larger);
    const rejected = create('O', larger); denied(rejected.result, 'RELEASE_FILE_INVALID'); assert.equal(fs.existsSync(rejected.output), false);
    assert.throws(() => SignRelease('O', rejected.version, rejected.file, key), /RELEASE_FILE_INVALID/);
    fs.appendFileSync(item.file, Buffer.from([0])); denied(inspect(item), 'EXE_FILE_INVALID');
    const ab = create('A', larger); ok(ab.result); ok(inspect(ab)); SignRelease('A', ab.version, ab.file, key);
  });
  test('File tampering and component relabeling cannot reuse an O approval', () => {
    const item = create('O', dll()); ok(item.result);
    const changed = Buffer.from(item.bytes); changed[700] ^= 1; fs.writeFileSync(item.file, changed);
    denied(inspect(item), 'EXE_SHA256_MISMATCH');
    fs.writeFileSync(item.file, item.bytes); const approval = JSON.parse(fs.readFileSync(item.output)); approval.component = 'A';
    fs.writeFileSync(item.output, JSON.stringify(approval)); denied(inspect(item, 'A'), 'SIGNATURE_INVALID');
  });
  test('Existing files and the existing private key remain unchanged', () => {
    const item = create('O', dll()); ok(item.result); const output = fs.readFileSync(item.output);
    denied(run('Create_Approval', { GC_APPROVAL_ACTION: 'sign', GC_APPROVAL_COMPONENT: 'O', GC_APPROVAL_VERSION: item.version, GC_APPROVAL_EXE: item.file, GC_APPROVAL_KEY: key, GC_APPROVAL_OUTPUT: item.output }), 'OUTPUT_ALREADY_EXISTS');
    assert.deepEqual(fs.readFileSync(item.output), output); assert.deepEqual(fs.readFileSync(item.file), item.bytes); assert.deepEqual(fs.readFileSync(key), Buffer.from(pem));
  });
  console.log(`Approval tools: ${count} groups passed (embedded Node workers; Windows dialogs not executed).`);
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
