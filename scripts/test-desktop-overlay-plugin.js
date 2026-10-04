'use strict';
// Synthetic DLL data exercises publication and the production pinned TLS wire.
// Nothing in this suite loads or executes a PE image.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-overlay-plugin-'));
process.env.DATA_DIR = temp;
process.env.STORAGE_ENGINE = 'json';
process.env.HA_ENABLED = '0';
process.env.DESKTOP_PUBLIC_HOST = '127.0.0.1';
process.env.HOST = '127.0.0.1';
process.env.ADMIN_SECRET = 'overlay-plugin-test-admin';
process.env.WEB_ADMIN_PUBLIC_ORIGIN = '';
process.env.WEB_ADMIN_TRUSTED_PROXY_IPS = '';
process.env.RAILWAY_PUBLIC_DOMAIN = '';
require('../core/utils').EnsureDirs();
const fixture = require('./desktop-bootstrap-fixture');
const licenses = require('../services/desktopLicenses');
const boot = require('../services/desktopBootstrap');
const store = require('../services/desktopBootstrapStore');
const overlay = require('../services/desktopOverlay');
const integrity = require('../services/desktopIntegrity');
const { ExportTable } = require('../services/desktopPeExports');
const authority = require('../services/desktopSecurityAuthority');
const operations = require('../services/desktopSecurityOperations');
const wire = require('./tls-request-fixture');
const transport = require('../services/desktopConnect');
const server = transport.CreateServer();
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
let profile, webServer, webBase, adminRequest, strictInventoryRows = null, checks = 0;

function dllFixture(names, marker = 'plugin-fixture', size = 2048) {
  const bytes = Buffer.alloc(size);
  fixture.PE('O', marker).copy(bytes);
  const pe = bytes.readUInt32LE(0x3c), opt = pe + 24;
  const table = opt + bytes.readUInt16LE(pe + 20), section = table + 40;
  bytes.writeUInt16LE(2, pe + 6);
  bytes.writeUInt16LE(bytes.readUInt16LE(pe + 22) | 0x2000, pe + 22);
  bytes.writeUInt32LE(0x3000, opt + 56);
  bytes.write('.rdata\0\0', section, 'ascii');
  for (const [offset, value] of [[8, 1024], [12, 8192], [16, 1024], [20, 1024], [36, 0x40000040]]) bytes.writeUInt32LE(value, section + offset);
  bytes.writeUInt32LE(8192, opt + 112);
  bytes.writeUInt32LE(1024, opt + 116);
  const namesSorted = [...names].sort(), at = 1024;
  const functions = 40, namePointers = functions + names.length * 4;
  const ordinals = namePointers + names.length * 4, dllName = ordinals + names.length * 2;
  let strings = dllName + Buffer.byteLength('GameOverlay.dll\0');
  assert.ok(strings < 1024);
  for (const [offset, value] of [[12, 8192 + dllName], [16, 1], [20, names.length], [24, names.length], [28, 8192 + functions], [32, 8192 + namePointers], [36, 8192 + ordinals]]) bytes.writeUInt32LE(value, at + offset);
  bytes.write('GameOverlay.dll\0', at + dllName, 'ascii');
  namesSorted.forEach((name, index) => {
    bytes[512 + index] = 0xc3;
    bytes.writeUInt32LE(4096 + index, at + functions + index * 4);
    bytes.writeUInt32LE(8192 + strings, at + namePointers + index * 4);
    bytes.writeUInt16LE(index, at + ordinals + index * 2);
    strings += bytes.write(name + '\0', at + strings, 'ascii');
  });
  assert.ok(strings < 1024);
  return bytes;
}

async function check(label, fn) { await fn(); checks++; console.log('PASS ' + label); }
function reject(code, fn) { assert.throws(fn, error => error.message === code, code); }
async function ok(operation, body) {
  const reply = await wire.Request(profile, operation, body);
  assert.equal(reply.ok, true, JSON.stringify(reply));
  return reply.data;
}
async function denied(code, operation, body) {
  const reply = await wire.Request(profile, operation, body);
  assert.equal(reply.ok, false, JSON.stringify(reply));
  assert.equal(reply.error, code, JSON.stringify(reply));
}
async function authorize() {
  const device = fixture.Device();
  fixture.Publish();
  let session;
  if (strictInventoryRows) {
    const start = fixture.Begin(device); fixture.Download(start.begin);
    await nativeSnapshot(device, { stage: 'A', sessionId: start.begin.flowId, sessionToken: start.begin.downloadTicket, machineId: device.machineId }, strictInventoryRows);
    session = fixture.Claim(device, start.begin, fixture.Finish(device, start.begin));
    await nativeSnapshot(device, { sessionId: session.sessionId, sessionToken: session.sessionToken, ...fixture.Evidence(device, session) }, strictInventoryRows);
  } else {
    const issue = boot.IssueLauncher({ requestId: crypto.randomUUID(), label: 'Overlay plugin regression' }, 'TEST');
    session = await fixture.RemoteSession(device, boot.LauncherBytes(issue.launcherId));
  }
  const issued = licenses.Create({ label: 'Overlay plugin regression' }, 'TEST');
  const payloadJSON = JSON.stringify({ ...fixture.Evidence(device, session), licenseKey: issued.licenseKey, appVersion: '94.0.0', bootstrapSessionId: session.sessionId, bootstrapSessionToken: session.sessionToken });
  const base = { action: 'redeem', requestId: crypto.randomUUID(), deviceId: device.deviceId, publicKey: device.publicKey, payloadHash: sha(payloadJSON) };
  const challenge = await ok('challenge', base);
  const license = await ok('execute', { ...base, challengeId: challenge.challengeId, payloadJSON, signature: fixture.Sign(device, challenge.canonical) });
  return { device, session, issued, license, completion: { action: 'completeLicense', requestId: crypto.randomUUID(), sessionId: session.sessionId, sessionToken: session.sessionToken, deviceId: device.deviceId, activationToken: license.activationToken } };
}
async function complete(item = null) {
  item ||= await authorize();
  item.grant = await ok('bootstrap', item.completion);
  item.auth = { action: 'poll', sessionId: item.grant.sessionId, sessionToken: item.grant.sessionToken, deviceId: item.device.deviceId };
  return item;
}
const flowFor = item => Object.values(store.Load().flows).find(row => row.sessionId === item.session.sessionId);

async function nativeSnapshot(device, context, rows) {
  const challenge = await ok('report', { ...context, action: 'challenge' });
  const payload = JSON.stringify({ version: 1, hashVersion: 2, check: 'MODULE_INVENTORY', reason: 'PERIODIC', scope: 'current-process', trust: 'client-reported', snapshotId: crypto.randomUUID(), batchIndex: 0, batchCount: 1, complete: true, truncated: false, totalModules: rows.length, measuredModules: rows.length, modules: rows });
  const canonical = require('../services/desktopIntegrityReports').Canonical(context.sessionId, challenge, payload);
  const result = await ok('report', { ...context, action: 'submit', reportId: challenge.reportId, payload, signature: fixture.Sign(device, canonical) });
  assert.equal(result.status, 'VERIFIED');
}

const requiredExport = 'GameOverlayRunV1';
const digestKeys = ['Sha256', 'Crc64', 'Xxh64', 'Blake3'];
const changed = value => (value[0] === '0' ? '1' : '0') + value.slice(1);
function measured(bytes) {
  const result = {}, file = integrity.Digests(bytes), code = integrity.CodeImage(bytes), exports = ExportTable(bytes);
  assert.equal(exports.status, 'MEASURED');
  for (const [prefix, source] of [['file', file], ['code', code], ['exportTable', exports]]) {
    for (const suffix of digestKeys) result[prefix + suffix] = source[suffix[0].toLowerCase() + suffix.slice(1)];
  }
  return result;
}
function pluginRow(bytes, name = 'GameOverlayPlugin.bin') {
  return { name, status: 'MATCH_LOCAL_FILE', codeStatus: 'MATCH_LOCAL_FILE', exportTableStatus: 'MEASURED', ...measured(bytes) };
}
function rejected(fn) { assert.throws(fn, error => error.desktopError === true); }
async function refused(operation, body) {
  const reply = await wire.Request(profile, operation, body);
  assert.equal(reply.ok, false, JSON.stringify(reply));
  assert.equal(typeof reply.error, 'string');
  return reply.error;
}
function approval(key, component, version, bytes) {
  return { keyId: key.keyId, signature: crypto.sign(null, Buffer.from(authority.ReleaseCanonical(component, version, sha(bytes))), key.privateKey).toString('base64') };
}
function signer() {
  const pair = crypto.generateKeyPairSync('ed25519');
  return { ...pair, keyId: sha(pair.publicKey.export({ type: 'spki', format: 'der' })), pem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
}

function hostMeasurement(item) {
  const artifact = store.Load().artifacts[flowFor(item).releaseId];
  const bytes = boot.ReadArtifactBytes(artifact), file = integrity.Digests(bytes), code = integrity.CodeImage(bytes);
  return { ...file, codeSha256: code.sha256, codeCrc64: code.crc64, codeXxh64: code.xxh64, codeBlake3: code.blake3 };
}

function inventory(item, modules, extra = {}) {
  const release = hostMeasurement(item);
  return {
    version: 1, hashVersion: 2, check: 'MODULE_INVENTORY', reason: 'PERIODIC',
    scope: 'current-process', trust: 'client-reported', snapshotId: item.manifest.reportId,
    batchIndex: 0, batchCount: 1, complete: true, truncated: false,
    totalModules: modules.length, measuredModules: modules.length,
    own: {
      status: 'MEASURED', fileSha256: release.sha256, fileCrc64: release.crc64,
      fileXxh64: release.xxh64, fileBlake3: release.blake3,
      codeSha256: release.codeSha256, codeCrc64: release.codeCrc64,
      codeXxh64: release.codeXxh64, codeBlake3: release.codeBlake3
    }, modules, ...extra
  };
}
async function manifest(item) {
  item.manifest = await ok('overlay', { ...item.auth, action: 'plugin-manifest' });
  return item.manifest;
}
function reportBody(item, payload) {
  return { ...item.auth, action: 'plugin-report', pluginId: item.manifest.pluginId, reportId: item.manifest.reportId, payload: JSON.stringify(payload) };
}
(async () => {
  try {
    const plugins = require('../services/desktopOverlayPlugin');
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    process.env.DESKTOP_PUBLIC_PORT = String(server.address().port);
    profile = require('../services/connectTransportKey').Profile();
    const bytes = dllFixture([requiredExport], 'first-plugin', 270000);
    let candidate, item;
    const activate = row => plugins.Activate({ id: row.id, expectedRevision: plugins.Overview().revision }, 'TEST');

    await check('A completed license without a published plugin cannot use an embedded display fallback', async () => {
      const unpublished = await complete();
      await denied('OVERLAY_PLUGIN_NOT_PUBLISHED', 'overlay', unpublished.auth);
      await denied('OVERLAY_SESSION_CLOSED', 'overlay', unpublished.auth);
      assert.equal(flowFor(unpublished).closedByLicenseCompletion, true);
    });

    await check('Only bounded Win64 DLL images with the executable ABI export can be staged', () => {
      assert.equal(plugins.MAX_BYTES, 16 * 1024 * 1024);
      reject('OVERLAY_PLUGIN_TOO_LARGE', () => plugins.Stage('1.0.0', Buffer.alloc(plugins.MAX_BYTES + 1), undefined, 'TEST'));
      const invalid = [fixture.PE('B'), Buffer.from('not a PE'), dllFixture(['OtherExport'])];
      const pe32 = Buffer.from(bytes); pe32.writeUInt16LE(0x14c, pe32.readUInt32LE(0x3c) + 4); invalid.push(pe32);
      const forwarder = dllFixture([requiredExport]); forwarder.writeUInt32LE(8192 + 500, 1024 + 40); forwarder.write('KERNELBASE.ReadFile\0', 1524, 'ascii'); invalid.push(forwarder);
      for (const bad of invalid) reject('OVERLAY_PLUGIN_PE_INVALID', () => plugins.Stage('1.0.0', bad, undefined, 'TEST'));
      candidate = plugins.Stage('1.0.0', bytes, undefined, 'TEST');
      assert.ok(candidate.id);
      assert.equal(candidate.fileName, 'GameOverlayPlugin.bin');
      assert.equal(plugins.Overview().revision >= 1, true);
      assert.equal(ExportTable(bytes).codeExportCount, 1);
    });

    await check('Activation is explicit and requires the current configuration revision', () => {
      rejected(() => plugins.Activate({ id: candidate.id, expectedRevision: -1 }, 'TEST'));
      rejected(() => plugins.Activate({ id: '0'.repeat(24), expectedRevision: plugins.Overview().revision }, 'TEST'));
      activate(candidate);
      const stale = plugins.Overview().revision - 1;
      rejected(() => plugins.Activate({ id: candidate.id, expectedRevision: stale }, 'TEST'));
    });

    await check('Real admin HTTP upload and activation require a live session and CSRF', async () => {
      const reserve = require('node:net').createServer();
      await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
      const port = reserve.address().port;
      await new Promise(resolve => reserve.close(resolve));
      require('../config/config').WEB_ADMIN_PORT = port;
      webServer = require('../web/webServer').StartWebAdmin();
      await new Promise((resolve, reject) => { webServer.once('listening', resolve); webServer.once('error', reject); });
      const base = 'http://127.0.0.1:' + port, route = '/api/desktop/bootstrap/overlay/plugins';
      webBase = base;
      const request = async (pathname, method = 'GET', body, headers = {}) => {
        const response = await fetch(base + pathname, { method, headers, ...(body === undefined ? {} : { body }), signal: AbortSignal.timeout(5000) });
        return { status: response.status, headers: response.headers, json: await response.json() };
      };
      adminRequest = request;
      assert.equal((await request(route)).status, 401);
      const login = await request('/api/login', 'POST', JSON.stringify({ role: 'admin', password: process.env.ADMIN_SECRET }), { 'Content-Type': 'application/json', Origin: base });
      assert.equal(login.status, 200, JSON.stringify(login.json));
      const cookie = login.headers.get('set-cookie').split(';')[0], owner = { Cookie: cookie, Origin: base, 'X-CSRF-Token': login.json.csrf };
      assert.equal((await request(route, 'GET', undefined, { Cookie: cookie })).status, 200);
      const upload = route + '?version=1.0.2&fileName=GameOverlayPlugin.bin', uploadBytes = dllFixture([requiredExport], 'http-upload');
      assert.equal((await request(upload, 'POST', uploadBytes, { Cookie: cookie, Origin: base, 'Content-Type': 'application/octet-stream' })).status, 403);
      assert.equal((await request(route + '?version=1.0.2&fileName=overlay.exe', 'POST', uploadBytes, { ...owner, 'Content-Type': 'application/octet-stream' })).status, 400);
      const staged = await request(upload, 'POST', uploadBytes, { ...owner, 'Content-Type': 'application/octet-stream' });
      assert.equal(staged.status, 200, JSON.stringify(staged.json));
      assert.equal(staged.json.artifact.sha256, sha(uploadBytes));
      assert.equal(staged.json.artifact.fileName, 'GameOverlayPlugin.bin');
      assert.equal(staged.json.activeUnchanged, true);
      assert.equal(plugins.Overview().activeId, candidate.id);
      const selection = JSON.stringify({ id: staged.json.artifact.id, expectedRevision: staged.json.revision });
      assert.equal((await request(route + '/activate', 'POST', selection, { Cookie: cookie, Origin: base, 'Content-Type': 'application/json' })).status, 403);
      const selected = await request(route + '/activate', 'POST', selection, { ...owner, 'Content-Type': 'application/json' });
      assert.equal(selected.status, 200, JSON.stringify(selected.json));
      assert.equal(plugins.Overview().activeId, staged.json.artifact.id);
      assert.equal((await request('/api/logout', 'POST', '{}', { ...owner, 'Content-Type': 'application/json' })).status, 200);
      assert.equal((await request(upload, 'POST', uploadBytes, { ...owner, 'Content-Type': 'application/octet-stream' })).status, 401);
      activate(candidate);
    });

    await check('License completion closes B while display waits for the plugin report', async () => {
      item = await complete();
      assert.equal(Object.keys(item.grant).length, 8, 'The existing completion receipt stays compatible');
      assert.equal(flowFor(item).status, 'CLOSED');
      assert.equal(flowFor(item).closedByLicenseCompletion, true);
      await denied('BOOTSTRAP_SESSION_CLOSED', 'bootstrap', { action: 'status', sessionId: item.session.sessionId, sessionToken: item.session.sessionToken });
      await denied('BOOTSTRAP_SESSION_CLOSED', 'report', { action: 'challenge', stage: 'B', sessionId: item.session.sessionId, sessionToken: item.session.sessionToken });
      await refused('overlay', item.auth);
    });

    await check('Plugin manifest authenticates the overlay owner and exposes independent file/code/export baselines', async () => {
      for (const patch of [{ deviceId: '0'.repeat(64) }, { sessionToken: item.session.sessionToken }, { sessionId: item.session.sessionId }]) {
        await refused('overlay', { ...item.auth, ...patch, action: 'plugin-manifest' });
      }
      const out = await manifest(item);
      assert.equal(out.pluginId, candidate.id);
      assert.equal(out.fileName, 'GameOverlayPlugin.bin');
      assert.equal(out.size, bytes.length);
      assert.equal(out.chunkSize, 262144);
      for (const [key, value] of Object.entries(measured(bytes))) {
        const manifestKey = key.startsWith('file') ? key[4].toLowerCase() + key.slice(5) : key;
        assert.equal(out[manifestKey], value, manifestKey);
      }
      assert.deepEqual(out.host, hostMeasurement(item));
      assert.equal(typeof out.reportId, 'string');
      assert.ok(out.installExpiresAt > Date.now());
      assert.ok(out.installExpiresAt <= Date.now() + 120000);
      assert.ok(out.reportExpiresAt <= out.installExpiresAt);
      assert.ok(!JSON.stringify(plugins.Overview()).includes(item.grant.sessionToken));
    });

    await check('Authenticated chunks are pinned, bounded and reconstruct the exact uploaded bytes', async () => {
      const request = { ...item.auth, action: 'plugin-chunk', pluginId: item.manifest.pluginId, offset: 0 };
      for (const patch of [{ sessionToken: 'x'.repeat(43) }, { deviceId: '0'.repeat(64) }, { pluginId: '0'.repeat(24) }, { offset: -1 }, { offset: 0.5 }, { offset: Number.MAX_SAFE_INTEGER }, { offset: bytes.length }]) await refused('overlay', { ...request, ...patch });
      const chunks = [];
      for (let offset = 0; offset < bytes.length;) {
        const out = await ok('overlay', { ...request, offset });
        assert.equal(out.offset, offset);
        const chunk = Buffer.from(out.data, 'base64');
        assert.ok(chunk.length > 0 && chunk.length <= 262144);
        assert.equal(chunk.toString('base64'), out.data);
        chunks.push(chunk); offset += chunk.length;
      }
      assert.equal(chunks.length, 2);
      assert.deepEqual(Buffer.concat(chunks), bytes);
    });

    await check('An issued capability keeps its immutable plugin pin after a new activation', async () => {
      const secondBytes = dllFixture([requiredExport], 'second-plugin');
      const second = plugins.Stage('1.0.1', secondBytes, undefined, 'TEST');
      activate(second);
      assert.equal((await manifest(item)).pluginId, candidate.id);
      const next = await complete();
      assert.equal((await manifest(next)).pluginId, second.id);
      await ok('overlay', { ...next.auth, action: 'close' });
      activate(candidate);
    });

    await check('Only a complete host and loaded-plugin inventory enables display', async () => {
      const first = inventory(item, [pluginRow(bytes)], { batchCount: 2, totalModules: 2, measuredModules: 2, complete: false });
      const partial = await ok('overlay', reportBody(item, first));
      assert.equal(partial.accepted, true); assert.equal(partial.status, 'PARTIAL'); assert.equal(partial.nextBatch, 1);
      await refused('overlay', item.auth);
      const second = inventory(item, [pluginRow(bytes, 'optional.dll')], { batchIndex: 1, batchCount: 2, totalModules: 2, measuredModules: 2 });
      const ready = await ok('overlay', reportBody(item, second));
      assert.equal(ready.status, 'READY'); assert.equal(ready.pluginId, candidate.id);
      const recovered = await ok('overlay', reportBody(item, second));
      assert.equal(recovered.status, 'READY'); assert.equal(recovered.leaseExpiresAt, ready.leaseExpiresAt);
      const polled = await ok('overlay', item.auth);
      assert.equal(polled.documentSha256, sha(polled.documentText));
      await denied('BOOTSTRAP_SESSION_CLOSED', 'bootstrap', { action: 'status', sessionId: item.session.sessionId, sessionToken: item.session.sessionToken });
    });

    await check('Forged reports cannot revoke another owner or make an unreported plugin ready', async () => {
      const target = await complete(); await manifest(target);
      const report = reportBody(target, inventory(target, [pluginRow(bytes)]));
      await refused('overlay', { ...report, sessionToken: 'x'.repeat(43) });
      await refused('overlay', { ...report, deviceId: '0'.repeat(64) });
      const accepted = await ok('overlay', report);
      assert.equal(accepted.status, 'READY');
      await ok('overlay', target.auth);
    });

    await check('Exact approved plugin bytes support random local names and existing Windows case-insensitive names', async () => {
      for (const name of ['gAmEoVeRlAyPlUgIn.BIN', 'OvErLaY.BIN', 'gc_' + crypto.randomBytes(16).toString('hex') + '-1.bin', 'a'.repeat(76) + '.bin']) {
        const target = await complete(); await manifest(target);
        assert.equal(target.manifest.fileName, 'GameOverlayPlugin.bin', 'Publication remains compatible with previous clients');
        assert.equal((await ok('overlay', reportBody(target, inventory(target, [pluginRow(bytes, name)])))).status, 'READY');
        await ok('overlay', target.auth);
        await ok('overlay', { ...target.auth, action: 'close' });
      }
      for (const name of ['GameOverlayPlugin.dll', '../overlay.bin', 'sub\\overlay.bin', 'overlay.bin:stream', 'local name.bin', '플러그인.bin', '.bin', 'name.bin.tmp', 'a'.repeat(77) + '.bin']) {
        const wrong = await complete(); await manifest(wrong);
        await refused('overlay', reportBody(wrong, inventory(wrong, [pluginRow(bytes, name)])));
        await refused('overlay', wrong.auth);
      }
    });

    await check('Canonical or random filenames cannot authorize modified contents or incomplete measurement statuses', async () => {
      const otherBytes = dllFixture([requiredExport], 'filename-spoofed-content');
      for (const row of [pluginRow(otherBytes), pluginRow(otherBytes, crypto.randomBytes(16).toString('hex') + '.bin'),
        { ...pluginRow(bytes), status: 'UNVERIFIED_BASELINE' },
        { ...pluginRow(bytes), codeStatus: 'READ_ERROR' },
        { ...pluginRow(bytes), exportTableStatus: 'READ_ERROR' }]) {
        const target = await complete(); await manifest(target);
        await denied('OVERLAY_PLUGIN_REPORT_MISMATCH', 'overlay', reportBody(target, inventory(target, [row])));
        await denied('OVERLAY_SESSION_CLOSED', 'overlay', target.auth);
      }
    });

    await check('An inventory requires exactly one approved image and one case-insensitive row for its local basename', async () => {
      const name = crypto.randomBytes(16).toString('hex') + '.bin';
      const row = pluginRow(bytes, name), changedRow = { ...row, name: name.toUpperCase(), codeSha256: changed(row.codeSha256) };
      for (const modules of [[row, { ...row, name: name.toUpperCase() }], [row, changedRow], [row, pluginRow(bytes, 'another-copy.bin')]]) {
        const target = await complete(); await manifest(target);
        await denied('OVERLAY_PLUGIN_REPORT_MISMATCH', 'overlay', reportBody(target, inventory(target, modules)));
        await denied('OVERLAY_SESSION_CLOSED', 'overlay', target.auth);
      }
      const target = await complete(); await manifest(target);
      const first = inventory(target, [row], { batchCount: 2, totalModules: 2, measuredModules: 2, complete: false });
      assert.equal((await ok('overlay', reportBody(target, first))).status, 'PARTIAL');
      const duplicate = inventory(target, [changedRow], { batchIndex: 1, batchCount: 2, totalModules: 2, measuredModules: 2 });
      await denied('OVERLAY_PLUGIN_REPORT_MISMATCH', 'overlay', reportBody(target, duplicate));
      await denied('OVERLAY_SESSION_CLOSED', 'overlay', target.auth);
    });

    await check('Stored overlay.bin artifacts keep their pinned manifest and inventory names across new publication', async () => {
      const legacyBytes = dllFixture([requiredExport], 'existing-overlay-bin');
      const legacy = plugins.Stage('1.0.4', legacyBytes, undefined, 'TEST');
      // Simulate the durable row produced by the previous release. Its bytes and
      // immutable artifact ID are unchanged; production validation must read it.
      store.Atomic(db => { db.overlayPlugins.artifacts[legacy.id].fileName = 'overlay.bin'; });
      plugins.ValidateState(store.Load().overlayPlugins);
      activate(legacy);
      const target = await complete();
      assert.equal((await manifest(target)).fileName, 'overlay.bin');
      assert.equal(target.manifest.pluginId, legacy.id);
      const republished = plugins.Stage('1.0.4', legacyBytes, undefined, 'TEST');
      assert.notEqual(republished.id, legacy.id, 'Republishing the same bytes creates the current canonical basename');
      assert.equal(republished.fileName, 'GameOverlayPlugin.bin');
      activate(republished);
      assert.equal((await manifest(target)).fileName, 'overlay.bin');
      const chunk = await ok('overlay', { ...target.auth, action: 'plugin-chunk', pluginId: legacy.id, offset: 0 });
      assert.deepEqual(Buffer.from(chunk.data, 'base64'), legacyBytes);
      assert.equal((await ok('overlay', reportBody(target, inventory(target, [pluginRow(legacyBytes, 'OvErLaY.BIN')])))).status, 'READY');
      assert.equal((await ok('overlay', target.auth)).sessionId, target.grant.sessionId);
      await ok('overlay', { ...target.auth, action: 'close' });
      activate(candidate);
    });

    await check('An unrelated unloaded optional module does not hide a verified plugin or bypass registered DLL comparisons', async () => {
      const target = await complete(); await manifest(target);
      const optional = { name: 'removed-license-module.dll', status: 'READ_ERROR', codeStatus: 'READ_ERROR' };
      const ready = await ok('overlay', reportBody(target, inventory(target, [pluginRow(bytes), optional], { measuredModules: 1 })));
      assert.equal(ready.status, 'READY');
      const reports = require('../services/desktopIntegrityReports');
      const knownBytes = dllFixture(['KnownExport'], 'known-system-module');
      reports.RegisterBaseline('ntdll.dll', 'Trusted test baseline', knownBytes, 'TEST');
      const mismatch = await complete(); await manifest(mismatch);
      const known = pluginRow(knownBytes, 'ntdll.dll'); known.codeSha256 = changed(known.codeSha256);
      await refused('overlay', reportBody(mismatch, inventory(mismatch, [pluginRow(bytes), known])));
      await refused('overlay', mismatch.auth);
    });

    await check('Missing loaded-plugin rows and every file/code/export hash mismatch reject display', async () => {
      for (const key of [null, ...Object.keys(measured(bytes))]) {
        const target = await complete(); await manifest(target);
        const row = pluginRow(bytes, crypto.randomBytes(16).toString('hex') + '.bin'); if (key) row[key] = changed(row[key]);
        await refused('overlay', reportBody(target, inventory(target, key ? [row] : [])));
        await refused('overlay', target.auth);
        assert.equal(flowFor(target).closedByLicenseCompletion, true);
      }
    });

    await check('Wrong host image, unsupported hash version and oversized/incomplete inventories reject display', async () => {
      for (const change of [
        p => { p.own.codeSha256 = '0'.repeat(64); },
        p => { p.own.fileXxh64 = changed(p.own.fileXxh64); },
        p => { delete p.own; },
        p => { p.hashVersion = 1; },
        p => { p.truncated = true; },
        p => { p.complete = false; },
        p => { p.batchCount = 257; },
        p => { p.totalModules = 1025; p.measuredModules = 1025; },
        p => { p.snapshotId = crypto.randomUUID(); },
        p => { p.measuredModules = 0; },
        p => { p.scope = 'another-process'; },
        p => { p.trust = 'hardware-attested'; },
        p => { p.modules.push(pluginRow(bytes)); p.totalModules = 2; p.measuredModules = 2; },
        p => { p.modules = Array.from({ length: 17 }, (_, i) => ({ name: 'module' + i + '.dll', status: 'READ_ERROR' })); p.totalModules = 17; p.measuredModules = 0; }
      ]) {
        const target = await complete(); await manifest(target);
        const payload = inventory(target, [pluginRow(bytes)]); change(payload);
        await refused('overlay', reportBody(target, payload));
        await refused('overlay', target.auth);
      }
      const target = await complete(); await manifest(target);
      await refused('overlay', { ...reportBody(target, {}), payload: ' '.repeat(8193) });
      await refused('overlay', target.auth);
    });

    await check('Snapshot metadata cannot change between accepted batches', async () => {
      for (const changedMetadata of [{ measuredModules: 1 }, { totalModules: 3 }, { batchCount: 3, complete: false }]) {
        const target = await complete(); await manifest(target);
        const first = inventory(target, [pluginRow(bytes)], { batchCount: 2, totalModules: 2, measuredModules: 2, complete: false });
        assert.equal((await ok('overlay', reportBody(target, first))).status, 'PARTIAL');
        const second = inventory(target, [pluginRow(bytes, 'optional.dll')], { batchIndex: 1, batchCount: 2, totalModules: 2, measuredModules: 2, ...changedMetadata });
        await refused('overlay', reportBody(target, second));
        await refused('overlay', target.auth);
      }
    });

    await check('Strict required DLLs need measured exports and a unique inventory row after signed A/B checks', async () => {
      const reports = require('../services/desktopIntegrityReports'), knownBytes = dllFixture(['KnownExport'], 'known-system-module');
      const known = pluginRow(knownBytes, 'ntdll.dll');
      reports.RegisterBaseline('ntdll.dll', 'Trusted test baseline', knownBytes, 'TEST');
      reports.SetPolicy({ enabled: true, requireExtendedHashes: true, requiredModules: ['ntdll.dll'] }, 'TEST');
      strictInventoryRows = [known];
      try {
        const valid = await complete(); await manifest(valid);
        assert.equal((await ok('overlay', reportBody(valid, inventory(valid, [pluginRow(bytes), known])))).status, 'READY');
        for (const modules of [
          [pluginRow(bytes), Object.fromEntries(Object.entries(known).filter(([key]) => !key.startsWith('exportTable')))],
          [pluginRow(bytes), known, { ...known }]
        ]) {
          const target = await complete(); await manifest(target);
          await refused('overlay', reportBody(target, inventory(target, modules)));
          await refused('overlay', target.auth);
        }
      } finally {
        strictInventoryRows = null;
        reports.SetPolicy({ enabled: false, requireExtendedHashes: false, requiredModules: ['ntdll.dll'] }, 'TEST');
      }
    });

    await check('Corrupt plugin hashes, pins and installation chronology fail durable validation', async () => {
      const target = await complete(); await manifest(target);
      const current = store.Load();
      plugins.ValidateState(current.overlayPlugins); overlay.ValidateState(current.overlayState, current);
      for (const mutate of [
        state => { state.artifacts[candidate.id].sha256 = 'not-a-digest'; },
        state => { state.artifacts[candidate.id].abi = 2; },
        state => { state.artifacts[candidate.id].size = plugins.MAX_BYTES + 1; },
        state => { state.activeId = '0'.repeat(24); }
      ]) {
        const copy = structuredClone(current.overlayPlugins); mutate(copy);
        assert.throws(() => plugins.ValidateState(copy));
      }
      for (const fileName of ['../overlay.bin', '/overlay.bin', 'sub\\overlay.bin', 'C:overlay.bin', 'overlay.bin:stream', 'overlay.bin\0', 'name with spaces.bin', '플러그인.bin', 'name.other.bin', '.bin', 'GameOverlayPlugin.dll', 'a'.repeat(77) + '.bin', '', null, 123]) {
        const copy = structuredClone(current.overlayPlugins);
        copy.artifacts[candidate.id].fileName = fileName;
        assert.throws(() => plugins.ValidateState(copy), /OVERLAY_PLUGIN_STORAGE_INVALID/, String(fileName));
      }
      for (const mutate of [
        row => { row.pluginId = '0'.repeat(24); },
        row => { row.pluginInstallExpiresAt = row.pluginInstallStartedAt + 120001; }
      ]) {
        const copy = structuredClone(current); mutate(copy.overlayState.sessions[target.grant.sessionId]);
        assert.throws(() => overlay.ValidateState(copy.overlayState, copy), /OVERLAY_STORAGE_INVALID/);
      }
    });

    await check('A maximum-size plugin downloads and reports beyond forty requests while each chunk retry stays bounded', async () => {
      const maximum = dllFixture([requiredExport], 'maximum-size-plugin', plugins.MAX_BYTES);
      const large = plugins.Stage('1.0.3', maximum, undefined, 'TEST'); activate(large);
      const target = await complete(); await manifest(target);
      const digest = crypto.createHash('sha256'); let chunks = 0, downloaded = 0;
      for (let offset = 0; offset < maximum.length; offset += 262144) {
        const out = await ok('overlay', { ...target.auth, action: 'plugin-chunk', pluginId: large.id, offset });
        const data = Buffer.from(out.data, 'base64'); assert.equal(data.length, out.size); digest.update(data); downloaded += data.length; chunks++;
      }
      assert.equal(chunks, 64); assert.equal(downloaded, plugins.MAX_BYTES); assert.equal(digest.digest('hex'), sha(maximum));
      const retry = { ...target.auth, action: 'plugin-chunk', pluginId: large.id, offset: 0 };
      await ok('overlay', retry); await ok('overlay', retry);
      await denied('OVERLAY_PLUGIN_DOWNLOAD_LIMIT', 'overlay', retry);
      const plugin = pluginRow(maximum);
      for (let batchIndex = 0; batchIndex < 64; batchIndex++) {
        const modules = batchIndex === 0 ? [plugin] : [{ name: 'optional' + batchIndex + '.dll', status: 'READ_ERROR', codeStatus: 'READ_ERROR' }];
        const payload = inventory(target, modules, { batchIndex, batchCount: 64, totalModules: 64, measuredModules: 1, complete: batchIndex === 63 });
        const result = await ok('overlay', reportBody(target, payload));
        assert.equal(result.status, batchIndex === 63 ? 'READY' : 'PARTIAL');
      }
      await ok('overlay', target.auth);
      await ok('overlay', { ...target.auth, action: 'close' });
      activate(candidate);
    });

    await check('Plugin installation has a fixed 120-second deadline that retries cannot renew', async () => {
      const target = await complete(), real = Date.now;
      try {
        const out = await manifest(target), firstDeadline = out.installExpiresAt;
        Date.now = () => firstDeadline - 1;
        assert.equal((await manifest(target)).installExpiresAt, firstDeadline);
        Date.now = () => firstDeadline + 1;
        await refused('overlay', { ...target.auth, action: 'plugin-manifest' });
        await refused('overlay', { ...target.auth, action: 'plugin-chunk', pluginId: candidate.id, offset: 0 });
        await refused('overlay', target.auth);
      } finally { Date.now = real; }
    });

    await check('Optional release signatures obey the existing O-domain trust and required-signature policy', () => {
      const key = signer(), version = '2.0.0', signedBytes = dllFixture([requiredExport], 'signed-plugin');
      authority.SetPolicy({ expectedRevision: authority.Policy().revision, trustedReleaseKeys: [{ keyId: key.keyId, publicKey: key.pem }] }, 'TEST');
      const before = structuredClone(authority.Policy());
      assert.deepEqual(plugins.Overview().approval, { required: false, component: 'O', trustedSignerKeyIds: [key.keyId] });
      assert.equal(plugins.Overview().fileName, 'GameOverlayPlugin.bin');
      reject('OVERLAY_PLUGIN_SIGNATURE_INVALID', () => plugins.Stage(version, signedBytes, approval(key, 'B', version, signedBytes), 'TEST'));
      reject('OVERLAY_PLUGIN_SIGNER_UNTRUSTED', () => plugins.Stage(version, signedBytes, { ...approval(key, 'O', version, signedBytes), keyId: '0'.repeat(64) }, 'TEST'));
      for (const malformed of [null, [], {}, { keyId: key.keyId }, { ...approval(key, 'O', version, signedBytes), extra: true }, { keyId: key.keyId.toUpperCase(), signature: approval(key, 'O', version, signedBytes).signature }, { keyId: key.keyId, signature: 'invalid' }]) {
        reject('OVERLAY_PLUGIN_APPROVAL_INVALID', () => plugins.Stage(version, signedBytes, malformed, 'TEST'));
      }
      const signed = plugins.Stage(version, signedBytes, approval(key, 'O', version, signedBytes), 'TEST');
      assert.ok(signed.id);
      assert.equal(signed.signatureValid, true);
      assert.deepEqual(authority.Policy(), before, 'Candidate upload never changes trust policy');
      for (const component of ['A', 'B']) {
        const native = fixture.PE(component, 'signed-host');
        boot.Publish(component, version, native, approval(key, component, version, native));
      }
      authority.SetPolicy({ expectedRevision: authority.Policy().revision, requireReleaseSignature: true }, 'TEST');
      reject('OVERLAY_PLUGIN_APPROVAL_REQUIRED', () => plugins.Stage('2.0.1', dllFixture([requiredExport], 'unsigned-denied'), undefined, 'TEST'));
      activate(signed);
      operations.SetSignerState({ expectedRevision: operations.Revision(), keyId: key.keyId, state: 'RETIRING' }, 'TEST');
      reject('SECURITY_SIGNER_NOT_ACTIVE', () => plugins.Stage(version, signedBytes, approval(key, 'O', version, signedBytes), 'TEST'));
      assert.equal(authority.Policy().requireReleaseSignature, true);
    });

    await check('Admin upload reports exact approval failures and keeps required signatures enabled through a valid O upload', async () => {
      const key = signer(), outsider = signer(), version = '2.1.0', signedBytes = dllFixture([requiredExport], 'http-signed-plugin');
      authority.SetPolicy({ expectedRevision: authority.Policy().revision, requireReleaseSignature: true, trustedReleaseKeys: [...authority.Policy().trustedReleaseKeys, { keyId: key.keyId, publicKey: key.pem }] }, 'TEST');
      const policyBefore = structuredClone(authority.Policy());
      const login = await adminRequest('/api/login', 'POST', JSON.stringify({ role: 'admin', password: process.env.ADMIN_SECRET }), { 'Content-Type': 'application/json', Origin: webBase });
      assert.equal(login.status, 200, JSON.stringify(login.json));
      const cookie = login.headers.get('set-cookie').split(';')[0];
      const owner = { Cookie: cookie, Origin: webBase, 'X-CSRF-Token': login.json.csrf };
      const route = '/api/desktop/bootstrap/overlay/plugins';
      const initial = await adminRequest(route, 'GET', undefined, { Cookie: cookie });
      assert.equal(initial.status, 200);
      assert.deepEqual(initial.json.approval, { required: true, component: 'O', trustedSignerKeyIds: policyBefore.trustedReleaseKeys.map(row => row.keyId) });
      const upload = (value, name = 'GameOverlayPlugin.bin', bytes = signedBytes, requestedVersion = version, metadata = {}) => adminRequest(route + '?version=' + requestedVersion + '&fileName=' + name, 'POST', bytes, { ...owner, 'Content-Type': 'application/octet-stream', ...(value ? { 'X-Game-Release-Key-Id': value.keyId, ...(value.signature === undefined ? {} : { 'X-Game-Release-Signature': value.signature }) } : {}), ...metadata });
      const valid = approval(key, 'O', version, signedBytes);
      for (const [expected, value, bytes, requestedVersion] of [
        ['OVERLAY_PLUGIN_APPROVAL_REQUIRED', undefined],
        ['OVERLAY_PLUGIN_APPROVAL_INVALID', { keyId: key.keyId }],
        ['OVERLAY_PLUGIN_APPROVAL_INVALID', { keyId: key.keyId, signature: 'malformed' }],
        ['OVERLAY_PLUGIN_SIGNER_UNTRUSTED', approval(outsider, 'O', version, signedBytes)],
        ['OVERLAY_PLUGIN_SIGNATURE_INVALID', approval(key, 'B', version, signedBytes)],
        ['OVERLAY_PLUGIN_SIGNATURE_INVALID', valid, signedBytes, '2.1.1'],
        ['OVERLAY_PLUGIN_SIGNATURE_INVALID', valid, dllFixture([requiredExport], 'different-content')]
      ]) {
        const result = await upload(value, 'GameOverlayPlugin.bin', bytes, requestedVersion);
        assert.ok(result.status >= 400 && result.status < 500, JSON.stringify(result));
        assert.equal(result.json.error, expected, JSON.stringify(result.json));
        assert.ok(result.json.problem, 'Admin receives the specific remediation');
        assert.deepEqual(authority.Policy(), policyBefore);
        assert.equal(plugins.Overview().revision, initial.json.revision, 'Rejected uploads cannot register a candidate');
        assert.equal(plugins.Overview().activeId, initial.json.activeId);
      }
      const metadata = { 'X-Game-Release-Component': 'O', 'X-Game-Release-Version': version, 'X-Game-Release-Sha256': sha(signedBytes) };
      for (const [expected, headers] of [
        ['OVERLAY_PLUGIN_APPROVAL_INVALID', { 'X-Game-Release-Component': 'O' }],
        ['OVERLAY_PLUGIN_APPROVAL_COMPONENT_MISMATCH', { ...metadata, 'X-Game-Release-Component': 'B' }],
        ['OVERLAY_PLUGIN_APPROVAL_VERSION_MISMATCH', { ...metadata, 'X-Game-Release-Version': '2.1.1' }],
        ['OVERLAY_PLUGIN_APPROVAL_HASH_MISMATCH', { ...metadata, 'X-Game-Release-Sha256': changed(metadata['X-Game-Release-Sha256']) }]
      ]) {
        const result = await upload(valid, 'GameOverlayPlugin.bin', signedBytes, version, headers);
        assert.ok(result.status >= 400 && result.status < 500, JSON.stringify(result));
        assert.equal(result.json.error, expected, JSON.stringify(result.json));
        assert.deepEqual(authority.Policy(), policyBefore);
        assert.equal(plugins.Overview().revision, initial.json.revision);
      }
      const staged = await upload(valid, 'GameOverlayPlugin.bin', signedBytes, version, metadata);
      assert.equal(staged.status, 200, JSON.stringify(staged.json));
      assert.equal(staged.json.artifact.fileName, 'GameOverlayPlugin.bin');
      assert.equal(staged.json.artifact.signatureValid, true);
      assert.equal(staged.json.artifact.sha256, sha(signedBytes));
      const sameBytesOtherName = await upload(valid, 'renamed-plugin.bin');
      assert.equal(sameBytesOtherName.status, 200, JSON.stringify(sameBytesOtherName.json));
      assert.equal(sameBytesOtherName.json.artifact.id, staged.json.artifact.id, 'Filename is not part of the release signature canonical string');
      assert.deepEqual(authority.Policy(), policyBefore);
      const selected = await adminRequest(route + '/activate', 'POST', JSON.stringify({ id: staged.json.artifact.id, expectedRevision: plugins.Overview().revision }), { ...owner, 'Content-Type': 'application/json' });
      assert.equal(selected.status, 200, JSON.stringify(selected.json));
      assert.equal(selected.json.ready, true);
      assert.equal(selected.json.approval.required, true);
      assert.equal((await adminRequest('/api/logout', 'POST', '{}', { ...owner, 'Content-Type': 'application/json' })).status, 200);
    });

    console.log('Desktop overlay plugin: ' + checks + ' publication and production-wire checks passed');
  } finally {
    if (webServer) { webServer.closeAllConnections(); await new Promise(resolve => webServer.close(resolve)); }
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(temp, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
