'use strict';
// Real loopback TLS, encrypted dispatch, proof workers and durable stores.
// Synthetic PE fixtures are never executed. No client-side guard is invoked.
// A reported file hash is not hardware attestation; an unused A is a bearer
// invitation. These tests assert server authority, not universal patch detection.
const test = require('node:test'), assert = require('node:assert/strict');
const crypto = require('node:crypto'), fs = require('node:fs'), os = require('node:os');
const path = require('node:path'), tls = require('node:tls');

test('server authorization bypass matrix over real encrypted TLS', {timeout: 90000}, async t => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cozy-authority-bypass-'));
  const originalLog = console.log, originalNow = Date.now;
  // Production event logging still writes to the isolated audit store. Never
  // print synthetic invitation/session/license capabilities in test output.
  console.log = (...args) => { if (!String(args[0]).startsWith('[EVENT]')) originalLog(...args); };
  Object.assign(process.env, {DATA_DIR: temp, STORAGE_ENGINE: 'sqlite', HA_ENABLED: '0', DESKTOP_PUBLIC_HOST: '127.0.0.1'});
  let server, transport, queues, profile, boot, licenses, authority, fixture, executionFailure;
  const clients = new Set();
  const same = (a, b, label) => assert.ok(JSON.stringify(a) === JSON.stringify(b), label);
  const sha = bytes => crypto.createHash('sha512').update(bytes).digest('hex');
  function State() {
    const db = boot.Initialize(), fields = (row, keys) => Object.fromEntries(keys.map(k => [k, row[k] ?? null]));
    return {
      launchers: Object.values(db.launchers).map(r => fields(r, ['id', 'status', 'flowId'])),
      flows: Object.values(db.flows).map(r => fields(r, ['id', 'status', 'deviceId', 'machineId', 'claimedAt', 'sessionExpiresAt', 'lastVerifiedAt', 'licenseId'])),
      licenses: Object.values(licenses.DB().licenses).map(r => fields(r, ['id', 'status', 'consumed', 'deviceId', 'bootstrapSessionId', 'activatedAt', 'expiresAt', 'releasedAt'])),
      overlays: Object.keys(db.overlays || {})
    };
  }
  async function Wire(wire) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({host: '127.0.0.1', port: profile.port, servername: profile.tlsServerName,
        rejectUnauthorized: false, minVersion: 'TLSv1.2'});
      clients.add(socket); let received = '', failure;
      socket.setTimeout(5000, () => { failure = Error('BYPASS_TEST_TIMEOUT'); socket.destroy(); });
      socket.once('secureConnect', () => {
        const cert = socket.getPeerCertificate();
        if (!cert.raw || fixture.sha256(cert.raw) !== profile.tlsCertificateSha256 ||
            tls.checkServerIdentity(profile.tlsServerName, cert) ||
            originalNow() < Date.parse(cert.valid_from) || originalNow() >= Date.parse(cert.valid_to)) {
          failure = Error('BYPASS_TEST_TLS_IDENTITY'); socket.destroy(); return;
        }
        socket.write(wire);
      });
      socket.on('data', bytes => {
        received += bytes.toString('utf8');
        if (received.length > 1024 * 1024) { failure = Error('BYPASS_TEST_RESPONSE_LIMIT'); socket.destroy(); }
      });
      socket.once('error', () => { failure = Error('BYPASS_TEST_CONNECTION_FAILED'); });
      socket.once('close', () => { clients.delete(socket); if (failure) reject(failure); else resolve(received); });
    });
  }
  async function Round(operation, body) {
    const key = crypto.randomBytes(32), nonce = crypto.randomBytes(12), requestId = crypto.randomUUID();
    const clear = Buffer.from(JSON.stringify({operation, body})); let decoded;
    try {
      const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
      cipher.setAAD(transport.Aad('REQUEST', requestId, profile.serverKeyId));
      const frame = {v: 1, keyId: profile.serverKeyId, requestId,
        wrappedKey: crypto.publicEncrypt({key: licenses.ParseKey(profile.serverPublicKey).key,
          oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING}, key).toString('base64'),
        nonce: nonce.toString('base64'), ciphertext: Buffer.concat([cipher.update(clear), cipher.final()]).toString('base64'),
        tag: cipher.getAuthTag().toString('base64')};
      const wire = JSON.stringify(frame) + '\n', raw = await Wire(wire);
      assert.ok(raw.length > 0, 'authenticated request must receive an encrypted result');
      const reply = JSON.parse(raw);
      assert.equal(reply.requestId, requestId); assert.notEqual(reply.nonce, frame.nonce);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(reply.nonce, 'base64'));
      decipher.setAAD(transport.Aad('RESPONSE', requestId, profile.serverKeyId));
      decipher.setAuthTag(Buffer.from(reply.tag, 'base64'));
      decoded = Buffer.concat([decipher.update(Buffer.from(reply.ciphertext, 'base64')), decipher.final()]);
      return {result: JSON.parse(decoded.toString('utf8')), wire};
    } finally { key.fill(0); nonce.fill(0); clear.fill(0); decoded?.fill(0); }
  }
  async function Ok(operation, body) {
    const {result} = await Round(operation, body);
    assert.equal(result.ok, true, 'expected success; error=' + (result.error || 'none'));
    return result.data;
  }
  async function Denied(operation, body, codes, {unchanged = true, revokedFlow = ''} = {}) {
    const before = State(), {result} = await Round(operation, body);
    assert.equal(result.ok, false, 'unauthorized request unexpectedly succeeded');
    assert.ok(codes.includes(result.error), 'unexpected denial code: ' + result.error);
    if (unchanged) {
      const after = State(), changed = [];
      if (revokedFlow) {
        const prior = before.flows.find(row => row.id === revokedFlow);
        const current = after.flows.find(row => row.id === revokedFlow);
        assert.equal(prior?.status, 'CLAIMED'); assert.equal(current?.status, 'REVOKED');
        // A server-side revocation is an expected reduction of authority.
        // All other grants, license fields and lease bounds must remain exact.
        prior.status = 'REVOKED';
      }
      for (const group of Object.keys(before)) for (let i = 0; i < Math.max(before[group].length, after[group].length); i++) {
        const a = before[group][i], b = after[group][i];
        if (!a || !b) { changed.push(group + '.count'); continue; }
        for (const field of Object.keys(a)) if (a[field] !== b[field]) changed.push(group + '.' + field);
      }
      same(after, before, 'denial must not advance grants; changed fields=' + [...new Set(changed)].join(','));
    }
    return result;
  }
  function Invitation(device) {
    const issued = boot.IssueLauncher({requestId: crypto.randomUUID()}, 'BYPASS_TEST');
    const bytes = boot.LauncherBytes(issued.launcherId), settings = fixture.Config(bytes), code = fixture.CodeImage(bytes);
    const body = {action: 'begin', requestId: crypto.randomUUID(), launcherId: issued.launcherId,
      launcherTicket: settings.launcherTicket, launcherSha512: sha(bytes), launcherCrc64: fixture.Crc64(bytes),
      aCodeSha512: code.sha512, aCodeCrc64: code.crc64, machineId: device.machineId,
      publicKey: device.publicKey, deviceId: device.deviceId};
    bytes.fill(0); return {issued, body};
  }
  function Context(device, session, intent, binding) {
    return {stage: 'B', sessionId: session.sessionId, sessionToken: session.sessionToken,
      machineId: device.machineId, intent, binding};
  }
  async function Measurement(device, context, patch = {}, signer = device) {
    const baseline = boot.AuthenticateIntegrityReport(context).integrityArtifact;
    const challenge = await Ok('security', {...context, action: 'challenge'});
    const payload = JSON.stringify({version: 1, hashVersion: 3, measurement: 'MEASURED',
      fileSha512: baseline.sha512, fileCrc64: baseline.crc64, codeSha512: baseline.codeSha512,
      codeCrc64: baseline.codeCrc64, codeXxh3_128: baseline.codeXxh3_128, codeBlake3: baseline.codeBlake3,
      crcLayers: baseline.crcLayers, apiSealed: true, apiSlots: 60, dynamicCode: 'ALLOWED', cfg: 'DISABLED', ...patch});
    return {...context, action: 'submit', challengeId: challenge.challengeId, payload,
      signature: fixture.Sign(signer, authority.Canonical(context, challenge, payload))};
  }
  async function Session(device) {
    const invitation = Invitation(device), begin = await Ok('bootstrap', invitation.body);
    await Ok('bootstrap', {action: 'chunk', flowId: begin.flowId, downloadTicket: begin.downloadTicket, offset: 0});
    const context = {stage: 'A', sessionId: begin.flowId, sessionToken: begin.downloadTicket,
      machineId: device.machineId, intent: 'finish', binding: authority.Binding(begin.flowId, begin.release.sha512)};
    const observation = await Ok('security', await Measurement(device, context));
    assert.equal(observation.proceed, true); assert.equal(observation.attested, false);
    const finish = await Ok('bootstrap', {action: 'finish', flowId: begin.flowId, downloadTicket: begin.downloadTicket,
      sha512: begin.release.sha512, crc64: begin.release.crc64, aCodeSha512: begin.finishCanonical.split('\n')[5],
      aCodeCrc64: begin.finishCanonical.split('\n')[6], signature: fixture.Sign(device, begin.finishCanonical)});
    return Ok('bootstrap', {action: 'claim', flowId: begin.flowId, handoffToken: finish.handoffToken,
      signature: fixture.Sign(device, finish.claimCanonical), binarySha512: begin.release.sha512,
      crc64: begin.release.crc64, bCodeSha512: begin.release.codeSha512, bCodeCrc64: begin.release.codeCrc64});
  }
  async function LicenseProof(device, session, action, extra, {observe = true, requestId = crypto.randomUUID()} = {}) {
    const payloadJSON = JSON.stringify({...fixture.Evidence(device, session), bootstrapSessionId: session.sessionId,
      bootstrapSessionToken: session.sessionToken, ...extra});
    const base = {action, requestId, deviceId: device.deviceId, publicKey: device.publicKey, payloadHash: sha(payloadJSON)};
    const challenge = await Ok('challenge', base);
    if (observe) {
      const context = Context(device, session, action === 'overlay' ? 'verify' : action, authority.Binding(requestId, base.payloadHash));
      const out = await Ok('security', await Measurement(device, context)); assert.equal(out.proceed, true);
    }
    return {...base, challengeId: challenge.challengeId, payloadJSON, signature: fixture.Sign(device, challenge.canonical)};
  }
  try {
    require('../../core/peace.utilities').EnsureDirs();
    transport = require('../../services/network/peace.desktop-connect');
    queues = require('../../services/runtime/peace.desktop-work-queue');
    boot = require('../../services/bootstrap/peace.desktop-bootstrap');
    licenses = require('../../services/licensing/peace.desktop-licenses');
    authority = require('../../services/security/peace.desktop-security-authority');
    fixture = require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');
    server = transport.CreateServer();
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    process.env.DESKTOP_PUBLIC_PORT = String(server.address().port);
    profile = require('../../services/network/peace.connect-transport-key').Profile();
    fixture.Publish();

    await t.test('changed A digests and wrong device binding cannot consume an invitation', async () => {
      const device = fixture.Device(), other = fixture.Device(), invitation = Invitation(device);
      for (const patch of [{launcherSha512: '0'.repeat(128)}, {aCodeSha512: '0'.repeat(128)},
        {launcherTicket: 'invalid'}, {deviceId: other.deviceId}]) {
        await Denied('bootstrap', {...invitation.body, ...patch},
          ['BOOTSTRAP_HASH_MISMATCH', 'BOOTSTRAP_CODE_MISMATCH', 'BOOTSTRAP_LAUNCHER_INVALID', 'BOOTSTRAP_PROOF_INVALID']);
      }
      await Ok('bootstrap', invitation.body);
      await Denied('bootstrap', {...invitation.body, requestId: crypto.randomUUID(),
        publicKey: other.publicKey, deviceId: other.deviceId, machineId: other.machineId}, ['BOOTSTRAP_LAUNCHER_USED']);
    });
    await t.test('skipping the client measurement exchange cannot finish A or redeem a license', async () => {
      const device = fixture.Device(), invitation = Invitation(device), begin = await Ok('bootstrap', invitation.body);
      await Ok('bootstrap', {action: 'chunk', flowId: begin.flowId, downloadTicket: begin.downloadTicket, offset: 0});
      await Denied('bootstrap', {action: 'finish', flowId: begin.flowId, downloadTicket: begin.downloadTicket,
        sha512: begin.release.sha512, crc64: begin.release.crc64, aCodeSha512: begin.finishCanonical.split('\n')[5],
        aCodeCrc64: begin.finishCanonical.split('\n')[6], signature: fixture.Sign(device, begin.finishCanonical)}, ['SECURITY_FRESH_OBSERVATION_REQUIRED']);
      const session = await Session(device), issued = licenses.Create({requestId: crypto.randomUUID()}, 'BYPASS_TEST');
      const proof = await LicenseProof(device, session, 'redeem', {licenseKey: issued.licenseKey}, {observe: false});
      await Denied('execute', proof, ['SECURITY_FRESH_OBSERVATION_REQUIRED']);
      assert.equal(licenses.Detail(issued.license.id).license.consumed, false);
    });
    await t.test('signed wrong B file or code measurements cannot redeem a license', async () => {
      for (const field of ['binarySha512', 'codeSha512']) {
        const device = fixture.Device(), session = await Session(device);
        const issued = licenses.Create({requestId: crypto.randomUUID()}, 'BYPASS_TEST');
        const proof = await LicenseProof(device, session, 'redeem', {licenseKey: issued.licenseKey, [field]: '0'.repeat(128)});
        const row = Object.values(boot.Initialize().flows).find(r => r.sessionId === session.sessionId);
        await Denied('execute', proof, [field === 'codeSha512' ? 'BOOTSTRAP_CODE_MISMATCH' : 'BOOTSTRAP_HASH_MISMATCH'],
          {revokedFlow: field === 'codeSha512' ? row.id : ''});
        assert.equal(licenses.Detail(issued.license.id).license.consumed, false);
      }
    });
    await t.test('wrong stage, machine and signature cannot mint authority decisions', async () => {
      const device = fixture.Device(), other = fixture.Device(), session = await Session(device);
      const context = Context(device, session, 'verify', sha('role-bound-operation'));
      await Denied('security', {...context, action: 'challenge', stage: 'O'}, ['BOOTSTRAP_SESSION_INVALID']);
      await Denied('security', {...context, action: 'challenge', machineId: other.machineId}, ['BOOTSTRAP_SESSION_INVALID']);
      const wrongSigner = await Measurement(device, context, {}, other), count = authority.List().decisionCount;
      await Denied('security', wrongSigner, ['SECURITY_SIGNATURE_INVALID']);
      assert.equal(authority.List().decisionCount, count);
      const proof = await Measurement(device, context);
      await Denied('security', {...proof, binding: sha('different operation')}, ['SECURITY_CHALLENGE_INVALID']);
      assert.equal(authority.List().decisionCount, count);
      const accepted = await Ok('security', proof); assert.equal(accepted.proceed, true); assert.equal(accepted.attested, false);
    });
    await t.test('inner receipt retries do not renew authority and outer frame replay is rejected', async () => {
      const device = fixture.Device(), session = await Session(device), context = Context(device, session, 'verify', sha('exact-retry'));
      const proof = await Measurement(device, context), accepted = await Round('security', proof), before = State();
      const decisions = authority.List().decisionCount, replay = await Ok('security', proof);
      same(replay, accepted.result.data, 'inner retry must return the original bounded receipt');
      same(State(), before, 'retry must not renew a session or authorize a new operation');
      assert.equal(authority.List().decisionCount, decisions);
      await Denied('security', {...proof, payload: proof.payload + ' '}, ['SECURITY_REQUEST_REUSED']);
      assert.equal(await Wire(accepted.wire), '', 'outer replay must receive no authenticated success');
      same(State(), before, 'outer replay must not advance authority');
    });
    await t.test('changed signed license payload and another device cannot consume a license', async () => {
      const device = fixture.Device(), other = fixture.Device(), session = await Session(device);
      const first = licenses.Create({requestId: crypto.randomUUID()}, 'BYPASS_TEST');
      const second = licenses.Create({requestId: crypto.randomUUID()}, 'BYPASS_TEST');
      const proof = await LicenseProof(device, session, 'redeem', {licenseKey: first.licenseKey});
      const changed = JSON.stringify({...JSON.parse(proof.payloadJSON), licenseKey: second.licenseKey});
      await Denied('execute', {...proof, payloadJSON: changed}, ['DESKTOP_PROOF_INVALID']);
      await Denied('execute', {...proof, deviceId: other.deviceId, publicKey: other.publicKey}, ['DESKTOP_PROOF_INVALID']);
      const valid = await Ok('execute', proof); assert.equal(valid.status, 'USED');
      assert.equal(licenses.Detail(second.license.id).license.consumed, false);
    });
    await t.test('revocation wins over previously signed valid requests and cached authority', async () => {
      const device = fixture.Device(), session = await Session(device), issued = licenses.Create({requestId: crypto.randomUUID()}, 'BYPASS_TEST');
      const redeem = await LicenseProof(device, session, 'redeem', {licenseKey: issued.licenseKey});
      const active = await Ok('execute', redeem);
      const verify = await LicenseProof(device, session, 'verify', {activationToken: active.activationToken});
      licenses.Revoke(issued.license.id, {requestId: crypto.randomUUID(), reason: 'Authorization regression'}, 'BYPASS_TEST');
      await Denied('execute', verify, ['DESKTOP_REVOKED']);
      const other = fixture.Device(), otherSession = await Session(other);
      const context = Context(other, otherSession, 'verify', sha('revoked-session'));
      const submit = await Measurement(other, context); await Ok('security', submit);
      boot.Revoke(otherSession.sessionId, {reason: 'Authorization regression'}, 'BYPASS_TEST');
      await Denied('security', submit, ['BOOTSTRAP_REVOKED', 'BOOTSTRAP_SESSION_INVALID']);
    });
    await t.test('expired challenges, sessions and invitations cannot regain authority', async () => {
      const device = fixture.Device(), session = await Session(device), context = Context(device, session, 'verify', sha('expired-challenge'));
      const submit = await Measurement(device, context), at = originalNow();
      try {
        Date.now = () => at + authority.Policy().challengeMs + 1;
        await Denied('security', submit, ['SECURITY_CHALLENGE_INVALID']);
      } finally { Date.now = originalNow; }
      try {
        Date.now = () => session.expiresAt + 1;
        await Denied('security', {...context, action: 'challenge'}, ['BOOTSTRAP_EXPIRED', 'BOOTSTRAP_SESSION_INVALID'], {unchanged: false});
        const row = Object.values(boot.Initialize().flows).find(r => r.sessionId === session.sessionId);
        assert.equal(row.status, 'EXPIRED'); assert.ok(row.sessionExpiresAt <= session.expiresAt);
      } finally { Date.now = originalNow; }
      await Denied('security', {...context, action: 'challenge'}, ['BOOTSTRAP_EXPIRED', 'BOOTSTRAP_SESSION_INVALID']);
      const invitation = Invitation(fixture.Device());
      try {
        Date.now = () => invitation.issued.expiresAt + 1;
        await Denied('bootstrap', invitation.body, ['BOOTSTRAP_EXPIRED', 'BOOTSTRAP_LAUNCHER_INVALID'], {unchanged: false});
        assert.equal(boot.Initialize().launchers[invitation.issued.launcherId].status, 'EXPIRED');
      } finally { Date.now = originalNow; }
      await Denied('bootstrap', invitation.body, ['BOOTSTRAP_EXPIRED', 'BOOTSTRAP_LAUNCHER_INVALID']);
    });
  } catch (error) {
    executionFailure = error;
  } finally {
    // Attempt every owned cleanup even if an earlier close rejects. Keep
    // cleanup diagnostics to fixed labels, never raw capability-bearing errors.
    const cleanupFailures = [];
    const cleanup = async (label, fn) => {
      try { await fn(); } catch (_) { cleanupFailures.push(label); }
    };
    Date.now = originalNow;
    await Promise.all(Array.from(clients, client => cleanup('CLIENT_SOCKET', () => client.destroy())));
    await cleanup('TRANSPORT', () => transport?.Stop());
    await cleanup('LISTENER', () => server?.listening ? new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())) : undefined);
    if (queues) await Promise.all(['auth', 'pe', 'proof', 'renewalProof', 'tpmAttestation'].map(name => cleanup('QUEUE_' + name, () => queues[name].close())));
    await cleanup('BOOTSTRAP', () => boot?.Stop());
    await cleanup('METRICS', () => require.cache[require.resolve('../../services/observability/peace.desktop-performance-metrics')]?.exports.Close());
    await cleanup('SQLITE', () => require.cache[require.resolve('../../storage/sqlite/peace.sqlite-database')]?.exports.Close());
    await cleanup('TEMP_DATA', () => fs.rmSync(temp, {recursive: true, force: true}));
    console.log = originalLog;
    await cleanup('SOCKET_CHECK', () => assert.equal(clients.size, 0, 'test sockets must be closed'));
    await cleanup('TEMP_CHECK', () => assert.equal(fs.existsSync(temp), false, 'synthetic credentials and data must be removed'));
    if (cleanupFailures.length) {
      const cleanupFailure = Error('BYPASS_TEST_CLEANUP_FAILED: ' + cleanupFailures.join(','));
      if (executionFailure) throw new AggregateError([executionFailure, cleanupFailure], 'BYPASS_TEST_EXECUTION_AND_CLEANUP_FAILED');
      throw cleanupFailure;
    }
  }
  if (executionFailure) throw executionFailure;
});
