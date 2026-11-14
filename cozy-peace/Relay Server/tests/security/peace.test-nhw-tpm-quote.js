'use strict';

// Synthetic TPM transcripts execute production certificate/activation/quote
// cryptography. This is not Windows, a hardware TPM, or a boot-health result.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cozy-nhw-quote-'));
Object.assign(process.env, { DATA_DIR: temp, STORAGE_ENGINE: 'json', HA_ENABLED: '0' });
process.once('exit', () => fs.rmSync(temp, { recursive: true, force: true }));
const { Device, Sign } = require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');
const { quote, trust, evidence, activate } = require('../fixtures/devices/peace.synthetic-tpm')(temp);
const app = Device(), persistent = Device();
let epoch = 4;
let db = { secret: crypto.randomBytes(32).toString('hex'), revision: 0, flows: {}, overlays: {}, launchers: {} };
const row = { id: 'F'.repeat(24), sessionId: 'B'.repeat(24), machineId: 'A'.repeat(64),
  deviceId: app.deviceId, publicKey: app.publicKey, status: 'CLAIMED' };
db.flows[row.id] = row;
const store = { Load: () => db, AfterCommit: fn => fn() };
const binding = machine => crypto.createHmac('sha256', Buffer.from(db.secret, 'hex')).update(machine).digest('hex');
const identityPath = path.resolve(__dirname, '../../services/devices/peace.desktop-device-identity.js');
const identityModule = new Module(identityPath, module);
const nativeRequire = Module.createRequire(identityPath);
identityModule.filename = identityPath;
identityModule.paths = Module._nodeModulePaths(path.dirname(identityPath));
const findings = [];
const overrides = {
  '../bootstrap/peace.desktop-bootstrap-store': store,
  '../bootstrap/peace.desktop-bootstrap': { EnsureSecurityAvailable() {}, AuthenticateIntegrityReport(body) {
    if (body.stage !== 'B' || body.sessionId !== row.sessionId || body.sessionToken !== 'TOKEN' ||
        db.flows[row.id].status !== 'CLAIMED') throw Error('DEVICE_AUTH_INVALID');
    return { ...db.flows[row.id] };
  } },
  './peace.desktop-device-registry': { BindingId: binding, AssertMachineAllowed() {}, RetireSessions() {} },
  '../recovery/peace.desktop-recovery': { Epoch: () => epoch },
  '../security/peace.desktop-security-authority': { InvalidateAll() {} },
  '../security/peace.security-detections': { RecordServer: event => findings.push(event) },
  '../storage/peace.desktop-operation-audit': { Run(_k, _a, _d, fn) {
    const next = structuredClone(db), result = fn(next); db = next; return result;
  } },
};
identityModule.require = name => Object.hasOwn(overrides, name) ? overrides[name] : nativeRequire(name);
identityModule._compile(fs.readFileSync(identityPath, 'utf8'), identityPath);
const identity = identityModule.exports;
const quotePath = path.resolve(__dirname, '../../services/security/peace.nhw-tpm-quote.js');
const quoteModule = new Module(quotePath, module);
const quoteRequire = Module.createRequire(quotePath);
quoteModule.filename = quotePath;
quoteModule.paths = Module._nodeModulePaths(path.dirname(quotePath));
quoteModule.require = name => name === '../bootstrap/peace.desktop-bootstrap-store' ? store :
  name === '../devices/peace.desktop-device-identity' ? identity :
  name === '../recovery/peace.desktop-recovery' ? { Epoch: () => epoch } : quoteRequire(name);
quoteModule._compile(fs.readFileSync(quotePath, 'utf8'), quotePath);
const verifier = quoteModule.exports;
const auth = { stage: 'B', sessionId: row.sessionId, sessionToken: 'TOKEN', machineId: row.machineId };
let checks = 0;
function check(name, run) { run(); checks++; console.log('PASS ' + name); }
function rejects(run) { assert.throws(run, e => /^(SECURITY_NHW_QUOTE_|DEVICE_)/.test(e.message)); }
function flip(value, field, offset) {
  const raw = Buffer.from(value[field], 'base64'); raw[offset] ^= 1;
  return { ...value, [field]: raw.toString('base64') };
}
const frame = Buffer.alloc(179);
frame.write('NHWA'); frame.writeUInt16LE(1, 4); frame[6] = 2; frame.writeUInt32LE(167, 8);
crypto.randomBytes(48).copy(frame, 12);
const sample = quote(frame);
try {
  check('unavailable TPM remains UNKNOWN and makes no hardware claim', () => {
    assert.deepEqual(verifier.VerifySession(undefined, frame, row, 'B'),
      { status: 'UNAVAILABLE', scope: 'NONE', bootHealthVerified: false });
  });
  check('uploaded quote key is never self-enrolled', () => rejects(() => verifier.VerifySession(sample, frame, row, 'B')));
  identity.AdminPolicy({ expectedRevision: 0, requestId: crypto.randomUUID(), mode: 'TPM_ATTESTED',
    requireForEnrolled: true, trust }, 'ADMIN');
  const challenge = identity.Handle({ ...auth, action: 'challenge', requestId: crypto.randomUUID(),
    publicKey: persistent.publicKey, keyProvider: 'PLATFORM' });
  const activation = identity.Handle({ ...auth, action: 'complete', challengeId: challenge.challengeId,
    signature: Sign(persistent, challenge.canonical), appSignature: Sign(app, challenge.canonical),
    tpmEvidence: evidence(persistent.publicKey, Buffer.from(challenge.nonce, 'base64')) });
  check('Certify without ActivateCredential cannot authorize a quote', () => {
    assert.equal(activation.status, 'TPM_ACTIVATION_REQUIRED');
    assert.equal(db.flows[row.id].deviceIdentityProofs, undefined);
    rejects(() => verifier.VerifySession(sample, frame, row, 'B'));
  });
  const secret = activate(activation);
  try {
    const response = identity.Handle({ ...auth, action: 'tpmActivate', challengeId: challenge.challengeId,
      secret: secret.toString('base64'), signature: Sign(persistent, activation.activationCanonical),
      appSignature: Sign(app, activation.activationCanonical) });
    assert.equal(response.assurance, 'TPM_KEY_ATTESTED');
  } finally { secret.fill(0); }
  const proof = () => db.flows[row.id].deviceIdentityProofs.B;
  const anchor = () => ({ akPublic: proof().nhwAkPublic, akQualifiedName: proof().nhwAkQualifiedName });
  check('activated exact AK verifies PCR0..7 and the complete NHW evidence transcript', () => {
    const value = verifier.VerifySession(sample, frame, row, 'B');
    assert.equal(value.status, 'VERIFIED'); assert.equal(value.scope, 'TPM_QUOTE_ONLY');
    assert.equal(value.bootHealthVerified, false); assert.deepEqual(value.pcrs, [0, 1, 2, 3, 4, 5, 6, 7]);
  });
  check('signed safe=0 is UNKNOWN clock continuity, never an attack', () => {
    const value=verifier.VerifySession(quote(frame,crypto.randomBytes(256),0),frame,row,'B');
    assert.equal(value.status,'UNKNOWN');assert.equal(value.reason,'TPM_CLOCK_UNSAFE');
    assert.equal(value.clockSafe,false);assert.equal(value.bootHealthVerified,false);
    rejects(()=>verifier.Verify(quote(frame,crypto.randomBytes(256),2),frame,anchor()));
  });
  check('every altered NHW nonce/epoch/evidence byte invalidates qualifyingData', () => {
    for (let i = 0; i < frame.length; i++) {
      const other = Buffer.from(frame); other[i] ^= 1;
      rejects(() => verifier.Verify(sample, other, anchor()));
    }
  });
  check('PCR, signature, signer, quote type, clock and selection substitutions reject', () => {
    for (const [field, offset] of [['pcrs', 0], ['signature', 261], ['attest', 4],
      ['attest', 8], ['attest', 92], ['attest', 106], ['attest', 110], ['attest', 114]])
      rejects(() => verifier.Verify(flip(sample, field, offset), frame, anchor()));
  });
  check('all quote truncations and trailing bytes fail strict TPM parsers', () => {
    for (const field of ['attest', 'signature', 'pcrs']) {
      const raw = Buffer.from(sample[field], 'base64');
      for (let i = 0; i < raw.length; i++)
        rejects(() => verifier.Verify({ ...sample, [field]: raw.subarray(0, i).toString('base64') }, frame, anchor()));
      rejects(() => verifier.Verify({ ...sample, [field]: Buffer.concat([raw, Buffer.alloc(1)]).toString('base64') }, frame, anchor()));
    }
    rejects(() => verifier.Verify({ ...sample, unknown: true }, frame, anchor()));
    rejects(() => verifier.Verify({ ...sample, signature: sample.signature + '\n' }, frame, anchor()));
  });
  check('different session, stage or app key cannot reuse enrolled quote authority', () => {
    rejects(() => verifier.VerifySession(sample, frame, { ...row, id: 'C'.repeat(24) }, 'B'));
    rejects(() => verifier.VerifySession(sample, frame, row, 'O'));
    rejects(() => verifier.VerifySession(sample, frame, { ...row, deviceId: Device().deviceId }, 'B'));
  });
  check('policy and recovery epochs fence retained quote keys', () => {
    epoch++; rejects(() => verifier.VerifySession(sample, frame, row, 'B')); epoch--;
    identity.State().revision++; rejects(() => verifier.VerifySession(sample, frame, row, 'B')); identity.State().revision--;
  });
  check('expiry and revoked EK leaf/root invalidate quote provenance', () => {
    const until = proof().nhwAttestedUntil;
    proof().nhwAttestedUntil = Date.now() - 1;
    rejects(() => verifier.VerifySession(sample, frame, row, 'B')); proof().nhwAttestedUntil = until;
    for (const value of [proof().nhwEkLeafSha256, proof().nhwEkRootSha256]) {
      identity.State().trust.revokedCertificateSha256 = [value];
      rejects(() => verifier.VerifySession(sample, frame, row, 'B'));
    }
    identity.State().trust.revokedCertificateSha256 = [];
    const enrollment = identity.State().enrollments[proof().enrollmentId];
    enrollment.status = 'REVOKED'; rejects(() => verifier.VerifySession(sample, frame, row, 'B'));
  });
  check('isolated identity denials retain unconfirmed causes without creating real authority storage', () => {
    assert.ok(findings.length > 0);
    for (const finding of findings) {
      assert.equal(finding.source, 'peace.desktop-device-identity');
      assert.equal(finding.confidence, 0); assert.equal(finding.correlation, false);
    }
    assert.equal(fs.existsSync(path.join(temp, 'desktop-bootstrap', 'authority.json')), false);
  });
  console.log('NHW TPM QUOTE PASS ' + checks + ' groups; synthetic cryptography, Windows/TPM hardware NOT RUN');
} finally {
  identity.ClearChallenges();
  fs.rmSync(temp, { recursive: true, force: true });
}
