'use strict';
const assert = require('node:assert/strict'), crypto = require('node:crypto'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-deadline-'));
process.env.DATA_DIR = temp; process.env.STORAGE_ENGINE = 'json'; process.env.HA_ENABLED = '0';
require('../core/utils').EnsureDirs();
const deadlines = require('../services/desktopDeadline'), { performance } = require('node:perf_hooks');
const f = require('./desktop-bootstrap-fixture'), licenses = require('../services/desktopLicenses'), reports = require('../services/desktopIntegrityReports');
function Reject(fn, code) { assert.throws(fn, error => error.message === code, code); }
function CrossDeadline(fn, expiry, monotonic, code) {
  const now = Date.now, verify = crypto.verify, prior = Object.getOwnPropertyDescriptor(performance, 'now'), future = performance.now() + monotonic;
  try {
    crypto.verify = function(...args) {
      const ok = Reflect.apply(verify, this, args);
      Date.now = () => expiry; Object.defineProperty(performance, 'now', { configurable: true, value: () => future });
      return ok;
    };
    Reject(fn, code);
  } finally {
    crypto.verify = verify; Date.now = now;
    if (prior) Object.defineProperty(performance, 'now', prior); else delete performance.now;
  }
}
function LicenseProof(device, licenseKey) {
  const requestId = crypto.randomUUID(), payload = f.LicensePayload(device, { licenseKey }, requestId), payloadJSON = JSON.stringify(payload);
  const payloadHash = crypto.createHash('sha512').update(payloadJSON).digest('hex');
  const body = { action: 'redeem', requestId, deviceId: device.deviceId, publicKey: device.publicKey, payloadHash };
  const challenge = licenses.Challenge(body); f.ObserveLicense(device, 'redeem', requestId, payloadHash, payload);
  return { challenge, body: { ...body, challengeId: challenge.challengeId, payloadJSON, signature: f.Sign(device, challenge.canonical) } };
}
try {
  const edge = { expiresAt: 100, deadline: 200 };
  assert.equal(deadlines.Expired(edge, { wall: 99, tick: 199 }), false);
  assert.equal(deadlines.Expired(edge, { wall: 100, tick: 199 }), true);
  assert.equal(deadlines.Expired(edge, { wall: 1, tick: 200 }), true);
  for (const bad of [undefined, {}, { expiresAt: 100, deadline: NaN }, { expiresAt: Infinity, deadline: 200 }]) assert.equal(deadlines.Expired(bad), true);
  for (const invalid of [0, -1, NaN, Infinity, 1.5]) assert.throws(() => deadlines.After(invalid), /DESKTOP_DEADLINE_INVALID/);
  for (const kind of ['wall', 'monotonic']) {
    const device = f.Device(), issued = licenses.Create({ label: 'deadline-' + kind }, 'TEST');
    const proof = LicenseProof(device, issued.licenseKey), revision = licenses.DB().revision;
    CrossDeadline(() => licenses.Execute(proof.body), kind === 'wall' ? proof.challenge.expiresAt : Date.now() - 1000,
      kind === 'monotonic' ? licenses.CHALLENGE_MS + 1 : 0, 'DESKTOP_CHALLENGE_EXPIRED');
    assert.equal(licenses.DB().licenses[issued.license.id].consumed, false); assert.equal(licenses.DB().revision, revision);
  }
  // A slow downstream gate must not leave the nonce unchecked at consumption.
  const device = f.Device(), issued = licenses.Create({ label: 'gate-boundary' }, 'TEST'), proof = LicenseProof(device, issued.licenseKey);
  const bootstrap = require('../services/desktopBootstrap'), gate = bootstrap.Gate, now = Date.now;
  try {
    bootstrap.Gate = function(...args) { const row = Reflect.apply(gate, this, args); Date.now = () => proof.challenge.expiresAt; return row; };
    Reject(() => licenses.Execute(proof.body), 'DESKTOP_CHALLENGE_EXPIRED'); assert.equal(licenses.DB().licenses[issued.license.id].consumed, false);
  } finally { bootstrap.Gate = gate; Date.now = now; }
  for (const kind of ['wall', 'monotonic']) {
    const device = f.Device(), session = f.Session(device), auth = { sessionId: session.sessionId, sessionToken: session.sessionToken, ...f.Evidence(device, session) };
    const challenge = reports.Execute({ action: 'challenge', ...auth });
    const payload = JSON.stringify({ version: 1, hashVersion: 3, check: 'OVERLAY_START', reason: 'OVERLAY_LAUNCH_FAILED' });
    const body = { action: 'submit', ...auth, reportId: challenge.reportId, payload, signature: f.Sign(device, reports.Canonical(session.sessionId, challenge, payload)) };
    const before = reports.List().revision;
    CrossDeadline(() => reports.Execute(body), kind === 'wall' ? challenge.expiresAt : Date.now() - 1000,
      kind === 'monotonic' ? 30001 : 0, 'INTEGRITY_REPORT_CHALLENGE_INVALID');
    assert.equal(reports.List().revision, before);
    Reject(() => reports.Execute(body), 'INTEGRITY_REPORT_CHALLENGE_INVALID');
  }
  console.log('DEADLINES PASS: exact expiry, malformed bounds, real RSA verification crossing wall/monotonic deadlines, backward wall clock, gate crossing, no consumed license/report and no replay.');
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
