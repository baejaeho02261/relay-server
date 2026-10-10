'use strict';
const assert = require('node:assert/strict'), crypto = require('node:crypto'), fs = require('node:fs'), os = require('node:os'), path = require('node:path'), cp = require('node:child_process');
if (['seed', 'recover', 'load-failure'].includes(process.argv[2])) {
  process.env.STORAGE_ENGINE ||= 'json'; process.env.HA_ENABLED = '0';
  require('../services/desktopSingleWriter').Acquire(process.env.DATA_DIR);
  require('../core/utils').EnsureDirs();
  const licenses = require('../services/desktopLicenses'), boot = require('../services/desktopBootstrap');
  if (process.argv[2] === 'load-failure') {
    const auditDir = path.join(process.env.DATA_DIR, 'audit');
    const before = fs.readdirSync(auditDir).map(name => [name, fs.readFileSync(path.join(auditDir, name))]);
    fs.writeFileSync(path.join(process.env.DATA_DIR, 'relay.db'), 'invalid SQLite database');
    assert.throws(() => require('../storage/database').LoadDatabase());
    for (const [name, bytes] of before) assert.deepEqual(fs.readFileSync(path.join(auditDir, name)), bytes, 'failed snapshot load must preserve audit bytes');
    console.log('FAILURE_AUDIT_PRESERVED'); process.exit(0);
  }
  if (process.argv[2] === 'recover') {
    require('../storage/database').LoadDatabase();
    require('../storage/audit').LoadRecentAudit();
    const expected = JSON.parse(Buffer.from(process.argv[3], 'base64url').toString('utf8'));
    assert.equal(licenses.DB().licenses[expected.licenseId].consumed, true);
    const report = licenses.ReconcileOperations(); assert.equal(report.reconciled, 1);
    const flow = boot.Initialize().flows[expected.flowId];
    assert.equal(flow.licenseId, expected.licenseId); assert.equal(flow.lastLicenseOperationId, expected.operationId);
    assert.equal(flow.lastLicenseOperationRevision, expected.operationRevision);
    assert.equal(flow.sessionExpiresAt, expected.sessionExpiresAt, 'recovery must never extend session authority');
    assert.equal(flow.lastVerifiedAt, expected.lastVerifiedAt, 'recovery is not a new verification');
    assert.equal(flow.status, expected.status);
    if (expected.status === 'CLOSED') { assert.equal(flow.closedByLicenseRelease, true); assert.equal(flow.sessionNonce, undefined); }
    const revision = boot.Initialize().revision; assert.equal(licenses.ReconcileOperations().reconciled, 0); assert.equal(boot.Initialize().revision, revision);
    assert.equal(licenses.DB().licenses[expected.licenseId].consumed, true);
    assert.equal(require('../storage/audit').VerifyAuditChain().ok, true, 'reconciliation must append to the restored audit head');
    console.log('RECOVERY_OK'); process.exit(0);
  }
  const f = require('./desktop-bootstrap-fixture'), device = f.Device(), issued = licenses.Create({ label: 'abrupt-recovery' }, 'TEST');
  function Proof(action, extra) {
    const requestId = crypto.randomUUID(), payload = f.LicensePayload(device, extra, requestId), payloadJSON = JSON.stringify(payload);
    const payloadHash = crypto.createHash('sha512').update(payloadJSON).digest('hex');
    const base = { action, requestId, deviceId: device.deviceId, publicKey: device.publicKey, payloadHash }, challenge = licenses.Challenge(base);
    f.ObserveLicense(device, action, requestId, payloadHash, payload);
    return { ...base, payloadJSON, challengeId: challenge.challengeId, signature: f.Sign(device, challenge.canonical) };
  }
  const mode = process.argv[3]; let proof;
  if (mode === 'release') {
    const result = licenses.Execute(Proof('redeem', { licenseKey: issued.licenseKey }));
    proof = Proof('release', { activationToken: result.activationToken });
  } else proof = Proof('redeem', { licenseKey: issued.licenseKey });
  if (mode === 'retry') {
    const touch = boot.TouchLicense; boot.TouchLicense = () => { throw Error('TEST_PROJECTION_WRITE_FAILED'); };
    assert.throws(() => licenses.Execute(proof), /TEST_PROJECTION_WRITE_FAILED/); boot.TouchLicense = touch;
    const revision = licenses.DB().revision, operation = structuredClone(licenses.DB().receipts[device.deviceId + ':' + proof.requestId]);
    const recovered = licenses.Execute(proof); assert.equal(recovered.status, 'USED'); assert.equal(licenses.DB().revision, revision+1, 'only the durable audit ACK commits during recovery');
    assert.deepEqual(licenses.DB().receipts[device.deviceId + ':' + proof.requestId], operation);
    assert.equal(boot.LicenseActivity(issued.license.id).sessionId, licenses.DB().licenses[issued.license.id].bootstrapSessionId);
    console.log('RETRY_OK'); process.exit(0);
  }
  boot.TouchLicense = function() {
    const license = licenses.DB().licenses[issued.license.id], receiptKey = device.deviceId + ':' + proof.requestId, receipt = licenses.DB().receipts[receiptKey];
    let flow = Object.values(boot.Initialize().flows).find(row => row.sessionId === license.bootstrapSessionId);
    const expectedOperation = crypto.createHash('sha256').update('GAME-LICENSE-OP-V1\n' + receiptKey + '\n' + receipt.fingerprint).digest('hex');
    assert.equal(receipt.operationId, expectedOperation); assert.equal(receipt.operationRevision, licenses.DB().revision);
    if (mode === 'terminal') {
      require('../services/desktopBootstrapStore').Atomic(db => { const row = db.flows[flow.id]; row.status = 'EXPIRED'; boot.RetireFlow(row); });
      flow = boot.Initialize().flows[flow.id];
    }
    fs.writeSync(1, '\nEXPECT ' + Buffer.from(JSON.stringify({ licenseId: license.id, flowId: flow.id, operationId: receipt.operationId,
      operationRevision: receipt.operationRevision, sessionExpiresAt: flow.sessionExpiresAt, lastVerifiedAt: flow.lastVerifiedAt,
      status: mode === 'release' ? 'CLOSED' : mode === 'terminal' ? 'EXPIRED' : 'CLAIMED' })).toString('base64url') + '\n');
    // Deliberately stop after the durable license journal and before projection.
    process.exit(91);
  };
  licenses.Execute(proof); throw Error('TEST_DID_NOT_REACH_COMMIT_BOUNDARY');
}
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-license-recovery-'));
try {
  for (const engine of ['json', 'sqlite']) for (const mode of ['redeem', 'release', 'terminal', 'retry']) {
    const data = path.join(temp, engine + '-' + mode), env = { ...process.env, DATA_DIR: data, HA_ENABLED: '0', STORAGE_ENGINE: engine };
    const seed = cp.spawnSync(process.execPath, [__filename, 'seed', mode], { env, encoding: 'utf8', timeout: 15000 });
    if (mode === 'retry') { assert.equal(seed.status, 0, seed.stderr + seed.stdout); assert.match(seed.stdout, /RETRY_OK/); continue; }
    assert.equal(seed.status, 91, seed.stderr + seed.stdout);
    const match = seed.stdout.match(/^EXPECT ([A-Za-z0-9_-]+)$/m); assert.ok(match);
    const recovered = cp.spawnSync(process.execPath, [__filename, 'recover', match[1]], { env, encoding: 'utf8', timeout: 15000 });
    assert.equal(recovered.status, 0, recovered.stderr + recovered.stdout); assert.match(recovered.stdout, /RECOVERY_OK/);
    if (engine === 'json' && mode === 'redeem') {
      const failed = cp.spawnSync(process.execPath, [__filename, 'load-failure'], { env: { ...env, STORAGE_ENGINE: 'sqlite' }, encoding: 'utf8', timeout: 15000 });
      assert.equal(failed.status, 0, failed.stderr + failed.stdout); assert.match(failed.stdout, /FAILURE_AUDIT_PRESERVED/);
    }
  }
  console.log('LICENSE RECOVERY PASS (JSON + SQLite): corrupt-load audit preservation, abrupt exit after durable redeem/release, stable operation IDs, fresh-process projection repair with intact audit chain, no authority extension/reopening, idempotent reconciliation and uncertain-response retry without reconsumption.');
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
