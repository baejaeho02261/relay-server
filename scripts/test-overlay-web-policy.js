'use strict';
// Real policy/operations services; synthetic PE fixtures and isolated storage.
const assert = require('node:assert/strict'), fs = require('node:fs');
const os = require('node:os'), path = require('node:path');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-overlay-web-policy-'));
process.env.DATA_DIR = temp; process.env.STORAGE_ENGINE = 'json'; process.env.HA_ENABLED = '0';
process.env.DESKTOP_PUBLIC_HOST = '127.0.0.1'; process.env.DESKTOP_PUBLIC_PORT = '29131';
require('../core/utils').EnsureDirs();
const boot = require('../services/desktopBootstrap'), auth = require('../services/desktopSecurityAuthority');
const ops = require('../services/desktopSecurityOperations'), store = require('../services/desktopBootstrapStore');
const { PE } = require('./desktop-bootstrap-fixture');
const authorityFile = path.join(temp, 'desktop-bootstrap/authority.json');
let checks = 0;
function check(name, fn) { fn(); checks++; console.log('PASS ' + name); }
function reject(fn, code) { assert.throws(fn, e => e.message === code, code); }
const bytes = () => fs.readFileSync(authorityFile);
const proposal = minVersionO => ({ expectedRevision: auth.Policy().revision, expectedOperationsRevision: ops.Revision(), minVersionO });
let a, b, oldO, nextO;
const pair = o => ({ aId: a.id, bId: b.id, oId: o.id });
const activate = o => ops.ActivatePair({ expectedRevision: ops.Revision(), expectedPolicyRevision: auth.Policy().revision, ...pair(o) }, 'TEST');
try {
  check('Legacy policy gains default O minimum only in a detached read-only view', () => {
    const legacy = auth.Defaults(); delete legacy.minVersionO;
    store.Atomic(db => { db.securityAuthorityPolicy = legacy; });
    const before = bytes(), revision = store.Load().revision;
    const view = auth.Policy(); assert.equal(view.minVersionO, '0');
    assert.equal(view.revision, legacy.revision);
    view.minVersionO = '99'; assert.equal(auth.Policy().minVersionO, '0');
    assert.equal(Object.hasOwn(store.Load().securityAuthorityPolicy, 'minVersionO'), false);
    assert.equal(store.Load().revision, revision); assert.deepEqual(bytes(), before);
  });
  check('Malformed O minima are rejected without writing policy', () => {
    const before = bytes();
    for (const value of ['', 'abc', '-1', '1.2.3.4.5', '1000000000', 3, null])
      reject(() => auth.PreviewPolicy(proposal(value)), 'SECURITY_POLICY_INVALID');
    assert.deepEqual(bytes(), before);
  });
  check('O candidate policy preview reports the active failure and preserves A/B', () => {
    a = boot.Publish('A', '1.0', PE('A'));
    b = boot.Publish('B', '1.0', PE('B'));
    oldO = boot.Publish('O', '2.0', PE('O'));
    nextO = ops.Stage('O', '3.0', PE('O', auth.DOMAIN + ' next'), undefined, 'TEST');
    const before = bytes(), active = { ...store.Load().active };
    const view = auth.PreviewPolicy(proposal('3.0'));
    assert.equal(view.readOnly, true); assert.equal(view.eligible, false);
    assert.equal(view.policy.minVersionO, '3.0');
    assert.equal(view.releases.find(x => x.id === oldO.id).reason, 'SECURITY_RELEASE_VERSION');
    for (const row of [a, b, nextO]) assert.equal(view.releases.find(x => x.id === row.id).reason, '');
    reject(() => auth.SetPolicy(proposal('3.0'), 'TEST'), 'SECURITY_RELEASE_VERSION');
    assert.equal(auth.Policy().minVersionO, '0');
    assert.deepEqual(store.Load().active, active); assert.deepEqual(bytes(), before);
  });
  check('Compatible O can be activated and its minimum saved independently of A/B', () => {
    activate(nextO);
    const body = proposal('3.0'), before = bytes();
    assert.equal(auth.PreviewPolicy(body).eligible, true); assert.deepEqual(bytes(), before);
    const saved = auth.SetPolicy(body, 'TEST');
    assert.equal(saved.minVersionO, '3.0'); assert.equal(saved.revision, body.expectedRevision + 1);
    assert.equal(saved.minVersionA, '0'); assert.equal(saved.minVersionB, '0');
    assert.deepEqual(store.Load().active, { A: a.id, B: b.id, O: nextO.id });
    assert.equal(ops.PreviewPair(pair(nextO)).eligible, true);
  });
  check('Rollback to O below the current minimum is rejected without replacing A/B/O', () => {
    const before = bytes(), view = ops.PreviewPair(pair(oldO));
    assert.equal(view.eligible, false); assert.deepEqual(view.reasons, ['SECURITY_RELEASE_VERSION']);
    reject(() => activate(oldO), 'SECURITY_RELEASE_VERSION');
    assert.deepEqual(bytes(), before);
    assert.deepEqual(store.Load().active, { A: a.id, B: b.id, O: nextO.id });
  });
  check('Old O cannot be uploaded under its minimum while unchanged A/B versions remain valid', () => {
    const active = { ...store.Load().active }, ids = Object.keys(store.Load().artifacts);
    reject(() => boot.Publish('O', '2.9', PE('O', auth.DOMAIN + ' rejected')), 'SECURITY_RELEASE_VERSION');
    reject(() => ops.Stage('O', '2.9', PE('O', auth.DOMAIN + ' rejected'), undefined, 'TEST'), 'SECURITY_RELEASE_VERSION');
    assert.deepEqual(Object.keys(store.Load().artifacts), ids);
    for (const component of ['A', 'B']) {
      const row = ops.Stage(component, '1.0', PE(component, auth.DOMAIN + ' candidate'), undefined, 'TEST');
      // Stage returns the public projection; policy admission requires the
      // server-owned CRC baselines retained in the stored artifact record.
      assert.equal(row.crcCoverage.complete, true);
      assert.equal(auth.ArtifactReason(store.Load().artifacts[row.id], auth.Policy()), '');
    }
    assert.deepEqual(store.Load().active, active);
  });
  console.log(`Overlay web policy: ${checks} checks passed (real services, synthetic PE; no Windows execution)`);
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
