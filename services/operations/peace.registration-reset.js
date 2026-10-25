'use strict';

// A deliberate, one-shot maintenance operation. No HTTP route enables this.
// The caller holds the data-directory writer lock and has not opened listeners.
const SCOPE = 'ABO_LICENSES_ISSUANCE_OPERATIONS_V1';
function Fail(code) { throw Error('REGISTRATION_RESET_' + code); }
function Request(environment = process.env) {
  const id = environment.COZY_REGISTRATION_RESET_ID || '';
  const scope = environment.COZY_REGISTRATION_RESET_SCOPE || '';
  if (!id && !scope) return null;
  if (!/^[a-f0-9]{64}$/.test(id) || scope !== SCOPE) Fail('REQUEST_INVALID');
  return {id, scope};
}
function Counts() {
  const db = require('../bootstrap/peace.desktop-bootstrap-store').Load();
  const licenses = require('../licensing/peace.desktop-licenses').DB();
  return {
    artifacts: Object.keys(db.artifacts).length,
    activeArtifacts: Object.keys(db.active).length,
    licenses: Object.keys(licenses.licenses).length,
    issuedLaunchers: Object.keys(db.launchers).length,
    flows: Object.keys(db.flows).length,
    overlays: Object.keys(db.overlays || {}).length,
    issueReceipts: Object.keys(db.issueReceipts).length,
    packingEvidence: Object.keys(db.packingEvidence || {}).length,
    releaseManifests: Object.keys(db.securityOperations?.releaseGovernance?.manifests || {}).length
  };
}
function ResetProductionOperations() {
  const production = require('../runtime/peace.production-state');
  const saved = production.ExportPersisted();
  // Preserve administrator passkeys, the authenticated audit head and transport
  // policy; clear application deployment transactions and operational reports.
  production.ImportPersisted({productionControl: {
    passkeyCredentials: saved.passkeyCredentials,
    auditChain: saved.auditChain,
    transportPolicy: saved.transportPolicy
  }});
}
function Run() {
  const request = Request();
  const store = require('../bootstrap/peace.desktop-bootstrap-store');
  const reset = require('../bootstrap/peace.desktop-registration-reset');
  const pending = reset.Status();
  if (!request) {
    if (pending && pending.phase !== 'COMPLETE') Fail('PENDING_AUTHORIZATION_REQUIRED');
    return {requested: false};
  }
  const prepared = reset.Prepare(request.id);
  if (prepared.phase === 'COMPLETE') {
    console.log('REGISTRATION_RESET_ALREADY_COMPLETED', request.id.slice(0, 16));
    return {requested: true, alreadyCompleted: true, id: request.id};
  }
  const licenses = require('../licensing/peace.desktop-licenses');
  const before = {bootstrap: store.Load().secret, license: licenses.DB().signingSecret};
  const next = require('../licensing/peace.desktop-journal').Reset(licenses.DB(), request.id);
  licenses.Import(next);
  const auxiliary = require('./peace.registration-reset-stores');
  auxiliary.Run(request.id);
  reset.Apply(request.id);
  ResetProductionOperations();
  if (store.Load().secret !== before.bootstrap || licenses.DB().signingSecret !== before.license) Fail('KEY_CHANGED');
  const after = Counts();
  if (Object.values(after).some(count => count !== 0)) Fail('INCOMPLETE');
  const related = auxiliary.Counts();
  const relatedFields = {
    machine: ['bindings', 'receipts'],
    integrity: ['records', 'baselines', 'observations'],
    workspace: ['metadata', 'jobs', 'receipts', 'releaseNotes']
  };
  const relatedAfter = {};
  for (const [name, fields] of Object.entries(relatedFields)) {
    relatedAfter[name] = Object.fromEntries(fields.map(field => [field, related[name][field]]));
    if (fields.some(field => related[name][field] !== 0)) Fail('RELATED_STORE_INCOMPLETE');
  }
  const audit = require('../../storage/audit/peace.audit').LogEvent('DESKTOP_REGISTRATION_RESET_APPLIED', JSON.stringify({
    operationId: request.id, scope: SCOPE, after, relatedAfter
  }), {durable: true});
  if (audit?.ok !== true) Fail('AUDIT_SAVE_FAILED');
  if (!require('../../storage/snapshots/peace.database').SaveDatabase()) Fail('SNAPSHOT_SAVE_FAILED');
  reset.Cleanup(request.id);
  const complete = reset.Finish(request.id);
  console.log('REGISTRATION_RESET_COMPLETE', JSON.stringify({
    operationId: request.id, scope: SCOPE, after,
    relatedAfter, artifactFilesCleared: complete.deletedFiles || 0,
    auditHistoryPreserved: true, keysPreserved: true
  }));
  return {requested: true, alreadyCompleted: false, id: request.id, after};
}
module.exports = {SCOPE, Request, Counts, Run};
