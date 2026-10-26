'use strict';
// Private server records, never desktop/bootstrap/download projections. Public
// commitments select an approved record; possession of a commitment grants no
// authority. Desktop-supplied programs and policy records are never evaluated.
const crypto = require('node:crypto');
const policy = require('../artifacts/peace.server-policy-protection');
const evidence = require('../artifacts/peace.desktop-packing-evidence');
const MAX = 384, ROLES = ['A', 'B', 'O'], ID = /^[a-f0-9]{64}$/;
const RECORD_FIELDS = ['version', 'role', 'policyId', 'policySha512', 'functionCount', 'maxSteps', 'programBase64'];
const plain = value => !!value && Object.getPrototypeOf(value) === Object.prototype;
const sha = bytes => crypto.createHash('sha512').update(bytes).digest('hex');
function Fail(code, status = 409) {
  const error = Error('COZY_SERVER_POLICY_' + code); error.desktopError = true; error.status = status; throw error;
}
function ExactRoles(value) {
  return plain(value) && Object.keys(value).length === 3 && ROLES.every(role => Object.hasOwn(value, role));
}
function ValidateStore(db) {
  if (!plain(db) || !plain(db.artifacts)) Fail('STORE_INVALID');
  const records = db.serverPolicies; if (records === undefined) return db;
  if (!plain(records) || Object.keys(records).length > MAX) Fail('STORE_INVALID');
  for (const [id, record] of Object.entries(records)) {
    if (!ID.test(id)) Fail('STORE_INVALID');
    policy.ValidateServerPolicy(record);
    if (id !== record.policyId) Fail('STORE_INVALID');
  }
  return db;
}
function CheckedReceipts(db, records) {
  ValidateStore(db); evidence.ValidateStore(db);
  if (!Array.isArray(records) || records.length !== 3) Fail('JOB_INVALID');
  const selected = {};
  for (const receipt of records) {
    const id = evidence.ReceiptId(receipt);
    if (Object.hasOwn(selected, id) || !Object.hasOwn(db.packingEvidence || {}, id)) Fail('JOB_BINDING_MISMATCH');
    selected[id] = receipt;
  }
  // The isolated map checks exact role coverage, one job, unique source IDs,
  // shared tool/actor/time and receipt IDs without omitting prior DB evidence.
  evidence.ValidateStore({ artifacts: {}, packingEvidence: selected });
  if (new Set(records.map(receipt => receipt.component)).size !== 3) Fail('JOB_BINDING_MISMATCH');
  return Object.fromEntries(records.map(receipt => [receipt.component, receipt]));
}
function MatchOutput(role, receipt, output) {
  if (!plain(output) || !Buffer.isBuffer(output.bytes) || !output.serverPolicy || !output.ownProtection) Fail('JOB_INVALID');
  const record = policy.ValidateServerPolicy(output.serverPolicy), claimed = policy.ValidateMetadata(output.ownProtection);
  const actual = policy.Inspect(output.bytes);
  if (!actual || actual.state !== 'BOUND' || actual.role !== role || claimed.state !== 'BOUND' || claimed.role !== role ||
      Object.keys(actual).some(key => actual[key] !== claimed[key]) || record.role !== role ||
      actual.policyId !== record.policyId || actual.policySha512 !== record.policySha512 || actual.functionCount !== record.functionCount ||
      output.inputSha512 !== receipt.inputSha512 || output.sha512 !== receipt.outputSha512 || sha(output.bytes) !== receipt.outputSha512 ||
      output.profileSha512 !== receipt.profileSha512 || record.policySha512 !== receipt.profileSha512 ||
      output.toolSha512 !== receipt.toolSha512 || output.bytes.length !== receipt.size) Fail('JOB_BINDING_MISMATCH');
  return record;
}
function CommitRecords(db, records) {
  const next = { ...(db.serverPolicies || {}) }, result = {};
  for (const record of records) {
    const old = next[record.policyId];
    if (old && RECORD_FIELDS.some(field => old[field] !== record[field])) Fail('RECORD_CONFLICT');
    next[record.policyId] = structuredClone(record); result[record.role] = record.policyId;
  }
  // No timer or independent mutation: prune only within the caller's existing
  // transaction. Retained receipts and artifact references both preserve IR.
  const digests = new Set(Object.values(db.packingEvidence || {}).map(receipt => receipt.profileSha512));
  const ids = new Set(Object.values(db.artifacts).map(artifact => artifact?.ownProtection?.policyId).filter(Boolean));
  for (const [id, record] of Object.entries(next)) if (!ids.has(id) && !digests.has(record.policySha512)) delete next[id];
  if (Object.keys(next).length > MAX) Fail('CAPACITY', 503);
  ValidateStore({ ...db, serverPolicies: next });
  db.serverPolicies = next; return result;
}
function RecordJob(db, records, outputs) {
  const receipts = CheckedReceipts(db, records);
  if (!ExactRoles(outputs)) Fail('JOB_INVALID');
  const policies = ROLES.map(role => MatchOutput(role, receipts[role], outputs[role]));
  return CommitRecords(db, policies);
}
function RecordPoliciesForExistingReceipts(db, records, serverPolicies, artifacts) {
  // Internal fixture/offline-import primitive only. No route accepts this data.
  // The caller must already own the exact three receipts, policy records and
  // final files; public slot metadata cannot reconstruct a private policy.
  const receipts = CheckedReceipts(db, records);
  if (!Array.isArray(serverPolicies) || serverPolicies.length !== 3 ||
      new Set(serverPolicies.map(record => record?.role)).size !== 3 || !ExactRoles(artifacts)) Fail('JOB_INVALID');
  const inputs = {};
  for (const role of ROLES) {
    const artifact = artifacts[role], record = serverPolicies.find(item => item?.role === role), receipt = receipts[role];
    if (!plain(artifact) || Object.keys(artifact).length !== 1 || !Object.hasOwn(artifact, 'bytes') || !Buffer.isBuffer(artifact.bytes) || !record) Fail('JOB_INVALID');
    inputs[role] = { bytes: artifact.bytes, ownProtection: policy.Inspect(artifact.bytes), serverPolicy: record,
      sha512: sha(artifact.bytes), inputSha512: receipt.inputSha512, profileSha512: record.policySha512, toolSha512: receipt.toolSha512 };
  }
  const policies = ROLES.map(role => MatchOutput(role, receipts[role], inputs[role]));
  return CommitRecords(db, policies);
}
function Reason(db, artifact, { allowUnsealed = false } = {}) {
  const metadata = artifact?.ownProtection;
  if (metadata?.engine !== policy.ENGINE) return '';
  try {
    policy.ValidateMetadata(metadata);
    if (metadata.state === 'UNSEALED' && allowUnsealed === true) return '';
    if (metadata.state !== 'BOUND' || metadata.role !== artifact.component) return 'COZY_SERVER_POLICY_NOT_BOUND';
    const record = db.serverPolicies?.[metadata.policyId]; if (!record) return 'COZY_SERVER_POLICY_RECORD_MISSING';
    policy.ValidateServerPolicy(record);
    if (record.policyId !== metadata.policyId || record.role !== metadata.role || record.policySha512 !== metadata.policySha512 ||
        record.functionCount !== metadata.functionCount) return 'COZY_SERVER_POLICY_RECORD_MISMATCH';
    const receipt = evidence.FindReceipt(db, artifact);
    if (!receipt || receipt.record.profileSha512 !== record.policySha512) return 'COZY_SERVER_POLICY_RECEIPT_REQUIRED';
    return '';
  } catch (_) { return 'COZY_SERVER_POLICY_RECORD_INVALID'; }
}
function RequireOperation(db, row, stage, grant) {
  // Only authority.RequireFresh calls this after authentication and current
  // device/session checks. The V2 path additionally requires enforce-mode PASS;
  // an observation, missing measurement or public commitment cannot grant use.
  if (!plain(db) || !plain(db.artifacts) || !ROLES.includes(stage) || !plain(row)) Fail('OPERATION_CONTEXT_INVALID', 403);
  const artifact = stage === 'A' ? db.artifacts[db.launchers?.[row.launcherId]?.artifactId] : db.artifacts[row.releaseId];
  if (!artifact || artifact.component !== stage) Fail('OPERATION_CONTEXT_INVALID', 403);
  if (artifact.ownProtection?.engine !== policy.ENGINE) return;
  if (!plain(grant) || grant.mode !== 'enforce' || grant.status !== 'PASS' || grant.measurementComplete !== true) Fail('AUTHORITY_REQUIRED', 403);
  const reason = Reason(db, artifact);
  if (reason) { const error = Error(reason); error.desktopError = true; error.status = 403; throw error; }
  const record = db.serverPolicies[artifact.ownProtection.policyId];
  if (policy.EvaluateServerPolicy(record, 1, [ROLES.indexOf(stage) + 1, 1, 1]) !== 1) Fail('OPERATION_REJECTED', 403);
}
module.exports = { MAX, ValidateStore, RecordJob, RecordPoliciesForExistingReceipts, Reason, RequireOperation };
