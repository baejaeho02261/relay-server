'use strict';
// Pure in-memory registry tests. Synthetic PE bytes are never executed and no
// server, socket, key, data directory or production authorization is created.
const test = require('node:test'), assert = require('node:assert/strict'), crypto = require('node:crypto');
const policy = require('../../services/artifacts/peace.server-policy-protection');
const registry = require('../../services/security/peace.server-policy-registry');
const evidence = require('../../services/artifacts/peace.desktop-packing-evidence');
const ROLES = ['A', 'B', 'O'], sha = bytes => crypto.createHash('sha512').update(bytes).digest('hex');
function PE(role) {
  const bytes = Buffer.alloc(5120), table = 392, optional = 152;
  bytes.write('MZ'); bytes.writeUInt32LE(128, 60); bytes.write('PE\0\0', 128, 'ascii'); bytes.writeUInt16LE(0x8664, 132);
  bytes.writeUInt16LE(2, 134); bytes.writeUInt16LE(240, 148); bytes.writeUInt16LE(0x22, 150); bytes.writeUInt16LE(0x20b, optional);
  bytes.writeUInt32LE(0x1000, optional + 16); bytes.writeUInt32LE(0x3000, optional + 56); bytes.writeUInt32LE(512, optional + 60);
  bytes.writeUInt16LE(2, optional + 68); bytes.writeUInt32LE(16, optional + 108);
  bytes.write('.text', table); bytes.writeUInt32LE(512, table + 8); bytes.writeUInt32LE(0x1000, table + 12);
  bytes.writeUInt32LE(512, table + 16); bytes.writeUInt32LE(512, table + 20); bytes.writeUInt32LE(0x60000020, table + 36);
  bytes.fill(0x90, 512, 1024); bytes.write('SYNTHETIC ' + role + ' DATA ONLY', 600, 'ascii');
  const data = table + 40; bytes.write('.cozy', data); bytes.writeUInt32LE(4096, data + 8); bytes.writeUInt32LE(0x2000, data + 12);
  bytes.writeUInt32LE(4096, data + 16); bytes.writeUInt32LE(1024, data + 20); bytes.writeUInt32LE(0xc0000040, data + 36);
  policy.CreateUnsealedSlot().copy(bytes, 1024); return bytes;
}
const Profile = number => ({ version: 1, functions: [{ id: 2, args: 0, body: { op: 'const', value: number } }] });
function Cohort(number = 1) {
  const db = { artifacts: {}, launchers: {} }, outputs = {}, records = [], jobId = number.toString(16).padStart(32, '0');
  for (const [index, role] of ROLES.entries()) {
    const bytes = PE(role), sourceArtifactId = (number * 10 + index + 1).toString(16).toUpperCase().padStart(24, '0');
    const out = policy.BindTemplate(bytes, role, Profile(number)); outputs[role] = out;
    db.artifacts[sourceArtifactId] = { id: sourceArtifactId, component: role, sha512: sha(bytes), size: bytes.length };
    records.push({ version: 1, purpose: evidence.DOMAIN, jobId, component: role, sourceArtifactId,
      inputSha512: out.inputSha512, outputSha512: out.sha512, size: out.bytes.length, toolSha512: out.toolSha512,
      profileSha512: out.profileSha512, createdAt: 1000 + number, actorHash: 'a'.repeat(128) });
  }
  evidence.RecordJob(db, records, { now: 1000 + number }); return { db, outputs, records };
}
function AddArtifacts(context) {
  const { db, outputs, records } = context, rows = {};
  for (const [index, role] of ROLES.entries()) {
    const out = outputs[role], record = records.find(value => value.component === role), id = 'D'.repeat(23) + (index + 1);
    const row = { id, component: role, sha512: out.sha512, size: out.bytes.length, ownProtection: structuredClone(out.ownProtection), packingReceiptId: evidence.ReceiptId(record) };
    db.artifacts[id] = row; rows[role] = row;
  }
  return rows;
}
function CloneOutputs(outputs) {
  return Object.fromEntries(ROLES.map(role => [role, { ...outputs[role], bytes: Buffer.from(outputs[role].bytes),
    ownProtection: structuredClone(outputs[role].ownProtection), serverPolicy: structuredClone(outputs[role].serverPolicy) }]));
}
function Reject(fn, code) { assert.throws(fn, error => error.message === 'COZY_SERVER_POLICY_' + code); }

test('registry commits one exact three-role cohort and survives JSON persistence without altering source outputs', () => {
  const context = Cohort(), before = JSON.stringify(context.outputs.A.serverPolicy);
  const publicIds = registry.RecordJob(context.db, context.records, context.outputs), rows = AddArtifacts(context);
  assert.deepEqual(Object.keys(publicIds).sort(), ['A', 'B', 'O']); assert.equal(Object.keys(context.db.serverPolicies).length, 3);
  assert.equal(JSON.stringify(context.outputs.A.serverPolicy), before);
  const restored = JSON.parse(JSON.stringify(context.db)); assert.equal(registry.ValidateStore(restored), restored);
  for (const role of ROLES) {
    assert.equal(registry.Reason(restored, restored.artifacts[rows[role].id]), '');
    assert.equal(publicIds[role], rows[role].ownProtection.policyId);
    assert.equal(publicIds[role].length, 64);
    assert.equal(JSON.stringify(evidence.Projection(restored, rows[role])).includes('programBase64'), false);
  }
  assert.equal(JSON.stringify(publicIds).includes('programBase64'), false);
  assert.notEqual(context.db.serverPolicies[publicIds.A], context.outputs.A.serverPolicy);
  // Different property insertion order after a serializer is not a conflict.
  context.db.serverPolicies[publicIds.A] = Object.fromEntries(Object.entries(context.db.serverPolicies[publicIds.A]).reverse());
  assert.deepEqual(registry.RecordJob(context.db, context.records, context.outputs), publicIds);
});
test('actual output bytes, input identity, tool identity, policy commitment and parsed slot are all verified', () => {
  const mutations = [
    out => { out.A.bytes[700] ^= 1; },
    out => { out.A.sha512 = 'b'.repeat(128); },
    out => { out.A.inputSha512 = 'b'.repeat(128); },
    out => { out.A.profileSha512 = 'b'.repeat(128); },
    out => { out.A.toolSha512 = 'b'.repeat(128); },
    out => { out.A.ownProtection.functionCount = 1; },
    out => { out.A.bytes.writeUInt32LE(1, 1024 + 32); out.A.ownProtection.functionCount = 1; },
    out => { out.A.serverPolicy = structuredClone(out.B.serverPolicy); },
    out => { out.A.ownProtection = structuredClone(out.B.ownProtection); }
  ];
  for (const mutate of mutations) {
    const context = Cohort(), out = CloneOutputs(context.outputs), before = JSON.stringify(context.db); mutate(out);
    Reject(() => registry.RecordJob(context.db, context.records, out), 'JOB_BINDING_MISMATCH');
    assert.equal(JSON.stringify(context.db), before);
  }
});
test('no partial registry commit is made when the last role has a damaged private program', () => {
  const context = Cohort(), out = CloneOutputs(context.outputs), before = JSON.stringify(context.db);
  const program = Buffer.from(out.O.serverPolicy.programBase64, 'base64'); program[program.length - 2] ^= 1;
  out.O.serverPolicy.programBase64 = program.toString('base64'); program.fill(0);
  Reject(() => registry.RecordJob(context.db, context.records, out), 'RECORD_COMMITMENT_MISMATCH');
  assert.equal(JSON.stringify(context.db), before); assert.equal(context.db.serverPolicies, undefined);
});
test('records must already exist with valid indexes and form one complete matching receipt cohort', () => {
  let context = Cohort(); delete context.db.packingEvidence[evidence.ReceiptId(context.records[1])];
  assert.throws(() => registry.RecordJob(context.db, context.records, context.outputs), /PACKING_EVIDENCE_INVALID/);
  context = Cohort(); const duplicate = [context.records[0], context.records[0], context.records[2]];
  Reject(() => registry.RecordJob(context.db, duplicate, context.outputs), 'JOB_BINDING_MISMATCH');
  context = Cohort(); const other = Cohort(2);
  Object.assign(context.db.artifacts, other.db.artifacts); Object.assign(context.db.packingEvidence, other.db.packingEvidence);
  assert.throws(() => registry.RecordJob(context.db, [context.records[0], context.records[1], other.records[2]], context.outputs), /PACKING_EVIDENCE_INVALID/);
  context = Cohort(); const key = evidence.ReceiptId(context.records[0]); context.db.packingEvidence[key].profileSha512 = 'b'.repeat(128);
  assert.throws(() => registry.RecordJob(context.db, context.records, context.outputs), /PACKING_EVIDENCE_INVALID/);
});
test('registry keys, record roles, count, canonical program and limits are checked after persistence', () => {
  const context = Cohort(); registry.RecordJob(context.db, context.records, context.outputs);
  const id = context.outputs.A.serverPolicy.policyId;
  for (const mutate of [db => { db.serverPolicies['0'.repeat(64)] = db.serverPolicies[id]; delete db.serverPolicies[id]; },
    db => { db.serverPolicies[id].role = 'B'; }, db => { db.serverPolicies[id].functionCount = 1; },
    db => { db.serverPolicies[id].programBase64 += '\n'; }, db => { db.serverPolicies[id].key = 'forbidden'; }]) {
    const restored = JSON.parse(JSON.stringify(context.db)); mutate(restored); assert.throws(() => registry.ValidateStore(restored), /COZY_SERVER_POLICY_/);
  }
  Reject(() => registry.ValidateStore({ artifacts: {}, serverPolicies: [] }), 'STORE_INVALID');
  Reject(() => registry.ValidateStore({ artifacts: {}, serverPolicies: Object.fromEntries(Array.from({ length: registry.MAX + 1 }, (_, i) => [String(i), {}])) }), 'STORE_INVALID');
});
test('artifact checks reject a missing policy, wrong role/count, missing receipt and wrong receipt profile', () => {
  const context = Cohort(); registry.RecordJob(context.db, context.records, context.outputs); const rows = AddArtifacts(context);
  const restored = () => JSON.parse(JSON.stringify(context.db));
  let db = restored(); delete db.serverPolicies[rows.A.ownProtection.policyId]; assert.equal(registry.Reason(db, rows.A), 'COZY_SERVER_POLICY_RECORD_MISSING');
  const wrongRole = { ...rows.A, component: 'B' }; assert.equal(registry.Reason(context.db, wrongRole), 'COZY_SERVER_POLICY_NOT_BOUND');
  const wrongCount = { ...rows.A, ownProtection: { ...rows.A.ownProtection, functionCount: 1 } };
  assert.equal(registry.Reason(context.db, wrongCount), 'COZY_SERVER_POLICY_RECORD_MISMATCH');
  db = restored(); delete db.packingEvidence[rows.A.packingReceiptId]; assert.equal(registry.Reason(db, rows.A), 'COZY_SERVER_POLICY_RECORD_INVALID');
  db = restored(); const original = db.packingEvidence[rows.A.packingReceiptId]; delete db.packingEvidence[rows.A.packingReceiptId];
  original.profileSha512 = 'b'.repeat(128); const changedId = evidence.ReceiptId(original); db.packingEvidence[changedId] = original;
  assert.equal(registry.Reason(db, { ...rows.A, packingReceiptId: changedId }), 'COZY_SERVER_POLICY_RECEIPT_REQUIRED');
});
test('only the explicit source-read exception admits valid unsealed templates', () => {
  const artifact = { component: 'A', ownProtection: policy.Inspect(PE('A')) };
  assert.equal(registry.Reason({ artifacts: {} }, artifact), 'COZY_SERVER_POLICY_NOT_BOUND');
  assert.equal(registry.Reason({ artifacts: {} }, artifact, { allowUnsealed: true }), '');
  const invalid = { ...artifact, ownProtection: { ...artifact.ownProtection, role: 'A' } };
  assert.equal(registry.Reason({ artifacts: {} }, invalid, { allowUnsealed: true }), 'COZY_SERVER_POLICY_RECORD_INVALID');
  const context = Cohort();
  assert.equal(registry.Reason(context.db, { component: 'A', ownProtection: context.outputs.A.ownProtection }, { allowUnsealed: true }), 'COZY_SERVER_POLICY_RECORD_MISSING');
});
test('private fixture import checks the same exact receipts, files and policies and returns public IDs only', () => {
  const context = Cohort(), serverPolicies = ROLES.map(role => context.outputs[role].serverPolicy);
  const artifacts = Object.fromEntries(ROLES.map(role => [role, { bytes: context.outputs[role].bytes }]));
  const ids = registry.RecordPoliciesForExistingReceipts(context.db, context.records, serverPolicies, artifacts);
  assert.equal(Object.keys(context.db.serverPolicies).length, 3); assert.equal(JSON.stringify(ids).includes('programBase64'), false);
  const missing = Cohort(); Reject(() => registry.RecordPoliciesForExistingReceipts(missing.db, missing.records, serverPolicies.slice(0, 2), artifacts), 'JOB_INVALID');
  const changed = Cohort(), wrongFiles = { ...artifacts, O: { bytes: Buffer.from(artifacts.O.bytes) } }; wrongFiles.O.bytes[800] ^= 1;
  Reject(() => registry.RecordPoliciesForExistingReceipts(changed.db, changed.records, serverPolicies, wrongFiles), 'JOB_BINDING_MISMATCH');
  assert.equal(changed.db.serverPolicies, undefined);
  const wrongRole = Cohort(); Reject(() => registry.RecordPoliciesForExistingReceipts(wrongRole.db, wrongRole.records, [serverPolicies[0], serverPolicies[0], serverPolicies[2]], artifacts), 'JOB_INVALID');
});
test('orphan policies are pruned transactionally while any artifact or retained receipt preserves its policy', () => {
  const old = Cohort(), next = Cohort(2); registry.RecordJob(old.db, old.records, old.outputs);
  const orphan = policy.BindTemplate(PE('A'), 'A', Profile(100)).serverPolicy;
  old.db.serverPolicies[orphan.policyId] = orphan;
  const artifactOnly = policy.BindTemplate(PE('A'), 'A', Profile(101));
  old.db.serverPolicies[artifactOnly.serverPolicy.policyId] = artifactOnly.serverPolicy;
  old.db.artifacts.ARCHIVED = { component: 'A', sha512: artifactOnly.sha512, size: artifactOnly.bytes.length, ownProtection: artifactOnly.ownProtection };
  Object.assign(old.db.artifacts, next.db.artifacts); Object.assign(old.db.packingEvidence, next.db.packingEvidence);
  registry.RecordJob(old.db, next.records, next.outputs);
  assert.equal(old.db.serverPolicies[orphan.policyId], undefined);
  assert.ok(old.db.serverPolicies[artifactOnly.serverPolicy.policyId]);
  for (const role of ROLES) assert.ok(old.db.serverPolicies[old.outputs[role].serverPolicy.policyId]);
  assert.equal(Object.keys(old.db.serverPolicies).length, 7);
});
test('capacity failure preserves every existing referenced record and commits none of the new cohort', () => {
  const context = Cohort(); context.db.serverPolicies = {};
  for (let i = 0; i < registry.MAX; i++) {
    const result = policy.BindTemplate(PE('A'), 'A', Profile(1000 + i)); context.db.serverPolicies[result.serverPolicy.policyId] = result.serverPolicy;
    context.db.artifacts['ARCHIVED_' + i] = { component: 'A', sha512: result.sha512, size: result.bytes.length, ownProtection: result.ownProtection };
  }
  const before = JSON.stringify(context.db.serverPolicies);
  assert.throws(() => registry.RecordJob(context.db, context.records, context.outputs), error => error.message === 'COZY_SERVER_POLICY_CAPACITY' && error.status === 503);
  assert.equal(JSON.stringify(context.db.serverPolicies), before);
});
test('operation lookup uses the actual A launcher and B/O release IDs and requires enforce-mode complete PASS', () => {
  const context = Cohort(); registry.RecordJob(context.db, context.records, context.outputs); const rows = AddArtifacts(context);
  context.db.launchers.LAUNCHER = { artifactId: rows.A.id };
  const grant = { mode: 'enforce', status: 'PASS', measurementComplete: true };
  {
    assert.doesNotThrow(() => registry.RequireOperation(context.db, { launcherId: 'LAUNCHER' }, 'A', grant));
    assert.doesNotThrow(() => registry.RequireOperation(context.db, { releaseId: rows.B.id }, 'B', grant));
    assert.doesNotThrow(() => registry.RequireOperation(context.db, { releaseId: rows.O.id, artifactId: rows.B.id }, 'O', grant));
    Reject(() => registry.RequireOperation(context.db, { releaseId: rows.B.id }, 'O', grant), 'OPERATION_CONTEXT_INVALID');
    Reject(() => registry.RequireOperation(context.db, { releaseId: 'MISSING' }, 'O', grant), 'OPERATION_CONTEXT_INVALID');
    for (const bad of [undefined, { ...grant, mode: 'observe' }, { ...grant, status: 'MISMATCH' },
      { ...grant, status: 'INDETERMINATE' }, { ...grant, measurementComplete: false }]) {
      Reject(() => registry.RequireOperation(context.db, { releaseId: rows.O.id }, 'O', bad), 'AUTHORITY_REQUIRED');
    }
    const id = rows.O.ownProtection.policyId; delete context.db.serverPolicies[id];
    Reject(() => registry.RequireOperation(context.db, { releaseId: rows.O.id }, 'O', grant), 'RECORD_MISSING');
  }
});
test('registry has no unauthenticated runtime evaluator or private record projection export', () => {
  for (const name of ['Evaluate', 'EvaluateServerPolicy', 'Execute', 'Handle', 'List', 'Export', 'Projection']) assert.equal(Object.hasOwn(registry, name), false);
  const context = Cohort(); registry.RecordJob(context.db, context.records, context.outputs); const rows = AddArtifacts(context);
  rows.B.ownProtection = { engine: 'COZY_VM_V1' };
  assert.doesNotThrow(() => registry.RequireOperation(context.db, { releaseId: rows.B.id }, 'B'));
});
