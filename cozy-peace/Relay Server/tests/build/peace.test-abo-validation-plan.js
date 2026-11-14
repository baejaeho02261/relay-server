'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const tool = require('../../tools/windows/peace.plan-abo-validation');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cozy-abo-plan-'));
const files = {}, originals = {};
for (const [index, role] of ['A', 'B', 'O'].entries()) {
  const data = Buffer.alloc(512); data.writeUInt16LE(0x5a4d); data.writeUInt32LE(128, 60);
  data.writeUInt32LE(0x4550, 128); data.writeUInt16LE(0x8664, 132); data.writeUInt16LE(0x20b, 152);
  data[400] = index; data.write('SYNTHETIC_PRIVATE_VALUE_NOT_FOR_REPORT', 420);
  files[role] = path.join(root, 'private-' + role + '.exe'); originals[role] = data; fs.writeFileSync(files[role], data);
}
test('plan binds three exact files without asserting execution or exposing strings and paths', () => {
  const output = path.join(root, 'plan.json'), plan = tool.WritePlan(files, output);
  assert.equal(plan.outcome, 'NOT_RUN'); assert.equal(plan.executionPerformed, false);
  assert.equal(plan.serverStateQueried, false); assert.equal(plan.productionApproved, false);
  assert.equal(plan.scenarios.length, 9);
  assert.equal(plan.scenarios.every(row => row.outcome === 'NOT_RUN'), true);
  const repeatedApproval = plan.scenarios.find(row => row.id === 'approval-each-new-issuance');
  assert.equal(repeatedApproval.implementationStatus, 'SERVER_IMPLEMENTED');
  assert.equal(repeatedApproval.scope, 'CURRENT_WINDOWS_ACCEPTANCE_TEST');
  assert.equal(repeatedApproval.implementationEvidence, 'SERVER_PROTOCOL_REGRESSION_ONLY');
  assert.equal(repeatedApproval.subjectCompatibility, 'NOT_VERIFIED');
  assert.equal(repeatedApproval.outcome, 'NOT_RUN');
  assert.doesNotMatch(JSON.stringify(plan), /SYNTHETIC_PRIVATE_VALUE|private-A|private-B|private-O/);
  assert.equal(JSON.stringify(plan).includes(root), false);
  for (const role of ['A', 'B', 'O']) assert.deepEqual(fs.readFileSync(files[role]), originals[role]);
  assert.throws(() => tool.WritePlan(files, output), /EEXIST/);
});
test('wrong role sets, duplicate files, non-PEs and relative paths are rejected', () => {
  assert.throws(() => tool.Plan({ A: files.A, B: files.B }), /THREE_ROLES_REQUIRED/);
  assert.throws(() => tool.Plan({ ...files, B: files.A }), /DISTINCT_ROLE_FILES_REQUIRED/);
  assert.throws(() => tool.Plan({ ...files, A: 'relative.exe' }), /ABSOLUTE_PATH_REQUIRED/);
  const invalid = path.join(root, 'invalid.exe'); fs.writeFileSync(invalid, 'not a PE');
  assert.throws(() => tool.Plan({ ...files, A: invalid }), /PE64_REQUIRED/);
});
test('existing inputs cannot be overwritten by an output path', () => {
  assert.throws(() => tool.WritePlan(files, files.A), /EEXIST/);
  assert.deepEqual(fs.readFileSync(files.A), originals.A);
});
test('symlinked file and directory inputs are rejected', { skip: process.platform === 'win32' }, () => {
  const linked = path.join(root, 'linked.exe'); fs.symlinkSync(files.A, linked);
  assert.throws(() => tool.Plan({ ...files, A: linked }), /SYMLINK_FORBIDDEN/);
  const linkdir = path.join(root, 'linked-directory'); fs.symlinkSync(root, linkdir);
  assert.throws(() => tool.WritePlan(files, path.join(linkdir, 'other.json')), /SYMLINK_FORBIDDEN/);
});
test.after(() => fs.rmSync(root, { recursive: true, force: true }));
