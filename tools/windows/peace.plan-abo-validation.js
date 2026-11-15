'use strict';
// Static planning only. Never launches a program, calls a server, changes an
// issuance, or converts an operator worksheet into execution evidence.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Read } = require('../../services/artifacts/peace.bounded-artifact-read');
const ROLES = Object.freeze(['A', 'B', 'O']);
const CASES = Object.freeze([
  ['happy-path', 'A_TO_B_TO_O', 'normal-flow-and-owned-cleanup'],
  ['issued-a-replay', 'A', 'same-issued-bytes-second-run-refused'],
  ['approval-pending', 'A', 'no-b-before-explicit-approval'],
  ['approval-rejected', 'A', 'rejection-ends-flow-without-b'],
  ['approval-each-new-issuance', 'A', 'previous-approval-does-not-approve-new-issuance'],
  ['device-blocked', 'A_TO_B_TO_O', 'blocked-device-cannot-start-or-renew-authority'],
  ['network-before-handoff', 'A_TO_B', 'bounded-failure-with-no-authorized-b'],
  ['network-after-handoff', 'B_TO_O', 'lease-expiry-and-actual-process-exit-observed-separately'],
  ['owned-cleanup', 'A_TO_B_TO_O', 'own-file-removal-and-unrelated-sentinel-preservation']
]);
function Fail(code) { throw Error('ABO_VALIDATION_PLAN_' + code); }
function NoLinks(file, parentOnly = false) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) Fail('ABSOLUTE_PATH_REQUIRED');
  const full = path.resolve(file), target = parentOnly ? path.dirname(full) : full;
  let at = path.parse(target).root;
  for (const part of target.slice(at.length).split(path.sep).filter(Boolean)) {
    at = path.join(at, part);
    if (fs.lstatSync(at).isSymbolicLink()) Fail('SYMLINK_FORBIDDEN');
  }
  return full;
}
function Inspect(file) {
  const bytes = Read(NoLinks(file), 64 * 1024 * 1024);
  try {
    // Header identification is not a release, signature or executable-safety verdict.
    if (bytes.length < 64 || bytes.readUInt16LE(0) !== 0x5a4d) Fail('PE64_REQUIRED');
    const pe = bytes.readUInt32LE(60);
    if (pe < 64 || pe > bytes.length - 26 || bytes.readUInt32LE(pe) !== 0x4550 ||
        bytes.readUInt16LE(pe + 4) !== 0x8664 || bytes.readUInt16LE(pe + 24) !== 0x20b) Fail('PE64_REQUIRED');
    return { sha512: crypto.createHash('sha512').update(bytes).digest('hex'), size: bytes.length,
      header: 'PE32+_AMD64', roleAuthenticity: 'NOT_VERIFIED', signature: 'NOT_CHECKED' };
  } finally { bytes.fill(0); }
}
function Plan(files) {
  if (!files || typeof files !== 'object' || Array.isArray(files) || Object.keys(files).sort().join(',') !== 'A,B,O') Fail('THREE_ROLES_REQUIRED');
  const subjects = Object.fromEntries(ROLES.map(role => [role, Inspect(files[role])]));
  if (new Set(ROLES.map(role => subjects[role].sha512)).size !== 3) Fail('DISTINCT_ROLE_FILES_REQUIRED');
  return { version: 1, kind: 'ABO_WINDOWS_VALIDATION_PLAN', createdAt: new Date().toISOString(),
    outcome: 'NOT_RUN', executionPerformed: false, productionApproved: false,
    sourceBuildAttested: false, serverStateQueried: false,
    scope: 'STATIC_PLAN_ONLY_NOT_EXECUTION_EVIDENCE', subjects,
    scenarios: CASES.map(([id, roles, expectation]) => ({ id, roles, expectation, outcome: 'NOT_RUN',
      ...(id === 'approval-each-new-issuance' ? { implementationStatus: 'SERVER_IMPLEMENTED', scope: 'CURRENT_WINDOWS_ACCEPTANCE_TEST', implementationEvidence: 'SERVER_PROTOCOL_REGRESSION_ONLY', subjectCompatibility: 'NOT_VERIFIED' } : {}),
      serverObservation: 'NOT_OBSERVED', processObservation: 'NOT_OBSERVED', fileObservation: 'NOT_OBSERVED' })) };
}
function WritePlan(files, output) {
  const target = NoLinks(output, true);
  const plan = Plan(files);
  fs.writeFileSync(target, JSON.stringify(plan, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return plan;
}
module.exports = { Plan, WritePlan, CASES };
if (require.main === module) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 4) Fail('USAGE_A_B_O_NEW_OUTPUT_REQUIRED');
    WritePlan({ A: args[0], B: args[1], O: args[2] }, args[3]);
    process.stdout.write('ABO_VALIDATION_PLAN_CREATED; WINDOWS_EXECUTION_NOT_RUN\n');
  } catch (error) {
    const code = typeof error?.message === 'string' && /^ABO_VALIDATION_PLAN_[A-Z0-9_]+$/.test(error.message) ? error.message : 'ABO_VALIDATION_PLAN_FAILED';
    process.stderr.write(code + '\n');
    process.exitCode = 1;
  }
}
