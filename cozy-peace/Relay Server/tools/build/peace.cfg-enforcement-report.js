'use strict';
// Acceptance policy for the standalone SDK probe. This report never attests A/B/O.
const fs = require('node:fs');
const crypto = require('node:crypto');

function requireTrue(condition, code) {
  if (!condition) throw Object.assign(new Error(code), { code });
}
function validateNative(report, exitCode) {
  requireTrue(report && report.version === 1 && report.kind === 'CFG_ENFORCEMENT_PROBE', 'CFG_PROBE_SCHEMA');
  requireTrue(report.scope === 'MSVC_PROBE_ONLY' && report.productionCoverage === false, 'CFG_PROBE_SCOPE');
  requireTrue(Array.isArray(report.cases) && report.cases.length === 3, 'CFG_PROBE_CASES');
  const ids = ['guarded-valid-target', 'guarded-invalid-target', 'unguarded-invalid-target'];
  for (let i = 0; i < ids.length; i++) {
    const value = report.cases[i];
    requireTrue(value && value.id === ids[i], 'CFG_PROBE_CASE_ORDER');
    requireTrue(value.launched === true && value.ready === true && value.exited === true &&
      value.policyQuerySucceeded === true && value.timedOut === false &&
      value.unexpectedException === 0 && value.win32Error === 0, 'CFG_PROBE_EXECUTION');
    requireTrue(typeof value.controlFlowGuardEnabled === 'boolean', 'CFG_PROBE_POLICY_RESULT');
    if (i < 2) requireTrue(value.controlFlowGuardEnabled === true, 'CFG_PROBE_DISABLED');
    if (i === 1) {
      requireTrue(value.exitCode === 0xC0000409 && value.exceptionCode === 0xC0000409 &&
        value.secondChance === true && value.fastFailCode === 10 && value.expectedExceptionCount === 1,
      'CFG_PROBE_EXACT_FAILFAST_REQUIRED');
    } else {
      requireTrue(value.exitCode === 0 && value.exceptionCode === 0 && value.secondChance === false &&
        value.expectedExceptionCount === 0, 'CFG_PROBE_CONTROL_FAILED');
    }
  }
  requireTrue(report.outcome === 'PASS' && exitCode === 0, 'CFG_PROBE_NATIVE_FAILED');
  return true;
}
function validateBinding(report) {
  requireTrue(report && report.version === 1 && report.kind === 'CFG_RUNTIME_ENFORCEMENT' &&
    report.scope === 'MSVC_PROBE_ONLY' && report.windowsExecuted === true && report.productionCfgCoverage === false &&
    report.publicationApproval === false, 'CFG_BINDING_SCOPE');
  validateNative(report.nativeReport, report.nativeExitCode);
  const expected = ['source', 'compiler', 'linker', 'guardedProbe', 'unguardedProbe'];
  requireTrue(report.bindings && typeof report.bindings === 'object', 'CFG_BINDING_MISSING');
  for (const name of expected) {
    const entry = report.bindings[name];
    requireTrue(entry && typeof entry.path === 'string' && /^[a-f0-9]{128}$/.test(entry.sha512), 'CFG_BINDING_HASH');
    const actual = crypto.createHash('sha512').update(fs.readFileSync(entry.path)).digest('hex');
    requireTrue(actual === entry.sha512, 'CFG_BINDING_FILE_CHANGED');
  }
  requireTrue(Array.isArray(report.stages) && report.stages.length === 4 &&
    report.stages.every((stage, i) => stage &&
      stage.id === ['compile-guarded', 'link-guarded', 'compile-control', 'link-control'][i] &&
      stage.exitCode === 0), 'CFG_BUILD_STAGES');
  requireTrue(report.outcome === 'PASS', 'CFG_BINDING_OUTCOME');
  return true;
}
if (require.main === module) {
  try {
    requireTrue(process.argv.length === 3, 'CFG_REPORT_PATH_REQUIRED');
    const file = JSON.parse(fs.readFileSync(process.argv[2], 'utf8').replace(/^\uFEFF/, ''));
    validateBinding(file);
    process.stdout.write('CFG_RUNTIME_PROBE_PASS_MSVC_ONLY_NOT_PRODUCTION_ATTESTATION\n');
  } catch (error) {
    process.stderr.write((error.code || 'CFG_REPORT_VALIDATION_FAILED') + '\n');
    process.exitCode = 1;
  }
}
module.exports = { validateNative, validateBinding };
