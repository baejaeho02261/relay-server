'use strict';

// This is a completion-evidence gate, not a sensor and not a publisher. It never
// runs A/B/O, changes policy, or turns a source-pattern check into runtime proof.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROLES = Object.freeze(['A', 'B', 'O']);
const IDLE_MINIMUM_MS = 2 * 60 * 60 * 1000;
const SHUTDOWN_MAXIMUM_MS = 4000;
const SHA512 = /^[a-f0-9]{128}$/;
const CHECKS = Object.freeze([
  ...ROLES.map(role => ({ id: `build-${role}`, kind: 'RAD13_BUILD', role })),
  { id: 'native-regressions', kind: 'NATIVE_SUITE' },
  ...ROLES.map(role => ({ id: `guard-idle-${role}`, kind: 'NHW_GUARD_RUN', role })),
  { id: 'overlay-visible', kind: 'ABO_VISIBLE_RUN' },
  { id: 'observer', kind: 'NATIVE_OBSERVER_RUN' },
  { id: 'response-paths', kind: 'NATIVE_RESPONSE_PATH_RUN' },
  { id: 'tpm-quote', kind: 'HARDWARE_TPM_QUOTE_RUN' },
  { id: 'normal-game', kind: 'NORMAL_GAME_RUN' },
  { id: 'normal-anticheat', kind: 'NORMAL_ANTICHEAT_RUN' },
  { id: 'cleanup-delay', kind: 'NATIVE_CLEANUP_RUN' },
]);

function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function integer(value, min = 0) { return Number.isSafeInteger(value) && value >= min; }
function digest(bytes) { return crypto.createHash('sha512').update(bytes).digest('hex'); }
function equal(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

function RequiredNativeCases() {
  const file = path.resolve(__dirname, '../../../Railway/Cozy.Tests/Cozy.NHW/Cozy.NHW.Validation/Cozy.NHW.Validation.Catalog.inc');
  const text = fs.readFileSync(file, 'utf8');
  const count = Number(text.match(/VALIDATION_TEST_COUNT\s*=\s*(\d+)/)?.[1]);
  const names = [...text.matchAll(/'(Cozy\.NHW\.[A-Za-z0-9.]+)'/g)].map(match => match[1]);
  if (count !== names.length || count < 79 || new Set(names).size !== count) throw Error('NATIVE_CATALOG_INVALID');
  // The retained upstream catalog contains its original 79 cases. This
  // integration regression is additional and must have real execution proof.
  return [...names, 'Cozy.NHW.DetectionJournal'];
}

function hashArtifacts(value) {
  if (!object(value) || Object.keys(value).length !== 3) return false;
  return ROLES.every(role => SHA512.test(value[role] || ''));
}

function validateBinding(value) {
  return object(value) && SHA512.test(value.sourceSha512 || '') && hashArtifacts(value.artifacts);
}

function readBoundFile(root, file, expected, maxBytes) {
  if (typeof file !== 'string' || !file || path.isAbsolute(file) || !SHA512.test(expected || '')) {
    throw Error('EVIDENCE_FILE_BINDING_INVALID');
  }
  const target = path.resolve(root, file);
  const relative = path.relative(root, target);
  if (relative.startsWith('..' + path.sep) || relative === '..' || path.isAbsolute(relative)) {
    throw Error('EVIDENCE_PATH_ESCAPES_ROOT');
  }
  const stat = fs.lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0 || stat.size > maxBytes) {
    throw Error('EVIDENCE_FILE_INVALID');
  }
  const real = fs.realpathSync(target);
  const realRelative = path.relative(fs.realpathSync(root), real);
  if (realRelative.startsWith('..' + path.sep) || realRelative === '..' || path.isAbsolute(realRelative)) {
    throw Error('EVIDENCE_LINK_ESCAPES_ROOT');
  }
  const bytes = fs.readFileSync(target);
  if (digest(bytes) !== expected) throw Error('EVIDENCE_DIGEST_MISMATCH');
  return bytes;
}

function sharedErrors(report, definition, binding) {
  const errors = [];
  if (!object(report)) return ['REPORT_INVALID'];
  if (report.schema !== 'COZY_NHW_EXECUTION_EVIDENCE_V1') errors.push('REPORT_SCHEMA_INVALID');
  if (report.id !== definition.id || report.kind !== definition.kind) errors.push('REPORT_SCOPE_MISMATCH');
  if (!equal(report.binding, binding)) errors.push('REPORT_SUBJECT_MISMATCH');
  if (report.platform !== 'win32' || report.architecture !== 'x64') errors.push('WINDOWS_WIN64_REQUIRED');
  if (report.execution !== 'ACTUAL' || report.synthetic !== false) errors.push('ACTUAL_EXECUTION_REQUIRED');
  if (report.sourceChecksOnly !== false) errors.push('SOURCE_CHECK_NOT_RUNTIME_EVIDENCE');
  if (report.outcome !== 'PASS' || report.exitCode !== 0) errors.push('EXECUTION_NOT_SUCCESSFUL');
  if (typeof report.runId !== 'string' || !/^[a-f0-9]{32}$/.test(report.runId)) errors.push('RUN_BINDING_REQUIRED');
  if (!integer(report.startedAt, 1) || !integer(report.finishedAt, report.startedAt)) errors.push('EXECUTION_TIME_INVALID');
  if (definition.role && report.role !== definition.role) errors.push('ROLE_MISMATCH');
  return errors;
}

function caseErrors(report, definition) {
  const errors = [];
  const require = (ok, code) => { if (!ok) errors.push(code); };
  switch (definition.kind) {
    case 'RAD13_BUILD':
      require(report.compiler === 'dcc64' && /^37\./.test(report.compilerVersion || ''), 'RAD_STUDIO_13_REQUIRED');
      require(report.configuration === 'Release' && report.rebuild === true, 'WIN64_RELEASE_REBUILD_REQUIRED');
      require(report.nativeBuild === true && report.artifactSha512 === report.binding.artifacts[definition.role], 'BUILT_ARTIFACT_MISMATCH');
      require(integer(report.compilerErrors) && report.compilerErrors === 0, 'COMPILER_ERRORS_PRESENT');
      break;
    case 'NATIVE_SUITE':
      require(Array.isArray(report.cases) && report.cases.length >= RequiredNativeCases().length, 'NATIVE_SUITE_INCOMPLETE');
      if (Array.isArray(report.cases)) {
        require(new Set(report.cases.map(row => row?.name)).size === report.cases.length, 'DUPLICATE_NATIVE_CASE');
        require(report.cases.every(row => object(row) && typeof row.name === 'string' && row.name.startsWith('Cozy.NHW.') &&
          row.executed === true && row.exitCode === 0 && row.skipped === false && row.timedOut === false && SHA512.test(row.binarySha512 || '')), 'NATIVE_CASE_NOT_EXECUTED');
      }
      require(RequiredNativeCases().every(name => report.cases?.some(row => row.name === name)), 'REQUIRED_NATIVE_CASE_MISSING');
      break;
    case 'NHW_GUARD_RUN':
      require(report.scope === 'SHARED_NHW_GUARD' && report.fullEngine === true, 'FULL_GUARD_REQUIRED');
      require(integer(report.requestedDurationMs, IDLE_MINIMUM_MS) && integer(report.durationMs, report.requestedDurationMs), 'IDLE_DURATION_INCOMPLETE');
      require(integer(report.kernelSamples, 2) && report.staleKernelSamples === 0 && report.falsePositiveConfirmed === false, 'IDLE_OBSERVATION_FAILED');
      require(integer(report.shutdownMs) && report.shutdownMs <= SHUTDOWN_MAXIMUM_MS, 'GUARD_SHUTDOWN_TOO_SLOW');
      require(report.nativeExited === true && report.ownedJobDrained === true && report.forcedTermination === false, 'GUARD_CLEANUP_NOT_OBSERVED');
      require(report.observerChildStarted === true && report.observerExitObserved === true && report.observerForcedTermination === false,
        'OBSERVER_GRACEFUL_CLEANUP_NOT_OBSERVED');
      break;
    case 'ABO_VISIBLE_RUN':
      require(report.scope === 'ACTUAL_ABO' && report.authenticatedHandoff === true && report.firstFramePresented === true &&
        report.visibleWindowObserved === true && report.overlayAuthorityActive === true, 'VISIBLE_AUTHORIZED_OVERLAY_NOT_OBSERVED');
      require(report.rolesWithFullEngine?.length === 3 && ROLES.every(role => report.rolesWithFullEngine.includes(role)), 'ABO_FULL_ENGINE_NOT_OBSERVED');
      require(report.abruptExit === false, 'OVERLAY_ABRUPT_EXIT');
      break;
    case 'NATIVE_OBSERVER_RUN':
      require(report.authenticatedChild === true && report.freshHeartbeat === true && report.wrongParentRejected === true &&
        report.replayRejected === true && report.ownedChildExited === true, 'OBSERVER_RUNTIME_INCOMPLETE');
      break;
    case 'NATIVE_RESPONSE_PATH_RUN': {
      require(Array.isArray(report.paths) && report.paths.length === 3, 'RESPONSE_PATHS_INCOMPLETE');
      for (const channel of ['trust', 'driver', 'integrity']) {
        const row = report.paths?.find(value => value.channel === channel);
        require(object(row) && row.nativeSent === true && row.serverReceived === true && row.signatureVerified === true &&
          row.sameSession === true && row.otherTwoDisabled === true && row.replayRejected === true && row.localReceiptRetained === true,
          `RESPONSE_PATH_${channel.toUpperCase()}_NOT_INDEPENDENT`);
      }
      break;
    }
    case 'HARDWARE_TPM_QUOTE_RUN':
      require(report.hardwareTpm === true && report.softwareTpm === false && report.quoteSignatureVerified === true &&
        report.attestationKeyVerified === true && report.pcrDigestVerified === true && report.nhwEvidenceNonceBound === true &&
        report.measuredBootDigestBound === true && report.replayRejected === true, 'HARDWARE_TPM_QUOTE_INCOMPLETE');
      require(report.scope === 'TPM_QUOTE_ONLY' && report.bootHealthVerified === false, 'TPM_QUOTE_SCOPE_MUST_NOT_CLAIM_BOOT_HEALTH');
      break;
    case 'NORMAL_GAME_RUN':
    case 'NORMAL_ANTICHEAT_RUN':
      require(report.scope === 'ACTUAL_ABO' && typeof report.product === 'string' && report.product.trim().length > 0,
        'NORMAL_ENVIRONMENT_NOT_IDENTIFIED');
      require(integer(report.durationMs, 15 * 60 * 1000) && report.falsePositiveConfirmed === false &&
        report.sessionStayedAuthorized === true && report.protectedGameModified === false, 'NORMAL_ENVIRONMENT_TEST_INCOMPLETE');
      if (definition.kind === 'NORMAL_ANTICHEAT_RUN') require(report.driverLoadObserved === true && report.driverUnloadObserved === true,
        'NORMAL_DRIVER_LIFECYCLE_NOT_OBSERVED');
      break;
    case 'NATIVE_CLEANUP_RUN':
      require(report.scope === 'ACTUAL_ABO' && report.ownedProcessesExited === true && report.ownedResourcesReleased === true &&
        report.serverSessionEnded === true && report.unrelatedResourcesUntouched === true, 'ACTUAL_CLEANUP_INCOMPLETE');
      for (const name of ['wmi-delay', 'wmi-unavailable', 'etw-drain', 'etw-unavailable']) {
        const row = report.cases?.find(value => value.name === name);
        require(object(row) && row.executed === true && row.controlledOwnDependency === true && integer(row.shutdownMs) &&
          row.shutdownMs <= SHUTDOWN_MAXIMUM_MS && row.forcedTermination === false, `CLEANUP_${name.toUpperCase()}_INCOMPLETE`);
      }
      break;
  }
  return errors;
}

function Evaluate(manifest, root) {
  const result = { schema: 'COZY_NHW_COMPLETION_GATE_V1', outcome: 'INCOMPLETE', complete: false, evidenceComplete: false,
    nativeExecutedByGate: false, checks: [], evidenceScope: 'Recorded evidence only. Hashes bind bytes, not their truth. External execution observations require review.' };
  if (!object(manifest) || manifest.schema !== 'COZY_NHW_EVIDENCE_SET_V1' || !validateBinding(manifest.binding)) {
    return { ...result, reason: 'EVIDENCE_SET_BINDING_MISSING_OR_INVALID' };
  }
  result.binding = manifest.binding;
  const entries = Array.isArray(manifest.reports) ? manifest.reports : [];
  const known = new Set(CHECKS.map(check => check.id));
  if (entries.some(row => !object(row) || !known.has(row.id)) || new Set(entries.map(row => row.id)).size !== entries.length) {
    return { ...result, outcome: 'FAIL', reason: 'DUPLICATE_OR_UNKNOWN_REPORT' };
  }
  for (const definition of CHECKS) {
    const entry = entries.find(row => row.id === definition.id);
    if (!entry) { result.checks.push({ id: definition.id, outcome: 'MISSING', reasons: ['ACTUAL_EVIDENCE_NOT_PROVIDED'] }); continue; }
    try {
      const bytes = readBoundFile(root, entry.file, entry.sha512, 8 * 1024 * 1024);
      const report = JSON.parse(bytes.toString('utf8'));
      const errors = sharedErrors(report, definition, manifest.binding);
      if (errors.length === 0) errors.push(...caseErrors(report, definition));
      // A report is never sufficient by itself: retain exact raw execution
      // output separately, hash it, and require bytes from this run.
      if (!Array.isArray(report.rawEvidence) || report.rawEvidence.length === 0) errors.push('RAW_EXECUTION_EVIDENCE_MISSING');
      else for (const raw of report.rawEvidence) {
        if (!object(raw)) throw Error('RAW_EXECUTION_EVIDENCE_INVALID');
        readBoundFile(root, raw.file, raw.sha512, 64 * 1024 * 1024);
      }
      result.checks.push({ id: definition.id, outcome: errors.length ? 'FAIL' : 'REVIEW_REQUIRED', reasons: errors, evidenceSha512: entry.sha512 });
    } catch (error) {
      result.checks.push({ id: definition.id, outcome: 'FAIL', reasons: [error.code === 'ENOENT' ? 'EVIDENCE_FILE_MISSING' : error.message] });
    }
  }
  result.evidenceComplete = result.checks.every(check => check.outcome === 'REVIEW_REQUIRED');
  result.outcome = result.evidenceComplete ? 'REVIEW_REQUIRED' : result.checks.some(check => check.outcome === 'FAIL') ? 'FAIL' : 'INCOMPLETE';
  return result;
}

function main(args) {
  if (args.length !== 1) {
    console.error('Usage: node tools/runtime/peace.nhw-validation-gate.js <evidence-set.json>');
    return 2;
  }
  const file = path.resolve(args[0]);
  let result;
  try { result = Evaluate(JSON.parse(fs.readFileSync(file, 'utf8')), path.dirname(file)); }
  catch (error) { result = { outcome: 'INCOMPLETE', complete: false, reason: error.code || 'EVIDENCE_SET_UNREADABLE', nativeExecutedByGate: false }; }
  console.log(JSON.stringify(result, null, 2));
  return result.evidenceComplete ? 3 : 2;
}

module.exports = { Evaluate, CHECKS, IDLE_MINIMUM_MS, SHUTDOWN_MAXIMUM_MS, RequiredNativeCases, sharedErrors, caseErrors, digest };
if (require.main === module) process.exitCode = main(process.argv.slice(2));
