'use strict';

// These are synthetic validator tests. No Windows program or TPM is executed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const gate = require('../../tools/runtime/peace.nhw-validation-gate');
const runtime = require('../../tools/runtime/peace.run-nhw-runtime-probe');
const binding = { sourceSha512: 'a'.repeat(128), artifacts: { A: 'b'.repeat(128), B: 'c'.repeat(128), O: 'd'.repeat(128) } };
let checks = 0;
function test(name, run) { run(); checks++; console.log('PASS validator: ' + name); }
function makeReport(definition) {
  const report = { schema: 'COZY_NHW_EXECUTION_EVIDENCE_V1', id: definition.id, kind: definition.kind,
    binding, platform: 'win32', architecture: 'x64', execution: 'ACTUAL', synthetic: false,
    sourceChecksOnly: false, outcome: 'PASS', exitCode: 0, runId: 'e'.repeat(32), startedAt: 1000, finishedAt: 9000000,
    rawEvidence: [{ file: 'raw.log', sha512: gate.digest(Buffer.from('SYNTHETIC VALIDATOR FIXTURE; NOT EXECUTION PROOF')) }] };
  if (definition.role) report.role = definition.role;
  switch (definition.kind) {
    case 'RAD13_BUILD': Object.assign(report, { compiler: 'dcc64', compilerVersion: '37.0.1', configuration: 'Release', rebuild: true,
      nativeBuild: true, compilerErrors: 0, artifactSha512: binding.artifacts[definition.role] }); break;
    case 'NATIVE_SUITE': report.cases = gate.RequiredNativeCases().map(name => ({ name, executed: true, skipped: false, timedOut: false,
      exitCode: 0, binarySha512: 'f'.repeat(128) })); break;
    case 'NHW_GUARD_RUN': Object.assign(report, { scope: 'SHARED_NHW_GUARD', fullEngine: true, requestedDurationMs: gate.IDLE_MINIMUM_MS,
      durationMs: gate.IDLE_MINIMUM_MS + 50, kernelSamples: 72000, staleKernelSamples: 0, falsePositiveConfirmed: false,
      shutdownMs: 125, nativeExited: true, ownedJobDrained: true, forcedTermination: false,
      observerChildStarted: true, observerExitObserved: true, observerForcedTermination: false, observerShutdownMs: 50 }); break;
    case 'ABO_VISIBLE_RUN': Object.assign(report, { scope: 'ACTUAL_ABO', authenticatedHandoff: true, firstFramePresented: true,
      visibleWindowObserved: true, overlayAuthorityActive: true, rolesWithFullEngine: ['A', 'B', 'O'], abruptExit: false }); break;
    case 'NATIVE_OBSERVER_RUN': Object.assign(report, { authenticatedChild: true, freshHeartbeat: true, wrongParentRejected: true,
      replayRejected: true, ownedChildExited: true }); break;
    case 'NATIVE_RESPONSE_PATH_RUN': report.paths = ['trust', 'driver', 'integrity'].map(channel => ({ channel, nativeSent: true,
      serverReceived: true, signatureVerified: true, sameSession: true, otherTwoDisabled: true, replayRejected: true, localReceiptRetained: true })); break;
    case 'HARDWARE_TPM_QUOTE_RUN': Object.assign(report, { hardwareTpm: true, softwareTpm: false, quoteSignatureVerified: true,
      attestationKeyVerified: true, pcrDigestVerified: true, nhwEvidenceNonceBound: true, measuredBootDigestBound: true,
      scope: 'TPM_QUOTE_ONLY', bootHealthVerified: false, replayRejected: true }); break;
    case 'NORMAL_GAME_RUN':
    case 'NORMAL_ANTICHEAT_RUN': Object.assign(report, { scope: 'ACTUAL_ABO', product: 'Validator fixture, not installed', durationMs: 900000,
      falsePositiveConfirmed: false, sessionStayedAuthorized: true, protectedGameModified: false, driverLoadObserved: true, driverUnloadObserved: true }); break;
    case 'NATIVE_CLEANUP_RUN': Object.assign(report, { scope: 'ACTUAL_ABO', ownedProcessesExited: true, ownedResourcesReleased: true,
      serverSessionEnded: true, unrelatedResourcesUntouched: true,
      cases: ['wmi-delay', 'wmi-unavailable', 'etw-drain', 'etw-unavailable'].map(name => ({ name, executed: true,
        controlledOwnDependency: true, shutdownMs: 250, forcedTermination: false })) }); break;
  }
  return report;
}
function withFixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cozy-nhw-gate-'));
  try {
    fs.writeFileSync(path.join(root, 'raw.log'), 'SYNTHETIC VALIDATOR FIXTURE; NOT EXECUTION PROOF');
    const reports = gate.CHECKS.map(makeReport);
    const manifest = { schema: 'COZY_NHW_EVIDENCE_SET_V1', binding, reports: [] };
    const save = report => {
      const bytes = Buffer.from(JSON.stringify(report));
      const file = report.id + '.json'; fs.writeFileSync(path.join(root, file), bytes);
      const entry = { id: report.id, file, sha512: gate.digest(bytes) };
      const index = manifest.reports.findIndex(row => row.id === report.id);
      if (index < 0) manifest.reports.push(entry); else manifest.reports[index] = entry;
    };
    reports.forEach(save);
    run({ root, reports, manifest, save, evaluate: () => gate.Evaluate(manifest, root) });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test('an absent evidence set cannot pass', () => {
  for (const value of [null, {}, { complete: true }, { schema: 'COZY_NHW_EVIDENCE_SET_V1', binding: {} }]) {
    const result = gate.Evaluate(value, os.tmpdir()); assert.equal(result.complete, false); assert.equal(result.outcome, 'INCOMPLETE');
  }
});
test('every required evidence category is missing when only binding exists', () => {
  const result = gate.Evaluate({ schema: 'COZY_NHW_EVIDENCE_SET_V1', binding }, os.tmpdir());
  assert.equal(result.checks.length, 14); assert(result.checks.every(row => row.outcome === 'MISSING'));
  assert.equal(result.outcome, 'INCOMPLETE');
});
test('even a fully populated synthetic example never becomes runtime-complete or PASS', () => withFixture(({ evaluate }) => {
  const result = evaluate(); assert.equal(result.evidenceComplete, true); assert.equal(result.complete, false);
  assert.equal(result.outcome, 'REVIEW_REQUIRED'); assert.equal(result.nativeExecutedByGate, false);
  assert(result.checks.every(row => row.outcome === 'REVIEW_REQUIRED'));
}));
test('every missing category leaves the completion gate closed', () => withFixture(({ manifest, evaluate }) => {
  const all = [...manifest.reports];
  for (const entry of all) {
    manifest.reports = all.filter(row => row !== entry);
    const result = evaluate(); assert.equal(result.evidenceComplete, false); assert.equal(result.complete, false);
    assert.equal(result.checks.find(row => row.id === entry.id).outcome, 'MISSING');
  }
}));
for (const [name, mutate] of Object.entries({
  linux: report => { report.platform = 'linux'; },
  sourceCheck: report => { report.sourceChecksOnly = true; },
  skipped: report => { report.execution = 'NOT_RUN'; },
  fixture: report => { report.synthetic = true; },
  changedSource: report => { report.binding = { ...binding, sourceSha512: '1'.repeat(128) }; },
  fail: report => { report.exitCode = 1; },
  noRawEvidence: report => { report.rawEvidence = []; },
  wrongRole: report => { report.role = 'O'; },
  unboundRun: report => { delete report.runId; },
})) test(name + ' cannot be accepted as Windows build evidence', () => withFixture(({ reports, save, evaluate }) => {
  mutate(reports[0]); save(reports[0]); const result = evaluate(); assert.equal(result.outcome, 'FAIL'); assert.equal(result.evidenceComplete, false);
}));
const negatives = [
  ['build-A', r => { r.compilerVersion = '36.0'; }, 'wrong compiler'],
  ['build-B', r => { r.configuration = 'Debug'; }, 'debug build'],
  ['native-regressions', r => { r.cases.pop(); }, 'missing native case'],
  ['native-regressions', r => { r.cases = r.cases.filter(row => row.name !== 'Cozy.NHW.DetectionJournal'); }, 'missing detection journal regression'],
  ['native-regressions', r => { r.cases[0].name = 'Cozy.NHW.MadeUp'; }, 'substituted native case'],
  ['native-regressions', r => { r.cases[0].skipped = true; }, 'skipped native case'],
  ['guard-idle-A', r => { r.durationMs = 60000; }, 'short idle'],
  ['guard-idle-B', r => { r.falsePositiveConfirmed = true; }, 'idle false positive'],
  ['guard-idle-O', r => { r.shutdownMs = 4001; }, 'slow shutdown'],
  ['guard-idle-B', r => { r.forcedTermination = true; }, 'forced process termination'],
  ['guard-idle-B', r => { r.observerForcedTermination = true; }, 'inner observer forced stop despite clean outer job'],
  ['guard-idle-A', r => { r.observerExitObserved = false; }, 'unobserved observer exit despite clean outer job'],
  ['guard-idle-O', r => { r.observerChildStarted = false; }, 'observer never started'],
  ['guard-idle-B', r => { delete r.observerForcedTermination; }, 'missing observer cleanup evidence'],
  ['guard-idle-A', r => { r.kernelSamples = 0; }, 'no actual engine cycle'],
  ['overlay-visible', r => { r.firstFramePresented = false; }, 'no first frame'],
  ['overlay-visible', r => { r.rolesWithFullEngine = ['B']; }, 'role subset'],
  ['observer', r => { r.freshHeartbeat = false; }, 'observer absent'],
  ['response-paths', r => { r.paths[0].otherTwoDisabled = false; }, 'shared response path only'],
  ['response-paths', r => { r.paths[1].serverReceived = false; }, 'undelivered driver response'],
  ['tpm-quote', r => { r.softwareTpm = true; }, 'software TPM'],
  ['tpm-quote', r => { r.pcrDigestVerified = false; }, 'WBCL hash without Quote'],
  ['tpm-quote', r => { r.bootHealthVerified = true; }, 'unsupported boot-health claim'],
  ['normal-game', r => { r.durationMs = 1000; }, 'game not observed long enough'],
  ['normal-anticheat', r => { r.driverUnloadObserved = false; }, 'normal driver lifecycle missing'],
  ['cleanup-delay', r => { r.cases.pop(); }, 'ETW unavailable path missing'],
  ['cleanup-delay', r => { r.cases[0].shutdownMs = 4001; }, 'unbounded WMI cleanup'],
];
for (const [id, mutate, name] of negatives) test(name + ' remains incomplete or failed', () => withFixture(({ reports, save, evaluate }) => {
  const report = reports.find(row => row.id === id); mutate(report); save(report);
  assert.equal(evaluate().checks.find(row => row.id === id).outcome, 'FAIL');
}));
test('modified evidence bytes fail exact digest binding', () => withFixture(({ root, evaluate }) => {
  fs.appendFileSync(path.join(root, 'raw.log'), 'modified'); assert.equal(evaluate().outcome, 'FAIL');
}));
test('duplicate reports cannot satisfy missing cases', () => withFixture(({ manifest, evaluate }) => {
  manifest.reports.push(manifest.reports[0]); assert.equal(evaluate().reason, 'DUPLICATE_OR_UNKNOWN_REPORT');
}));
test('paths outside evidence root are never read', () => withFixture(({ manifest, evaluate }) => {
  manifest.reports[0].file = '../outside.json';
  assert(evaluate().checks[0].reasons.includes('EVIDENCE_PATH_ESCAPES_ROOT'));
}));
test('CLI does not silently succeed for absent or review-only evidence', () => withFixture(({ root, manifest }) => {
  const script = path.resolve(__dirname, '../../tools/runtime/peace.nhw-validation-gate.js');
  assert.equal(spawnSync(process.execPath, [script, path.join(root, 'missing.json')]).status, 2);
  const file = path.join(root, 'set.json'); fs.writeFileSync(file, JSON.stringify(manifest));
  const result = spawnSync(process.execPath, [script, file], { encoding: 'utf8' });
  assert.equal(result.status, 3); assert.equal(JSON.parse(result.stdout).complete, false);
}));
function outputFixture() {
  const common = { schema: 'COZY_NHW_RUNTIME_PROBE_V1', role: 'B', scope: 'SHARED_NHW_GUARD', platform: 'win32', architecture: 'x64' };
  return [
    { ...common, event: 'started', requestedDurationMs: 10000, fullEngine: true },
    { ...common, event: 'shutdown-begin' },
    { ...common, event: 'guard-result', requestedDurationMs: 10000, durationMs: 10050, shutdownMs: 120,
      kernelSamples: 17, staleKernelSamples: 0, falsePositiveConfirmed: false, durationReached: true,
      startupFailed: false, cancelled: false, exitCode: 0, actualAboExecuted: false,
      observerChildStarted: true, observerExitObserved: true, observerForcedTermination: false, observerShutdownMs: 25 },
    { ...common, event: 'parent-result', nativeExited: true, ownedJobDrained: true, forcedTermination: false,
      timedOut: false, elapsedMs: 10500, exitCode: 0, outcome: 'PASS', actualAboExecuted: false },
  ];
}
function asOutput(rows) { return rows.map(row => JSON.stringify(row)).join('\n'); }
test('native parser preserves shared-guard scope and exact event sequence', () => {
  const result = runtime.ParseProbeOutput(asOutput(outputFixture()), 'B');
  assert.equal(result.good, true); assert.equal(result.guard.actualAboExecuted, false);
});
for (const [name, change] of Object.entries({
  missingResult: rows => rows.pop(),
  reordered: rows => rows.reverse(),
  changedRole: rows => { rows[2].role = 'O'; },
  unsupportedScope: rows => { rows[2].actualAboExecuted = true; },
})) test('native parser rejects ' + name, () => {
  const rows = outputFixture(); change(rows); assert.throws(() => runtime.ParseProbeOutput(asOutput(rows), 'B'));
});
for (const [name, change] of Object.entries({
  forcedChild: rows => { rows[3].forcedTermination = true; },
  forcedInnerObserver: rows => { rows[2].observerForcedTermination = true; },
  missingInnerObserverExit: rows => { rows[2].observerExitObserved = false; },
  neverStartedInnerObserver: rows => { rows[2].observerChildStarted = false; },
  unreportedInnerObserverStop: rows => { delete rows[2].observerForcedTermination; },
  staleCycle: rows => { rows[2].staleKernelSamples = 1; },
  tooSlow: rows => { rows[2].shutdownMs = 4001; },
  noCycles: rows => { rows[2].kernelSamples = 0; },
  durationMismatch: rows => { rows[0].requestedDurationMs = 90000; },
  falsePositive: rows => { rows[2].falsePositiveConfirmed = true; },
})) test('native parser retains failure for ' + name, () => {
  const rows = outputFixture(); change(rows); assert.equal(runtime.ParseProbeOutput(asOutput(rows), 'B').good, false);
});
test('runtime runner cannot execute or manufacture Windows evidence on this Linux host', () => {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    assert.throws(() => runtime.Run('nonexistent.exe', 'absent-binding.json', 'must-not-create'), /WINDOWS_X64_REQUIRED_NOT_RUN/);
  }
});
console.log(JSON.stringify({ suite: 'NHW_VALIDATION_GATE', checks, nativeExecuted: false, hardwareTpmExecuted: false,
  outcome: 'VALIDATOR_TESTS_PASS', runtimeVerification: 'NOT_RUN' }));
