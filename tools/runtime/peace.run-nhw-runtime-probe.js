'use strict';

// Runs the dedicated shared-guard probe only. No license is consumed, no game
// is opened, and this tool never launches the production A/B/O executables.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { digest, IDLE_MINIMUM_MS, SHUTDOWN_MAXIMUM_MS } = require('./peace.nhw-validation-gate');

function ParseProbeOutput(text, role) {
  const rows = text.split(/\r?\n/).filter(line => line.startsWith('{')).map(line => JSON.parse(line));
  const events = rows.filter(row => row.schema === 'COZY_NHW_RUNTIME_PROBE_V1');
  if (events.length !== 4 || events.some(row => row.role !== role || row.scope !== 'SHARED_NHW_GUARD' ||
    row.platform !== 'win32' || row.architecture !== 'x64')) throw Error('NATIVE_PROBE_OUTPUT_SCOPE_INVALID');
  if (events.map(row => row.event).join(',') !== 'started,shutdown-begin,guard-result,parent-result') {
    throw Error('NATIVE_PROBE_EVENTS_INCOMPLETE');
  }
  const [started, , guard, parent] = events;
  if (started.fullEngine !== true || guard.actualAboExecuted !== false || parent.actualAboExecuted !== false) {
    throw Error('NATIVE_PROBE_SCOPE_OVERCLAIM');
  }
  const numeric = ['requestedDurationMs', 'durationMs', 'shutdownMs', 'kernelSamples', 'staleKernelSamples', 'observerShutdownMs'];
  if (numeric.some(name => !Number.isSafeInteger(guard[name]) || guard[name] < 0)) throw Error('NATIVE_PROBE_MEASUREMENTS_INVALID');
  const good = guard.exitCode === 0 && parent.exitCode === 0 && parent.outcome === 'PASS' &&
    guard.durationReached === true && guard.startupFailed === false && guard.cancelled === false &&
    guard.falsePositiveConfirmed === false && parent.nativeExited === true && parent.ownedJobDrained === true &&
    guard.observerChildStarted === true && guard.observerExitObserved === true && guard.observerForcedTermination === false &&
    parent.forcedTermination === false && parent.timedOut === false &&
    started.requestedDurationMs === guard.requestedDurationMs && guard.durationMs >= guard.requestedDurationMs &&
    guard.shutdownMs <= SHUTDOWN_MAXIMUM_MS && guard.kernelSamples >= 2 && guard.staleKernelSamples === 0;
  return { started, guard, parent, good };
}

function IsWin64PE(bytes) {
  if (bytes.length < 256 || bytes.readUInt16LE(0) !== 0x5a4d) return false;
  const pe = bytes.readUInt32LE(0x3c);
  return pe >= 64 && pe <= bytes.length - 26 && bytes.readUInt32LE(pe) === 0x4550 &&
    bytes.readUInt16LE(pe + 4) === 0x8664 && bytes.readUInt16LE(pe + 24) === 0x20b;
}

function Run(executable, bindingFile, output, duration = IDLE_MINIMUM_MS) {
  if (process.platform !== 'win32' || process.arch !== 'x64') throw Error('WINDOWS_X64_REQUIRED_NOT_RUN');
  if (!Number.isSafeInteger(duration) || duration < 10000 || duration > 86400000) throw Error('DURATION_INVALID');
  const exe = path.resolve(executable);
  const binary = fs.readFileSync(exe);
  if (!IsWin64PE(binary)) throw Error('REAL_WIN64_PROBE_EXE_REQUIRED');
  const binarySha512 = digest(binary);
  const binding = JSON.parse(fs.readFileSync(path.resolve(bindingFile), 'utf8'));
  if (!/^[a-f0-9]{128}$/.test(binding.sourceSha512 || '') || !binding.artifacts ||
    !['A', 'B', 'O'].every(role => /^[a-f0-9]{128}$/.test(binding.artifacts[role] || ''))) throw Error('SOURCE_ARTIFACT_BINDING_REQUIRED');
  const root = path.resolve(output);
  fs.mkdirSync(root); // Existing evidence is never overwritten.
  const manifest = { schema: 'COZY_NHW_EVIDENCE_SET_V1', binding, reports: [] };
  const runId = crypto.randomBytes(16).toString('hex');
  let allPassed = true;
  for (const role of ['A', 'B', 'O']) {
    const startedAt = Date.now();
    const child = spawnSync(exe, [`--role=${role}`, `--duration-ms=${duration}`], {
      cwd: path.dirname(exe), encoding: 'utf8', windowsHide: true,
      timeout: duration + 120000, maxBuffer: 2 * 1024 * 1024,
    });
    const finishedAt = Date.now();
    const raw = Buffer.from((child.stdout || '') + (child.stderr || '') +
      (child.error ? `\nNATIVE_RUNNER_ERROR ${child.error.code || 'FAILED'}\n` : ''));
    const rawFile = `guard-${role}.log`;
    fs.writeFileSync(path.join(root, rawFile), raw, { flag: 'wx' });
    let observation;
    let failure;
    try { observation = ParseProbeOutput(child.stdout || '', role); }
    catch (error) { failure = error.message; }
    const unchanged = digest(fs.readFileSync(exe)) === binarySha512;
    const good = child.status === 0 && !child.error && unchanged && observation?.good === true &&
      observation.guard.requestedDurationMs === duration;
    allPassed &&= good;
    const report = {
      schema: 'COZY_NHW_EXECUTION_EVIDENCE_V1', id: `guard-idle-${role}`, kind: 'NHW_GUARD_RUN', binding,
      platform: process.platform, architecture: process.arch, execution: child.pid > 0 ? 'ACTUAL' : 'NOT_RUN', synthetic: false,
      sourceChecksOnly: false, outcome: good ? 'PASS' : 'FAIL', exitCode: child.status ?? -1, runId, startedAt, finishedAt,
      role, scope: 'SHARED_NHW_GUARD', fullEngine: observation?.started.fullEngine === true,
      requestedDurationMs: duration, durationMs: observation?.guard.durationMs,
      shutdownMs: observation?.guard.shutdownMs, kernelSamples: observation?.guard.kernelSamples,
      staleKernelSamples: observation?.guard.staleKernelSamples,
      falsePositiveConfirmed: observation?.guard.falsePositiveConfirmed,
      nativeExited: observation?.parent.nativeExited === true, ownedJobDrained: observation?.parent.ownedJobDrained === true,
      forcedTermination: observation ? observation.parent.forcedTermination !== false || observation.guard.observerForcedTermination !== false || Boolean(child.error) : null,
      observerChildStarted: observation?.guard.observerChildStarted === true,
      observerExitObserved: observation?.guard.observerExitObserved === true,
      observerForcedTermination: observation ? observation.guard.observerForcedTermination : null,
      observerShutdownMs: observation?.guard.observerShutdownMs,
      binarySha512, binaryUnchanged: unchanged, sourceBindingProvidedByOperator: true,
      actualAboExecuted: false, failure: failure || child.error?.code || null,
      rawEvidence: [{ file: rawFile, sha512: digest(raw) }],
    };
    const bytes = Buffer.from(JSON.stringify(report, null, 2));
    const file = `guard-${role}.json`; fs.writeFileSync(path.join(root, file), bytes, { flag: 'wx' });
    manifest.reports.push({ id: report.id, file, sha512: digest(bytes) });
  }
  const target = path.join(root, 'evidence-set.json');
  fs.writeFileSync(target, JSON.stringify(manifest, null, 2), { flag: 'wx' });
  return { outcome: allPassed ? 'GUARD_RUNS_OBSERVED' : 'FAIL', evidenceFile: target,
    durationMs: duration, allOtherRequiredChecks: 'MISSING', projectFullyVerified: false };
}

function main(args) {
  if (args.length < 3 || args.length > 4) {
    console.error('Usage: node tools/runtime/peace.run-nhw-runtime-probe.js <probe.exe> <source-and-artifact-binding.json> <new-output-directory> [duration-ms]');
    console.error('Default: 7200000 ms per role. Requires an actual Win64 Release probe built by RAD Studio 13.');
    return 2;
  }
  try {
    const result = Run(args[0], args[1], args[2], args.length === 4 ? Number(args[3]) : IDLE_MINIMUM_MS);
    console.log(JSON.stringify(result, null, 2));
    return result.outcome === 'GUARD_RUNS_OBSERVED' ? 0 : 1;
  } catch (error) {
    console.log(JSON.stringify({ outcome: error.message === 'WINDOWS_X64_REQUIRED_NOT_RUN' ? 'NOT_RUN' : 'INCOMPLETE',
      reason: error.code || error.message, projectFullyVerified: false }));
    return 2;
  }
}

module.exports = { ParseProbeOutput, IsWin64PE, Run };
if (require.main === module) process.exitCode = main(process.argv.slice(2));
