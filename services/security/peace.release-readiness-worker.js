'use strict';
// A short-lived CPU/IO worker, not an OS sandbox. No store or private signer is
// imported; only bounded registered paths, public metadata and hashes arrive.
const { parentPort, workerData } = require('node:worker_threads');
const { Read } = require('../artifacts/peace.bounded-artifact-read');
const { AuditBytes, Base, MAX_FILE_BYTES, MAX_TOTAL_BYTES } = require('./peace.release-readiness');
function Run(input) {
  if (!input || !Array.isArray(input.artifacts) || input.artifacts.length !== 3) throw Error('RELEASE_AUDIT_FAILED');
  const releases = []; let remaining = MAX_TOTAL_BYTES, issuedAInspection = null;
  for (let i = 0; i < 3; i++) {
    const component = ['A', 'B', 'O'][i], artifact = input.artifacts[i];
    if (!artifact) { releases.push(Base(null, component)); continue; }
    let bytes, row;
    try {
      if (artifact.component !== component || !Number.isSafeInteger(artifact.size) || artifact.size < 1 ||
          artifact.size > MAX_FILE_BYTES || artifact.size > remaining) throw Error('RELEASE_AUDIT_BUDGET_EXCEEDED');
      remaining -= artifact.size;
      bytes = Read(artifact.file, artifact.size);
      row = AuditBytes(artifact, bytes, { policy: input.policy });
      if (component === 'A' && row.checks.fileIdentity.status === 'MATCH' && row.checks.pe.status === 'VALID') {
        try {
          const signing = require('../bootstrap/peace.issued-a-signing');
          const anchor = signing.InspectTemplate(bytes);
          issuedAInspection = { templateSize: bytes.length, templateSha512: row.measuredSha512,
            publicBlob: anchor.blob.toString('hex') };
        } catch (error) {
          issuedAInspection = { reason: /^ISSUED_A_[A-Z0-9_]{1,80}$/.test(error.message) ? error.message : 'ISSUED_A_SIGNING_UNAVAILABLE' };
        }
      }
    } catch (error) {
      row = Base(artifact, component); row.staticStatus = 'ISSUES_FOUND';
      row.issues.push(error.message === 'RELEASE_AUDIT_BUDGET_EXCEEDED' ? error.message : 'RELEASE_FILE_UNAVAILABLE_OR_CHANGED');
    } finally { bytes?.fill(0); }
    releases.push(row);
  }
  return { releases, issuedAInspection };
}
try { parentPort.postMessage({ ok: true, result: Run(workerData) }); }
catch (_) { parentPort.postMessage({ ok: false }); }
