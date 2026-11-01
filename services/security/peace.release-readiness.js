'use strict';
// On-demand, read-only diagnostics of the exact registered release bytes.
// This is neither a publication grant nor Windows execution / publisher trust.
const crypto = require('node:crypto');
const { ValidatePeImage } = require('../artifacts/peace.pe-preflight');
const { PeCapabilities } = require('../artifacts/peace.pe-capabilities');
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 128 * 1024 * 1024;
const sha512 = bytes => crypto.createHash('sha512').update(bytes).digest('hex');
const digest = value => typeof value === 'string' && /^[a-f0-9]{128}$/.test(value);
const token = (value, expression) => typeof value === 'string' && expression.test(value) ? value : '';

function Base(artifact, component) {
  return {
    component, id: token(artifact?.id, /^(?:DA-)?[A-F0-9]{24}$/),
    version: token(artifact?.version, /^\d{1,9}(?:\.\d{1,9}){0,3}$/),
    registeredSha512: digest(artifact?.sha512) ? artifact.sha512 : '',
    measuredSha512: '', registeredSize: Number.isSafeInteger(artifact?.size) ? artifact.size : 0,
    measuredSize: 0, staticStatus: 'NOT_REGISTERED', issues: [],
    checks: {
      fileIdentity: { status: 'UNAVAILABLE' },
      pe: { status: 'NOT_CHECKED' },
      cfg: { status: 'NOT_CHECKED', compiledCfg: false, reason: '', callSiteCoverage: 'NOT_VERIFIED' },
      releaseApproval: { status: 'NOT_CHECKED' },
      authenticode: { status: 'NOT_CHECKED', certificateCount: 0, windowsTrust: 'NOT_VERIFIED' },
      issuedAApplicationSignature: { status: component === 'A' ? 'NOT_CHECKED' : 'NOT_APPLICABLE',
        scope: 'TEMPLATE_SIGNER_CHALLENGE', finalIssuedFile: 'NOT_CHECKED' }
    }
  };
}

// The security directory is a FILE offset, not an RVA. A structurally bounded
// WIN_CERTIFICATE table is not evidence of a valid PKCS#7 signature or CA trust.
function CertificateStructure(bytes, optional, sectionTable, sectionCount) {
  const result = { status: 'ABSENT', certificateCount: 0, windowsTrust: 'NOT_VERIFIED' };
  if (bytes.readUInt32LE(optional + 108) < 5) return result;
  const offset = bytes.readUInt32LE(optional + 144), size = bytes.readUInt32LE(optional + 148);
  if (!offset && !size) return result;
  const invalid = () => ({ ...result, status: 'INVALID' });
  let imageEnd = bytes.readUInt32LE(optional + 60);
  for (let i = 0; i < sectionCount; i++) {
    const at = sectionTable + i * 40;
    imageEnd = Math.max(imageEnd, bytes.readUInt32LE(at + 20) + bytes.readUInt32LE(at + 16));
  }
  if (!offset || size < 8 || offset % 8 || size % 8 || offset < imageEnd ||
      offset + size > bytes.length || size > 16 * 1024 * 1024) return invalid();
  const end = offset + size; let cursor = offset, count = 0;
  while (cursor < end) {
    if (cursor + 8 > end || ++count > 256) return invalid();
    const length = bytes.readUInt32LE(cursor), revision = bytes.readUInt16LE(cursor + 4), type = bytes.readUInt16LE(cursor + 6);
    if (length <= 8 || cursor + length > end || revision !== 0x0200 || type !== 0x0002) return invalid();
    const next = cursor + Math.ceil(length / 8) * 8;
    if (next > end) return invalid();
    for (let p = cursor + length; p < next; p++) if (bytes[p] !== 0) return invalid();
    cursor = next;
  }
  return { ...result, status: 'PRESENT_STRUCTURE_ONLY', certificateCount: count };
}

function AuditBytes(artifact, bytes, { policy, verifyApproval } = {}) {
  const result = Base(artifact, artifact?.component);
  result.staticStatus = 'ISSUES_FOUND';
  if (!['A', 'B', 'O'].includes(artifact?.component) || !result.id || !result.registeredSha512 ||
      !Number.isSafeInteger(artifact.size) || artifact.size < 1 || artifact.size > MAX_FILE_BYTES ||
      !Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_FILE_BYTES) {
    result.issues.push('RELEASE_READINESS_INPUT_INVALID'); return result;
  }
  result.measuredSha512 = sha512(bytes); result.measuredSize = bytes.length;
  const matches = result.measuredSha512 === artifact.sha512 && bytes.length === artifact.size;
  result.checks.fileIdentity.status = matches ? 'MATCH' : 'MISMATCH';
  if (!matches) result.issues.push('RELEASE_FILE_IDENTITY_MISMATCH');
  try {
    ValidatePeImage(bytes, code => { throw Error(code); });
    const pe = bytes.readUInt32LE(0x3c), optional = pe + 24, count = bytes.readUInt16LE(pe + 6);
    const table = optional + bytes.readUInt16LE(pe + 20), flags = bytes.readUInt16LE(optional + 70);
    let writableExecutableSections = 0;
    for (let i = 0; i < count; i++) {
      const permissions = bytes.readUInt32LE(table + i * 40 + 36);
      if ((permissions & 0x20000000) && (permissions & 0x80000000)) writableExecutableSections++;
    }
    result.checks.pe = { status: 'VALID', dep: !!(flags & 0x100), aslr: !!(flags & 0x40),
      highEntropyVa: !!(flags & 0x20), writableExecutableSections };
    const caps = PeCapabilities(bytes);
    result.checks.cfg = { status: caps.cfg.status, compiledCfg: caps.compiledCfg,
      reason: caps.cfg.reason, callSiteCoverage: 'NOT_VERIFIED' };
    if (caps.cfg.status === 'INVALID') result.issues.push('RELEASE_CFG_METADATA_INVALID');
    if (policy?.requireCfg && !caps.compiledCfg) result.issues.push('SECURITY_CFG_BUILD_REQUIRED');
    if (typeof artifact.compiledCfg === 'boolean' && artifact.compiledCfg !== caps.compiledCfg)
      result.issues.push('RELEASE_CFG_REGISTRATION_MISMATCH');
    if (!result.checks.pe.dep) result.issues.push('RELEASE_DEP_NOT_DECLARED');
    if (!result.checks.pe.aslr) result.issues.push('RELEASE_ASLR_NOT_DECLARED');
    if (writableExecutableSections) result.issues.push('RELEASE_WRITABLE_EXECUTABLE_SECTION');
    result.checks.authenticode = CertificateStructure(bytes, optional, table, count);
    if (result.checks.authenticode.status === 'INVALID') result.issues.push('RELEASE_CERTIFICATE_TABLE_INVALID');
  } catch (_) { result.checks.pe.status = 'INVALID'; result.issues.push('RELEASE_PE_INVALID'); }
  if (!artifact.releaseApproval) {
    result.checks.releaseApproval.status = 'MISSING';
    if (policy?.requireReleaseSignature) result.issues.push('SECURITY_RELEASE_SIGNATURE');
  } else if (matches && result.checks.pe.status === 'VALID' && typeof verifyApproval === 'function') {
    // Bind verification to the measured digest rather than trusting the stored
    // digest alone. The production callback also checks signer revocation.
    try {
      const valid = verifyApproval({ ...artifact, sha512: result.measuredSha512 }, policy) === true;
      result.checks.releaseApproval.status = valid ? 'VALID' : 'INVALID';
      if (!valid) result.issues.push('SECURITY_RELEASE_SIGNATURE');
    } catch (_) { result.checks.releaseApproval.status = 'INVALID'; result.issues.push('SECURITY_RELEASE_SIGNATURE'); }
  }
  // Legacy revocations bind the actual bytes as well; registration metadata may
  // predate that field or be stale. Do not trust artifact.legacyRevocationSha256.
  const legacyRevoked = Array.isArray(policy?.revokedLegacySha256) && policy.revokedLegacySha256.length > 0 &&
    policy.revokedLegacySha256.includes(crypto.createHash('sha256').update(bytes).digest('hex'));
  if (policy?.revokedSha512?.includes(result.measuredSha512) || legacyRevoked) result.issues.push('SECURITY_RELEASE_REVOKED');
  result.issues = [...new Set(result.issues)];
  result.staticStatus = result.issues.length ? 'ISSUES_FOUND' : 'CHECKED';
  return result;
}

function Fail(code, status = 503) {
  const error = Error(code); error.desktopError = true; error.status = status; throw error;
}
function ArtifactSnapshot(artifact, component) {
  if (!artifact) return null;
  return { id: artifact.id, component, version: artifact.version, sha512: artifact.sha512,
    size: artifact.size, compiledCfg: artifact.compiledCfg,
    releaseApproval: artifact.releaseApproval ? { keyId: artifact.releaseApproval.keyId,
      signature: artifact.releaseApproval.signature } : null };
}
function StateSnapshot(store, authority) {
  const db = store.Load(), policy = authority.Policy();
  const artifacts = ['A', 'B', 'O'].map(component => ArtifactSnapshot(db.artifacts[db.active[component]], component));
  // Runtime heartbeats also advance db.revision. Bind only the inspected release
  // selection and security revisions, so unrelated live sessions do not starve
  // an administrator's read-only check.
  return { artifactRevision: db.revision, policy, artifacts,
    identity: JSON.stringify({ artifacts, active: db.active, policyRevision: policy.revision,
      operationsRevision: db.securityOperations?.revision || 0 }) };
}
let runner, stopRegistered = false;
function Runner() {
  if (!runner) runner = require('./peace.release-audit-runner').CreateRunner();
  if (!stopRegistered) {
    require('../../core/peace.lifecycle').RegisterShutdownHook(() => runner.Close());
    stopRegistered = true;
  }
  return runner;
}
async function AuditActive({ signal, checkAccess } = {}) {
  const store = require('../bootstrap/peace.desktop-bootstrap-store');
  const authority = require('./peace.desktop-security-authority');
  const snapshot = StateSnapshot(store, authority);
  const policy = snapshot.policy;
  const input = { artifacts: snapshot.artifacts.map(artifact => artifact && ({
    ...artifact, releaseApproval: artifact.releaseApproval ? {} : null,
    file: store.ArtifactPath(artifact.id) })), policy: {
    requireCfg: policy.requireCfg, requireReleaseSignature: policy.requireReleaseSignature,
    revokedSha512: policy.revokedSha512, revokedLegacySha256: policy.revokedLegacySha256 } };
  const completed = await Runner().Run(input, { signal, checkAccess });
  if (signal?.aborted) Fail('RELEASE_AUDIT_CANCELLED', 499);
  checkAccess?.();
  if (StateSnapshot(store, authority).identity !== snapshot.identity) Fail('RELEASE_AUDIT_STALE', 409);
  if (!completed || !Array.isArray(completed.releases) || completed.releases.length !== 3)
    Fail('RELEASE_AUDIT_FAILED');
  const releases = completed.releases;
  for (let i = 0; i < releases.length; i++) {
    const row = releases[i], artifact = snapshot.artifacts[i];
    if (!artifact) continue;
    if (row.component !== artifact.component || row.id !== artifact.id || row.registeredSha512 !== artifact.sha512)
      Fail('RELEASE_AUDIT_FAILED');
    if (artifact.releaseApproval && row.checks.fileIdentity.status === 'MATCH' && row.checks.pe.status === 'VALID') {
      let valid = false;
      try { valid = authority.VerifyApproval({ ...artifact, sha512: row.measuredSha512 }, policy) === true; }
      catch (_) { /* public failure below */ }
      row.checks.releaseApproval.status = valid ? 'VALID' : 'INVALID';
      if (!valid) row.issues.push('SECURITY_RELEASE_SIGNATURE');
    }
    if (artifact.component === 'A' && row.checks.fileIdentity.status === 'MATCH' && row.checks.pe.status === 'VALID') {
      // Only the small public inspection crosses back to the authority thread.
      // The signer/private environment never goes to the parsing worker.
      const inspection = completed.issuedAInspection;
      let ready;
      if (inspection?.templateSha512 !== row.measuredSha512 || inspection?.templateSize !== row.measuredSize)
        ready = { ready: false, reason: inspection?.reason || 'ISSUED_A_SIGNING_UNAVAILABLE' };
      else ready = require('../bootstrap/peace.issued-a-signing').ReadinessFromInspection(inspection);
      const reason = token(ready.reason, /^ISSUED_A_[A-Z0-9_]{1,80}$/) || 'ISSUED_A_SIGNING_UNAVAILABLE';
      row.checks.issuedAApplicationSignature = { status: ready.ready ? 'READY' : 'UNAVAILABLE',
        scope: 'TEMPLATE_SIGNER_CHALLENGE', finalIssuedFile: 'NOT_CHECKED', ...(ready.ready ? {} : { reason }) };
      if (!ready.ready) row.issues.push(reason);
    }
    row.issues = [...new Set(row.issues)];
    row.staticStatus = row.issues.length ? 'ISSUES_FOUND' : 'CHECKED';
  }
  checkAccess?.();
  if (signal?.aborted) Fail('RELEASE_AUDIT_CANCELLED', 499);
  if (StateSnapshot(store, authority).identity !== snapshot.identity) Fail('RELEASE_AUDIT_STALE', 409);
  return { version: 1, scope: 'REGISTERED_RELEASE_BYTES', readOnly: true,
    authorizesPublication: false, checkedAt: Date.now(), artifactRevision: snapshot.artifactRevision,
    policyRevision: policy.revision, nativeExecution: 'NOT_RUN', windowsPublisherTrust: 'NOT_VERIFIED', releases };
}

module.exports = { AuditActive, AuditBytes, Base, MAX_FILE_BYTES, MAX_TOTAL_BYTES };
