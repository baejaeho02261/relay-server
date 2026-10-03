'use strict';
// Server-owned policy and short-lived decisions. Signed client observations are
// NOT hardware attestation and never replace the existing license/session gate.
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const store = require('./desktopBootstrapStore');
const DOMAIN = 'GAME-AUTHORITY-V1';
const RELEASE_DOMAIN = 'GAME-RELEASE-APPROVAL-V1';
const pending = new Map(), decisions = new Map(), rates = new Map(), events = [];
const epoch = crypto.randomBytes(24).toString('hex');
let sequence = 0;
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
function Fail(code, status = 403) { const error = Error(code); error.desktopError = true; error.status = status; throw error; }
function Fields(value, allowed) { if (!plain(value) || Object.keys(value).some(key => !allowed.includes(key))) Fail('SECURITY_INPUT_INVALID', 400); }
function Defaults() {
  return { version: 1, revision: 0, mode: 'enforce', enforceLegacy: false,
    freshnessMs: 45000, challengeMs: 15000, requireReadonlyApi: true,
    dynamicCode: 'observe', requireCfg: false, minVersionA: '0', minVersionB: '0',
    requireReleaseSignature: false, trustedReleaseKeys: [], revokedSha256: [] };
}
function ValidatePolicy(value) {
  Fields(value, Object.keys(Defaults()));
  if (Object.keys(value).length !== Object.keys(Defaults()).length || value.version !== 1 ||
      !Number.isSafeInteger(value.revision) || value.revision < 0 || !['observe', 'enforce'].includes(value.mode) ||
      !['observe', 'prohibit'].includes(value.dynamicCode) ||
      ['enforceLegacy', 'requireReadonlyApi', 'requireCfg', 'requireReleaseSignature'].some(k => typeof value[k] !== 'boolean') ||
      !Number.isInteger(value.freshnessMs) || value.freshnessMs < 5000 || value.freshnessMs > 120000 ||
      !Number.isInteger(value.challengeMs) || value.challengeMs < 5000 || value.challengeMs > 30000 ||
      ['minVersionA', 'minVersionB'].some(k => typeof value[k] !== 'string' || !/^\d{1,9}(?:\.\d{1,9}){0,3}$/.test(value[k])) ||
      !Array.isArray(value.trustedReleaseKeys) || value.trustedReleaseKeys.length > 8 ||
      !Array.isArray(value.revokedSha256) || value.revokedSha256.length > 512 ||
      value.revokedSha256.some(x => typeof x !== 'string' || !/^[a-f0-9]{64}$/.test(x)) ||
      new Set(value.revokedSha256).size !== value.revokedSha256.length) Fail('SECURITY_POLICY_INVALID', 400);
  const ids = new Set();
  for (const entry of value.trustedReleaseKeys) {
    Fields(entry, ['keyId', 'publicKey']);
    if (typeof entry.publicKey !== 'string' || entry.publicKey.length > 4096 || !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----\r?\n?$/.test(entry.publicKey) || ids.has(entry.keyId)) Fail('SECURITY_POLICY_INVALID', 400);
    let key; try { key = crypto.createPublicKey(entry.publicKey); } catch (_) { Fail('SECURITY_POLICY_INVALID', 400); }
    if (key.asymmetricKeyType !== 'ed25519' || entry.keyId !== sha(key.export({ type: 'spki', format: 'der' }))) Fail('SECURITY_POLICY_INVALID', 400);
    ids.add(entry.keyId);
  }
  if (value.requireReleaseSignature && !ids.size) Fail('SECURITY_SIGNER_REQUIRED', 409);
  return value;
}
function Policy() {
  const value = store.Load().securityAuthorityPolicy || Defaults();
  ValidatePolicy(value);
  return structuredClone(value);
}
function Audit(kind, reason, row, extra = {}) {
  // Whitelist only: no tokens, private/public blobs, payloads, paths or raw memory.
  const event = { at: Date.now(), kind, reason, stage: row?.stage || '',
    sessionId: row?.sessionId || '', flowId: row?.id || '', releaseId: row?.releaseId || '', attested: false,
    ...(['finish','redeem','verify','observe'].includes(extra.intent) ? { intent: extra.intent } : {}),
    ...(typeof extra.actor === 'string' ? { actor: extra.actor.slice(0,100).replace(/[\x00-\x1f\x7f]/g,'') } : {}),
    ...(Number.isSafeInteger(extra.sequence) ? { sequence: extra.sequence } : {}),
    ...(Number.isSafeInteger(extra.revision) ? { revision: extra.revision } : {}) };
  events.push(event); if (events.length > 256) events.shift();
  try { require('../storage/audit').LogEvent('DESKTOP_SECURITY_AUTHORITY', JSON.stringify(event)); }
  catch (_) { console.error('DESKTOP_SECURITY_AUDIT_FAILED'); }
}
function VersionAtLeast(version, minimum) {
  if (typeof version !== 'string' || version.length > 40 || !/^\d+(?:\.\d+){0,3}$/.test(version)) return false;
  const a = version.split('.').map(BigInt), b = minimum.split('.').map(BigInt);
  for (let i = 0; i < 4; i++) { if ((a[i] || 0n) !== (b[i] || 0n)) return (a[i] || 0n) > (b[i] || 0n); }
  return true;
}
function ReleaseCanonical(component, version, digest) { return [RELEASE_DOMAIN, component, version, digest].join('\n'); }
function VerifyApproval(artifact, policy) {
  const approval = artifact.releaseApproval;
  if (!approval) return !policy.requireReleaseSignature;
  if (!plain(approval) || typeof approval.keyId !== 'string' || typeof approval.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(approval.signature)) return false;
  const signer = policy.trustedReleaseKeys.find(x => x.keyId === approval.keyId);
  if (!signer || Buffer.from(approval.signature, 'base64').toString('base64') !== approval.signature) return false;
  try { return crypto.verify(null, Buffer.from(ReleaseCanonical(artifact.component, artifact.version, artifact.sha256)), signer.publicKey, Buffer.from(approval.signature, 'base64')); }
  catch (_) { return false; }
}
function ArtifactReason(artifact, policy) {
  if (!artifact) return 'SECURITY_RELEASE_MISSING';
  if (policy.revokedSha256.includes(artifact.sha256)) return 'SECURITY_RELEASE_REVOKED';
  if (!VersionAtLeast(artifact.version, artifact.component === 'A' ? policy.minVersionA : policy.minVersionB)) return 'SECURITY_RELEASE_VERSION';
  if (!VerifyApproval(artifact, policy)) return 'SECURITY_RELEASE_SIGNATURE';
  if (policy.enforceLegacy && artifact.authorityVersion !== 1) return 'SECURITY_CLIENT_UPGRADE_REQUIRED';
  if (policy.requireCfg && artifact.compiledCfg !== true) return 'SECURITY_CFG_BUILD_REQUIRED';
  return '';
}
function RequireArtifact(artifact) { const reason = ArtifactReason(artifact, Policy()); if (reason) Fail(reason); }
function PeCapabilities(bytes) {
  // Only metadata of administrator-uploaded bytes, never a client capability claim.
  const authorityVersion = bytes.includes(Buffer.from(DOMAIN)) || bytes.includes(Buffer.from(DOMAIN, 'utf16le')) ? 1 : 0;
  let compiledCfg = false;
  try {
    const pe = bytes.readUInt32LE(0x3c), opt = pe + 24, optSize = bytes.readUInt16LE(pe + 20), count = bytes.readUInt16LE(pe + 6);
    if (bytes.readUInt16LE(opt) === 0x20b && optSize >= 200 && (bytes.readUInt16LE(opt + 70) & 0x4000) && bytes.readUInt32LE(opt + 108) > 10) {
      const rva = bytes.readUInt32LE(opt + 112 + 80), size = bytes.readUInt32LE(opt + 116 + 80);
      for (let i = 0; i < count; i++) {
        const at = opt + optSize + i * 40, va = bytes.readUInt32LE(at + 12), rawSize = bytes.readUInt32LE(at + 16), raw = bytes.readUInt32LE(at + 20);
        if (size >= 148 && rva >= va && rva - va + 148 <= rawSize && raw + rva - va + 148 <= bytes.length) {
          const lc = raw + rva - va;
          compiledCfg = bytes.readUInt32LE(lc) >= 148 && (bytes.readUInt32LE(lc + 144) & 0x500) === 0x500 && bytes.readBigUInt64LE(lc + 136) > 0n;
        }
      }
    }
  } catch (_) { compiledCfg = false; }
  return { authorityVersion, compiledCfg };
}
function PublishMetadata(component, version, bytes, approval) {
  const row = { component, version, sha256: sha(bytes), ...PeCapabilities(bytes) };
  if (approval !== undefined) { Fields(approval, ['keyId', 'signature']); row.releaseApproval = structuredClone(approval); }
  RequireArtifact(row);
  return { authorityVersion: row.authorityVersion, compiledCfg: row.compiledCfg, ...(row.releaseApproval ? { releaseApproval: row.releaseApproval } : {}) };
}
function SetPolicy(body, actor) {
  Fields(body, [...Object.keys(Defaults()).filter(k => !['version', 'revision'].includes(k)), 'expectedRevision']);
  const old = Policy();
  if (body.expectedRevision !== old.revision) Fail('SECURITY_POLICY_CONFLICT', 409);
  const patch = { ...body }; delete patch.expectedRevision;
  const next = ValidatePolicy({ ...old, ...patch, revision: old.revision + 1 });
  // Avoid bricking the active pair when enabling signer/CFG/upgrade requirements.
  const db = store.Load();
  for (const component of ['A', 'B']) {
    const artifact = db.artifacts[db.active[component]];
    if (artifact) { const reason = ArtifactReason(artifact, next); if (reason) Fail(reason, 409); }
  }
  store.Atomic(state => { state.securityAuthorityPolicy = next; });
  pending.clear(); decisions.clear();
  Audit('POLICY', 'POLICY_CHANGED', null, { revision: next.revision, actor });
  return Policy();
}
function Context(row, stage) { return stage + ':' + (stage === 'A' ? row.id : row.sessionId); }
function Binding(operationId, payloadHash) { return sha(operationId + '|' + payloadHash); }
function RowArtifact(row, stage) {
  const db = store.Load();
  return db.artifacts[stage === 'A' ? db.launchers[row.launcherId]?.artifactId : row.releaseId];
}
function Prune() {
  const at = Date.now(), tick = performance.now();
  for (const [id, item] of pending) if (item.expiresAt <= at || item.deadline <= tick) pending.delete(id);
  for (const [id, item] of decisions) if (item.expiresAt <= at || item.deadline <= tick) decisions.delete(id);
  for (const [id, item] of rates) if (item.deadline <= tick) rates.delete(id);
}
const AUTH_FIELDS = ['action', 'stage', 'sessionId', 'sessionToken', 'machineId', 'intent', 'binding'];
function Authenticate(body) {
  if (!['A', 'B'].includes(body.stage) || !['finish', 'redeem', 'verify', 'observe'].includes(body.intent) ||
      (body.stage === 'A' ? !['finish', 'observe'].includes(body.intent) : body.intent === 'finish') ||
      typeof body.machineId !== 'string' || !/^[A-F0-9]{64}$/.test(body.machineId) ||
      typeof body.binding !== 'string' || !/^[a-f0-9]{64}$/.test(body.binding)) Fail('SECURITY_INPUT_INVALID', 400);
  const row = require('./desktopBootstrap').AuthenticateIntegrityReport(body);
  RequireArtifact(RowArtifact(row, body.stage));
  return row;
}
function Challenge(body) {
  Fields(body, AUTH_FIELDS);
  const row = Authenticate(body), policy = Policy(), context = Context(row, body.stage);
  Prune(); const rate = rates.get(context) || { count: 0, deadline: performance.now() + 60000 };
  if (++rate.count > 40 || pending.size >= 1024 || rates.size >= 4096 && !rates.has(context)) Fail('SECURITY_RATE_LIMIT', 429);
  rates.set(context, rate);
  const item = { challengeId: crypto.randomBytes(24).toString('hex'), nonce: crypto.randomBytes(24).toString('hex'),
    epoch, sequence: ++sequence, revision: policy.revision, expiresAt: Date.now() + policy.challengeMs,
    deadline: performance.now() + policy.challengeMs, context, stage: body.stage, intent: body.intent, binding: body.binding };
  pending.set(item.challengeId, item);
  return { version: 1, challengeId: item.challengeId, nonce: item.nonce, epoch, sequence: item.sequence,
    revision: item.revision, expiresAt: item.expiresAt, dynamicCode: policy.dynamicCode };
}
function Canonical(body, challenge, payload) {
  return [DOMAIN, body.stage, body.sessionId, body.intent, body.binding, challenge.challengeId,
    challenge.nonce, challenge.epoch, String(challenge.sequence), String(challenge.revision),
    String(challenge.expiresAt), sha(payload)].join('\n');
}
function Payload(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 2048) Fail('SECURITY_INPUT_INVALID', 400);
  let value; try { value = JSON.parse(text); } catch (_) { Fail('SECURITY_INPUT_INVALID', 400); }
  Fields(value, ['version', 'measurement', 'fileSha256', 'fileCrc64', 'codeSha256', 'codeCrc64', 'apiSealed', 'apiSlots', 'dynamicCode', 'cfg']);
  if (Object.keys(value).length !== 10 || value.version !== 1 || !['MEASURED', 'READ_ERROR'].includes(value.measurement) ||
      typeof value.apiSealed !== 'boolean' || !Number.isInteger(value.apiSlots) || value.apiSlots < 0 || value.apiSlots > 1024 ||
      !['UNAVAILABLE', 'ALLOWED', 'PROHIBITED'].includes(value.dynamicCode) || !['UNAVAILABLE', 'DISABLED', 'ENABLED'].includes(value.cfg)) Fail('SECURITY_INPUT_INVALID', 400);
  for (const k of ['fileSha256', 'codeSha256']) if (typeof value[k] !== 'string' || !(value.measurement === 'READ_ERROR' && value[k] === '') && !/^[a-f0-9]{64}$/.test(value[k])) Fail('SECURITY_INPUT_INVALID', 400);
  for (const k of ['fileCrc64', 'codeCrc64']) if (typeof value[k] !== 'string' || !(value.measurement === 'READ_ERROR' && value[k] === '') && !/^[A-F0-9]{16}$/.test(value[k])) Fail('SECURITY_INPUT_INVALID', 400);
  return value;
}
function Evaluate(value, baseline, policy) {
  if (value.measurement !== 'MEASURED') return { status: 'INDETERMINATE', reason: 'MEASUREMENT_UNAVAILABLE' };
  if (value.fileSha256 !== baseline.sha256 || value.fileCrc64 !== baseline.crc64 || value.codeSha256 !== baseline.codeSha256 || value.codeCrc64 !== baseline.codeCrc64) return { status: 'MISMATCH', reason: 'IMAGE_DIGEST_MISMATCH' };
  if (policy.requireReadonlyApi && (!value.apiSealed || value.apiSlots < 1)) return { status: 'INDETERMINATE', reason: 'API_STORAGE_NOT_SEALED' };
  if (policy.dynamicCode === 'prohibit' && value.dynamicCode !== 'PROHIBITED') return { status: 'INDETERMINATE', reason: 'DYNAMIC_CODE_POLICY_UNAVAILABLE' };
  if (policy.requireCfg && value.cfg !== 'ENABLED') return { status: 'INDETERMINATE', reason: 'CFG_UNAVAILABLE' };
  return { status: 'PASS', reason: 'BASELINE_MATCH' };
}
function Submit(body) {
  Fields(body, [...AUTH_FIELDS, 'challengeId', 'payload', 'signature']);
  const row = Authenticate(body), policy = Policy(); Prune();
  const challenge = pending.get(body.challengeId), context = Context(row, body.stage);
  if (!challenge || challenge.context !== context || challenge.intent !== body.intent || challenge.binding !== body.binding || challenge.revision !== policy.revision) Fail('SECURITY_CHALLENGE_INVALID', 401);
  const value = Payload(body.payload);
  if (typeof body.signature !== 'string' || !/^[A-Za-z0-9+/]{342}==$/.test(body.signature)) Fail('SECURITY_SIGNATURE_INVALID', 401);
  const key = require('./desktopLicenses').ParseKey(row.publicKey).key;
  if (!crypto.verify('sha256', Buffer.from(Canonical(body, challenge, body.payload)), { key, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(body.signature, 'base64'))) Fail('SECURITY_SIGNATURE_INVALID', 401);
  pending.delete(body.challengeId);
  const id = context + ':' + body.intent + ':' + body.binding, old = decisions.get(id);
  if (old && old.sequence >= challenge.sequence) Fail('SECURITY_OBSERVATION_REPLAY', 409);
  if (!old && decisions.size >= 4096) Fail('SECURITY_CAPACITY', 503);
  const result = Evaluate(value, row.integrityArtifact, policy);
  const decision = { ...result, revision: policy.revision, sequence: challenge.sequence,
    expiresAt: Date.now() + policy.freshnessMs, deadline: performance.now() + policy.freshnessMs };
  decisions.set(id, decision);
  Audit('OBSERVATION', result.reason, row, { sequence: challenge.sequence, revision: policy.revision, intent: body.intent });
  return { version: 1, accepted: true, ...result, proceed: result.status === 'PASS' || policy.mode === 'observe',
    sequence: challenge.sequence, expiresAt: decision.expiresAt, attested: false };
}
function RequireFresh(row, stage, intent, binding) {
  const policy = Policy(), artifact = RowArtifact(row, stage); RequireArtifact(artifact);
  if (policy.mode !== 'enforce' || !policy.enforceLegacy && artifact.authorityVersion !== 1) return;
  Prune(); const item = decisions.get(Context(row, stage) + ':' + intent + ':' + binding);
  let code = '';
  if (!item || item.revision !== policy.revision) code = 'SECURITY_FRESH_OBSERVATION_REQUIRED';
  else if (item.status === 'MISMATCH') code = 'SECURITY_OBSERVATION_MISMATCH';
  else if (item.status !== 'PASS') code = 'SECURITY_OBSERVATION_INDETERMINATE';
  if (code) { Audit('HOLD', code, { ...row, stage }, { revision: policy.revision, intent }); Fail(code); }
}
function UsesAuthority(row, stage) {
  return Policy().enforceLegacy || RowArtifact(row, stage)?.authorityVersion === 1;
}
function Invalidate(row, stage, reason) {
  const prefix = Context(row, stage) + ':';
  for (const id of decisions.keys()) if (id.startsWith(prefix)) decisions.delete(id);
  for (const [id, item] of pending) if (item.context === Context(row, stage)) pending.delete(id);
  Audit('INVALIDATED', reason, { ...row, stage });
}
function Execute(body) {
  if (!plain(body)) Fail('SECURITY_INPUT_INVALID', 400);
  require('./desktopBootstrap').EnsureSecurityAvailable();
  if (body.action === 'challenge') return Challenge(body);
  if (body.action === 'submit') return Submit(body);
  Fail('SECURITY_INPUT_INVALID', 400);
}
function List() {
  Prune(); const policy = Policy();
  const releases = Object.values(store.Load().artifacts).map(row => ({
    id: row.id, component: row.component, version: row.version, sha256: row.sha256,
    authorityVersion: row.authorityVersion || 0, compiledCfg: row.compiledCfg === true,
    signaturePresent: !!row.releaseApproval, signatureValid: !!row.releaseApproval && VerifyApproval(row, policy),
    signerKeyId: row.releaseApproval?.keyId || '', policyReason: ArtifactReason(row, policy)
  }));
  return { policy, releases, events: events.slice().reverse(), pendingCount: pending.size,
    decisionCount: decisions.size, attested: false,
    persistence: 'policy and audit: server; fresh decisions: server RAM only' };
}
module.exports = { DOMAIN, RELEASE_DOMAIN, Defaults, ValidatePolicy, Policy, SetPolicy, List,
  Binding, Canonical, Payload, Evaluate, Execute, RequireFresh, RequireArtifact, PublishMetadata,
  ReleaseCanonical, PeCapabilities, VerifyApproval, VersionAtLeast, UsesAuthority, Invalidate };
