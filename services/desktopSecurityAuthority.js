'use strict';
// Server-owned policy and short-lived decisions. Signed client observations are
// NOT hardware attestation and never replace the existing license/session gate.
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const deadline = require('./desktopDeadline');
const requestProtocol = require('./desktopRequestProtocol');
const receipts = requestProtocol.CreateReceipts({ conflict: 'SECURITY_REQUEST_REUSED' });
const store = require('./desktopBootstrapStore');
const DOMAIN = 'GAME-AUTHORITY-V2';
const RELEASE_DOMAIN = 'GAME-RELEASE-APPROVAL-V2';
const pending = new Map(), decisions = new Map(), rates = new Map(), events = [], observations = new Map();
const epoch = crypto.randomBytes(24).toString('hex');
let sequence = 0;
const sha = value => crypto.createHash('sha512').update(value).digest('hex');
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
function Fail(code, status = 403) { const error = Error(code); error.desktopError = true; error.status = status; throw error; }
function Fields(value, allowed) { if (!plain(value) || Object.keys(value).some(key => !allowed.includes(key))) Fail('SECURITY_INPUT_INVALID', 400); }
function Defaults() {
  return { version: 1, revision: 0, mode: 'enforce', enforceLegacy: false,
    freshnessMs: 45000, challengeMs: 15000, requireReadonlyApi: true, requireCompleteCrcLayers:true,
    dynamicCode: 'observe', requireCfg: false, minVersionA: '0', minVersionB: '0', minVersionO: '0',
    requireReleaseSignature: false, trustedReleaseKeys: [], revokedSha512: [], revokedLegacySha256: [] };
}
function ValidatePolicy(value) {
  // Version 1 stores predate O. Reading an old policy is a detached, lossless
  // projection; no policy write or revision increment occurs during migration.
  if(plain(value)&&!Object.hasOwn(value,'requireCompleteCrcLayers'))value={...value,requireCompleteCrcLayers:true};
  if(plain(value)&&!Object.hasOwn(value,'revokedLegacySha256'))value={...value,revokedLegacySha256:[]};
  if (plain(value) && !Object.hasOwn(value,'minVersionO')) value={...value,minVersionO:'0'};
  Fields(value, Object.keys(Defaults()));
  if (Object.keys(value).length !== Object.keys(Defaults()).length || value.version !== 1 ||
      !Number.isSafeInteger(value.revision) || value.revision < 0 || !['observe', 'enforce'].includes(value.mode) ||
      !['observe', 'prohibit'].includes(value.dynamicCode) ||
      ['enforceLegacy', 'requireReadonlyApi', 'requireCompleteCrcLayers', 'requireCfg', 'requireReleaseSignature'].some(k => typeof value[k] !== 'boolean') ||
      !Number.isInteger(value.freshnessMs) || value.freshnessMs < 5000 || value.freshnessMs > 120000 ||
      !Number.isInteger(value.challengeMs) || value.challengeMs < 5000 || value.challengeMs > 30000 ||
      ['minVersionA', 'minVersionB', 'minVersionO'].some(k => typeof value[k] !== 'string' || !/^\d{1,9}(?:\.\d{1,9}){0,3}$/.test(value[k])) ||
      !Array.isArray(value.trustedReleaseKeys) || value.trustedReleaseKeys.length > 8 ||
      !Array.isArray(value.revokedSha512) || value.revokedSha512.length > 512 ||
      value.revokedSha512.some(x => typeof x !== 'string' || !/^[a-f0-9]{128}$/.test(x)) ||
      new Set(value.revokedSha512).size !== value.revokedSha512.length || !Array.isArray(value.revokedLegacySha256)||value.revokedLegacySha256.length>512||value.revokedLegacySha256.some(x=>typeof x!=='string'||!/^[a-f0-9]{64}$/.test(x))) Fail('SECURITY_POLICY_INVALID', 400);
  const ids = new Set();
  for (const entry of value.trustedReleaseKeys) {
    Fields(entry, ['keyId', 'publicKey']);
    if (typeof entry.publicKey !== 'string' || entry.publicKey.length > 4096 || !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----\r?\n?$/.test(entry.publicKey) || ids.has(entry.keyId)) Fail('SECURITY_POLICY_INVALID', 400);
    let key; try { key = crypto.createPublicKey(entry.publicKey); } catch (_) { Fail('SECURITY_POLICY_INVALID', 400); }
    if (key.asymmetricKeyType !== 'ed25519' || entry.keyId !== crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex')) Fail('SECURITY_POLICY_INVALID', 400);
    ids.add(entry.keyId);
  }
  if (value.requireReleaseSignature && !ids.size) Fail('SECURITY_SIGNER_REQUIRED', 409);
  return value;
}
function Policy() {
  const value = store.Load().securityAuthorityPolicy || Defaults();
  return structuredClone(ValidatePolicy(value));
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
  if(signer)require('./desktopKeyPurposes').Assert(signer.publicKey,'RELEASE_APPROVAL');
  if (!signer || !require('./desktopSecurityOperations').SignerAllowed(approval.keyId) || Buffer.from(approval.signature, 'base64').toString('base64') !== approval.signature) return false;
  try { return crypto.verify(null, Buffer.from(ReleaseCanonical(artifact.component, artifact.version, artifact.sha512)), signer.publicKey, Buffer.from(approval.signature, 'base64')); }
  catch (_) { return false; }
}
function ArtifactMetadataReason(artifact, policy) {
  if (!artifact) return 'SECURITY_RELEASE_MISSING';
  if (policy.revokedSha512.includes(artifact.sha512)||artifact.legacyRevocationSha256&&policy.revokedLegacySha256.includes(artifact.legacyRevocationSha256)) return 'SECURITY_RELEASE_REVOKED';
  if (!['A','B','O'].includes(artifact.component)) return 'SECURITY_RELEASE_COMPONENT';
  if (!VersionAtLeast(artifact.version, policy['minVersion'+artifact.component] || '0')) return 'SECURITY_RELEASE_VERSION';
  if (!VerifyApproval(artifact, policy)) return 'SECURITY_RELEASE_SIGNATURE';
  if (policy.enforceLegacy && artifact.authorityVersion !== 1) return 'SECURITY_CLIENT_UPGRADE_REQUIRED';
  if (policy.requireCfg && artifact.compiledCfg !== true) return 'SECURITY_CFG_BUILD_REQUIRED';
  return '';
}
function CoverageReason(artifact, policy) {
  const coverage = require('./desktopCrcPolicy').Compare(artifact?.crcLayers, artifact?.crcLayers);
  if (!coverage.matched) return 'CRC_BASELINE_UNAVAILABLE';
  if (policy.requireCompleteCrcLayers && !coverage.complete) return 'CRC_COVERAGE_INCOMPLETE';
  return '';
}
function ArtifactReason(artifact, policy) {
  return ArtifactMetadataReason(artifact, policy) || CoverageReason(artifact, policy);
}
function RequireArtifact(artifact) { const reason = ArtifactReason(artifact, Policy()) || require('./desktopSecurityOperations').ArtifactReason(artifact); if (reason) Fail(reason); }
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
  const row = { component, version, hashVersion:3,sha512: sha(bytes), legacyRevocationSha256:crypto.createHash('sha256').update(bytes).digest('hex'), ...PeCapabilities(bytes) };
  if (approval !== undefined) { Fields(approval, ['keyId', 'signature']); row.releaseApproval = structuredClone(approval); }
  // The CRC baseline is computed by Publish after these signature/capability
  // checks. Only this provisional metadata row omits coverage validation.
  const reason = ArtifactMetadataReason(row, Policy()); if(reason) Fail(reason);
  if(approval && !require('./desktopSecurityOperations').SignerAllowed(approval.keyId,true)) Fail('SECURITY_SIGNER_NOT_ACTIVE',409);
  return { authorityVersion: row.authorityVersion, compiledCfg: row.compiledCfg, legacyRevocationSha256:row.legacyRevocationSha256, ...(row.releaseApproval ? { releaseApproval: row.releaseApproval } : {}) };
}
function ProposedPolicy(body) {
  Fields(body, [...Object.keys(Defaults()).filter(k => !['version', 'revision'].includes(k)), 'expectedRevision', 'expectedOperationsRevision']);
  const old = Policy();
  if (body.expectedRevision !== old.revision) Fail('SECURITY_POLICY_CONFLICT', 409);
  if (body.expectedOperationsRevision !== undefined && body.expectedOperationsRevision !== require('./desktopSecurityOperations').Revision()) Fail('SECURITY_OPERATIONS_CONFLICT',409);
  const patch = { ...body }; delete patch.expectedRevision; delete patch.expectedOperationsRevision;
  const next = ValidatePolicy({ ...old, ...patch, revision: old.revision + 1 });
  require('./desktopSecurityOperations').AssertReleaseKeyPurpose(next.trustedReleaseKeys);
  return next;
}
function PreviewPolicy(body) {
  const next=ProposedPolicy(body),db=store.Load(),at=Date.now(),ops=require('./desktopSecurityOperations');
  const releases=Object.values(db.artifacts).map(a=>({id:a.id,component:a.component,version:a.version,sha512:a.sha512,active:db.active[a.component]===a.id,reason:ArtifactReason(a,next)||ops.ArtifactReason(a)}));
  const recent=[];
  for(const item of observations.values()) {
    if(at-item.at>600000) continue;
    const artifact=db.artifacts[item.artifactId]; if(!artifact) continue;
    const releaseReason=ArtifactReason(artifact,next)||ops.ArtifactReason(artifact);
    const result=releaseReason?{status:'INDETERMINATE',reason:releaseReason}:Evaluate(item.value,item.baseline,next,artifact);
    recent.push({stage:item.stage,sessionId:item.sessionId,artifactId:item.artifactId,observedAt:item.at,...result});
  }
  return {policy:next,baseRevision:Policy().revision,operationsRevision:ops.Revision(),releases,recentObservations:recent.slice(-256),
    evaluatedObservationCount:recent.length,willClearRollout:ops.State().rollout.enabled,
    eligible:!releases.some(r=>r.active&&r.reason),runtimeCompatibility:'RECENT_OBSERVATIONS_ONLY_NOT_OFFLINE_PC_PROOF',readOnly:true};
}
function PreviewRollout(body) {
  const ops=require('./desktopSecurityOperations'),rollout=ops.ProposedRollout(body),policy=Policy(),db=store.Load(),at=Date.now();
  const effective=artifact=>rollout.enabled&&rollout.artifactKeys.includes(ops.BuildKey(artifact))?{...policy,...rollout.patch}:policy;
  const releases=Object.values(db.artifacts).map(a=>({id:a.id,component:a.component,version:a.version,sha512:a.sha512,selected:rollout.enabled&&rollout.artifactKeys.includes(ops.BuildKey(a)),reason:ArtifactReason(a,effective(a))||ops.ArtifactReason(a)}));
  const recent=[];
  for(const item of observations.values()) {
    if(at-item.at>600000)continue;
    const artifact=db.artifacts[item.artifactId];if(!artifact)continue;
    const next=effective(artifact),reason=ArtifactReason(artifact,next)||ops.ArtifactReason(artifact);
    recent.push({stage:item.stage,sessionId:item.sessionId,artifactId:artifact.id,observedAt:item.at,selected:rollout.enabled&&rollout.artifactKeys.includes(ops.BuildKey(artifact)),...(reason?{status:'INDETERMINATE',reason}:Evaluate(item.value,item.baseline,next,artifact))});
  }
  return {rollout,baseRevision:policy.revision,operationsRevision:ops.Revision(),releases,recentObservations:recent.slice(-256),evaluatedObservationCount:recent.length,readOnly:true,runtimeCompatibility:'RECENT_OBSERVATIONS_ONLY_NOT_OFFLINE_PC_PROOF'};
}
function SetPolicy(body, actor) {
  const next=ProposedPolicy(body),db=store.Load();
  for(const component of ['A','B','O']) {
    const artifact=db.artifacts[db.active[component]];
    if(artifact) { const reason=ArtifactReason(artifact,next)||require('./desktopSecurityOperations').ArtifactReason(artifact);if(reason) Fail(reason,409); }
  }
  require('./desktopSecurityOperations').AuditIntent('POLICY_CHANGED',actor);
  store.Atomic(state=>{
    const purposesChanged=require('./desktopSecurityOperations').RememberReleaseKeys(state,next.trustedReleaseKeys);
    const rolloutChanged=!!state.securityOperations?.rollout.enabled;
    // A global policy commit ends the explicit build-scoped pilot, atomically.
    if(rolloutChanged) {
      state.securityOperations.rollout={enabled:false,artifactKeys:[],patch:{}};
    }
    if(purposesChanged||rolloutChanged)state.securityOperations.revision++;
    state.securityAuthorityPolicy=next;
  });
  InvalidateAll();
  Audit('POLICY','POLICY_CHANGED',null,{revision:next.revision,actor});
  return Policy();
}
function InvalidateAll() { pending.clear(); decisions.clear(); receipts.clear(); }
function RetireContext(row,stage){const context=Context(row,stage);for(const [id,value]of pending)if(value.context===context)pending.delete(id);for(const id of decisions.keys())if(id.startsWith(context+':'))decisions.delete(id);receipts.deleteWhere(meta=>meta.context===context);rates.delete(context);observations.delete(context);}
function Context(row, stage) { return stage + ':' + (stage === 'A' ? row.id : row.sessionId); }
function Binding(operationId, payloadHash) { return sha(operationId + '|' + payloadHash); }
function RowArtifact(row, stage) {
  const db = store.Load();
  return db.artifacts[stage === 'A' ? db.launchers[row.launcherId]?.artifactId : row.releaseId];
}
function Prune() {
  const clock = deadline.Now(), at = clock.wall, tick = clock.tick;
  for (const [id, item] of pending) if (deadline.Expired(item, clock)) pending.delete(id);
  for (const [id, item] of decisions) if (deadline.Expired(item, clock)) decisions.delete(id);
  for (const [id, item] of rates) if (item.deadline <= tick) rates.delete(id);
  for (const [id,item] of observations) if(at-item.at>600000) observations.delete(id);
}
const AUTH_FIELDS = ['action', 'stage', 'sessionId', 'sessionToken', 'machineId', 'intent', 'binding'];
function Authenticate(body) {
  if (!['A', 'B', 'O'].includes(body.stage) || !['finish', 'redeem', 'verify', 'observe'].includes(body.intent) ||
      (body.stage === 'A' ? !['finish', 'observe'].includes(body.intent) : body.intent === 'finish') ||
      typeof body.machineId !== 'string' || !/^[A-F0-9]{64}$/.test(body.machineId) ||
      typeof body.binding !== 'string' || !/^[a-f0-9]{128}$/.test(body.binding)) Fail('SECURITY_INPUT_INVALID', 400);
  const row = require('./desktopBootstrap').AuthenticateIntegrityReport(body);
  RequireArtifact(RowArtifact(row, body.stage));
  return row;
}
function Challenge(body) {
  Fields(body, AUTH_FIELDS);
  const row = Authenticate(body), policy = require('./desktopSecurityOperations').EffectivePolicy(Policy(),RowArtifact(row,body.stage)), context = Context(row, body.stage);
  Prune(); const rate = rates.get(context) || { count: 0, deadline: performance.now() + 60000 };
  if (++rate.count > 40 || pending.size >= 1024 || rates.size >= 4096 && !rates.has(context)) Fail('SECURITY_RATE_LIMIT', 429);
  if([...pending.values()].filter(x=>x.context===context&&x.intent===body.intent&&x.binding===body.binding).length>=2) Fail('SECURITY_OBSERVATION_BUSY',429);
  rates.set(context, rate);
  const item = { challengeId: crypto.randomBytes(24).toString('hex'), nonce: crypto.randomBytes(24).toString('hex'),
    epoch, sequence: ++sequence, revision: policy.revision, operationsRevision:require('./desktopSecurityOperations').Revision(), ...deadline.After(policy.challengeMs), context, stage: body.stage, intent: body.intent, binding: body.binding };
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
  if (typeof text !== 'string' || Buffer.byteLength(text) > 16384) Fail('SECURITY_INPUT_INVALID', 400);
  let value; try { value = JSON.parse(text); } catch (_) { Fail('SECURITY_INPUT_INVALID', 400); }
  Fields(value, ['version', 'hashVersion', 'measurement', 'fileSha512', 'fileCrc64', 'codeSha512', 'codeCrc64', 'codeXxh3_128', 'codeBlake3', 'crcLayers', 'apiSealed', 'apiSlots', 'dynamicCode', 'cfg']);
  if (value.hashVersion !== 3 || value.version !== 1 || !['MEASURED', 'READ_ERROR'].includes(value.measurement) ||
      typeof value.apiSealed !== 'boolean' || !Number.isInteger(value.apiSlots) || value.apiSlots < 0 || value.apiSlots > 1024 ||
      !['UNAVAILABLE', 'ALLOWED', 'PROHIBITED'].includes(value.dynamicCode) || !['UNAVAILABLE', 'DISABLED', 'ENABLED'].includes(value.cfg)) Fail('SECURITY_INPUT_INVALID', 400);
  for (const k of ['fileSha512', 'codeSha512']) if (typeof value[k] !== 'string' || !(value.measurement === 'READ_ERROR' && value[k] === '') && !/^[a-f0-9]{128}$/.test(value[k])) Fail('SECURITY_INPUT_INVALID', 400);
  for (const k of ['fileCrc64', 'codeCrc64']) if (typeof value[k] !== 'string' || !(value.measurement === 'READ_ERROR' && value[k] === '') && !/^[A-F0-9]{16}$/.test(value[k])) Fail('SECURITY_INPUT_INVALID', 400);
  if(value.measurement==='MEASURED'&&!require('./desktopCrcPolicy').Validate(value.crcLayers))Fail('SECURITY_INPUT_INVALID',400);
  for(const [key,length] of [['codeXxh3_128',32],['codeBlake3',64]])if(typeof value[key]!=='string'||!(value.measurement==='READ_ERROR'&&value[key]==='')&&!new RegExp('^[a-f0-9]{'+length+'}$').test(value[key]))Fail('SECURITY_INPUT_INVALID',400);
  return value;
}
function Evaluate(value, baseline, policy, artifact) {
  if(value.hashVersion!==3||baseline.hashVersion!==3)return {status:'INDETERMINATE',reason:'HASH_VERSION_MISMATCH'};
  if (value.measurement !== 'MEASURED') return { status: 'INDETERMINATE', reason: 'MEASUREMENT_UNAVAILABLE' };
  if (value.fileSha512 !== baseline.sha512 || value.fileCrc64 !== baseline.crc64 || value.codeSha512 !== baseline.codeSha512 || value.codeCrc64 !== baseline.codeCrc64 || value.codeXxh3_128!==baseline.codeXxh3_128 || value.codeBlake3!==baseline.codeBlake3) return { status: 'MISMATCH', reason: 'IMAGE_DIGEST_MISMATCH' };
  const crcComparison=require('./desktopCrcPolicy').Compare(value.crcLayers,baseline.crcLayers);
  if(!crcComparison.matched)return {status:'MISMATCH',reason:crcComparison.reason,crcComparison};
  if(policy.requireCompleteCrcLayers&&!crcComparison.complete)return {status:'INDETERMINATE',reason:'CRC_COVERAGE_INCOMPLETE',crcComparison};
  if (policy.requireReadonlyApi && (!value.apiSealed || value.apiSlots < 1)) return { status: 'INDETERMINATE', reason: 'API_STORAGE_NOT_SEALED' };
  if(artifact) { const contractResult=require('./desktopSecurityOperations').EvaluateContract(value,artifact);if(contractResult) return contractResult; }
  if (policy.dynamicCode === 'prohibit' && value.dynamicCode !== 'PROHIBITED') return { status: 'INDETERMINATE', reason: 'DYNAMIC_CODE_POLICY_UNAVAILABLE' };
  if (policy.requireCfg && value.cfg !== 'ENABLED') return { status: 'INDETERMINATE', reason: 'CFG_UNAVAILABLE' };
  return { status: 'PASS', reason: 'BASELINE_MATCH',crcComparison }; 
}
function Submit(body) {
  Fields(body, [...AUTH_FIELDS, 'challengeId', 'payload', 'signature']);
  const row = Authenticate(body), artifact=RowArtifact(row,body.stage), policy = require('./desktopSecurityOperations').EffectivePolicy(Policy(),artifact); Prune();
  const receipt = receipts.get(body.challengeId, 'authority.submit', body);
  if (receipt) {
    const current = decisions.get(receipt.meta.id);
    // Recovery is a copy of the original response, never a new measurement or
    // lease. A newer result, changed policy, or retired context wins.
    if (!current || current.sequence !== receipt.response.sequence || current.revision !== policy.revision || current.operationsRevision !== require('./desktopSecurityOperations').Revision()) Fail('SECURITY_CHALLENGE_INVALID', 401);
    return receipt.response;
  }
  const challenge = pending.get(body.challengeId), context = Context(row, body.stage);
  if (!challenge || challenge.context !== context || challenge.intent !== body.intent || challenge.binding !== body.binding || challenge.revision !== policy.revision || challenge.operationsRevision!==require('./desktopSecurityOperations').Revision()) Fail('SECURITY_CHALLENGE_INVALID', 401);
  const value = Payload(body.payload);
  if (typeof body.signature !== 'string' || !/^[A-Za-z0-9+/]{342}==$/.test(body.signature) || Buffer.from(body.signature, 'base64').toString('base64') !== body.signature) Fail('SECURITY_SIGNATURE_INVALID', 401);
  const key = require('./desktopLicenses').ParseKey(row.publicKey).key;
  if (!crypto.verify('sha256', Buffer.from(Canonical(body, challenge, body.payload)), { key, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(body.signature, 'base64'))) Fail('SECURITY_SIGNATURE_INVALID', 401);
  pending.delete(body.challengeId);
  // Verification may cross a deadline. Both server clocks must still permit
  // consumption; client timestamps never extend this one-use capability.
  if (deadline.Expired(challenge)) Fail('SECURITY_CHALLENGE_INVALID', 401);
  const id = context + ':' + body.intent + ':' + body.binding, old = decisions.get(id);
  if (challenge.superseded || old && old.sequence >= challenge.sequence) Fail('SECURITY_OBSERVATION_REPLAY', 409);
  if (!old && decisions.size >= 4096) Fail('SECURITY_CAPACITY', 503);
  const result = Evaluate(value, row.integrityArtifact, policy, artifact);
  if (deadline.Expired(challenge)) Fail('SECURITY_CHALLENGE_INVALID', 401);
  if(observations.size>=4096&&!observations.has(context)) observations.delete(observations.keys().next().value);
  observations.set(context,{at:Date.now(),stage:body.stage,sessionId:body.sessionId,artifactId:artifact.id,value:{...value},baseline:Object.fromEntries(['hashVersion','sha512','crc64','codeSha512','codeCrc64','codeXxh3_128','codeBlake3','crcLayers'].map(k=>[k,row.integrityArtifact[k]]))});
  const decision = { ...result, revision: policy.revision, operationsRevision:require('./desktopSecurityOperations').Revision(), sequence: challenge.sequence,
    ...deadline.After(policy.freshnessMs) };
  decisions.set(id, decision);
  // A decision can expire before an older challenge (freshnessMs may be less
  // than challengeMs). Retain the ordering rejection on that pending challenge
  // itself so pruning the newer decision cannot revive an older measurement.
  for (const item of pending.values()) if (item.context === context && item.intent === body.intent && item.binding === body.binding && item.sequence < challenge.sequence) item.superseded = true;
  Audit('OBSERVATION', result.reason, {...row,stage:body.stage}, { sequence: challenge.sequence, revision: policy.revision, intent: body.intent });
  const response = { version: 1, accepted: true, status:result.status,reason:result.reason, proceed: result.status === 'PASS' || policy.mode === 'observe',
    sequence: challenge.sequence, expiresAt: decision.expiresAt, attested: false };
  receipts.put(body.challengeId, 'authority.submit', body, response, { context, id }, { ttlMs: policy.freshnessMs });
  return response;
}
function RequireFresh(row, stage, intent, binding) {
  const artifact = RowArtifact(row, stage), policy = require('./desktopSecurityOperations').EffectivePolicy(Policy(),artifact); RequireArtifact(artifact);
  if (policy.mode !== 'enforce') return;
  Prune(); const item = decisions.get(Context(row, stage) + ':' + intent + ':' + binding);
  let code = '';
  if (!item || item.revision !== policy.revision || item.operationsRevision!==require('./desktopSecurityOperations').Revision()) code = 'SECURITY_FRESH_OBSERVATION_REQUIRED';
  else if (item.status === 'MISMATCH') code = 'SECURITY_OBSERVATION_MISMATCH';
  else if (item.status !== 'PASS') code = 'SECURITY_OBSERVATION_INDETERMINATE';
  if (code) { Audit('HOLD', code, { ...row, stage }, { revision: policy.revision, intent }); Fail(code); }
}
function UsesAuthority(row, stage) {
  return Policy().enforceLegacy || RowArtifact(row, stage)?.hashVersion === 3;
}
function Invalidate(row, stage, reason) {
  const prefix = Context(row, stage) + ':';
  for (const id of decisions.keys()) if (id.startsWith(prefix)) decisions.delete(id);
  for (const [id, item] of pending) if (item.context === Context(row, stage)) pending.delete(id);
  receipts.deleteWhere(meta=>meta.context===Context(row,stage));
  Audit('INVALIDATED', reason, { ...row, stage });
}
function Execute(body) {
  if (!plain(body)) Fail('SECURITY_INPUT_INVALID', 400);
  require('./desktopBootstrap').EnsureSecurityAvailable();
  if (body.action === 'challenge') { requestProtocol.Purpose('authority.challenge'); return Challenge(body); }
  if (body.action === 'submit') { requestProtocol.Purpose('authority.submit'); return Submit(body); }
  Fail('SECURITY_INPUT_INVALID', 400);
}
function ActivationObservations(policy, artifactIds) {
  const at=Date.now(),latest=new Map();
  for(const item of observations.values()) {
    if(!artifactIds.includes(item.artifactId)||item.at>at||at-item.at>600000)continue;
    const artifact=store.Load().artifacts[item.artifactId];if(!artifact)continue;
    const reason=ArtifactReason(artifact,policy);
    const result=reason?{status:'INDETERMINATE',reason}:Evaluate(item.value,item.baseline,policy,artifact);
    const previous=latest.get(item.artifactId);
    if(!previous||item.at>=previous.observedAt)latest.set(item.artifactId,{artifactId:item.artifactId,stage:item.stage,observedAt:item.at,...result,
      apiSlots:item.value.apiSlots,apiSealed:item.value.apiSealed,dynamicCode:item.value.dynamicCode,cfg:item.value.cfg});
  }
  return Array.from(latest.values());
}
function RecentBuildObservations() {
  const grouped=new Map(),at=Date.now();
  for(const item of observations.values()) {
    if(at-item.at>600000)continue;
    let view=grouped.get(item.artifactId);
    if(!view){view={artifactId:item.artifactId,observations:0,minApiSlots:item.value.apiSlots,maxApiSlots:item.value.apiSlots,lastObservedAt:0,reportedNotAttested:true};grouped.set(item.artifactId,view);}
    view.observations++;view.minApiSlots=Math.min(view.minApiSlots,item.value.apiSlots);view.maxApiSlots=Math.max(view.maxApiSlots,item.value.apiSlots);view.lastObservedAt=Math.max(view.lastObservedAt,item.at);
  }
  return Array.from(grouped.values());
}
function List() {
  Prune(); const policy = Policy();
  const releases = Object.values(store.Load().artifacts).map(row => ({
    id: row.id, component: row.component, version: row.version, sha512: row.sha512,
    authorityVersion: row.authorityVersion || 0, compiledCfg: row.compiledCfg === true,
    signaturePresent: !!row.releaseApproval, signatureValid: !!row.releaseApproval && VerifyApproval(row, policy),
    signerKeyId: row.releaseApproval?.keyId || '', policyReason: ArtifactReason(row, policy)
  }));
  return { policy, releases, recentBuildObservations:RecentBuildObservations(), operations:require('./desktopSecurityOperations').List(), events: events.slice().reverse(), pendingCount: pending.size,
    decisionCount: decisions.size, attested: false,
    persistence: 'policy and audit: server; fresh decisions: server RAM only' };
}
module.exports = { RetireContext, ActivationObservations, PreviewRollout, PreviewPolicy, ArtifactReason, InvalidateAll, DOMAIN, RELEASE_DOMAIN, Defaults, ValidatePolicy, Policy, SetPolicy, List,
  Binding, Canonical, Payload, Evaluate, Execute, RequireFresh, RequireArtifact, PublishMetadata,
  ReleaseCanonical, PeCapabilities, VerifyApproval, VersionAtLeast, UsesAuthority, Invalidate };
