'use strict';
// Deployment identity and CI evidence are separate from executable approval.
// This verifies a trusted CI signer's claim, not hardware attestation or proof
// that a compiler/test runner actually ran. All enforcement is opt-in.
const crypto = require('node:crypto');
const HASH = /^[a-f0-9]{128}$/, KEY = /^[a-f0-9]{64}$/;
const MANIFEST_DOMAIN = 'GAME-DEPLOYMENT-MANIFEST-V1';
const CI_DOMAIN = 'GAME-CI-ATTESTATION-V1';
const OUTCOMES = ['PASS', 'FAIL', 'NOT_RUN'];
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
function Fail(code, status = 400) { const e = Error(code); e.desktopError = true; e.status = status; throw e; }
function Fields(value, names) { if (!plain(value) || Object.keys(value).length !== names.length || names.some(k => !Object.hasOwn(value, k))) Fail('SECURITY_PROVENANCE_INVALID'); }
function Text(value, max = 160) { if (typeof value !== 'string' || !value.trim() || value !== value.trim() || value.length > max || /[\x00-\x1f\x7f]/.test(value)) Fail('SECURITY_PROVENANCE_INVALID'); }
function Time(value) { return Number.isSafeInteger(value) && value > 0; }
function Stable(value) { if (Array.isArray(value)) return '[' + value.map(Stable).join(',') + ']'; if (plain(value)) return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + Stable(value[k])).join(',') + '}'; return JSON.stringify(value); }
const Hash = value => crypto.createHash('sha512').update(value).digest('hex');
function Defaults() { return { version:1, requireManifest:false, requireCiEvidence:false, minimumSecurityVersion:0, manifests:{}, ciKeys:{}, ciEvidence:{}, releaseKeyIds:[], recoveryPlans:{} }; }
function ValidateManifest(m) {
  Fields(m, ['version','releaseName','securityVersion','protocol','hashVersion','handoffVersion','sourceManifestSha512','policySha512','toolchain','artifacts']);
  if (m.version !== 1 || m.protocol !== 'GAME-CONNECT-4' || m.hashVersion !== 3 || ![1,3].includes(m.handoffVersion) || !Number.isSafeInteger(m.securityVersion) || m.securityVersion < 1 || !HASH.test(m.sourceManifestSha512) || !HASH.test(m.policySha512)) Fail('SECURITY_RELEASE_MANIFEST_INVALID');
  Text(m.releaseName); Fields(m.toolchain, ['delphi','cpp','windowsSdk','imgui']); for (const v of Object.values(m.toolchain)) Text(v);
  Fields(m.artifacts, ['A','B','O']); for (const v of Object.values(m.artifacts)) if (typeof v !== 'string' || !HASH.test(v)) Fail('SECURITY_RELEASE_MANIFEST_INVALID');
  return m;
}
function ManifestId(m) { ValidateManifest(m); return Hash(MANIFEST_DOMAIN + '\n' + Stable(m)); }
function PolicyDigest(policy) { if (!plain(policy)) Fail('SECURITY_PROVENANCE_INVALID'); return Hash(Stable(policy)); }
function KeyId(key) { return crypto.createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex'); }
function PublicKey(pem) {
  if (typeof pem !== 'string' || pem.length > 2048 || !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----\r?\n?$/.test(pem)) Fail('SECURITY_CI_SIGNER_INVALID');
  let key; try { key = crypto.createPublicKey(pem); } catch (_) { Fail('SECURITY_CI_SIGNER_INVALID'); }
  if (key.asymmetricKeyType !== 'ed25519') Fail('SECURITY_CI_SIGNER_INVALID');
  return key;
}
function ValidateKey(k) {
  Fields(k, ['keyId','publicKey','purpose','state','notBefore','notAfter','changedAt','changedBy']);
  if (k.purpose !== CI_DOMAIN || !KEY.test(k.keyId) || !['ACTIVE','RETIRING','REVOKED'].includes(k.state) || !Time(k.notBefore) || !Time(k.notAfter) || k.notAfter <= k.notBefore || !Time(k.changedAt) || KeyId(PublicKey(k.publicKey)) !== k.keyId) Fail('SECURITY_CI_SIGNER_INVALID');
  Text(k.changedBy); return k;
}
function ValidateStatement(s) {
  Fields(s, ['version','purpose','manifestId','runId','issuedAt','nativeBuild','apiProbe','integration','logsSha512']);
  if (s.version !== 1 || s.purpose !== CI_DOMAIN || !HASH.test(s.manifestId) || !HASH.test(s.logsSha512) || !Time(s.issuedAt) || ['nativeBuild','apiProbe','integration'].some(k => !OUTCOMES.includes(s[k]))) Fail('SECURITY_CI_EVIDENCE_INVALID');
  Text(s.runId); return s;
}
function Canonical(s) { ValidateStatement(s); return CI_DOMAIN + '\n' + Stable(s); }
function ValidateEnvelope(e) {
  Fields(e, ['keyId','statement','signature']); ValidateStatement(e.statement);
  if (!KEY.test(e.keyId) || typeof e.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(e.signature) || Buffer.from(e.signature,'base64').toString('base64') !== e.signature) Fail('SECURITY_CI_EVIDENCE_INVALID');
  return e;
}
function ValidateState(g) {
  if(plain(g)&&!Object.hasOwn(g,'releaseKeyIds'))g={...g,releaseKeyIds:[]};
  if(plain(g)&&!Object.hasOwn(g,'recoveryPlans'))g={...g,recoveryPlans:{}};
  Fields(g, Object.keys(Defaults()));
  if(!Array.isArray(g.releaseKeyIds)||g.releaseKeyIds.length>512||new Set(g.releaseKeyIds).size!==g.releaseKeyIds.length||g.releaseKeyIds.some(id=>typeof id!=='string'||!KEY.test(id)))Fail('SECURITY_RELEASE_GOVERNANCE_INVALID');
  if (g.version !== 1 || typeof g.requireManifest !== 'boolean' || typeof g.requireCiEvidence !== 'boolean' || !Number.isSafeInteger(g.minimumSecurityVersion) || g.minimumSecurityVersion < 0 || (g.requireCiEvidence || g.minimumSecurityVersion > 0) && !g.requireManifest) Fail('SECURITY_RELEASE_GOVERNANCE_INVALID');
  for (const [k,max] of [['manifests',256],['ciKeys',32],['ciEvidence',256],['recoveryPlans',100]]) if (!plain(g[k]) || Object.keys(g[k]).length > max) Fail('SECURITY_RELEASE_GOVERNANCE_INVALID');
  const pairs = new Set();
  for (const [id,r] of Object.entries(g.manifests)) {
    if(!plain(r)||Object.keys(r).some(k=>!['manifest','recordedAt','recordedBy','registration'].includes(k))||!['manifest','recordedAt','recordedBy'].every(k=>Object.hasOwn(r,k))||r.registration!==undefined&&!['PLANNED','REGISTERED'].includes(r.registration))Fail('SECURITY_RELEASE_MANIFEST_INVALID');
    if (!HASH.test(id) || ManifestId(r.manifest) !== id || !Time(r.recordedAt)) Fail('SECURITY_RELEASE_MANIFEST_INVALID');
    Text(r.recordedBy); const pair = Tuple(r.manifest.artifacts); if (pairs.has(pair)) Fail('SECURITY_RELEASE_MANIFEST_CONFLICT'); pairs.add(pair);
  }
  for (const [id,k] of Object.entries(g.ciKeys)) { ValidateKey(k); if (id !== k.keyId || g.releaseKeyIds.includes(id)) Fail('SECURITY_CI_SIGNER_INVALID'); }
  for (const [id,r] of Object.entries(g.ciEvidence)) {
    Fields(r,['envelope','recordedAt','recordedBy','evidenceType']); ValidateEnvelope(r.envelope);
    if (id !== r.envelope.statement.manifestId || !g.manifests[id] || !g.ciKeys[r.envelope.keyId] || !Time(r.recordedAt) || r.evidenceType !== 'CI_SIGNED_VERIFIED') Fail('SECURITY_CI_EVIDENCE_INVALID');
    Text(r.recordedBy);
  }
  for(const[id,r]of Object.entries(g.recoveryPlans))ValidateRecovery(id,r);
  return g;
}
function ValidateRecovery(id,r){
  Fields(r,['version','requestId','fingerprint','preparedBy','reason','createdAt','expiresAt','preparedRevision','policyRevision','selection','previous','manifestId','status','appliedAt']);
  if(!/^[A-F0-9]{24}$/.test(id)||r.version!==1||typeof r.requestId!=='string'||!/^[a-zA-Z0-9_-]{16,80}$/.test(r.requestId)||!HASH.test(r.fingerprint)||!Time(r.createdAt)||!Time(r.expiresAt)||r.expiresAt<=r.createdAt||r.expiresAt-r.createdAt>300000||!Number.isSafeInteger(r.preparedRevision)||r.preparedRevision<1||!Number.isSafeInteger(r.policyRevision)||r.policyRevision<0||!['PREPARED','APPLIED'].includes(r.status)||(r.status==='APPLIED'?!Time(r.appliedAt):r.appliedAt!==0)||typeof r.manifestId!=='string'||r.manifestId!==''&&!HASH.test(r.manifestId))Fail('SECURITY_RECOVERY_INVALID');
  Text(r.preparedBy);Text(r.reason,500);Fields(r.selection,['aId','bId','oId']);Fields(r.previous,['A','B','O']);
  for(const[k,v]of Object.entries(r.selection))if(typeof v!=='string'||!(k==='oId'&&v==='')&&!/^(?:DA-)?[A-F0-9]{24}$/.test(v))Fail('SECURITY_RECOVERY_INVALID');
  for(const v of Object.values(r.previous))if(typeof v!=='string'||v!==''&&!/^(?:DA-)?[A-F0-9]{24}$/.test(v))Fail('SECURITY_RECOVERY_INVALID');return r;
}
function Tuple(artifacts) { return ['A','B','O'].map(k => artifacts[k] || '').join(':'); }
function FindManifest(g,a,b,o) { const target=Tuple({A:a?.sha512,B:b?.sha512,O:o?.sha512}); return Object.entries(g.manifests).find(([,r]) => Tuple(r.manifest.artifacts) === target) || null; }
function VerifyEnvelope(e,k,releaseKeys=[]) {
  try {
    ValidateEnvelope(e); ValidateKey(k);
    if (e.keyId !== k.keyId || k.state === 'REVOKED' || releaseKeys.some(x => x.keyId === k.keyId) || e.statement.issuedAt < k.notBefore || e.statement.issuedAt > k.notAfter) return false;
    return crypto.verify(null,Buffer.from(Canonical(e.statement),'utf8'),PublicKey(k.publicKey),Buffer.from(e.signature,'base64'));
  } catch (_) { return false; }
}
function Evaluate(g,a,b,o,releaseKeys=[]) {
  const entry=FindManifest(g,a,b,o), manifestId=entry?.[0] || '', manifest=entry?.[1].manifest || null;
  const record=manifestId ? g.ciEvidence[manifestId] : null;
  const ciVerified=!!record && VerifyEnvelope(record.envelope,g.ciKeys[record.envelope.keyId],releaseKeys);
  let reason='';
  const declarations=[a,b,o].filter(Boolean).map(row=>row.deploymentManifestId||'');
  if(declarations.some(Boolean)&&(new Set(declarations).size!==1||declarations[0]!==manifestId))reason='SECURITY_RELEASE_MIXED_MANIFEST';
  else if(manifest&&(g.requireManifest||declarations.some(Boolean))&&entry[1].registration==='PLANNED')reason='SECURITY_RELEASE_MANIFEST_NOT_REGISTERED';
  else if (g.requireManifest && !manifest) {
    const selected={A:a?.sha512,B:b?.sha512,O:o?.sha512};
    const known=Object.values(g.manifests).some(r => ['A','B','O'].some(k => selected[k] && r.manifest.artifacts[k] === selected[k]));
    reason=known ? 'SECURITY_RELEASE_MIXED_MANIFEST' : 'SECURITY_RELEASE_MANIFEST_REQUIRED';
  } else if (manifest && manifest.securityVersion < g.minimumSecurityVersion) reason='SECURITY_RELEASE_DOWNGRADE';
  else if (g.requireCiEvidence && (!ciVerified || ['nativeBuild','apiProbe','integration'].some(k => record.envelope.statement[k] !== 'PASS'))) reason='SECURITY_CI_EVIDENCE_REQUIRED';
  return {manifestId,securityVersion:manifest?.securityVersion || 0,reason,evidenceType:ciVerified?'CI_SIGNED_VERIFIED':manifest?'OPERATOR_RECORDED':'NONE',ciOutcomes:ciVerified?{nativeBuild:record.envelope.statement.nativeBuild,apiProbe:record.envelope.statement.apiProbe,integration:record.envelope.statement.integration}:null,hardwareAttested:false};
}
module.exports={ValidateRecovery,Defaults,ValidateState,ValidateManifest,ManifestId,PolicyDigest,KeyId,PublicKey,ValidateKey,ValidateStatement,ValidateEnvelope,Canonical,VerifyEnvelope,Evaluate,FindManifest,Tuple,Stable,CI_DOMAIN};
