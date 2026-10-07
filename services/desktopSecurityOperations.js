'use strict';
// All approval policy, build contracts, rollout selection and test evidence live
// in the server authority store. Native evidence stays on the existing V1 wire.
const crypto = require('node:crypto');
const store = require('./desktopBootstrapStore');
const HASH = /^[a-f0-9]{128}$/;
const KEY_ID = /^[a-f0-9]{64}$/;
const BUILD = /^[ABO]:[a-f0-9]{128}$/;
const OUTCOMES = ['PASS', 'FAIL', 'NOT_RUN'];
const CHECKS = ['ownImage', 'apiStorage', 'mitigations'];
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const plain = x => !!x && typeof x === 'object' && !Array.isArray(x) && Object.getPrototypeOf(x) === Object.prototype;
function Fail(code, status = 400) { const e = Error(code); e.desktopError = true; e.status = status; throw e; }
function Fields(value, allowed, required = allowed) {
  if (!plain(value) || Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(value, k))) Fail('SECURITY_OPERATIONS_INVALID');
}
function Text(value, max = 160) { if (typeof value !== 'string' || !value.trim() || value.length > max || /[\x00-\x1f\x7f]/.test(value)) Fail('SECURITY_OPERATIONS_INVALID'); return value.trim(); }
function Actor(value) { return String(value || 'ADMIN').replace(/[\x00-\x1f\x7f]/g, '').slice(0,160); }
function Defaults() { return { version:1, revision:0, requireBuildContract:false, requireTestEvidence:false, contracts:{}, signerStates:{}, pairEvidence:{}, rollout:{enabled:false,artifactKeys:[],patch:{}}, activations:[] }; }
function BuildKey(artifact) { return artifact.component + ':' + artifact.sha512; }
function PairKey(a, b, o) { return a.sha512 + ':' + b.sha512 + (o ? ':' + o.sha512 : ''); }
function ValidateContract(c) {
  Fields(c, ['version','evidenceVersion','minApiSlots','maxApiSlots','requiredChecks']);
  if (c.version !== 1 || c.evidenceVersion !== 1 || !Number.isInteger(c.minApiSlots) || !Number.isInteger(c.maxApiSlots) || c.minApiSlots < 1 || c.maxApiSlots < c.minApiSlots || c.maxApiSlots > 1024 || !Array.isArray(c.requiredChecks) || c.requiredChecks.length !== CHECKS.length || CHECKS.some(x => !c.requiredChecks.includes(x))) Fail('SECURITY_BUILD_CONTRACT_INVALID');
  return c;
}
function ValidateRollout(r) {
  Fields(r, ['enabled','artifactKeys','patch']);
  Fields(r.patch, ['mode','requireReadonlyApi','dynamicCode','requireCfg'], []);
  if (typeof r.enabled !== 'boolean' || !Array.isArray(r.artifactKeys) || r.artifactKeys.length > 128 || new Set(r.artifactKeys).size !== r.artifactKeys.length || r.artifactKeys.some(k => !BUILD.test(k)) || r.enabled && (!r.artifactKeys.length || !Object.keys(r.patch).length)) Fail('SECURITY_ROLLOUT_INVALID');
  if (Object.hasOwn(r.patch,'mode') && !['observe','enforce'].includes(r.patch.mode) || Object.hasOwn(r.patch,'dynamicCode') && !['observe','prohibit'].includes(r.patch.dynamicCode) || ['requireReadonlyApi','requireCfg'].some(k => Object.hasOwn(r.patch,k) && typeof r.patch[k] !== 'boolean')) Fail('SECURITY_ROLLOUT_INVALID');
  return r;
}
function ValidateEvidence(e) {
  const fields=['version','aSha512','bSha512','sourceManifestSha512','logsSha512','nativeBuild','apiProbe','integration','note','recordedAt','recordedBy','evidenceType'];
  Fields(e, [...fields,'oSha512'], fields);
  if (e.version !== 1 || e.evidenceType !== 'OPERATOR_RECORDED' || ['aSha512','bSha512','sourceManifestSha512','logsSha512'].some(k => !HASH.test(e[k])) || ['nativeBuild','apiProbe','integration'].some(k => !OUTCOMES.includes(e[k])) || !Number.isSafeInteger(e.recordedAt) || e.recordedAt < 1) Fail('SECURITY_TEST_EVIDENCE_INVALID');
  if (Object.hasOwn(e,'oSha512') && (typeof e.oSha512 !== 'string' || !HASH.test(e.oSha512))) Fail('SECURITY_TEST_EVIDENCE_INVALID');
  Text(e.note,500); Text(e.recordedBy); return e;
}
function ValidateState(s) {
  Fields(s, Object.keys(Defaults()));
  if (s.version !== 1 || !Number.isSafeInteger(s.revision) || s.revision < 0 || typeof s.requireBuildContract !== 'boolean' || typeof s.requireTestEvidence !== 'boolean') Fail('SECURITY_OPERATIONS_STORAGE_INVALID');
  for (const [key, limit] of [['contracts',512],['signerStates',64],['pairEvidence',256]]) if (!plain(s[key]) || Object.keys(s[key]).length > limit) Fail('SECURITY_OPERATIONS_STORAGE_INVALID');
  for (const [key,c] of Object.entries(s.contracts)) { if (!BUILD.test(key)) Fail('SECURITY_OPERATIONS_STORAGE_INVALID'); ValidateContract(c); }
  for (const [key,r] of Object.entries(s.signerStates)) { Fields(r,['state','changedAt','changedBy']); if (!KEY_ID.test(key) || !['ACTIVE','RETIRING','REVOKED'].includes(r.state) || !Number.isSafeInteger(r.changedAt) || r.changedAt<1) Fail('SECURITY_OPERATIONS_STORAGE_INVALID'); Text(r.changedBy); }
  for (const [key,e] of Object.entries(s.pairEvidence)) { ValidateEvidence(e); if (key !== e.aSha512+':'+e.bSha512+(e.oSha512?':'+e.oSha512:'')) Fail('SECURITY_OPERATIONS_STORAGE_INVALID'); }
  ValidateRollout(s.rollout);
  if (!Array.isArray(s.activations) || s.activations.length > 100) Fail('SECURITY_OPERATIONS_STORAGE_INVALID');
  for (const a of s.activations) {
    const fields=['at','actor','aId','bId','aSha512','bSha512','previousA','previousB','policyRevision','operationsRevision'];
    Fields(a,[...fields,'oId','oSha512','previousO'],fields);
    if (!Number.isSafeInteger(a.at) || a.at < 1 || !HASH.test(a.aSha512) || !HASH.test(a.bSha512) || !Number.isSafeInteger(a.policyRevision) || !Number.isSafeInteger(a.operationsRevision)) Fail('SECURITY_OPERATIONS_STORAGE_INVALID');
    for (const k of ['aId','bId','previousA','previousB']) if (typeof a[k] !== 'string' || !/^(?:(?:DA-)?[A-F0-9]{24})?$/.test(a[k])) Fail('SECURITY_OPERATIONS_STORAGE_INVALID');
    if (['oId','oSha512','previousO'].some(k=>Object.hasOwn(a,k))) {
      if (['oId','previousO'].some(k=>typeof a[k]!=='string'||!/^(?:(?:DA-)?[A-F0-9]{24})?$/.test(a[k])) || typeof a.oSha512!=='string' || (a.oId ? !HASH.test(a.oSha512) : a.oSha512!=='')) Fail('SECURITY_OPERATIONS_STORAGE_INVALID');
    }
    Text(a.actor);
  }
  return s;
}
function State() { return structuredClone(ValidateState(store.Load().securityOperations || Defaults())); }
function Revision() { return State().revision; }
function CheckRevision(body, policyRequired = false) {
  if (!Number.isSafeInteger(body.expectedRevision) || body.expectedRevision !== Revision()) Fail('SECURITY_OPERATIONS_CONFLICT',409);
  if (policyRequired && body.expectedPolicyRevision !== require('./desktopSecurityAuthority').Policy().revision) Fail('SECURITY_POLICY_CONFLICT',409);
}
function AuditIntent(kind, actor) {
  const result = require('../storage/audit').LogEvent('DESKTOP_SECURITY_CHANGE_INTENT',JSON.stringify({kind,actor:Actor(actor)}),{durable:true});
  if (!result || result.ok !== true) Fail('SECURITY_AUDIT_UNAVAILABLE',503);
}
function Commit(next, actor, kind, apply) {
  ValidateState(next); AuditIntent(kind,actor);
  store.Atomic(db => {
    const before = db.securityOperations || Defaults();
    if (next.revision !== before.revision+1) Fail('SECURITY_OPERATIONS_CONFLICT',409);
    db.securityOperations = next;
    if (apply) apply(db);
  });
  require('./desktopSecurityAuthority').InvalidateAll();
  require('../storage/audit').LogEvent('DESKTOP_SECURITY_OPERATIONS',JSON.stringify({kind,revision:next.revision,actor:Actor(actor)}));
  return State();
}
function SignerState(keyId) { return State().signerStates[keyId]?.state || 'ACTIVE'; }
function SignerAllowed(keyId, newUpload = false) { const state = SignerState(keyId); return state !== 'REVOKED' && (!newUpload || state === 'ACTIVE'); }
function ArtifactReason(artifact, s = State(), publishing = false) {
  if (!artifact) return 'SECURITY_RELEASE_MISSING';
  if (artifact.releaseApproval && s.signerStates[artifact.releaseApproval.keyId]?.state === 'REVOKED') return 'SECURITY_SIGNER_REVOKED';
  if (!publishing && s.requireBuildContract && !s.contracts[BuildKey(artifact)]) return 'SECURITY_BUILD_CONTRACT_REQUIRED';
  return '';
}
function EffectivePolicy(policy, artifact) {
  const s=State(),r=s.rollout;
  return r.enabled && artifact && r.artifactKeys.includes(BuildKey(artifact)) ? {...policy,...r.patch} : policy;
}
function EvaluateContract(value, artifact) {
  const s=State(),c=artifact && s.contracts[BuildKey(artifact)];
  if (!c) return s.requireBuildContract ? {status:'INDETERMINATE',reason:'BUILD_CONTRACT_REQUIRED'} : null;
  if (value.version !== c.evidenceVersion) return {status:'INDETERMINATE',reason:'EVIDENCE_VERSION_MISMATCH'};
  if (value.apiSlots < c.minApiSlots || value.apiSlots > c.maxApiSlots) return {status:'INDETERMINATE',reason:'API_SLOT_COUNT_MISMATCH'};
  return null;
}
function ValidateActive(next) {
  const db=store.Load();
  for (const component of ['A','B','O']) { const row=db.artifacts[db.active[component]]; if (row) { const reason=ArtifactReason(row,next); if(reason) Fail(reason,409); } }
  if (next.requireTestEvidence && db.active.A && db.active.B) RequirePairEvidence(db.artifacts[db.active.A],db.artifacts[db.active.B],next,db.artifacts[db.active.O]);
}
function SetControls(body,actor) {
  Fields(body,['expectedRevision','requireBuildContract','requireTestEvidence'],['expectedRevision']); CheckRevision(body);
  const s=State(); for(const k of ['requireBuildContract','requireTestEvidence']) if(Object.hasOwn(body,k)) s[k]=body[k];
  s.revision++; ValidateState(s); ValidateActive(s); return Commit(s,actor,'CONTROLS_CHANGED');
}
function SetContract(body,actor) {
  Fields(body,['expectedRevision','artifactId','contract']); CheckRevision(body);
  const artifact=store.Load().artifacts[body.artifactId]; if (!artifact) Fail('SECURITY_RELEASE_MISSING',404);
  if (artifact.authorityVersion !== 1) Fail('SECURITY_CLIENT_UPGRADE_REQUIRED',409);
  const c=structuredClone(ValidateContract(body.contract)),s=State(); s.contracts[BuildKey(artifact)]=c;s.revision++;
  return Commit(s,actor,'BUILD_CONTRACT_CHANGED');
}
function SetSignerState(body,actor) {
  Fields(body,['expectedRevision','keyId','state']); CheckRevision(body);
  if (!KEY_ID.test(body.keyId) || !['ACTIVE','RETIRING','REVOKED'].includes(body.state) || !require('./desktopSecurityAuthority').Policy().trustedReleaseKeys.some(k=>k.keyId===body.keyId)) Fail('SECURITY_SIGNER_INVALID');
  const s=State(); if (s.signerStates[body.keyId]?.state==='REVOKED' && body.state!=='REVOKED') Fail('SECURITY_SIGNER_REVOKE_FINAL',409);
  s.signerStates[body.keyId]={state:body.state,changedAt:Date.now(),changedBy:Actor(actor)};s.revision++;
  // Emergency revocation is allowed even when an active artifact becomes invalid.
  // Runtime gates fail closed; publishing a trusted replacement is still allowed.
  return Commit(s,actor,'SIGNER_'+body.state);
}
function ProposedRollout(body) {
  Fields(body,['expectedRevision','expectedPolicyRevision','rollout']);CheckRevision(body,true);
  const r=structuredClone(ValidateRollout(body.rollout)),db=store.Load(),auth=require('./desktopSecurityAuthority');
  for (const key of r.artifactKeys) {
    const artifact=Object.values(db.artifacts).find(a=>BuildKey(a)===key); if(!artifact) Fail('SECURITY_RELEASE_MISSING',404);
    const policy={...auth.Policy(),...r.patch}; if(r.enabled&&policy.requireCfg&&!artifact.compiledCfg) Fail('SECURITY_CFG_BUILD_REQUIRED',409);
    if(r.enabled&&artifact.authorityVersion!==1) Fail('SECURITY_CLIENT_UPGRADE_REQUIRED',409);
  }
  return r;
}
function SetRollout(body,actor) {
  const r=ProposedRollout(body),s=State();s.rollout=r;s.revision++;return Commit(s,actor,'ROLLOUT_CHANGED');
}
function RecordEvidence(body,actor) {
  Fields(body,['expectedRevision','aId','bId','oId','report'],['expectedRevision','aId','bId','report']);CheckRevision(body);
  const [a,b]=Pair(body.aId,body.bId);
  const o=Overlay(body.oId===undefined?'':body.oId);
  const fields=['version','aSha512','bSha512','sourceManifestSha512','logsSha512','nativeBuild','apiProbe','integration','note'];
  Fields(body.report,[...fields,'oSha512'],fields);
  if (body.report.aSha512!==a.sha512 || body.report.bSha512!==b.sha512 || (o ? body.report.oSha512!==o.sha512 : Object.hasOwn(body.report,'oSha512'))) Fail('SECURITY_EVIDENCE_ARTIFACT_MISMATCH',409);
  const e=ValidateEvidence({...structuredClone(body.report),recordedAt:Date.now(),recordedBy:Actor(actor),evidenceType:'OPERATOR_RECORDED'});
  const s=State();s.pairEvidence[PairKey(a,b,o)]=e;s.revision++;return Commit(s,actor,'TEST_EVIDENCE_RECORDED');
}
function Pair(aId,bId) { const db=store.Load(),a=db.artifacts[aId],b=db.artifacts[bId];if(!a||a.component!=='A'||!b||b.component!=='B'||a.protocol!=='GAME-CONNECT-4'||b.protocol!==a.protocol) Fail('SECURITY_RELEASE_PAIR_INVALID');return[a,b]; }
function Overlay(id) {
  if (id==='') return null;
  const o=typeof id==='string'&&store.Load().artifacts[id];
  if (!o||o.component!=='O'||o.protocol!=='GAME-CONNECT-4') Fail('SECURITY_RELEASE_PAIR_INVALID');
  return o;
}
function SelectedOverlay(body) { return Overlay(Object.hasOwn(body,'oId')?body.oId:store.Load().active.O||''); }
function RequirePairEvidence(a,b,s=State(),o=null) { const e=s.pairEvidence[PairKey(a,b,o)];if(!e||['nativeBuild','apiProbe','integration'].some(k=>e[k]!=='PASS')) Fail('SECURITY_TEST_EVIDENCE_REQUIRED',409);return e; }
function RequireRuntimePair(a,b,o=null) {
  const state=State();if(!state.requireTestEvidence)return;
  if(!a||!b||a.component!=='A'||b.component!=='B'||o&&o.component!=='O')Fail('SECURITY_RELEASE_PAIR_INVALID',409);
  RequirePairEvidence(a,b,state,o);
}
function PreviewPair(body) {
  Fields(body,['aId','bId','oId'],['aId','bId']); const [a,b]=Pair(body.aId,body.bId),o=SelectedOverlay(body),s=State(),auth=require('./desktopSecurityAuthority'),p=auth.Policy();
  const reasons=[a,b,...(o?[o]:[])].map(row=>auth.ArtifactReason(row,p)||ArtifactReason(row,s)).filter(Boolean);
  const e=s.pairEvidence[PairKey(a,b,o)]||null;
  if(s.requireTestEvidence&&(!e||['nativeBuild','apiProbe','integration'].some(k=>e[k]!=='PASS'))) reasons.push('SECURITY_TEST_EVIDENCE_REQUIRED');
  return {aId:a.id,bId:b.id,oId:o?.id||'',aSha512:a.sha512,bSha512:b.sha512,oSha512:o?.sha512||'',eligible:!reasons.length,reasons,policyRevision:p.revision,operationsRevision:s.revision,testEvidence:e,hardwareAttested:false};
}
function ActivatePair(body,actor) {
  Fields(body,['expectedRevision','expectedPolicyRevision','aId','bId','oId'],['expectedRevision','expectedPolicyRevision','aId','bId']);CheckRevision(body,true);
  const selected={aId:body.aId,bId:body.bId,...(Object.hasOwn(body,'oId')?{oId:body.oId}:{})};
  const view=PreviewPair(selected); if(!view.eligible) Fail(view.reasons[0],409);
  const [a,b]=Pair(body.aId,body.bId),o=Overlay(view.oId),db=store.Load(),boot=require('./desktopBootstrap');
  // Re-read bytes just before the atomic pointer swap, not the upload's old result.
  boot.ReadArtifactBytes(a);boot.ReadArtifactBytes(b);if(o)boot.ReadArtifactBytes(o);
  const s=State();s.revision++;s.activations.push({at:Date.now(),actor:Actor(actor),aId:a.id,bId:b.id,aSha512:a.sha512,bSha512:b.sha512,previousA:db.active.A||'',previousB:db.active.B||'',...(o||db.active.O?{oId:o?.id||'',oSha512:o?.sha512||'',previousO:db.active.O||''}:{}),policyRevision:body.expectedPolicyRevision,operationsRevision:s.revision});s.activations=s.activations.slice(-100);
  Commit(s,actor,'PAIR_ACTIVATED',next=>{next.active={A:a.id,B:b.id,...(o?{O:o.id}:{})};});return PreviewPair({aId:a.id,bId:b.id,oId:o?.id||''});
}
function Stage(component,version,bytes,approval,actor) {
  AuditIntent('ARTIFACT_STAGE',actor);
  if(approval && !SignerAllowed(approval.keyId,true)) Fail('SECURITY_SIGNER_NOT_ACTIVE',409);
  return require('./desktopBootstrap').Publish(component,version,bytes,approval,{activate:false,deduplicate:true});
}
function List() {
  const s=State(),db=store.Load();
  return {operations:s,active:{...db.active},auditHealth:require('../storage/audit').WriteHealth(),
    adminProtection:require('./desktopAdminGuard').Status(),
    storage:'SERVER_ONLY',testEvidenceTrust:'OPERATOR_RECORDED_NOT_ATTESTATION',
    candidates:Object.values(db.artifacts).map(a=>({id:a.id,component:a.component,version:a.version,sha512:a.sha512,createdAt:a.createdAt,active:db.active[a.component]===a.id,contract:s.contracts[BuildKey(a)]||null}))};
}
module.exports={Defaults,ValidateState,State,Revision,BuildKey,PairKey,ValidateContract,ValidateEvidence,ValidateRollout,ProposedRollout,SignerAllowed,SignerState,ArtifactReason,EffectivePolicy,EvaluateContract,SetControls,SetContract,SetSignerState,SetRollout,RecordEvidence,RequirePairEvidence,RequireRuntimePair,PreviewPair,ActivatePair,Stage,List,AuditIntent,sha};
