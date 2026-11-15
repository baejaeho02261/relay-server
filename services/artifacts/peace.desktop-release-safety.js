'use strict';
// Server-only baseline preservation, release retirement and exact cohort checks.
// Mandatory regression-report publication gates and report creation were removed.
// Existing persisted reports are validated as read-only archives so upgrading
// does not rewrite or erase authority history. They never authorize/block release.
const crypto = require('node:crypto');
const provenance = require('./peace.desktop-release-provenance');
const HASH = /^[a-f0-9]{128}$/;
const ROLES = Object.freeze(['A', 'B', 'O']);
const ARCHIVED_CHECKS = Object.freeze([
  ['source-package', 'STATIC_SOURCE'], ['startup-api-contract', 'STATIC_SOURCE'],
  ['resource-contract', 'STATIC_SOURCE'], ['server-authorization', 'SERVER_EXECUTED'],
  ['server-replay-mixed', 'SERVER_EXECUTED'], ['windows-abo-handoff', 'WINDOWS_EXECUTED'],
  ['windows-overlay-renewal', 'WINDOWS_EXECUTED'], ['windows-expiry-cancel', 'WINDOWS_EXECUTED'],
  ['windows-cleanup', 'WINDOWS_EXECUTED']
].map(([id, scope]) => Object.freeze({id, scope})));
const MAX_ARCHIVED_REPORTS = 256;
const plain = x => !!x && Object.getPrototypeOf(x) === Object.prototype;
const digest = x => typeof x === 'string' && HASH.test(x);
const hash = x => crypto.createHash('sha512').update(x).digest('hex');
function Fail(code, status = 409) { const e = Error(code); e.desktopError = true; e.status = status; throw e; }
function Shape(x, names) { if (!plain(x) || Object.keys(x).length !== names.length || names.some(k => !Object.hasOwn(x, k))) Fail('RELEASE_SAFETY_INVALID', 400); }
function Time(x) { return Number.isSafeInteger(x) && x > 0; }
function Text(x, max=500) { if (typeof x !== 'string' || !x.trim() || x !== x.trim() || x.length > max || /[\x00-\x1f\x7f]/.test(x)) Fail('RELEASE_SAFETY_INVALID',400); return x; }
function ArtifactTuple(x) { Shape(x, ROLES); if (ROLES.some(r => !digest(x[r]))) Fail('RELEASE_SAFETY_INVALID',400); return x; }
function Defaults() { return {version:1, revision:0, baseline:null, reports:{}, revokedCohorts:{}}; }
function ArchivedReportId(report) { return hash('GAME-RELEASE-REGRESSION-V1\n'+provenance.Stable(report)); }
function ValidateArchivedReport(r) {
  Shape(r, ['version','kind','runId','manifestId','sourceManifestSha512','policySha512','artifacts','startedAt','finishedAt','platform','architecture','checks','hardwareAttested']);
  if (r.version!==1 || r.kind!=='RELEASE_REGRESSION' || typeof r.runId!=='string' || !/^[A-Za-z0-9_-]{8,100}$/.test(r.runId||'') || !digest(r.manifestId) || !digest(r.sourceManifestSha512) || !digest(r.policySha512) || r.platform!=='win32' || r.architecture!=='x64' || r.hardwareAttested!==false || !Time(r.startedAt) || !Time(r.finishedAt) || r.finishedAt<r.startedAt || r.finishedAt-r.startedAt>7*86400000) Fail('RELEASE_ARCHIVE_INVALID',400);
  ArtifactTuple(r.artifacts);
  if (!Array.isArray(r.checks) || r.checks.length!==ARCHIVED_CHECKS.length) Fail('RELEASE_ARCHIVE_INVALID',400);
  const ids=new Set();
  for (const c of r.checks) {
    Shape(c,['id','scope','outcome','evidenceSha512','durationMs','completedSnapshots','reasonCode']);
    const spec=ARCHIVED_CHECKS.find(x=>x.id===c.id);
    if (!spec || ids.has(c.id) || c.scope!==spec.scope || !['PASS','FAIL','NOT_RUN'].includes(c.outcome) || !Number.isSafeInteger(c.durationMs) || c.durationMs<0 || c.durationMs>r.finishedAt-r.startedAt || !Number.isSafeInteger(c.completedSnapshots) || c.completedSnapshots<0 || c.completedSnapshots>100000 || typeof c.reasonCode!=='string' || !/^[A-Z0-9_]{0,100}$/.test(c.reasonCode)) Fail('RELEASE_ARCHIVE_INVALID',400);
    if (c.outcome==='NOT_RUN' ? c.evidenceSha512!==null || c.durationMs!==0 || c.completedSnapshots!==0 || !c.reasonCode : !digest(c.evidenceSha512)) Fail('RELEASE_ARCHIVE_INVALID',400);
    if (c.outcome==='FAIL'&&!c.reasonCode || c.outcome==='PASS'&&c.reasonCode || c.id!=='windows-overlay-renewal'&&c.completedSnapshots!==0) Fail('RELEASE_ARCHIVE_INVALID',400);
    ids.add(c.id);
  }
  return r;
}
function ValidateState(s) {
  Shape(s,Object.keys(Defaults()));
  if (s.version!==1 || !Number.isSafeInteger(s.revision) || s.revision<0 || !plain(s.reports) || Object.keys(s.reports).length>MAX_ARCHIVED_REPORTS || !plain(s.revokedCohorts) || Object.keys(s.revokedCohorts).length>256) Fail('RELEASE_SAFETY_STORAGE_INVALID',503);
  if(s.baseline!==null){const b=s.baseline;Shape(b,['version','manifestId','sourceManifestSha512','policySha512','artifacts','pinnedAt','actorHash','note','evidenceTrust']);if(b.version!==1||!digest(b.manifestId)||!digest(b.sourceManifestSha512)||!digest(b.policySha512)||!digest(b.actorHash)||!Time(b.pinnedAt)||b.evidenceTrust!=='OPERATOR_PIN_NOT_TEST_PASS')Fail('RELEASE_SAFETY_STORAGE_INVALID',503);ArtifactTuple(b.artifacts);Text(b.note);}
  for(const [id,row] of Object.entries(s.reports)){Shape(row,['report','recordedAt','actorHash','evidenceTrust']);ValidateArchivedReport(row.report);if(!digest(id)||ArchivedReportId(row.report)!==id||!Time(row.recordedAt)||row.report.finishedAt>row.recordedAt+300000||!digest(row.actorHash)||row.evidenceTrust!=='AUTHENTICATED_OPERATOR_RECORD')Fail('RELEASE_SAFETY_STORAGE_INVALID',503);}
  for(const [id,r] of Object.entries(s.revokedCohorts)){Shape(r,['at','actorHash','reason']);if(!digest(id)||!Time(r.at)||!digest(r.actorHash))Fail('RELEASE_SAFETY_STORAGE_INVALID',503);Text(r.reason);}
  return s;
}
function DB(){return require("../bootstrap/peace.desktop-bootstrap-store").Load();}
function State(db=DB()){return structuredClone(ValidateState(db.releaseSafety||Defaults()));}
function PolicyHash(db=DB()) {const a=require("../security/peace.desktop-security-authority");return provenance.PolicyDigest(a.ValidatePolicy(db.securityAuthorityPolicy||a.Defaults()));}
function CheckRevision(body,db) {if(!Number.isSafeInteger(body.expectedRevision)||body.expectedRevision!==State(db).revision)Fail('RELEASE_SAFETY_CONFLICT');}
function Manifest(db,id){const row=db.securityOperations?.releaseGovernance?.manifests?.[id];if(!row||row.registration==='PLANNED')Fail('SECURITY_RELEASE_MANIFEST_NOT_REGISTERED');provenance.ValidateManifest(row.manifest);if(provenance.ManifestId(row.manifest)!==id)Fail('SECURITY_RELEASE_MANIFEST_INVALID');return row.manifest;}
function Mutate(body,actor,kind,fn){const at=Date.now(),actorHash=hash(String(actor));CheckRevision(body,DB());require("../storage/peace.desktop-operation-audit").Run(kind,actor,{},db=>{CheckRevision(body,db);const next=State(db);fn(next,db,at,actorHash);next.revision++;ValidateState(next);db.releaseSafety=next;});return Status();}
function PinBaseline(body,actor){Shape(body,['expectedRevision','expectedOperationsRevision','expectedPolicyRevision','manifestId','note']);Text(body.note);const db=DB();const ops=require("../security/peace.desktop-security-operations"),p=require("../security/peace.desktop-security-authority").Policy();if(body.expectedOperationsRevision!==ops.Revision()||body.expectedPolicyRevision!==p.revision)Fail('SECURITY_OPERATIONS_CONFLICT');const selected=ROLES.map(k=>db.artifacts[db.active[k]]);ops.RequireRuntimePair(...selected);const id=provenance.FindManifest(ops.State().releaseGovernance,...selected)?.[0];if(id!==body.manifestId)Fail('RELEASE_BASELINE_ACTIVE_CHANGED');for(const a of selected){require("../security/peace.desktop-security-authority").RequireArtifact(a);const bytes=require("../bootstrap/peace.desktop-bootstrap").ReadArtifactBytes(a);bytes.fill(0);}return Mutate(body,actor,'RELEASE_BASELINE_PINNED',(s,next,at,actorHash)=>{if((next.securityOperations?.revision||0)!==body.expectedOperationsRevision||(next.securityAuthorityPolicy?.revision||0)!==body.expectedPolicyRevision||ROLES.some((k,i)=>next.active[k]!==selected[i].id))Fail('RELEASE_BASELINE_ACTIVE_CHANGED');const m=Manifest(next,id);if(CohortReason(next,id))Fail(CohortReason(next,id));s.baseline={version:1,manifestId:id,sourceManifestSha512:m.sourceManifestSha512,policySha512:PolicyHash(next),artifacts:{...m.artifacts},pinnedAt:at,actorHash,note:body.note,evidenceTrust:'OPERATOR_PIN_NOT_TEST_PASS'};});}
function RevokeCohort(body,actor){Shape(body,['expectedRevision','manifestId','reason']);Text(body.reason);return Mutate(body,actor,'RELEASE_COHORT_REVOKED',(s,db,at,actorHash)=>{Manifest(db,body.manifestId);if(!s.revokedCohorts[body.manifestId])s.revokedCohorts[body.manifestId]={at,actorHash,reason:body.reason};});}
function CohortReason(db,id){return id&&Object.hasOwn(db.releaseSafety?.revokedCohorts||{},id)?'SECURITY_RELEASE_COHORT_REVOKED':'';}
function EvaluateCohort(db, rows, id, {sameActive=false}={}) {
  const revoked = CohortReason(db, id);
  if (revoked) return {eligible:false, reason:revoked};
  let m;
  try { m=Manifest(db,id); } catch (error) { return {eligible:false,reason:error.message}; }
  if (!Array.isArray(rows) || rows.length!==ROLES.length || rows.some((a,i)=>
      !a || a.component!==ROLES[i] || a.sha512!==m.artifacts[ROLES[i]])) {
    return {eligible:false, reason:'SECURITY_MANIFEST_ARTIFACT_MISMATCH'};
  }
  // Reconfirming exact active IDs does not introduce a new release. Preserve
  // compatibility for their original recorded policy; all runtime gates remain.
  const unchanged = sameActive && rows.every((a,i)=>db.active[ROLES[i]]===a.id);
  if (!unchanged && m.policySha512!==PolicyHash(db)) {
    return {eligible:false,reason:'SECURITY_MANIFEST_POLICY_MISMATCH'};
  }
  return {eligible:true,reason:'',status:unchanged?'UNCHANGED_ACTIVE':'COHORT_VALIDATED',
    regressionReportRequired:false,executionTestPerformed:false,hardwareAttested:false};
}
function RequireCohort(db,rows,id,options={}) {
  const view=EvaluateCohort(db,rows,id,options);
  if (!view.eligible) Fail(view.reason);
  return view;
}
function ValidateSelection(db,s){Shape(s,['version','manifestId','A','B','O']);if(s.version!==1||!digest(s.manifestId))Fail('RELEASE_SELECTION_INVALID');const m=Manifest(db,s.manifestId);for(const k of ROLES){Shape(s[k],['id','sha512']);const a=db.artifacts[s[k].id];if(!a||a.component!==k||!digest(s[k].sha512)||a.sha512!==s[k].sha512||a.sha512!==m.artifacts[k])Fail('RELEASE_SELECTION_INVALID');}return s;}
function Selection(db){const a=ROLES.map(k=>db.artifacts[db.active[k]]);const entry=provenance.FindManifest(db.securityOperations?.releaseGovernance||provenance.Defaults(),...a);if(!entry)return null;return ValidateSelection(db,{version:1,manifestId:entry[0],...Object.fromEntries(ROLES.map((r,i)=>[r,{id:a[i]?.id,sha512:a[i]?.sha512}]))});}
function RequireSelection(db,row){if(!row.releaseSelection)return;ValidateSelection(db,row.releaseSelection);if(CohortReason(db,row.releaseSelection.manifestId))Fail('SECURITY_RELEASE_COHORT_REVOKED');if(ROLES.some(k=>db.active[k]!==row.releaseSelection[k].id))Fail('BOOTSTRAP_RELEASE_SELECTION_CHANGED');if(row.artifactId!==row.releaseSelection.A.id)Fail('RELEASE_SELECTION_INVALID');}
function Status(){const db=DB(),s=State(db);const {reports,...visible}=s;return {...visible,archivedReportCount:Object.keys(reports).length,currentPolicySha512:PolicyHash(db),baselineIsTestPass:false,storage:'SERVER_ONLY'};}
module.exports={ROLES,Defaults,ValidateState,State,Status,PolicyHash,EvaluateCohort,RequireCohort,PinBaseline,RevokeCohort,CohortReason,Selection,RequireSelection,ValidateSelection};
