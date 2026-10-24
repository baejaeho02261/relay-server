'use strict';
// An administrator's execution record, never a CI signature, hardware proof,
// compiler provenance or an input to execution/publication authorization.
const crypto=require('node:crypto');
const HASH=/^[a-f0-9]{128}$/;
const digest=x=>typeof x==='string'&&HASH.test(x);
const STAGES=['probe-build-output-contracts','startup','abi-layout','hash-contracts','handoff-kdf','blake3-parallel','handoff-crypto','handoff-pipe','handoff-process','memory-lifetime','thread-inventory','device-signals','module-generation','native-api','device-key-construction','hardening-contracts','deterministic-state-core','pe-corpus','independent-pe','independent-crc','hash-reference','deterministic-state','abi-sdk-compare','overlay-first-frame','overlay-privacy','overlay-shutdown','overlay-gpu-faults','mitigation-readback','abo-integration'];
// V1 receipts keep their original digest and meaning. V2 additionally records
// the full independently selected native PE/CRC stream comparison.
const CURRENT_STAGES=[...STAGES.slice(0,-1),'independent-crc-pe',STAGES.at(-1)];
const plain=x=>!!x&&Object.getPrototypeOf(x)===Object.prototype;
function Fail(code='MANUAL_VERIFICATION_INVALID',status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Shape(x,keys){if(!plain(x)||Object.keys(x).length!==keys.length||keys.some(k=>!Object.hasOwn(x,k)))Fail();}
function ValidateLegacyReport(value){
 Shape(value,['version','kind','runId','startedAt','finishedAt','platform','architecture','sourceManifestSha512','sourceManifestUnchanged','artifacts','stages','nativeBuild','hardwareAttested','ciEvidenceCreated','publicationApproval']);
 if(![1,2].includes(value.version)||value.kind!=='MANUAL_VERIFICATION'||typeof value.runId!=='string'||!/^[A-Za-z0-9_-]{1,120}$/.test(value.runId)||value.platform!=='win32'||value.architecture!=='x64'||!digest(value.sourceManifestSha512)||typeof value.sourceManifestUnchanged!=='boolean'||value.nativeBuild!=='NOT_RUN'||value.hardwareAttested!==false||value.ciEvidenceCreated!==false||value.publicationApproval!==false)Fail();
 for(const k of ['startedAt','finishedAt'])if(typeof value[k]!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value[k])||!Number.isFinite(Date.parse(value[k]))||new Date(value[k]).toISOString()!==value[k])Fail();
 if(Date.parse(value.finishedAt)<Date.parse(value.startedAt))Fail();
 Shape(value.artifacts,['A','B','O']);for(const row of Object.values(value.artifacts)){Shape(row,['sha512','unchanged']);if(!digest(row.sha512)||typeof row.unchanged!=='boolean')Fail();}
 const expectedStages=value.version===2?CURRENT_STAGES:STAGES;
 if(!Array.isArray(value.stages)||value.stages.length!==expectedStages.length)Fail();
 const seen=new Set();for(const row of value.stages){Shape(row,['id','outcome']);if(!expectedStages.includes(row.id)||seen.has(row.id)||!['PASS','FAIL','PARTIAL','NOT_RUN'].includes(row.outcome))Fail();seen.add(row.id);}
 // Canonical order makes repeated uploads idempotent despite JSON field order.
 return {version:value.version,kind:'MANUAL_VERIFICATION',runId:value.runId,startedAt:value.startedAt,finishedAt:value.finishedAt,platform:'win32',architecture:'x64',sourceManifestSha512:value.sourceManifestSha512,sourceManifestUnchanged:value.sourceManifestUnchanged,artifacts:Object.fromEntries(['A','B','O'].map(k=>[k,{sha512:value.artifacts[k].sha512,unchanged:value.artifacts[k].unchanged}])),stages:expectedStages.map(id=>({id,outcome:value.stages.find(x=>x.id===id).outcome})),nativeBuild:'NOT_RUN',hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false};
}
const Digest=report=>crypto.createHash('sha512').update(JSON.stringify(report)).digest('hex');
function Validate(rows){
 if(!plain(rows)||Object.keys(rows).length>64)Fail('MANUAL_VERIFICATION_STORAGE_INVALID',503);
 for(const [id,row] of Object.entries(rows)){
  Shape(row,['report','recordedAt','actorHash','manifestId']);
  const report=ValidateReport(row.report);if(!digest(id)||!digest(row.manifestId)||Digest(report)!==id||report.version===3&&report.manifestId!==row.manifestId||!Number.isSafeInteger(row.recordedAt)||row.recordedAt<1||!/^[a-f0-9]{64}$/.test(row.actorHash))Fail('MANUAL_VERIFICATION_STORAGE_INVALID',503);
 }
}
function PolicyStamp(db){
 const authority=require("../security/peace.desktop-security-authority"),policy=authority.ValidatePolicy(db.securityAuthorityPolicy||authority.Defaults());
 // Settings outside the authority revision must also invalidate an older
 // report. Only a bounded, named configuration subset is hashed; never hash
 // passwords/tokens (which would expose an offline credential verifier).
 const names=['WEB_ADMIN_TRUSTED_PROXIES','WEB_ADMIN_REQUIRE_HTTPS','WEB_ADMIN_SECURE_COOKIE','WEB_ADMIN_SESSION_MS','WEB_ADMIN_ABSOLUTE_SESSION_MS','WEB_ADMIN_MAX_SESSIONS','WEB_ADMIN_LOGIN_WINDOW_MS','WEB_ADMIN_LOGIN_IP_MAX','WEB_ADMIN_LOGIN_ROLE_MAX','WEB_ADMIN_LOGIN_GLOBAL_MAX','WEB_ADMIN_CREDENTIAL_REVISION','DESKTOP_ADMIN_REAUTH_MS','DESKTOP_ADMIN_REAUTH_REQUIRED','DESKTOP_RECOVERY_WITNESS_DIR','DESKTOP_RECOVERY_WITNESS_REQUIRED','OVERLAY_CAPTURE_PRIVACY','HA_ENABLED'];
 const settings={version:1,environment:Object.fromEntries(names.map(k=>[k,process.env[k]||''])),storageEngine:require("../../config/peace.runtime-configuration").STORAGE_ENGINE,overlayCapturePrivacy:require("../../config/peace.runtime-configuration").OVERLAY_CAPTURE_PRIVACY,mitigationProfiles:db.mitigationProfiles||null};
 return {authorityRevision:policy.revision,authoritySha512:require("../artifacts/peace.desktop-release-provenance").PolicyDigest(policy),operationsRevision:db.securityOperations?.revision||0,deviceIdentityRevision:db.deviceIdentity?.revision||0,tlsPinGeneration:db.tlsPinTransition?.generation||0,deploymentConfigurationSha512:require("../artifacts/peace.desktop-release-provenance").PolicyDigest(settings)};
}
function ValidatePolicyStamp(value){
 Shape(value,['authorityRevision','authoritySha512','operationsRevision','deviceIdentityRevision','tlsPinGeneration','deploymentConfigurationSha512']);
 if(!digest(value.authoritySha512)||!digest(value.deploymentConfigurationSha512)||['authorityRevision','operationsRevision','deviceIdentityRevision','tlsPinGeneration'].some(k=>!Number.isSafeInteger(value[k])||value[k]<0))Fail();
 return Object.fromEntries(['authorityRevision','authoritySha512','operationsRevision','deviceIdentityRevision','tlsPinGeneration','deploymentConfigurationSha512'].map(k=>[k,value[k]]));
}
const catalog=require('./peace.desktop-verification-catalog');
function ValidateReport(value){
 if(value?.version!==3)return ValidateLegacyReport(value);
 Shape(value,['version','kind','runId','startedAt','finishedAt','platform','architecture','manifestId','sourceManifestSha512','sourceManifestUnchanged','artifacts','policy','domains','nativeBuild','hardwareAttested','ciEvidenceCreated','publicationApproval']);
 if(value.kind!=='MANUAL_VERIFICATION'||typeof value.runId!=='string'||!/^[A-Za-z0-9_-]{1,120}$/.test(value.runId)||!['win32','linux','darwin'].includes(value.platform)||!['x64','arm64'].includes(value.architecture)||!digest(value.manifestId)||!digest(value.sourceManifestSha512)||typeof value.sourceManifestUnchanged!=='boolean'||value.nativeBuild!=='NOT_RUN'||value.hardwareAttested!==false||value.ciEvidenceCreated!==false||value.publicationApproval!==false)Fail();
 for(const k of ['startedAt','finishedAt'])if(typeof value[k]!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value[k])||!Number.isFinite(Date.parse(value[k]))||new Date(value[k]).toISOString()!==value[k])Fail();
 if(Date.parse(value.finishedAt)<Date.parse(value.startedAt))Fail();
 Shape(value.artifacts,['A','B','O']);for(const row of Object.values(value.artifacts)){Shape(row,['sha512','unchanged']);if(!digest(row.sha512)||typeof row.unchanged!=='boolean')Fail();}
 const policy=ValidatePolicyStamp(value.policy);
 if(!Array.isArray(value.domains)||value.domains.length<1||value.domains.length>14)Fail();
 const seen=new Set(),domains=[];
 for(const domain of value.domains){
  Shape(domain,['id','checks']);const specification=catalog.CATALOG.find(x=>x.id===domain.id);
  if(!specification||seen.has(domain.id)||!Array.isArray(domain.checks)||domain.checks.length<1||domain.checks.length>specification.checks.length)Fail();seen.add(domain.id);
  const checks=[],ids=new Set();
  for(const check of domain.checks){
   Shape(check,['id','outcome','scope','execution','evidenceSha512','reasonCode','subjectArtifacts']);
   const known=specification.checks.find(x=>x.id===check.id);
   if(!known||ids.has(check.id)||!catalog.OUTCOMES.includes(check.outcome)||!known.allowedScopes.includes(check.scope)||typeof check.reasonCode!=='string'||!/^[A-Z0-9_]{0,100}$/.test(check.reasonCode)||check.outcome!=='PASS'&&!check.reasonCode)Fail();ids.add(check.id);
   if(check.outcome==='NOT_RUN'){
    if(check.execution!=='NOT_EXECUTED'||check.evidenceSha512!==null||!check.reasonCode)Fail();
   }else if(check.execution!==catalog.EXECUTION[check.scope]||!digest(check.evidenceSha512))Fail();
   if(check.execution==='WINDOWS_EXECUTED'&&(value.platform!=='win32'||value.architecture!=='x64')||check.execution==='PHYSICAL_EXECUTED'&&value.platform!=='win32')Fail();
   let subjectArtifacts=null;
   // A prepared, unexecuted dedicated scenario has no testbuild yet. Keep
   // that absence explicit; every executed outcome still requires its exact
   // A/B/O tuple, and selected-final checks always bind to the manifest tuple.
   const pendingTestBuild=check.scope==='DEDICATED_PRODUCT_TESTBUILD'&&check.outcome==='NOT_RUN'&&check.execution==='NOT_EXECUTED'&&check.subjectArtifacts===null;
   if(['SELECTED_FINAL_ABO','DEDICATED_PRODUCT_TESTBUILD'].includes(check.scope)&&!pendingTestBuild){
    Shape(check.subjectArtifacts,['A','B','O']);if(Object.values(check.subjectArtifacts).some(x=>!digest(x)))Fail();
    subjectArtifacts=Object.fromEntries(['A','B','O'].map(k=>[k,check.subjectArtifacts[k]]));
    const same=['A','B','O'].every(k=>subjectArtifacts[k]===value.artifacts[k].sha512);
    if(check.scope==='SELECTED_FINAL_ABO'&&!same||check.scope==='DEDICATED_PRODUCT_TESTBUILD'&&same)Fail('MANUAL_VERIFICATION_SUBJECT_MISMATCH');
   }else if(check.subjectArtifacts!==null)Fail();
   checks.push({id:check.id,outcome:check.outcome,scope:check.scope,execution:check.execution,evidenceSha512:check.evidenceSha512,reasonCode:check.reasonCode,subjectArtifacts});
  }
  domains.push({id:domain.id,checks:specification.checks.map(x=>checks.find(c=>c.id===x.id)).filter(Boolean)});
 }
 return {version:3,kind:'MANUAL_VERIFICATION',runId:value.runId,startedAt:value.startedAt,finishedAt:value.finishedAt,platform:value.platform,architecture:value.architecture,manifestId:value.manifestId,sourceManifestSha512:value.sourceManifestSha512,sourceManifestUnchanged:value.sourceManifestUnchanged,artifacts:Object.fromEntries(['A','B','O'].map(k=>[k,{sha512:value.artifacts[k].sha512,unchanged:value.artifacts[k].unchanged}])),policy,domains:catalog.CATALOG.map(x=>domains.find(d=>d.id===x.id)).filter(Boolean),nativeBuild:'NOT_RUN',hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false};
}
function ReportChecks(r,domainId){
 if(r.version===3)return r.domains.find(x=>x.id===domainId)?.checks||[];
 const spec=catalog.CATALOG.find(x=>x.id===domainId);
 // Legacy stage IDs are mapped only where the stage existed. Missing domains
 // and newly introduced physical scenarios remain explicitly NOT_RECORDED.
 return spec.checks.filter(x=>r.stages.some(s=>s.id===x.id)).map(x=>{
  const stage=r.stages.find(s=>s.id===x.id),scope=x.id==='abo-integration'?'SELECTED_FINAL_ABO':'WINDOWS_PROBE';
  return {id:x.id,outcome:stage.outcome,scope,execution:stage.outcome==='NOT_RUN'?'NOT_EXECUTED':'WINDOWS_EXECUTED',evidenceSha512:null,reasonCode:'LEGACY_REPORT_NO_PER_CHECK_EVIDENCE',subjectArtifacts:scope==='SELECTED_FINAL_ABO'?Object.fromEntries(['A','B','O'].map(k=>[k,r.artifacts[k].sha512])):null};
 });
}
function PolicyStatus(r,current){return r.version!==3?'UNBOUND':JSON.stringify(r.policy)===JSON.stringify(current)?'CURRENT':'STALE';}
function Unchanged(r){return r.sourceManifestUnchanged&&Object.values(r.artifacts).every(x=>x.unchanged);}
const SortRows=(a,b)=>Date.parse(b[1].report.finishedAt)-Date.parse(a[1].report.finishedAt)||b[1].recordedAt-a[1].recordedAt||b[0].localeCompare(a[0]);
function DomainSummaries(entries,current){
 return catalog.CATALOG.map(spec=>{
  const checks=spec.checks.map(known=>{
   for(const [id,row] of entries){const check=ReportChecks(row.report,spec.id).find(x=>x.id===known.id);if(check)return {...check,outcome:Unchanged(row.report)?check.outcome:'FAIL',inputsUnchanged:Unchanged(row.report),recordId:id,recordedAt:row.recordedAt,finishedAt:row.report.finishedAt,policyStatus:PolicyStatus(row.report,current),policy:row.report.policy||null,finalArtifactsExecuted:check.scope==='SELECTED_FINAL_ABO'&&check.execution==='WINDOWS_EXECUTED'};}
   return {id:known.id,outcome:'NOT_RECORDED',scope:null,execution:null,evidenceSha512:null,reasonCode:'',subjectArtifacts:null,recordId:null,recordedAt:null,finishedAt:null,policyStatus:'NOT_RECORDED',policy:null,finalArtifactsExecuted:false};
  });
  const recorded=checks.filter(x=>x.outcome!=='NOT_RECORDED'),outcome=!recorded.length?'NOT_RECORDED':checks.some(x=>x.outcome==='FAIL')?'FAIL':checks.every(x=>x.outcome==='PASS')?'PASS_REPORTED':checks.every(x=>x.outcome==='NOT_RUN')?'NOT_RUN':'PARTIAL';
  const policies=[...new Set(recorded.map(x=>x.policyStatus))];
  return {id:spec.id,name:spec.name,status:recorded.length?'OPERATOR_RECORDED':'NOT_RECORDED',scope:spec.scope,outcome,checks,policyStatus:policies.length===1?policies[0]:policies.length?'MIXED':'NOT_RECORDED',missingChecks:checks.filter(x=>x.outcome==='NOT_RECORDED').map(x=>x.id),scopeLimitedToListedChecks:true,evidenceCreated:false,hardwareAttested:false,publicationApproval:false};
 });
}
function Summary(id,row,current){
 const r=row.report,checks=r.version===3?r.domains.flatMap(x=>x.checks):r.stages;
 const totalChecks=catalog.CATALOG.reduce((n,d)=>n+d.checks.length,0),complete=r.version!==3||r.domains.length===14&&checks.length===totalChecks;
 return {id,version:r.version,runId:r.runId,manifestId:row.manifestId,sourceManifestSha512:r.sourceManifestSha512,recordedAt:row.recordedAt,finishedAt:r.finishedAt,evidenceType:'OPERATOR_RECORDED',outcome:!Unchanged(r)||checks.some(x=>x.outcome==='FAIL')?'FAIL':complete&&checks.every(x=>x.outcome==='PASS')?'PASS_REPORTED':'INCOMPLETE',coverage:r.version===3?{recordedChecks:checks.length,totalChecks,recordedDomains:r.domains.length,totalDomains:14}:null,reportScope:'LISTED_CHECKS_ONLY',artifacts:r.artifacts,stages:r.stages||[],domains:DomainSummaries([[id,row]],current),policy:r.policy||null,policyStatus:PolicyStatus(r,current),policyScope:'NAMED_SERVER_POLICIES_AND_DEPLOYMENT_SETTINGS_NOT_ENVIRONMENT_ATTESTATION',platform:r.platform,architecture:r.architecture,nativeBuild:'NOT_RUN',hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false,physicalChecks:'NOT_ATTESTED'};
}
function MatchingManifest(db,r){
 for(const role of ['A','B','O'])if(!Object.values(db.artifacts).some(x=>x.component===role&&x.sha512===r.artifacts[role].sha512))Fail('MANUAL_VERIFICATION_ARTIFACT_NOT_REGISTERED',409);
 const matches=Object.entries(db.securityOperations?.releaseGovernance?.manifests||{}).filter(([manifestId,row])=>digest(manifestId)&&row.registration==='REGISTERED'&&row.manifest.sourceManifestSha512===r.sourceManifestSha512&&['A','B','O'].every(role=>row.manifest.artifacts[role]===r.artifacts[role].sha512&&Object.values(db.artifacts).some(x=>x.component===role&&x.sha512===r.artifacts[role].sha512&&x.deploymentManifestId===manifestId))).map(([id])=>id).sort();
 if(!matches.length||r.version===3&&!matches.includes(r.manifestId))Fail('MANUAL_VERIFICATION_MANIFEST_MISMATCH',409);return r.version===3?r.manifestId:matches[0];
}
function RunConflict(rows,report,id){
 if(report.version!==3)return; // Legacy import identities retain V1/V2 semantics.
 if(Object.entries(rows).some(([other,row])=>other!==id&&row.manifestId===report.manifestId&&row.report.version===report.version&&row.report.runId===report.runId&&row.report.sourceManifestSha512===report.sourceManifestSha512&&['A','B','O'].every(k=>row.report.artifacts[k].sha512===report.artifacts[k].sha512)))Fail('MANUAL_VERIFICATION_RUN_CONFLICT',409);
}
function Import(body,actor){
 Shape(body,['reportText']);if(typeof body.reportText!=='string')Fail();
 let report;try{const parsed=require("../protocol/peace.strict-json").Parse(body.reportText,{maxBytes:65536,maxNodes:8192,maxDepth:10});if(parsed.version!==3&&Buffer.byteLength(body.reportText)>32768)Fail();report=ValidateReport(parsed);}catch(e){if(e.desktopError)throw e;Fail();}
 if(Date.parse(report.finishedAt)>Date.now()+300000)Fail('MANUAL_VERIFICATION_FUTURE_TIME');
 const id=Digest(report),store=require("../bootstrap/peace.desktop-bootstrap-store"),db=store.Load(),manifestId=MatchingManifest(db,report);Validate(db.manualVerifications||{});RunConflict(db.manualVerifications||{},report,id);
 if(db.manualVerifications?.[id]&&db.manualVerifications[id].manifestId!==manifestId)Fail('MANUAL_VERIFICATION_BINDING_CHANGED',409);
 if(db.manualVerifications?.[id])return {record:Summary(id,db.manualVerifications[id],PolicyStamp(db)),replayed:true};
 return require("../storage/peace.desktop-operation-audit").Run('MANUAL_VERIFICATION_IMPORT',actor,{fingerprint:crypto.createHash('sha256').update(id).digest('hex')},next=>{
  if(MatchingManifest(next,report)!==manifestId)Fail('MANUAL_VERIFICATION_BINDING_CHANGED',409);const rows=next.manualVerifications||{};Validate(rows);RunConflict(rows,report,id);
  if(rows[id])return {record:Summary(id,rows[id],PolicyStamp(next)),replayed:true};
  if(Object.keys(rows).length>=64)Fail('MANUAL_VERIFICATION_CAPACITY',409);
  rows[id]={report,manifestId,recordedAt:Date.now(),actorHash:crypto.createHash('sha256').update(String(actor)).digest('hex')};next.manualVerifications=rows;
  return {record:Summary(id,rows[id],PolicyStamp(next)),replayed:false};
 });
}
function Context(manifestId,db=require("../bootstrap/peace.desktop-bootstrap-store").Load()){
 if(!digest(manifestId))Fail('MANUAL_VERIFICATION_MANIFEST_INVALID');
 const row=db.securityOperations?.releaseGovernance?.manifests?.[manifestId];if(row?.registration!=='REGISTERED')Fail('MANUAL_VERIFICATION_MANIFEST_MISMATCH',409);
 const manifest=row.manifest,artifacts=Object.fromEntries(['A','B','O'].map(role=>[role,manifest.artifacts[role]]));
 MatchingManifest(db,{version:3,manifestId,sourceManifestSha512:manifest.sourceManifestSha512,artifacts:Object.fromEntries(['A','B','O'].map(k=>[k,{sha512:artifacts[k]}]))});
 return {version:1,kind:'MANUAL_VERIFICATION_CONTEXT',manifestId,sourceManifestSha512:manifest.sourceManifestSha512,artifacts,policy:PolicyStamp(db),catalog:structuredClone(catalog.CATALOG),readOnly:true,usedForPublicationAuthorization:false};
}
function Status(db=require("../bootstrap/peace.desktop-bootstrap-store").Load()){
 const rows=db.manualVerifications||{};Validate(rows);const currentPolicy=PolicyStamp(db),entries=Object.entries(rows).sort(SortRows);
 const active=Object.fromEntries(['A','B','O'].map(role=>[role,db.artifacts[db.active[role]]?.sha512||null]));
 const matching=entries.filter(([,row])=>{const manifest=db.securityOperations?.releaseGovernance?.manifests?.[row.manifestId];return manifest?.registration==='REGISTERED'&&manifest.manifest.sourceManifestSha512===row.report.sourceManifestSha512&&['A','B','O'].every(role=>row.report.artifacts[role].sha512===active[role]&&manifest.manifest.artifacts[role]===active[role]&&db.artifacts[db.active[role]].deploymentManifestId===row.manifestId);});
 const builds=new Map();
 const add=(manifestId,sourceManifestSha512,artifacts,registration)=>{
  const buildKey=Digest([manifestId,sourceManifestSha512,...['A','B','O'].map(k=>artifacts[k])]);
  if(!builds.has(buildKey))builds.set(buildKey,{buildKey,manifestId,sourceManifestSha512,artifacts,registration,active:registration==='REGISTERED'&&['A','B','O'].every(k=>active[k]===artifacts[k]&&db.artifacts[db.active[k]]?.deploymentManifestId===manifestId),entries:[]});return builds.get(buildKey);
 };
 for(const [manifestId,row] of Object.entries(db.securityOperations?.releaseGovernance?.manifests||{}))if(digest(manifestId)&&row.registration==='REGISTERED'&&digest(row.manifest?.sourceManifestSha512)&&['A','B','O'].every(k=>digest(row.manifest.artifacts?.[k])&&Object.values(db.artifacts).some(a=>a.component===k&&a.sha512===row.manifest.artifacts[k]&&a.deploymentManifestId===manifestId)))add(manifestId,row.manifest.sourceManifestSha512,{...row.manifest.artifacts},'REGISTERED');
 for(const entry of entries){const [id,row]=entry,manifest=db.securityOperations?.releaseGovernance?.manifests?.[row.manifestId];add(row.manifestId,row.report.sourceManifestSha512,Object.fromEntries(['A','B','O'].map(k=>[k,row.report.artifacts[k].sha512])),manifest?.registration||'NOT_REGISTERED').entries.push(entry);}
 return {status:matching.length?'OPERATOR_RECORD_PRESENT':'NOT_RECORDED',activeArtifacts:active,record:matching.length?Summary(...matching[0],currentPolicy):null,recordCount:entries.length,usedForPublicationAuthorization:false,currentPolicy,domains:DomainSummaries(matching,currentPolicy),history:entries.map(([id,row])=>Summary(id,row,currentPolicy)),builds:[...builds.values()].map(({entries:items,...build})=>({...build,latestRecordedAt:items.length?Math.max(...items.map(([,row])=>row.recordedAt)):null,recordCount:items.length,history:items.map(([id])=>id),domains:DomainSummaries(items,currentPolicy)})).sort((a,b)=>Number(b.active)-Number(a.active)||(b.latestRecordedAt||0)-(a.latestRecordedAt||0)||a.buildKey.localeCompare(b.buildKey)),catalog:structuredClone(catalog.CATALOG),retention:{maximumRecords:64,automaticDeletion:false,onFull:'REJECT_NEW_REPORT_KEEP_HISTORY'}};
}
module.exports={STAGES,CURRENT_STAGES,ValidateReport,Validate,Import,Status,Context,PolicyStamp,ValidatePolicyStamp,CATALOG:catalog.CATALOG};
