'use strict';
// Optional operator records of actual linked-native-unit trials. Reports never
// become execution authority, CI evidence or full A/B/O workflow attestation.
const crypto=require('node:crypto'),stable=require("../artifacts/peace.desktop-release-provenance").Stable;
const HASH=/^[a-f0-9]{128}$/,MODES=['observe','prohibit'],SCOPES=['AB','O'];
const plain=x=>!!x&&Object.getPrototypeOf(x)===Object.prototype;
const hash=x=>crypto.createHash('sha512').update(x).digest('hex');
function Fail(code='MITIGATION_COMPATIBILITY_INVALID',status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Shape(x,keys){if(!plain(x)||Object.keys(x).sort().join(',')!==keys.slice().sort().join(','))Fail();}
function Digest(x){return typeof x==='string'&&HASH.test(x);}
function Time(x){return typeof x==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;}
function PolicyReadback(settings,o){
 const required=[...(settings.dynamicCode==='prohibit'?[['dynamic',7,1]]:[]),...(settings.strictHandles?[['strictHandle',3,3]]:[]),...(settings.imageLoadMask?[['imageLoad',settings.imageLoadMask,settings.imageLoadMask]]:[]),...(settings.requireCfg?[['cfg',1,1]]:[])];
 if(required.some(([name])=>!o[name+'Queried']&&[50,87,120].includes(o[name+'Error'])))return 'UNSUPPORTED';
 return required.every(([name,mask,expected])=>o[name+'Queried']&&(o[name+'Flags']&mask)===expected)?'PASS':'FAIL';
}
function NativeResult(r,mode,scope){
 Shape(r,['version','kind','componentScope','environment','settings','observation','policyReadback','renderer','visibleFrames','scope']);
 if(r.version!==1||r.kind!=='NATIVE_MITIGATION_OBSERVATION'||r.componentScope!==scope)Fail();
 require('./peace.desktop-mitigation-profiles').Environment(r.environment);require('./peace.desktop-mitigation-profiles').Settings(r.settings);
 if(r.settings.dynamicCode!==mode||r.settings.strictHandles!==true||r.settings.imageLoadMask!==3||r.settings.requireCfg!==false)Fail();
 const o=r.observation;if(!plain(o))Fail();
 require('./peace.mitigation-contract').Validate(o,o.dynamicQueried?((o.dynamicFlags&7)===1?'PROHIBITED':'ALLOWED'):'UNAVAILABLE',o.cfgQueried?((o.cfgFlags&1)?'ENABLED':'DISABLED'):'UNAVAILABLE');
 if(o.version!==2||o.profileId!=='a'.repeat(128)||o.requestedMode!==mode||r.policyReadback!==PolicyReadback(r.settings,o))Fail();
 if(!Number.isInteger(r.visibleFrames)||r.visibleFrames<0||r.visibleFrames>1)Fail();
 if(scope==='AB'){
  if(r.environment.gpuIdentitySha512!=='none'||r.renderer!=='NOT_RUN'||r.visibleFrames!==0||r.scope!=='NATIVE_POLICY_READBACK_NOT_PRODUCT_WORKFLOW')Fail();
 }else if(!Digest(r.environment.gpuIdentitySha512)||!['PASS','FAIL'].includes(r.renderer)||r.renderer==='PASS'&&r.visibleFrames!==1||r.scope!=='REAL_RENDERER_POLICY_AND_VISIBLE_PRESENT')Fail();
 return r;
}
function Outcome(row){
 if(!row.executed)return 'NOT_RUN';
 // A trustworthy-looking partial stdout record cannot replace child completion.
 // Probe-defined exit 1 may report unsupported policy; a timeout, launch error,
 // crash/abnormal status or invalid record always remains a failed trial.
 if(!row.result||row.exitCode===null||![0,1].includes(row.exitCode)||['PROBE_EXECUTION_FAILED','NATIVE_REPORT_INVALID'].includes(row.reason))return 'FAIL';
 if(row.result.policyReadback==='UNSUPPORTED')return row.exitCode===1?'UNSUPPORTED':'FAIL';
 if(row.exitCode!==0||row.reason!==''||row.result.policyReadback!=='PASS'||row.componentScope==='O'&&row.result.renderer!=='PASS')return 'FAIL';
 return 'PASS';
}
function ValidateReport(r){
 Shape(r,['version','kind','runId','startedAt','finishedAt','platform','architecture','sourceManifestSha512','sourceManifestUnchanged','artifacts','probes','rows','windowsExecuted','hardwareAttested','ciEvidenceCreated','publicationApproval','scope']);
 if(r.version!==1||r.kind!=='MITIGATION_COMPATIBILITY_OBSERVATION'||typeof r.runId!=='string'||!/^mitigation-[A-Za-z0-9_-]{1,100}$/.test(r.runId)||!Time(r.startedAt)||!Time(r.finishedAt)||Date.parse(r.finishedAt)<Date.parse(r.startedAt)||r.platform!=='win32'||r.architecture!=='x64'||!Digest(r.sourceManifestSha512)||typeof r.sourceManifestUnchanged!=='boolean'||typeof r.windowsExecuted!=='boolean'||r.hardwareAttested!==false||r.ciEvidenceCreated!==false||r.publicationApproval!==false||r.scope!=='LINKED_RELEASE_UNITS_ONLY_NOT_PRODUCT_WORKFLOW')Fail();
 Shape(r.artifacts,['A','B','O']);for(const row of Object.values(r.artifacts)){Shape(row,['sha512','unchanged']);if(!Digest(row.sha512)||typeof row.unchanged!=='boolean')Fail();}
 Shape(r.probes,['AB','O']);for(const p of Object.values(r.probes)){Shape(p,['sha512','unchanged']);if(p.sha512!==null&&!Digest(p.sha512)||typeof p.unchanged!=='boolean'||p.sha512===null&&p.unchanged)Fail();}
 if(!Array.isArray(r.rows)||r.rows.length!==4)Fail();const seen=new Set();let windowsBuild;const gpu=new Set();
 for(const row of r.rows){
  Shape(row,['mode','componentScope','probeSha512','executed','exitCode','status','reason','logSha512','result']);
  const key=row.mode+':'+row.componentScope;if(!MODES.includes(row.mode)||!SCOPES.includes(row.componentScope)||seen.has(key)||typeof row.executed!=='boolean'||row.probeSha512!==r.probes[row.componentScope].sha512||row.exitCode!==null&&(!Number.isInteger(row.exitCode)||row.exitCode<0||row.exitCode>0xffffffff)||!Digest(row.logSha512)||!['','PROBE_MISSING','PROBE_EXECUTION_FAILED','NATIVE_REPORT_INVALID','NATIVE_COMPATIBILITY_FAILURE'].includes(row.reason))Fail();seen.add(key);
  if(!row.executed&&(row.exitCode!==null||row.result!==null||row.reason!=='PROBE_MISSING')||row.executed&&!Digest(row.probeSha512))Fail();
  if(row.result){NativeResult(row.result,row.mode,row.componentScope);const build=row.result.environment.windowsBuild;if(windowsBuild!==undefined&&windowsBuild!==build)Fail('MITIGATION_COMPATIBILITY_OS_CHANGED');windowsBuild=build;if(row.componentScope==='O')gpu.add(row.result.environment.gpuIdentitySha512);}
  if(row.status!==Outcome(row)||row.status==='PASS'&&row.reason!=='')Fail();
 }
 if(gpu.size>1)Fail('MITIGATION_COMPATIBILITY_GPU_CHANGED');
 if(r.windowsExecuted!==r.rows.some(row=>row.result!==null))Fail();
 const normalized=JSON.parse(stable(r));
 normalized.rows.sort((a,b)=>MODES.indexOf(a.mode)-MODES.indexOf(b.mode)||SCOPES.indexOf(a.componentScope)-SCOPES.indexOf(b.componentScope));
 return normalized;
}
const ReportId=r=>hash(stable(ValidateReport(r)));
function Validate(rows){
 if(!plain(rows)||Object.keys(rows).length>32)Fail('MITIGATION_COMPATIBILITY_STORAGE_INVALID',503);
 try{for(const[id,row]of Object.entries(rows)){Shape(row,['report','manifestId','recordedAt','actorHash']);if(!Digest(id)||!Digest(row.manifestId)||!Number.isSafeInteger(row.recordedAt)||row.recordedAt<1||!Digest(row.actorHash)||ReportId(row.report)!==id)Fail();}}
 catch(_){Fail('MITIGATION_COMPATIBILITY_STORAGE_INVALID',503);}
 return rows;
}
function Binding(db,report){
 const matches=Object.entries(db.securityOperations?.releaseGovernance?.manifests||{}).filter(([id,row])=>Digest(id)&&row.registration==='REGISTERED'&&row.manifest.sourceManifestSha512===report.sourceManifestSha512&&['A','B','O'].every(role=>row.manifest.artifacts[role]===report.artifacts[role].sha512&&Object.values(db.artifacts||{}).some(a=>a.component===role&&a.sha512===report.artifacts[role].sha512&&a.deploymentManifestId===id))).map(([id])=>id).sort();
 if(!matches.length)Fail('MITIGATION_COMPATIBILITY_MANIFEST_MISMATCH',409);return matches[0];
}
function Summary(id,row,db,now=Date.now()){
 const r=row.report,unchanged=r.sourceManifestUnchanged&&Object.values(r.artifacts).every(a=>a.unchanged)&&Object.values(r.probes).every(p=>p.sha512===null||p.unchanged);
 const active=['A','B','O'].every(role=>db.artifacts?.[db.active?.[role]]?.sha512===r.artifacts[role].sha512&&db.artifacts[db.active[role]].deploymentManifestId===row.manifestId);
 let current=true;try{current=Binding(db,r)===row.manifestId;}catch(_){current=false;}
 return {id,runId:r.runId,manifestId:row.manifestId,recordedAt:row.recordedAt,finishedAt:r.finishedAt,artifacts:r.artifacts,currentBinding:current,activeArtifacts:active,evidenceType:'OPERATOR_RECORDED',windowsExecuted:r.windowsExecuted,scope:r.scope,productWorkflow:'NOT_RUN',hardwareAttested:false,ciEvidenceCreated:false,usedForAuthorization:false,rows:r.rows.map(x=>{const result=x.result,environment=result?.environment||null,stale=now-Date.parse(r.finishedAt)>30*86400000;let judgement='NOT_RUN';if(!unchanged||!current)judgement='INPUT_OR_RELEASE_CHANGED';else if(stale)judgement='STALE_RETEST_REQUIRED';else if(x.status==='FAIL'||x.status==='UNSUPPORTED')judgement='DO_NOT_APPLY';else if(x.status==='PASS')judgement='PROBE_PASS_PRODUCT_VALIDATION_REQUIRED';return{mode:x.mode,componentScope:x.componentScope,status:x.status,environment,environmentId:environment?hash(stable(environment)):null,driverBinding:x.componentScope==='O'?'DXGI_ADAPTER_AND_UMD_VERSION_SHA512':'NOT_GRAPHICS_TESTED',settings:result?.settings||null,observation:result?.observation||null,renderer:result?.renderer||'NOT_RUN',judgement};})};
}
function Import(body,actor){
 Shape(body,['reportText']);if(typeof body.reportText!=='string')Fail();let report;
 try{report=ValidateReport(require("../protocol/peace.strict-json").Parse(body.reportText,{maxBytes:32768,maxNodes:4096,maxDepth:10}));}catch(e){if(e.desktopError)throw e;Fail();}
 if(Date.parse(report.finishedAt)>Date.now()+300000)Fail('MITIGATION_COMPATIBILITY_FUTURE_TIME');
 const store=require("../bootstrap/peace.desktop-bootstrap-store"),db=store.Load(),id=ReportId(report),manifestId=Binding(db,report);Validate(db.mitigationCompatibility||{});
 if(db.mitigationCompatibility?.[id])return {record:Summary(id,db.mitigationCompatibility[id],db),replayed:true};
 return require("../storage/peace.desktop-operation-audit").Run('MITIGATION_COMPATIBILITY_IMPORT',actor,{fingerprint:hash(id).slice(0,64)},next=>{
  if(Binding(next,report)!==manifestId)Fail('MITIGATION_COMPATIBILITY_BINDING_CHANGED',409);const rows=next.mitigationCompatibility||{};Validate(rows);
  if(rows[id])return {record:Summary(id,rows[id],next),replayed:true};
  if(Object.keys(rows).length>=32)Fail('MITIGATION_COMPATIBILITY_CAPACITY',409);
  rows[id]={report,manifestId,recordedAt:Date.now(),actorHash:hash(String(actor))};next.mitigationCompatibility=rows;
  return {record:Summary(id,rows[id],next),replayed:false};
 });
}
function Status(db=require("../bootstrap/peace.desktop-bootstrap-store").Load()){
 const rows=Validate(db.mitigationCompatibility||{});return {version:1,kind:'OPTIONAL_OPERATOR_COMPATIBILITY_MATRIX',recordCount:Object.keys(rows).length,records:Object.entries(rows).sort((a,b)=>b[1].recordedAt-a[1].recordedAt).map(([id,row])=>Summary(id,row,db)),defaultJudgement:'NOT_RUN',usedForAuthorization:false,ciRequired:false,hardwareAttested:false,automaticPolicyChange:false};
}
module.exports={PolicyReadback,NativeResult,Outcome,ValidateReport,ReportId,Validate,Import,Status};
