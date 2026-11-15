'use strict';
// Evidence validation, not a device/OS attestation. Every fault case is scoped
// to a separate marked test executable; the final Release baseline is separate.
const CASES=Object.freeze(['lifecycle-cleanup-success','authority-measurement-skipped','authority-report-stopped','authority-local-stop-held']);
const fail=reason=>({outcome:'FAIL',reason});
function EvaluateCase(id,r){
 if(!CASES.slice(1).includes(id))return fail('AUTHORITY_CASE_INVALID');
 const events=r.nativeEvents||[],owned=e=>e.version===1&&e.runId===r.runId&&e.scenario===id&&e.stage===id&&e.pid===r.overlayPid&&r.verifiedPids?.includes(e.pid);
 const grants=events.filter(e=>owned(e)&&e.event==='authority-grant'),faults=events.filter(e=>owned(e)&&e.event==='fault-observed');
 if(grants.length!==1||faults.length!==1)return fail('AUTHORITY_NATIVE_FAULT_NOT_OBSERVED');
 const g=grants[0],f=faults[0],lease=r.fixture?.lease;
 if(['observedTick','requestStartedTick','leaseMs','deadlineTick'].some(k=>!Number.isSafeInteger(g[k])||g[k]<=0)||g.leaseMs>120000||g.requestStartedTick+g.leaseMs!==g.deadlineTick||g.observedTick<g.requestStartedTick||g.observedTick>=g.deadlineTick||!Number.isSafeInteger(f.observedTick)||f.observedTick<g.observedTick)return fail('AUTHORITY_PRIOR_GRANT_BINDING_MISSING');
 if(!lease||['authorizedAt','expiresAt'].some(k=>!Number.isSafeInteger(lease[k])||lease[k]<=0)||lease.grantObserved!==true||lease.renewalAcceptedAfterGrant!==false||lease.serverTerminal!==true||lease.runtimeSecretsRetired!==true||lease.deviceRuntimeAuthorityRetired!==true||lease.oldAuthorityRejected!==true||lease.expiresAt-lease.authorizedAt!==g.leaseMs)return fail('AUTHORITY_SERVER_RETIREMENT_MISSING');
 if(!r.overlayObserved||!r.parentCleanupObserved||r.fixture.consumedCount!==1||r.fixture.transferCommitted!==true)return fail('AUTHORITY_REAL_ABO_FLOW_REQUIRED');
 if(id==='authority-local-stop-held'){
  if(r.serverDeniedWhileClientAlive!==true||!Number.isSafeInteger(r.denialObservedAt)||r.denialObservedAt<lease.expiresAt||lease.serverExpired!==true||f.observedTick<g.deadlineTick||f.observedTick>=g.deadlineTick+30000)return fail('AUTHORITY_DENIAL_WHILE_OWNED_CLIENT_ALIVE_MISSING');
 }
 return {outcome:'PASS',scope:'DEDICATED_PRODUCT_TESTBUILD'};
}
function Validate(result,finalArtifacts,sourceManifestSha512,policy){
 if(policy){const p={...policy};delete p.trustedReleaseKeys;const digest=require('node:crypto').createHash('sha512').update(require("../../services/artifacts/peace.desktop-release-provenance").Stable(p)).digest('hex');if(result?.testPolicySha512!==digest||result?.policyScope!=='EXACT_SETTINGS_EXCEPT_DISPOSABLE_TEST_TRUST_KEYS')throw Error('AUTHORITY_TESTED_POLICY_MISMATCH');}
 if(!result||result.version!==1||result.kind!=='PRODUCT_FAULT_EXECUTION'||result.outcome!=='PASS'||result.environment?.platform!=='win32'||result.environment?.architecture!=='x64'||result.sourceManifestSha512!==sourceManifestSha512||result.sourceManifestUnchanged!==true||result.inputsUnchanged!==true||!Array.isArray(result.cases)||result.cases.length!==CASES.length||new Set(result.cases.map(x=>x.id)).size!==CASES.length)throw Error('AUTHORITY_ACTUAL_WINDOWS_EVIDENCE_REQUIRED');
 for(const role of ['A','B','O']){
  const base=result.inputs?.artifacts?.[role],fault=result.inputs?.faultArtifacts?.[role];
  if(!base||base.sha512!==finalArtifacts[role]||base.unchanged!==true||!fault||fault.unchanged!==true||!/^[a-f0-9]{128}$/.test(fault.sha512)||fault.sha512===base.sha512)throw Error('AUTHORITY_FINAL_AND_TEST_IMAGE_BINDING_REQUIRED');
 }
 const contract=require("../runtime/peace.product-fault-tests");
 for(const id of CASES){const row=result.cases.find(x=>x.id===id);if(!row||row.outcome!=='PASS'||row.evidence?.runId!==result.runId||contract.Evaluate(id,row.evidence).outcome!=='PASS')throw Error('AUTHORITY_CASE_EVIDENCE_INVALID');}
 return {outcome:'PASS',windowsExecuted:true,finalBaseline:'lifecycle-cleanup-success',dedicatedFaultCases:CASES.slice(1),hardwareAttested:false};
}
module.exports={CASES,EvaluateCase,Validate};
