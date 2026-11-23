'use strict';
// Revalidate public diagnostics from actual product-fault execution. Booleans
// alone cannot substitute the exact process, session, receipt and event binding.
const HEX=/^[a-f0-9]{128}$/;
function Evaluate(id,r){
 const fail=reason=>({outcome:'FAIL',reason});
 const l=r.fixture?.lifecycle,f=l?.flow,p=r.parentPids;
 if(!l||l.flowCount!==1||!f||l.overviewMatches!==true||l.workspaceMatches!==true||f.processTruth!=='AUTHENTICATED_CLIENT_OBSERVATION_ONLY'||!Array.isArray(f.events)||!Array.isArray(l.reports)||!p||!Number.isSafeInteger(p.A)||!Number.isSafeInteger(p.B)||!Number.isSafeInteger(r.overlayPid)||new Set([p.A,p.B,r.overlayPid]).size!==3||[p.A,p.B,r.overlayPid].some(pid=>!r.verifiedPids?.includes(pid)))return fail('LIFECYCLE_SAME_FLOW_OBSERVATION_MISSING');
 const expected=id==='lifecycle-cleanup-refused'?'FAILED':id==='lifecycle-cleanup-scheduled'?'SCHEDULED':'REMOVED';
 for(const role of ['A','B','O'])if(!f.roles?.[role]?.authorityEnded)return fail('LIFECYCLE_AUTHORITY_NOT_TERMINAL');
 for(const role of ['A','B']){
  const child=role==='A'?'B':'O',events=f.events.filter(e=>e.source==='CLIENT_REPORTED'&&e.role===role&&e.targetSessionId===f.roles[role].sessionId&&e.reporterRole===child&&e.reporterSessionId===f.roles[child].sessionId);
  const exit=events.find(e=>e.event==='PROCESS_EXIT'&&e.status==='OBSERVED'&&e.pid===p[role]),cleanup=events.find(e=>e.event==='FILE_CLEANUP'&&e.status===(role==='B'?expected:'REMOVED')&&e.pid===p[role]);
  const observation=r.processObservations?.[role];
  if(!exit||!cleanup||!observation||observation.pid!==p[role]||observation.exited!==true||observation.exitCode!==0||f.roles[role].processExit!=='CLIENT_REPORTED'||f.roles[role].fileCleanup!==(role==='B'?expected:'REMOVED'))return fail('LIFECYCLE_PARENT_EXIT_CLEANUP_PROOF_MISSING');
  if(!l.reports.some(x=>x.flowId===f.flowId&&x.reporterRole===child&&x.targetRole===role&&x.reporterSessionId===f.roles[child].sessionId&&x.targetSessionId===f.roles[role].sessionId&&x.eventIds?.includes(exit.id)&&x.eventIds.includes(cleanup.id)))return fail('LIFECYCLE_PARENT_RECEIPT_MISSING');
 }
 const self=f.events.filter(e=>e.source==='CLIENT_REPORTED'&&e.role==='O'&&e.reporterRole==='O'&&e.targetSessionId===f.roles.O.sessionId&&e.reporterSessionId===f.roles.O.sessionId);
 if(self.some(e=>e.event==='PROCESS_EXIT'&&e.status==='OBSERVED')||!self.some(e=>e.event==='SHUTDOWN_BEGIN'&&e.status==='REQUESTED'&&e.pid===r.overlayPid)||!self.some(e=>e.event==='FILE_CLEANUP')||!self.some(e=>e.event==='CLOSE_RESPONSE'&&['ACKNOWLEDGED','FAILED'].includes(e.status)))return fail('LIFECYCLE_SELF_REPORT_INVALID_OR_MISSING');
 const receipt=l.reports.find(x=>x.flowId===f.flowId&&x.targetRole==='O'&&x.reporterRole==='O'&&x.reporterSessionId===f.roles.O.sessionId&&x.targetSessionId===f.roles.O.sessionId&&x.afterAuthorityEnded===true&&self.every(e=>x.eventIds?.includes(e.id)));
 if(!receipt||!Number.isSafeInteger(receipt.recordedAt)||receipt.recordedAt<1)return fail('LIFECYCLE_POST_RETIREMENT_RECEIPT_MISSING');
 if(id==='overlay-lease-expiry'){
  if(receipt.afterLeaseExpired!==true||receipt.recordedAt<r.fixture.lease?.prunedAt||!self.some(e=>e.event==='LEASE_EXPIRED'&&e.status==='OBSERVED')||!self.some(e=>e.event==='UI_HIDDEN'&&e.status==='OBSERVED')||!r.nativeEvents?.some(e=>e.version===1&&e.runId===r.runId&&e.scenario===id&&e.pid===r.overlayPid&&e.stage===id&&e.event==='lifecycle-late-report-released'))return fail('LIFECYCLE_AFTER_ACTUAL_LEASE_EXPIRY_REPORT_MISSING');
 }
 if(expected!=='REMOVED'){
  const file=r.lifecycleFile;
  if(!file||file.mode!==expected||!HEX.test(file.sha512||'')||file.sha512!==r.expectedBHash||file.hashMatched!==true||file.heldSameIdentity!==true||file.initialPathMatched!==true||file.handleError!==0||!(file.heldPathMatches===true||(expected==='SCHEDULED'&&file.deletePending===true&&Number.isSafeInteger(file.heldPathError)&&file.heldPathError>0))||typeof file.identity!=='string'||!file.identity||file.filePresentBefore!==true||file.pathAbsent!==false||file.disposed!==false||file.afterReleaseDisposed!==true)return fail('LIFECYCLE_HELD_FILE_BINDING_MISSING');
  if(!r.nativeEvents?.some(e=>e.version===1&&e.runId===r.runId&&e.scenario===id&&e.pid===r.overlayPid&&e.childPid===p.B&&e.stage==='lifecycle-parent-cleanup'&&e.event==='fault-observed'))return fail('LIFECYCLE_CONTROLLED_OS_PATH_NOT_OBSERVED');
  const b=f.events.find(e=>e.role==='B'&&e.reporterRole==='O'&&e.event==='FILE_CLEANUP'&&e.status===expected);
  if(expected==='FAILED'&&(file.pathError!==0||file.pathIdentityMatched!==true||file.deletePending!==false||file.absentAfterRelease!==false||!Number.isSafeInteger(b?.win32Error)||b.win32Error===0||f.bResidual?.code!=='B_FILE_CLEANUP_FAILED'))return fail('LIFECYCLE_REAL_DELETE_REFUSAL_MISSING');
  if(expected==='SCHEDULED'&&(file.deletePending!==true||file.absentAfterRelease!==true||f.bResidual?.code!=='B_FILE_CLEANUP_PENDING'))return fail('LIFECYCLE_REAL_PENDING_DELETE_MISSING');
 }else if(r.parentCleanupObserved!==true||f.bResidual?.code!=='B_CLEANUP_CLIENT_REPORTED')return fail('LIFECYCLE_REMOVED_FILE_OBSERVATION_MISSING');
 return {outcome:'PASS',scope:id==='lifecycle-cleanup-success'?'SELECTED_FINAL_RELEASE':'DEDICATED_PRODUCT_TESTBUILD'};
}
module.exports={Evaluate};
