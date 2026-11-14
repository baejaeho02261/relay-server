'use strict';
// Synthetic validator input only. It is never emitted as Windows evidence.
function Attach(result){
 const r=result,expected=r.scenario==='lifecycle-cleanup-refused'?'FAILED':r.scenario==='lifecycle-cleanup-scheduled'?'SCHEDULED':'REMOVED';
 const lease=r.scenario==='overlay-lease-expiry',flowId='A'.repeat(24),bSession='B'.repeat(24),oSession='C'.repeat(24),ids={A:flowId,B:bSession,O:oSession};
 Object.assign(r,{overlayPid:13,parentPids:{A:11,B:12},verifiedPids:[11,12,13],expectedBHash:'b'.repeat(128),processObservations:{A:{pid:11,exited:true,exitCode:0},B:{pid:12,exited:true,exitCode:0}}});
 Object.assign(r.fixture,{flowCount:1,overlayCount:1,consumedCount:1,transferCommitted:true});r.nativeEvents||=[];
 const events=[],reports=[];let count=0;
 function batch(role,reporter,entries){const added=entries.map(e=>({...e,id:(++count).toString(16).padStart(24,'0'),at:1120100,source:'CLIENT_REPORTED',role,reporterRole:reporter,targetSessionId:ids[role],reporterSessionId:ids[reporter]}));events.push(...added);reports.push({flowId,targetRole:role,reporterRole:reporter,targetSessionId:ids[role],reporterSessionId:ids[reporter],eventIds:added.map(e=>e.id),recordedAt:1120100,afterAuthorityEnded:role==='O',afterLeaseExpired:role==='O'&&lease});}
 batch('A','B',[{event:'PROCESS_EXIT',status:'OBSERVED',pid:11},{event:'FILE_CLEANUP',status:'REMOVED',pid:11}]);
 batch('B','O',[{event:'PROCESS_EXIT',status:'OBSERVED',pid:12},{event:'FILE_CLEANUP',status:expected,pid:12,...(expected==='FAILED'?{win32Error:32}:{})}]);
 batch('O','O',[{event:'SHUTDOWN_BEGIN',status:'REQUESTED',pid:13},{event:'CLOSE_RESPONSE',status:lease?'FAILED':'ACKNOWLEDGED'},{event:'FILE_CLEANUP',status:'REMOVED',pid:13},{event:'UI_HIDDEN',status:'OBSERVED'},...(lease?[{event:'LEASE_EXPIRED',status:'OBSERVED'}]:[])]);
 const code=expected==='FAILED'?'B_FILE_CLEANUP_FAILED':expected==='SCHEDULED'?'B_FILE_CLEANUP_PENDING':'B_CLEANUP_CLIENT_REPORTED';
 r.fixture.lifecycle={flowCount:1,flow:{flowId,roles:{A:{sessionId:flowId,authorityEnded:true,processExit:'CLIENT_REPORTED',fileCleanup:'REMOVED'},B:{sessionId:bSession,authorityEnded:true,processExit:'CLIENT_REPORTED',fileCleanup:expected},O:{sessionId:oSession,authorityEnded:true}},events,bResidual:{code},processTruth:'AUTHENTICATED_CLIENT_OBSERVATION_ONLY'},overviewMatches:true,workspaceMatches:true,reports};
 if(lease)r.nativeEvents.push({version:1,runId:r.runId,scenario:r.scenario,pid:13,stage:r.scenario,event:'lifecycle-late-report-released'});
 if(expected!=='REMOVED'){
  r.lifecycleFile={mode:expected,identity:'1234:5678',sha512:r.expectedBHash,hashMatched:true,heldSameIdentity:true,initialPathMatched:true,heldPathMatches:true,heldPathError:0,handleError:0,deletePending:expected==='SCHEDULED',filePresentBefore:true,pathAbsent:false,pathIdentityMatched:expected==='FAILED',pathError:expected==='FAILED'?0:5,disposed:false,afterReleaseDisposed:true,absentAfterRelease:expected==='SCHEDULED'};
  r.nativeEvents.push({version:1,runId:r.runId,scenario:r.scenario,pid:13,childPid:12,stage:'lifecycle-parent-cleanup',event:'fault-observed'});
 }
 return r;
}
module.exports={Attach};
