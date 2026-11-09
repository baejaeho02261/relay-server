'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Source contracts + explicit timing models + actual server handlers with isolated
// state. NOT Delphi execution, a Windows file deletion test or live GPU proof.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {OverlayFixture}=require("../fixtures/security/peace.security-state-test-fixture");
const nativeRoot=process.env.GAME_TEST_NATIVE_ROOT||path.resolve(MODULE_RESOURCE_ROOT,'../../Railway');
const read=n=>ReadContractFile(path.join(nativeRoot,n),'utf8').replaceAll('\r','');
const overlay=read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas"),client=read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas"),handoff=read("Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas"),state=read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.State.pas");
function part(s,a,b){const i=s.indexOf(a);assert.ok(i>=0,a);const j=s.indexOf(b,i+a.length);assert.ok(j>i,b);return s.slice(i,j);}
function order(s,...markers){let n=-1;for(const m of markers){n=s.indexOf(m,n+1);assert.ok(n>=0,'missing/order: '+m);}}
const refresh=part(overlay,'procedure TOverlayWorker.Refresh;','procedure TOverlayWorker.StartAuthorized;');
const core=part(client,'procedure TOverlayClient.ReportIntegrityCore(','procedure TOverlayClient.CloseCore;');
const execute=part(overlay,'procedure TOverlayWorker.Execute;','{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}\nprocedure OverlayTestTerminalWorker');

test('source: full-snapshot due time is completion-based and transfer-aware',()=>{
 assert.match(state,/Result := LastAcceptedTick = 0[\s\S]*not Transferred[\s\S]*NowTick - LastAcceptedTick >= 15000/);
 order(refresh,'OverlaySnapshotDue(CozyTick, FLastSnapshotAt, FTransferred,','FClient.ReportIntegrity(','FLastSnapshotAt := CozyTick;');
 assert.doesNotMatch(refresh,/if IncludeModules then FLastSnapshotAt := CozyTick;\s*FClient.ReportIntegrity/);
});
test('source: first frame is not raced by another measurement',()=>{
 order(execute,'if ShouldClose then','if not AwaitingTransfer then','CozyWaitForDelay(100, function: Boolean begin Result := Terminated; end);','Continue;','ReportVisible := FVisibleReportPending;','StartupPhase(\'VISIBLE\')');
});
test('source: parent exit confirmation takes the cheap path before full refresh',()=>{
 order(execute,'if not FParentRetirementDone and not FContext.ParentIsAlive then','MaintainLease(True);','else if CozyTick >= NextCheck then','Refresh;');
});
test('source: long initial/full-snapshot cost is not the cheap renewal estimate',()=>{
 order(refresh,'if IncludeModules then LeaseStarted := CozyTick;','RenewLease(Image, LeaseStarted);');
 assert.match(refresh,/FLastRefreshDuration := CozyTick - RefreshStarted/);
});
test('source: batch callback cannot manufacture a lease',()=>{
 order(refresh,'procedure TOverlayWorker.MaintainLease','RequestCancelled','OverlayLeaseNeedsMaintenance','FImage.VerifyNow','RenewLease(Image, Started)');
 assert.match(refresh,/Lease := FClient.Verify/);assert.match(client,/RequireServerObservation\(/);
 assert.match(client,/FLeaseDeadlineTick := VerifyRequestTick \+ UInt64\(Result\)/);
 assert.doesNotMatch(refresh,/FDeadline := CozyTick \+/);
});
test('source: periodic scan starts with ordinary renewal; unchanged snapshot across batches',()=>{
 const payload=part(core,'function CreateModulePayload(Index, Count: Integer): TJSONObject;',"begin\n  StartupPhaseCore('OWN_BEGIN')");
 order(payload,'Body := TJSONObject.Create;',"Body.AddPair('snapshotId', SnapshotID)","Body.AddPair('batchIndex', TJSONNumber.Create(Index))","Body.AddPair('batchCount', TJSONNumber.Create(Count))",'Result := Body;');
 assert.match(payload,/Meta := Snapshot\.GetValue\(Name\);[\s\S]*TJSONValue\(Meta\.Clone\)/);
 order(core,"StartupPhaseCore('MODULES_BEGIN')",'MaintainLease(True);','if Assigned(Cancelled) and Cancelled() then',"raise EBootstrap.Create('OVERLAY_CLOSING')",'Snapshot := CollectModuleInventoryJSON','SnapshotID := BootstrapRequestID;','repeat','MaintainLease(False);','Payload := CreateModulePayload(BatchIndex, BatchCount);','Send(Payload);','Payload.Free;','until BatchIndex >= BatchCount;','Snapshot.Free;');
 assert.equal((core.match(/CollectModuleInventoryJSON\(/g)||[]).length,1);
 assert.equal((core.match(/SnapshotID := BootstrapRequestID/g)||[]).length,1);
 const batches=part(core,'BatchIndex := 0;',"StartupPhaseCore('MODULES_READY')");
 assert.doesNotMatch(batches,/Snapshot\s*:=|SnapshotID\s*:=|CollectModuleInventoryJSON/);
 const post=part(core,'function ReportPost(Body: TJSONObject;', 'procedure Send(Payload: TJSONObject);');
 order(post,'if Assigned(Cancelled) and Cancelled() then','for Attempt := 1 to Attempts do','if Assigned(Cancelled) and Cancelled() then','FTransport.PostJSON(','if Assigned(Cancelled) and Cancelled() then','Result := TJSONObject(DataValue.Clone);');
});
test('source: default nil callback preserves existing callers',()=>{
 assert.equal((client.match(/const MaintainLease: TProc<Boolean> = nil/g)||[]).length,2);
 assert.match(client,/ReportIntegrityCore\(Security, CodeIntegrity, Image, IncludeModules, Cancelled, FailureStatus, OwnImage, MaintainLease\)/);
});
test('source: old grant/cancellation is checked before publication',()=>{
 const s=part(overlay,'procedure TOverlayWorker.RenewLease(','procedure TOverlayWorker.StartAuthorized;');
 order(s,'if Terminated or FFailed or','CozyTick >= FDeadline','FFailed := True;','FDeadline := 0;','FDeadline := Deadline;','FContext.CleanupTransferredParent;');
});
test('source: transfer race has only two fresh attempts, no local flag spoofing',()=>{
 const s=part(overlay,'procedure TOverlayWorker.RenewLease(','procedure TOverlayWorker.StartAuthorized;');
 order(s,'for Attempt := 1 to 2 do','RequestCancelled','FClient.Verify','TransferConfirmed := FClient.TransferConfirmed','if not ParentExited or TransferConfirmed then Break','if Attempt = 2 then raise');
 assert.doesNotMatch(s,/TransferConfirmed := True/);
});
test('source: B cleanup occurs only after exact parent exit and server confirmation',()=>{
 const s=part(overlay,'procedure TOverlayWorker.RenewLease(','procedure TOverlayWorker.StartAuthorized;');
 order(s,'ParentExited := not FContext.ParentIsAlive','TransferConfirmed := FClient.TransferConfirmed','if TransferConfirmed and not FTransferred then','FTransferred := True','CleanupParent := ParentExited and FTransferred and not FParentRetirementDone','FContext.CleanupTransferredParent',"Lifecycle.ObserveCleanup('B'", "Lifecycle.Submit('B')");
 const c=part(handoff,'procedure THandoffContext.CleanupTransferredParentCore;','procedure THandoffContext.CleanupBinaryAfterLicenseCore;');
 order(c,'WaitForSingleObject(FParentProcess, 0) = WAIT_OBJECT_0','SameText(HashHandle(FParentImage), LauncherSHA512)','OpenSafeImage(FLauncherPath, True','SameIdentity(HeldInfo, DeleteInfo)','SetFileInfo(DeleteFile');
});
test('source: cleanup native refusal is nonfatal but hash/identity failure still raises',()=>{
 const s=part(handoff,'procedure THandoffContext.CleanupTransferredParent;','function THandoffContext.ParentIsAlive:');
 order(s,'Close(FParentImage); Close(FParentProcess); CloseAll(FParentPins);','FParentObservation.ExitObserved','FParentObservation.CleanupAttempted','FParentObservation.Win32Error <> 0','FParentRetired := True','else raise');
 const c=part(handoff,'procedure THandoffContext.CleanupTransferredParentCore;','procedure THandoffContext.CleanupBinaryAfterLicenseCore;');
 order(c,'FParentObservation.Win32Error := 0','GetFileInformationByHandle(FParentImage','FParentObservation.Win32Error := GetLastError');
 assert.doesNotMatch(s,/FileRemoved := True|DispositionAccepted := True|DeleteFileW|MoveFileEx|cmd\.exe/i);
});
test('source: OS disposal success and observed removal remain distinct',()=>{
 const c=part(handoff,'procedure THandoffContext.CleanupTransferredParentCore;','procedure THandoffContext.CleanupBinaryAfterLicenseCore;');
 order(c,'SetFileInfo(DeleteFile','Close(DeleteFile);','Close(FParentImage);','Attributes := GetFileAttributesW','Error = ERROR_FILE_NOT_FOUND');
});

// Independently declared scheduling models; source contracts above bind the
// intended constants/ordering, but do not turn these into native execution.
function due(now,accepted,transferred){return accepted===0||(transferred&&now>=accepted&&now-accepted>=15000);}
function maintenance(now,deadline,last,force=false){if(!deadline)return false;if(now>=deadline)throw Error('EXPIRED');return force||deadline-now<=Math.max(20000,Math.min(last,120000)*2+2000);}
function next(now,deadline,last){if(now>=deadline)throw Error('EXPIRED');const remaining=deadline-now,margin=Math.min(last,120000)*2+1000;if(remaining<=margin)return now;return now+Math.min(remaining/2,10000,remaining-margin);}
test('model: initial inventory is mandatory',()=>assert.equal(due(100,0,false),true));
test('model: even long startup cannot schedule full rescan before confirmed transfer',()=>assert.equal(due(90000,10000,false),false));
test('model: full inventory is due at 15 seconds after acceptance, not earlier',()=>{assert.equal(due(62999,48000,true),false);assert.equal(due(63000,48000,true),true);});
test('model: captured 53s startup estimate produced immediate old renewal',()=>assert.equal(next(54000,80000,53359),54000));
test('model: cheap 5s estimate permits first frame and cleanup runway',()=>assert.equal(next(54000,80000,5000),64000));
test('model: 37s scan before cleanup exceeds short initial 26s grant',()=>{
 const oldDeadline=80000,oldImmediateStart=54000,ownCost=3500,scanStart=10578;
 assert.ok(oldImmediateStart+ownCost-scanStart>=45000);
 assert.ok(oldImmediateStart+ownCost+37000>oldDeadline);
 const newConfirmedAt=56000+8000,cleanupAt=newConfirmedAt+1500;
 assert.ok(cleanupAt<oldDeadline);assert.equal(due(newConfirmedAt,48000,false),false);
});
test('model: renewal callback is disabled only for initial zero grant',()=>assert.equal(maintenance(123,0,0,true),false));
test('model: maintenance never rescues an already expired grant',()=>{assert.throws(()=>maintenance(1000,1000,1,true),/EXPIRED/);assert.throws(()=>maintenance(1001,1000,1,false),/EXPIRED/);});
test('model: renew before a long scan even with more than 20s remaining',()=>assert.equal(maintenance(1000,40000,3000,true),true));
test('model: renew while sending batches when remaining window drops to 20s',()=>{assert.equal(maintenance(10000,31000,4000),false);assert.equal(maintenance(11000,31000,4000),true);});
test('model: a 30s scan plus twelve 2s batches survives only with fresh renewals',()=>{
 // Previous complete report was accepted at 5s. A periodic report starts
 // 45s later, with the server's existing 120s snapshot policy still unchanged.
 const previousAccepted=5000;
 let now=previousAccepted+45000,deadline=now+45000,previousSnapshotExpiry=previousAccepted+120000,renewals=0;
 now+=30000;
 for(let batch=0;batch<12;batch++){
  if(maintenance(now,deadline,4000)){const prior=deadline;now+=4000;assert.ok(now<prior);deadline=Math.min(now+45000,previousSnapshotExpiry);renewals++;}
  now+=2000;assert.ok(now<deadline);assert.ok(now<previousSnapshotExpiry);
 }
 assert.ok(renewals>0);assert.ok(50000+30000+12*2000>95000);
});
test('model: expired old snapshot remains fatal despite fresh own image',()=>{
 let now=100000,deadline=120000;assert.equal(maintenance(now,deadline,4000),true);
 now+=4000;deadline=Math.min(now+45000,120000);assert.equal(deadline,120000);assert.throws(()=>maintenance(120001,deadline,4000,true),/EXPIRED/);
});

test('real server: commit closes B without extending O grant',()=>{
 const f=OverlayFixture({observationId:'initial',observationExpiry:Date.now()+20000,snapshotExpiry:Date.now()+90000});f.row.status='CLAIMED';
 const granted=f.api.__probe.Verify(f.verify);f.api.__probe.Commit(f.commit);
 assert.equal(f.parent.status,'CLOSED');assert.equal(f.row.sessionExpiresAt,granted.expiresAt);
});
test('real server: post-transfer fresh proof returns transferConfirmed true',async()=>{
 const f=OverlayFixture({observationId:'first',observationExpiry:Date.now()+25000,snapshotExpiry:Date.now()+90000});f.row.status='CLAIMED';
 assert.equal(f.api.__probe.Verify(f.verify).transferConfirmed,false);f.api.__probe.Commit(f.commit);
 // Production requires a new issuance generation. Do not fake a different
 // lifetime within the same wall-clock millisecond in this direct fixture.
 await new Promise(resolve=>setTimeout(resolve,5));
 f.options.observationId='second';f.options.observationExpiry=Date.now()+40000;
 assert.equal(f.api.__probe.Verify(f.verify).transferConfirmed,true);
});
test('real server: pre-transfer response may stay false on exact replay; new proof resolves race',async()=>{
 const f=OverlayFixture({observationId:'race-first',observationExpiry:Date.now()+20000});f.row.status='CLAIMED';
 const prior=f.api.__probe.Verify(f.verify);f.api.__probe.Commit(f.commit);assert.deepEqual(f.api.__probe.Verify(f.verify),prior);
 await new Promise(resolve=>setTimeout(resolve,5));
 f.options.observationId='race-second';assert.equal(f.api.__probe.Verify(f.verify).transferConfirmed,true);
});
test('real server: later fresh O proof can outlive expired B only after committed transfer',async()=>{
 const f=OverlayFixture({observationId:'old'});f.row.status='CLAIMED';f.api.__probe.Verify(f.verify);f.api.__probe.Commit(f.commit);
 await new Promise(resolve=>setTimeout(resolve,5));
 f.parent.sessionExpiresAt=Date.now()-1;f.options.observationId='fresh';
 assert.equal(f.api.__probe.Verify(f.verify).transferConfirmed,true);
});
test('real server: no transfer means expired B still blocks O',()=>{
 const f=OverlayFixture();f.row.status='CLAIMED';f.parent.sessionExpiresAt=Date.now()-1;assert.throws(()=>f.api.__probe.Verify(f.verify),/FLOW_INVALID|EXPIRED/);
});
test('real server: repeating one observation never extends its old receipt',()=>{
 const f=OverlayFixture({observationId:'same'});f.row.status='CLAIMED';const old=f.api.__probe.Verify(f.verify),writes=f.calls.writes;
 f.options.observationExpiry=Date.now()+90000;assert.deepEqual(f.api.__probe.Verify(f.verify),old);assert.equal(f.calls.writes,writes);
});
test('real server: stale module snapshot still rejects fresh own authorization',()=>{
 const f=OverlayFixture({snapshotExpiry:Date.now()-1});f.row.status='CLAIMED';assert.throws(()=>f.api.__probe.Verify(f.verify),/FRESH_OBSERVATION/);
});
test('real server: revocation remains fatal after transfer',()=>{
 const f=OverlayFixture();f.row.status='CLAIMED';f.api.__probe.Verify(f.verify);f.api.__probe.Commit(f.commit);f.options.observationId='later';f.revoked.add('O');
 assert.throws(()=>f.api.__probe.Verify(f.verify),/RELEASE_REVOKED/);
});
test('real server: license expiry still caps the O grant',()=>{
 const f=OverlayFixture({observationExpiry:Date.now()+45000});f.row.status='CLAIMED';f.license.expiresAt=Date.now()+15000;
 assert.equal(f.api.__probe.Verify(f.verify).expiresAt,f.license.expiresAt);
});
test('server explanation: OVERLAY_TRANSFERRED is normal handoff, not an unknown failure',()=>{
 const r=require("../../services/runtime/peace.desktop-operations-errors").Explain('OVERLAY_TRANSFERRED');
 assert.match(r.title,/인계를 완료/);assert.doesNotMatch(r.current,/완료를 확인하지 못했습니다/);assert.match(r.next,/별도로/);
});

// Recovery model is intentionally labelled: the supported native probe calls
// the actual Pascal scheduling predicate; this model tests independent traces.
const transientCodes=new Set(['CONNECT_TIMEOUT']);
function retryAllowed(now,deadline,cost,retried,code){if(retried||deadline<=now||!transientCodes.has(code))return false;return deadline-now>Math.max(12000,Math.min(cost,120000)*2+1000);}
test('recovery model: one transient timeout can obtain fresh proof inside the unchanged old grant',()=>{
 const state={now:1000,deadline:22000,cost:3000,retried:false,proofs:0};
 assert(retryAllowed(state.now,state.deadline,state.cost,state.retried,'CONNECT_TIMEOUT'));
 state.retried=true;state.now+=250;const old=state.deadline;
 // The retry itself grants nothing; only an authenticated fresh response may
 // publish a new lease while the preexisting one is still valid.
 state.now+=4000;state.proofs++;assert(state.now<old);assert.equal(state.deadline,old);
 assert(!retryAllowed(state.now,state.deadline,state.cost,state.retried,'CONNECT_TIMEOUT'));
 state.deadline=state.now+40000;assert.equal(state.proofs,1);
});
test('recovery model: cancellation, invalid authority and exhausted time never become retries',()=>{
 for(const code of ['CONNECT_CANCELLED','CONNECT_AUTHENTICATION_FAILED','CONNECT_CRYPTO_FAILED','CONNECT_INVALID_RESPONSE','CONNECT_FAILED','INTEGRITY_REJECTED','BOOTSTRAP_REVOKED','CONNECT_UNAVAILABLE','CONNECT_SEND_FAILED','CONNECT_RECEIVE_FAILED','NETWORK_UNAVAILABLE',''])assert(!retryAllowed(1000,60000,3000,false,code),code);
 for(const [now,deadline,cost,retried]of [[1000,1000,0,false],[1000,13000,0,false],[1000,22000,3000,true],[1000,120000,Number.MAX_SAFE_INTEGER,false]])assert(!retryAllowed(now,deadline,cost,retried,'CONNECT_TIMEOUT'));
 assert(retryAllowed(1000,13001,0,false,'CONNECT_TIMEOUT'));
});
test('source: renewal retry preserves the live grant and cancellation generation',()=>{
 const recover=part(overlay,'function TOverlayWorker.RecoverTransientRenewal(', 'procedure TOverlayWorker.NoteRenewalFailure(');
 order(recover,'not Terminated and not FFailed and FReadyForTransfer','OverlayTransientRetryAllowed(CozyTick, FDeadline,','if Allowed then Retried := True;','CozyWaitForDelay(250,','if RequestCancelled then Exit;','MaintainLease(True);','Result := not RequestCancelled;');
 assert.doesNotMatch(recover,/FDeadline\s*:=|FFailed\s*:=|ResetCancellation|CancelPending|FRunState|RequestCohortShutdown/);
 const predicate=part(state,'function OverlayTransientRetryAllowed(NowTick, Deadline, LastDuration: UInt64;\n  AlreadyRetried: Boolean; const TransportCode: string): Boolean;\nvar Reserve:', 'function OverlayGraphicsFailure(');
 for(const code of transientCodes)assert(predicate.includes("'"+code+"'"));
 assert.match(predicate,/AlreadyRetried or \(Deadline <= NowTick\)/);assert.match(predicate,/Reserve < 12000/);assert.match(predicate,/Deadline - NowTick > Reserve/);
 assert.doesNotMatch(predicate,/SessionToken|FDeadline\s*:=|osAuthorized/);
 order(execute,'on E: EConnectTransport do','RecoverTransientRenewal(E.Code, Retried)','NextCheck := CozyTick;','Continue;');
});
test('source: failed renewal and runtime UI causes use closed optional diagnostic events',()=>{
 const note=part(overlay,'procedure TOverlayWorker.NoteRenewalFailure(', 'procedure TOverlayWorker.Execute;');
 assert.match(note,/TransportCode = 'CONNECT_TIMEOUT'/);assert.match(note,/Outcome := 'TIMEOUT'/);assert.match(note,/Outcome := 'FAILED'/);
 assert.match(note,/Lifecycle\.Note\('O', 'RENEWAL_FAILED', Outcome\)/);assert.doesNotMatch(note,/\.Message|\.Post|Submit\(|SessionToken/);
 assert.match(overlay,/Lifecycle\.Note\('O', 'UI_RUNTIME_FAILURE', 'FAILED',\s+0, Cardinal\(NativeCode\)\)/);
 const failure=execute.slice(execute.lastIndexOf('on E: Exception do'));
 order(failure,'if not Terminated and not ConfirmedWatch then','NoteRenewalFailure(EConnectTransport(E).Code)',"else NoteRenewalFailure('');",'end;','Stop;','finally if FCompleted <> nil then FCompleted.SetEvent;');
 assert.match(failure,/else NoteRenewalFailure\(''\);\s*end;\s*\{[^}]*\}\s*Stop;/,'stopping remains outside the diagnostic-only guard');
 const cancelled=part(overlay,'function TOverlayWorker.RequestCancelled: Boolean;','procedure TOverlayWorker.FirstFrameReady;');
 order(cancelled,'Result := Terminated or FFailed or ConfirmedWatch or','if Result then','FFailed := True;','FDeadline := 0;','FShutdownGuard.Arm(');
 const stop=part(overlay,'procedure TOverlayWorker.Stop;','function TOverlayWorker.JoinBefore(');
 order(stop,'Terminate;','FShutdownGuard.Arm(','FClient.CancelPending;','FFailed := True;','FDeadline := 0;','FProductRunQueued := False;','FProductGrantDeadline := 0;');
});
test('source: START is no longer connected to native cohort shutdown',()=>{
 assert.doesNotMatch(overlay,/ProcessRunRequest|Worker\.RequestRun|Worker\.RunState|FRunRequestedAt|RequestCohortShutdown/);
 assert.doesNotMatch(client,/procedure TOverlayClient\.RequestCohortShutdown/);
 assert.match(overlay,/nil,nil,nil,nil,\s+procedure\(Stage: string; NativeCode: Integer\)/);
 assert.match(overlay,/Client\.ShutdownClose\(Budget\.Deadline/,'ordinary close cleanup remains');
});
