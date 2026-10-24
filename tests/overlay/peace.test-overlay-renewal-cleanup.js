'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Source contracts + explicit timing models + actual server handlers with isolated
// state. NOT Delphi execution, a Windows file deletion test or live GPU proof.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {OverlayFixture}=require("../fixtures/security/peace.security-state-test-fixture");
const nativeRoot=process.env.GAME_TEST_NATIVE_ROOT||path.resolve(MODULE_RESOURCE_ROOT,'../../Railway');
const read=n=>fs.readFileSync(path.join(nativeRoot,n),'utf8').replaceAll('\r','');
const overlay=read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas"),client=read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas"),handoff=read("Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas"),state=read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.State.pas");
function part(s,a,b){const i=s.indexOf(a);assert.ok(i>=0,a);const j=s.indexOf(b,i+a.length);assert.ok(j>i,b);return s.slice(i,j);}
function order(s,...markers){let n=-1;for(const m of markers){n=s.indexOf(m,n+1);assert.ok(n>=0,'missing/order: '+m);}}
const refresh=part(overlay,'procedure TOverlayWorker.Refresh;','procedure TOverlayWorker.StartAuthorized;');
const core=part(client,'procedure TOverlayClient.ReportIntegrityCore(','procedure TOverlayClient.CloseCore;');
const execute=part(overlay,'procedure TOverlayWorker.Execute;','{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}\nprocedure OverlayTestTerminalWorker');

test('source: full-snapshot due time is completion-based and transfer-aware',()=>{
 assert.match(state,/Result := LastAcceptedTick = 0[\s\S]*not Transferred[\s\S]*NowTick - LastAcceptedTick >= 15000/);
 order(refresh,'OverlaySnapshotDue(TickCount, FLastSnapshotAt, FTransferred,','FClient.ReportIntegrity(','FLastSnapshotAt := TickCount;');
 assert.doesNotMatch(refresh,/if IncludeModules then FLastSnapshotAt := TickCount;\s*FClient.ReportIntegrity/);
});
test('source: first frame is not raced by another measurement',()=>{
 order(execute,'if ShouldClose then','if not AwaitingTransfer then','PauseWorker(100);','Continue;','ReportVisible := FVisibleReportPending;','StartupPhase(\'VISIBLE\')');
});
test('source: parent exit confirmation takes the cheap path before full refresh',()=>{
 order(execute,'if not FParentRetirementDone and not FContext.ParentIsAlive then','MaintainLease(True);','else if TickCount >= NextCheck then','Refresh;');
});
test('source: long initial/full-snapshot cost is not the cheap renewal estimate',()=>{
 order(refresh,'if IncludeModules then LeaseStarted := TickCount;','RenewLease(Image, LeaseStarted);');
 assert.match(refresh,/FLastRefreshDuration := TickCount - RefreshStarted/);
});
test('source: batch callback cannot manufacture a lease',()=>{
 order(refresh,'procedure TOverlayWorker.MaintainLease','RequestCancelled','OverlayLeaseNeedsMaintenance','FImage.VerifyNow','RenewLease(Image, Started)');
 assert.match(refresh,/Lease := FClient.Verify/);assert.match(client,/RequireServerObservation\(/);
 assert.match(client,/FLeaseDeadlineTick := VerifyRequestTick \+ UInt64\(Result\)/);
 assert.doesNotMatch(refresh,/FDeadline := TickCount \+/);
});
test('source: periodic scan starts with ordinary renewal; unchanged snapshot across batches',()=>{
 order(core,"StartupPhaseCore('MODULES_BEGIN')",'MaintainLease(True);','Snapshot := CollectModuleInventoryJSON','SnapshotID := BootstrapRequestID;','repeat','MaintainLease(False);','Payload := TJSONObject.Create;',"Payload.AddPair('snapshotId', SnapshotID)",'Send(Payload);');
 assert.equal((core.match(/CollectModuleInventoryJSON\(/g)||[]).length,1);
 assert.equal((core.match(/SnapshotID := BootstrapRequestID/g)||[]).length,1);
 assert.match(core,/Snapshot.Free/);
});
test('source: default nil callback preserves existing callers',()=>{
 assert.equal((client.match(/const MaintainLease: TProc<Boolean> = nil/g)||[]).length,2);
 assert.match(client,/ReportIntegrityCore\(Security, CodeIntegrity, Image, IncludeModules, Cancelled, FailureStatus, OwnImage, MaintainLease\)/);
});
test('source: old grant/cancellation is checked before publication',()=>{
 const s=part(overlay,'procedure TOverlayWorker.RenewLease(','procedure TOverlayWorker.StartAuthorized;');
 order(s,'if Terminated or FFailed or','TickCount >= FDeadline','FFailed := True;','FDeadline := 0;','FDeadline := Deadline;','FContext.CleanupTransferredParent;');
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
