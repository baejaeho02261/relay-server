'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Source/protocol and deadline-model checks. These are deliberately NOT a
// Delphi compilation, Windows execution or proof of physical file removal.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const native = path.resolve(MODULE_RESOURCE_ROOT, '../../Railway');
const read = name => ReadContractFile(path.join(native, name), 'utf8').replaceAll('\r', '');
const reporter = read("Cozy.Source/Cozy.Lifecycle/Cozy.Lifecycle.pas"), handoff = read("Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas");
const overlay = read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas"), client = read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas");
const licenseSource = read("Cozy.Source/Cozy.License/Cozy.License.Session.pas"), api = read("Cozy.Source/Cozy.Platform/Cozy.Api.pas");
const launcher = read("Cozy.Source/Cozy.Application/Cozy.Launcher.pas"), renderer = read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas");
const service = ReadContractFile(path.join(MODULE_RESOURCE_ROOT, "../services/observability/peace.desktop-lifecycle-trace.js"), 'utf8');
let count = 0;
function test(name, fn) { fn(); count++; console.log('PASS ' + name); }
function order(source, markers) {
  let previous = -1;
  for (const marker of markers) {
    const at = source.indexOf(marker, previous + 1);
    assert(at > previous, 'Missing/out-of-order: ' + marker);
    previous = at;
  }
}
test('Signed late report has identical v1 domain, exact retry identity and no session token', () => {
  const submit = reporter.split('procedure TLifecycleReporter.Submit(')[1];
  assert.match(submit, /'GAME-LIFECYCLE-REPORT-V1' \+ #10 \+ C\.PermitID \+ #10 \+\s*C\.Nonce \+ #10 \+ C\.RequestID \+ #10 \+ IntegritySHA512Text\(Text\)/);
  assert.match(service, /\['GAME-LIFECYCLE-REPORT-V1',p\.id,p\.nonce,requestId,sha\(eventsJson\)\]\.join\('\\n'\)/);
  assert.doesNotMatch(submit, /AddPair\('sessionToken'/);
  assert.match(submit, /Body\.AddPair\('requestId', C\.RequestID\)/);
  assert.match(reporter, /C\.RequestID := ID/);
  const retry = reporter.split('function TLifecycleReporter.Post(')[1].split('procedure TLifecycleReporter.Prepare(')[0];
  assert.match(retry, /for Attempt := 1 to 2 do/);
  assert.match(retry, /PostJSON\('bootstrap', Body, Cardinal\(DeadlineTick - At\)\)/);
  assert.doesNotMatch(retry, /\.Sign\(|BootstrapRequestID|DeadlineTick :=/);
  const events = '[{"event":"FILE_CLEANUP","status":"REMOVED"}]';
  const canonical = ['GAME-LIFECYCLE-REPORT-V1', 'a'.repeat(32), 'b'.repeat(48), 'request-test', crypto.createHash('sha512').update(events, 'utf8').digest('hex')].join('\n');
  assert.equal(canonical.split('\n').length, 5);
  assert.notEqual(canonical, canonical + '\n');
});
test('Finished or expired report grants are wiped under request ownership after JSON aliases are released', () => {
  const submit=reporter.split('procedure TLifecycleReporter.Submit(')[1];
  order(submit,['C.Submitted := True','Reply := Post(Body, DeadlineTick)','FreeAndNil(Body); FreeAndNil(Reply);','C.ClearGrant;','TMonitor.Exit(FRequestLock)']);
  assert.match(submit,/if C\.Submitted or \(\(C\.Deadline <> 0\) and \(Tick >= C\.Deadline\)\) then\s+C\.ClearGrant/);
  const clear=reporter.split('procedure TLifecycleReporter.TChannel.ClearGrant;')[1].split('destructor TLifecycleReporter.TChannel.Destroy;')[0];
  for(const field of ['PermitID','Nonce','RequestID'])assert(clear.includes('WipeText('+field+')'));
  assert.match(clear,/Deadline := 0/);
  const prepare=reporter.split('procedure TLifecycleReporter.Prepare(')[1].split('procedure TLifecycleReporter.Note(')[0];
  order(prepare,['TMonitor.Enter(FRequestLock','if (C.Deadline <> 0) and (At >= C.Deadline) then C.ClearGrant;','C.NextPrepare']);
  assert.match(reporter,/destructor TLifecycleReporter.TChannel.Destroy;\s+begin\s+ClearGrant;/);
});
test('Permit refresh covers last O lease at every renewal phase without increasing business lifetime', () => {
  const ttl = Number(service.match(/const TTL=(\d+)/)[1]);
  const reserve = Number(reporter.match(/TargetRole = 'O'\) then Reserve := (\d+)/)[1]);
  const shutdown = Number(read("Cozy.Source/Cozy.Lifecycle/Cozy.ShutdownBudget.pas").match(/OverlayShutdownTotalMs = (\d+)/)[1]);
  assert.equal(ttl, 180000);
  assert.equal(reserve, 130000);
  assert(reserve > 120000 + shutdown);
  assert.match(reporter, /C\.Deadline - At > Reserve/);
  assert.match(client, /\(Result > 120000\)/);
  // All millisecond phases of an existing permit: a successful renewal either
  // retains >130s or refreshes to180s, enough for120s lease +5s termination.
  for (let age = 0; age <= ttl; age++) {
    const remaining = ttl - age;
    const afterPrepare = remaining > reserve ? remaining : ttl;
    assert(afterPrepare > 120000 + shutdown);
  }
  // Earliest successful refreshes are50s apart; four180s permits suffice.
  const interval = ttl - reserve;
  assert.equal(Math.ceil(ttl / interval), 4);
  assert.match(service, /length>=4\)/);
});
test('Shutdown reporter uses shared deadlines and never claims its own observed exit', () => {
  assert.match(reporter, /TMonitor\.Enter\(FRequestLock, Cardinal\(DeadlineTick - At\)\)/);
  assert.match(reporter, /DeadlineTick > At \+ 1500/);
  assert.match(reporter, /\(TargetRole = FRole\) and \(Event = 'PROCESS_EXIT'\) and \(Status = 'OBSERVED'\) then Exit/);
  assert.match(overlay, /Lifecycle\.Submit\('O', Budget\.Deadline\)/);
  assert.doesNotMatch(reporter, /WriteAll|WriteFile|CreateFile|\.SaveToFile|Sleep\(/);
});
test('A and B obtain permits before authority handoff and refresh during long active lifetimes', () => {
  const runA = launcher.split('function RunLauncher: Integer;')[2];
  order(runA, ['Client.BeginKeylessFlow(', "Lifecycle.Prepare('A'", 'Client.ReportIntegrity(']);
  order(runA, ["Lifecycle.Prepare('A'", 'Grant := Client.Finish(', 'HandoffSucceeded := LaunchWithHandoff(']);
  assert.match(launcher, /Bytes := Client\.Chunk\(Flow, Offset\);\s+if Lifecycle <> nil then Lifecycle\.Prepare\('A'/);
  order(licenseSource, ['Session := Bootstrap.Claim(', "Lifecycle.Prepare('B'", "Lifecycle.Prepare('A'", 'Context.CompleteClaimAndCleanup(']);
  const startOverlay = api.split('function TGameApi.StartOverlayCore(RestrictedPrivileges: Boolean;')[1].split('function TGameApi.RedeemCore')[0];
  order(startOverlay, ["FLifecycle.Prepare('B'", 'TransferClient.CommitTransfer(', "FLifecycle.Note('B', 'CLOSE_RESPONSE', 'ACKNOWLEDGED')"]);
  const check = api.split('procedure TGameApi.CheckIntegrity;')[1].split('procedure TGameApi.RetireImagesForShutdown;')[0];
  assert.match(check, /FLifecycle\.Prepare\('B'/);
});
test('Parent exit observations use the inherited exact process handle, before its retirement', () => {
  const a = handoff.split('procedure THandoffContext.CompleteClaimAndCleanupCore(')[1].split('function THandoffContext.ParentIsAliveCore')[0];
  order(a, ['GetProcessId(FParentProcess) = FParentID', 'WaitResult := WaitForSingleObject(FParentProcess, ParentExitTimeoutMS)', 'ExitObserved := WaitResult = WAIT_OBJECT_0', 'Close(FParentProcess)', 'Attributes := GetFileAttributesW']);
  const b = handoff.split('procedure THandoffContext.CleanupTransferredParentCore;')[1].split('procedure THandoffContext.CleanupBinaryAfterLicenseCore;')[0];
  order(b, ['GetProcessId(FParentProcess) = FParentID', 'WaitForSingleObject(FParentProcess, 0) = WAIT_OBJECT_0', 'ExitObserved := True', 'Close(FParentImage)', 'Close(FParentProcess)', 'Attributes := GetFileAttributesW']);
  assert.match(a, /Error = ERROR_FILE_NOT_FOUND/);
  assert.match(b, /Error = ERROR_FILE_NOT_FOUND/);
  assert.match(reporter, /Observation\.FileRemoved and Observation\.CleanupAttempted and\s+\(Observation\.Win32Error = 0\) then Status := 'REMOVED'/);
  assert.match(reporter, /Observation\.DispositionAccepted then Status := 'SCHEDULED'/);
});
test('Actual cleanup follows worker join and image reader retirement, before final report', () => {
  const b = licenseSource.split('function RunLicenseClient: Integer;')[2];
  order(b, ['Worker.Free;', 'Api.RetireImagesForShutdown', 'Context.CleanupOwnImageForShutdown', 'Bootstrap.Close;', "Lifecycle.Submit('B'"]);
  const o = overlay.split('function RunOverlay: Integer;')[2];
  order(o, ['Worker.WaitFor;', 'FreeAndNil(Image)', 'Context.CleanupOwnImageForShutdown', 'Client.ShutdownClose(', "Lifecycle.Submit('O'"]);
  assert.match(handoff, /if not FCompleted then Exit;\s+FOwnObservation\.CleanupAttempted := True/);
  assert.match(handoff, /SameIdentity\(Info, FBinaryCleanupInfo\)/);
  assert.match(handoff, /UnlinkVerifiedOwnImage\(\s*FBinaryCleanupFile, FBinaryPath, BinarySHA512, FBinaryCleanupInfo/);
});
test('UI_HIDDEN follows actual native visibility query, never shutdown intent alone', () => {
  const hide = renderer.split('procedure TOverlayWindow.BeginClosing;')[1].split('destructor TOverlayWindow.Destroy;')[0];
  order(hide, ['ApiShowWindow(FWindow, SW_HIDE)', 'ObserveHidden;', 'procedure TOverlayWindow.ObserveHidden;', 'ApiIsWindowVisible(FWindow) then Exit', 'FOnHidden()']);
  assert.match(renderer, /BindApiPointer\(Slot_IsWindowVisible, RequireProcAddressHash64\('user32\.dll', HASH_IsWindowVisible\)\)/);
  assert.match(overlay, /FDeadline <> 0\) and \(CozyTick >= FDeadline\)[\s\S]*?Lifecycle\.Note\('O', 'LEASE_EXPIRED', 'OBSERVED'\)/);
});
test('A and B arm an own-process deadline before final joins without freeing live worker ownership', () => {
  const a = launcher.split('function RunLauncher: Integer;')[2];
  const b = licenseSource.split('function RunLicenseClient: Integer;')[2];
  order(a, ['ShutdownGuard.Start;', 'ShutdownGuard.ArmAfter(15000)', 'Watch.RequestStop;', 'Watch.Free;', 'ShutdownGuard.Cancel; ShutdownGuard.Free;']);
  order(b, ['ShutdownGuard.Start;', 'ShutdownGuard.ArmAfter(15000)', 'Worker.RequestStop;', 'Worker.StopAndJoin;', 'Worker.Free;', 'Watch.Free;', 'ShutdownGuard.Cancel; ShutdownGuard.Free;']);
  const guard=read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.ShutdownGuard.pas');
  assert(guard.includes('At > UInt64(High(Int64)) - UInt64(TimeoutMS)'));
  assert(guard.includes('Call(THandle(High(NativeUInt)), $E0000009)'));
  assert.doesNotMatch(guard, /TerminateThread|OpenProcess|CreateProcess/i);
});
test('A and B can deliver NHW reports before handoff or license entry', () => {
  const bootstrap = read('Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas');
  const beginFlow = bootstrap.split('function TBootstrapClient.BeginKeylessFlowCore(')[1]
    .split('function TBootstrapClient.ChunkCore')[0];
  order(beginFlow, ["EnsureDeviceIdentity(FTransport, Security, 'A', Result.FlowID, Result.DownloadTicket, FNHWQuoter);",
    "FNHWAuthority.ConfigureResponses(FTransport, Security, 'A',", 'Result.FlowID, Result.DownloadTicket);']);
  const startup = licenseSource.split('procedure TLicenseWorker.Execute;')[1];
  order(startup, ['FApi.CheckIntegrity;', 'FWatch.Start;',
    'InterlockedExchange(FInitializationSucceeded, 1);', 'RedeemPending(QueuedKey);']);
  const check = api.split('procedure TGameApi.CheckIntegrityCore(')[1]
    .split('procedure TGameApi.AddBootstrapSession')[0];
  order(check, ['SendIntegrityReport(Payload, Cancelled);', 'if Status <> msMeasured then',
    'if FNHWAuthority <> nil then', "FNHWAuthority.ConfigureResponses(FTransport, FSecurity, 'B',",
    'FBootstrapSessionID, FBootstrapSessionToken);']);
});
test('Bounded security-cause flush precedes session closure and stays outside UI callbacks', () => {
  const a = launcher.split('function RunLauncher: Integer;')[2];
  const b = licenseSource.split('function RunLicenseClient: Integer;')[2];
  const o = overlay.split('function RunOverlay: Integer;')[2];
  order(a, ['Watch.RequestStop;', 'Client.FlushNHWReports;', 'Client.AbortFlow(Flow)']);
  order(b, ['Worker.Free;', 'Api.FlushNHWReports;', 'Api.FinishNHWStop;', 'Bootstrap.Close;']);
  order(o, ['Worker.WaitFor;', 'Client.FlushNHWReports(Cardinal(ReportBudget))', 'Client.ShutdownClose(']);
  assert(o.includes('ReportBudget := (Budget.Deadline - ReportNow) div 2'));
  assert(o.includes('if ReportBudget > 750 then ReportBudget := 750'));
  for (const [text,type] of [[api,'TGameApi'],[client,'TOverlayClient'],[read('Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas'),'TBootstrapClient']]) {
    const flush=text.split('procedure '+type+'.FlushNHWReports(')[1].split('procedure '+type+'.AttachNHW(')[0];
    const cap = type === 'TOverlayClient' ? 3500 : 7000;
    assert(flush.includes(`if TimeoutMS > ${cap} then TimeoutMS := ${cap}`));
    assert(flush.includes('except'));
  }
});
test('Pre-handoff security drains precede fresh proofs and recheck rejection without extending authority', () => {
  const a = launcher.split('function RunLauncher: Integer;')[2];
  order(a, ['Result := 31034;', 'RequireLauncherWatch(Watch);', 'ReportNow := BootstrapUTCNowMS;',
    'if (ReportNow <= 0) or (Flow.ExpiresAt <= ReportNow) then Fail;',
    'ReportBudget := Flow.ExpiresAt - ReportNow;', 'if ReportBudget > 7000 then ReportBudget := 7000;',
    'Client.FlushNHWReports(Cardinal(ReportBudget));', 'RequireLauncherWatch(Watch);',
    'if BootstrapUTCNowMS >= Flow.ExpiresAt then Fail;', 'Grant := Client.Finish(',
    'RequireLauncherWatch(Watch);', 'HandoffSucceeded := LaunchWithHandoff(']);
  assert.match(launcher, /if \(Watch <> nil\) and Watch\.Confirmed then Fail;/);
  const start = api.split('function TGameApi.StartOverlayCore(RestrictedPrivileges: Boolean;')[1].split('function TGameApi.RedeemCore')[0];
  const maintenance = start.split('      MaintainParent :=')[1].split('      CheckIntegrityCore;')[0];
  order(maintenance, ['if BeforeChild then', 'ReportDeadline := ParentStartupDeadline;',
    'if FCurrent.LeaseDeadlineTick < ReportDeadline then', 'ReportDeadline := FCurrent.LeaseDeadlineTick;',
    'At := CozyTick;', 'if At < ReportDeadline then', 'ReportBudget := ReportDeadline - At;',
    'if ReportBudget > 7000 then ReportBudget := 7000;', 'FlushNHWReports(Cardinal(ReportBudget));',
    'RequireParentPending();', 'if BeforeChild or', 'then RenewParent();', 'ParentWaitingForChild := True;']);
  const launch = client.split('function LaunchOverlay(Profile: TConnectServerProfile; Security: TDeviceSecurity;').at(-1).split('function TOverlayClient.ClaimCore')[0];
  order(launch, ['FileHandle := DownloadVerifiedBinary(', "Client.Post('overlayFinish'", 'OwnedParentMaintenance(True);', 'Result := LaunchWithHandoff(']);
  const afterReady = start.slice(start.indexOf('Result := LaunchOverlay('));
  order(afterReady, ['RequireParentPending();', 'TransferClient.CommitTransfer(']);
  assert(!afterReady.includes('FlushNHWReports('), 'no drain wait consumes O fresh-proof lifetime after native ready');
  const pending = start.split('      RequireParentPending :=')[1].split('      RenewParent :=')[0];
  order(pending, ['RequireRunning;', 'RequireModuleSnapshotLease;', 'CozyTick >= ParentStartupDeadline', 'FCurrent.LeaseDeadlineTick <= CozyTick']);
  assert.match(api, /procedure TGameApi\.RequireRunning;[\s\S]*?FStopRequested, 0, 0\) <> 0\) or NHWStopConfirmed then/);
  const authority = read('Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Authority.pas').split('procedure TCozyNHWAuthority.FlushSecurityReports(')[1];
  order(authority, ['Started := ObserverClockTick;', 'WakeForFlush;', 'repeat', 'HasPending', 'ObserverClockTick - Started >= TimeoutMS']);
  assert.equal((authority.match(/Started := ObserverClockTick/g) || []).length, 1, 'one total drain budget across all paths');
});
test('Pre-handoff deadline model blocks a verdict during drain and keeps offline waits bounded', () => {
  // Independent model of the source ordering above, not native execution.
  function beforeHandoff(now, deadline, pendingUntil, rejectAt) {
    if (now <= 0 || now >= deadline) return { handoff: false, waited: 0 };
    const budget = Math.min(7000, deadline - now);
    const waited = Math.min(budget, Math.max(0, pendingUntil - now));
    const after = now + waited;
    return { handoff: after < deadline && !(rejectAt >= now && rejectAt <= after), waited };
  }
  assert.deepEqual(beforeHandoff(100, 10000, 100, Infinity), { handoff: true, waited: 0 });
  assert.deepEqual(beforeHandoff(100, 10000, 500, 450), { handoff: false, waited: 400 });
  assert.deepEqual(beforeHandoff(100, 10000, Infinity, Infinity), { handoff: true, waited: 7000 });
  assert.deepEqual(beforeHandoff(100, 500, Infinity, Infinity), { handoff: false, waited: 400 });
  assert.deepEqual(beforeHandoff(500, 500, Infinity, Infinity), { handoff: false, waited: 0 });
  for (let remaining = 1; remaining < 14000; remaining++) {
    const result = beforeHandoff(100, 100 + remaining, Infinity, Infinity);
    assert(result.waited <= Math.min(7000, remaining));
  }
});
test('ETW consumer initializes execution fields before RTL-owned start and keeps join ownership', () => {
  const etw = read('Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETW.Consumer.pas');
  const ctor = etw.split('constructor TETWConsumerThread.Create(Handle: UInt64);')[1].split('function TETWConsumerThread.ProcessingStopped:')[0];
  order(ctor, ['FTrace := Handle;', 'FWorkerFinished := 0;', 'inherited Create(False);', 'FreeOnTerminate := False;']);
  assert.doesNotMatch(ctor, /^\s*Start\s*;/m);
  assert.match(etw, /finally\s+TInterlocked\.Exchange\(FWorkerFinished, 1\);/);
  const monitor = read('Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETW.pas');
  const destroy = monitor.split('destructor TETWMonitor.Destroy;')[1];
  order(destroy, ['RequestStop;', 'EtwCloseTrace(FConsumer);', 'FWorker.WaitFor;', 'FWorker.Free;', 'FFastRing.Free;']);
});
test('Authenticated B and O stop callbacks latch, arm shutdown and cancel owned ordinary connections', () => {
  const b = api.split('procedure TGameApi.AttachNHW(')[1].split('procedure TGameApi.JoinNHWReports')[0];
  const o = client.split('procedure TOverlayClient.AttachNHW(')[1].split('constructor TOverlayClient.Create')[0];
  order(b, ['Guard.ApplyAuthenticatedServerStop;', 'RequestStopCore;', 'OwnedStop();',
    'FTransport.CancelPending;', 'FOverlayStartupClient.CancelPending;']);
  order(o, ['Guard.ApplyAuthenticatedServerStop;', 'OwnedStop();', 'CancelPending;']);
  for (const callback of [b, o]) assert.doesNotMatch(callback, /TMonitor\.(Enter|TryEnter)|FGate\.Enter/);
  const runB = licenseSource.split('function RunLicenseClient: Integer;')[2];
  const runO = overlay.split('function RunOverlay: Integer;')[2];
  order(runB, ['Api.AttachNHW(Watch, Bootstrap.NHWQuoter,', 'ShutdownGuard.ArmAfter(15000);',
    'Worker.Free;', 'Api.FlushNHWReports;', 'Api.JoinNHWReports;',
    'SecurityStopped := SecurityStopped or Watch.Confirmed;', 'Api.Free;', 'Watch.Free;', 'ShutdownGuard.Cancel;']);
  order(runO, ['Client.AttachNHW(Watch,', 'Guard.ArmAfter(OverlayShutdownTotalMs);', 'Worker.WaitFor;',
    'Client.FlushNHWReports(Cardinal(ReportBudget));', 'Client.JoinNHWReports;', 'Watch.Confirmed',
    'Client.Free;', 'Watch.Free;', 'Guard.Cancel;']);
  const startB = api.split('function TGameApi.StartOverlayCore(')[1].split('function TGameApi.RedeemCore')[0];
  order(startB, ['MaintainParent, Progress, FOverlayStartupClient);',
    'TransferClient := FOverlayStartupClient;', 'TransferClient.CommitTransfer(']);
  const destroyB = api.split('destructor TGameApi.Destroy;')[1].split('end;\n\nfunction')[0];
  order(destroyB, ['FGate.CloseAndWait;', 'FNHWAuthority := nil;', 'FOverlayStartupClient.Free;', 'FTransport.Free;']);
});

test('Late replies cannot publish new authority while cleanup uses a separate connection', () => {
  const postB = api.split('function TGameApi.PostJSON(')[1].split('function TGameApi.ExecuteProof(')[0];
  order(postB, ['Response := FTransport.PostJSON(', 'RequireRunning;',
    'DataValue := Response.GetValue', 'RequireRunning;', 'Result := TJSONObject(DataValue.Clone);']);
  const postO = client.split('function TOverlayClient.Post(')[1].split('function OverlayCanonical(')[0];
  order(postO, ['IsClose := Action', 'if not IsClose then RequireSessionRunning;',
    'Reply := RequestTransport.PostJSON(', 'if not IsClose then RequireSessionRunning;',
    'Result := TJSONObject(Value.Clone);']);
  const ready = overlay.split('procedure TOverlayWorker.FirstFrameReady;')[1].split('procedure TOverlayWorker.Refresh;')[0];
  order(ready, ['if Terminated or FFailed or ConfirmedWatch', 'FContext.ConfirmOverlayReady;',
    'if ConfirmedWatch then', 'FReadyForTransfer := True;']);
  const close = client.split('procedure TOverlayClient.ShutdownClose(')[1].split('procedure TOverlayClient.Close;')[0];
  order(close, ['FGate.CloseAndWait;', 'ClosingTransport := FTransport.Fork;',
    'CloseCore(ClosingTransport);', 'ClosingTransport.Free;']);
  assert.doesNotMatch(close, /ResetCancellationAfterJoin/);
  const redeem = licenseSource.split('procedure TLicenseWorker.RedeemPending(')[1].split('procedure TLicenseWorker.Execute;')[0];
  order(redeem, ['if FWatch.Confirmed then Exit;', 'FCommands.Complete(WorkerTransferred);',
    "'DESKTOP_REVOKED'", 'if FWatch.Confirmed then FCommands.Complete(WorkerFailed)',
    'FCommands.Complete(WorkerIdle);']);
});
console.log(`NATIVE_LIFECYCLE_SOURCE_CONTRACTS_PASS ${count}; Windows execution NOT_RUN`);
