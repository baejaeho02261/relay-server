'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/spacex.native-string-contract");
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Source/protocol and deadline-model checks. These are deliberately NOT a
// Delphi compilation, Windows execution or proof of physical file removal.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const native = path.resolve(MODULE_RESOURCE_ROOT, '../../Desktop');
const read = name => ReadContractFile(path.join(native, name), 'utf8').replaceAll('\r', '');
const reporter = read("SpaceX.Source/SpaceX.Lifecycle/SpaceX.Lifecycle.pas"), handoff = read("SpaceX.Source/SpaceX.Handoff/SpaceX.Handoff.pas");
const overlay = read("SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.pas"), client = read("SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.Client.pas");
const licenseSource = read("SpaceX.Source/SpaceX.License/SpaceX.License.Session.pas"), api = read("SpaceX.Source/SpaceX.Platform/SpaceX.Api.pas");
const launcher = read("SpaceX.Source/SpaceX.Application/SpaceX.Launcher.pas"), renderer = read("SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.Renderer.pas");
const service = ReadContractFile(path.join(MODULE_RESOURCE_ROOT, "../services/observability/spacex.desktop-lifecycle-trace.js"), 'utf8');
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
  const shutdown = Number(read("SpaceX.Source/SpaceX.Lifecycle/SpaceX.ShutdownBudget.pas").match(/OverlayShutdownTotalMs = (\d+)/)[1]);
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
  const runA = launcher.split('function RunLauncher(const Monitor: ICozyProtectionSession): Integer;')[1];
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
test('Failed O startup reports only the exact held child exit and verified file cleanup', () => {
  const wait = handoff.split('function LaunchWithHandoff(').at(-1);
  const cleanup = wait.slice(wait.indexOf('if not Result and (Process.hProcess <> 0) then'), wait.indexOf('Close(Process.hProcess)'));
  order(cleanup, ['Observation := Default(THandoffCleanupObservation)', 'Observation.ProcessID := Process.dwProcessId', 'WaitForSingleObject(Process.hProcess, 0)', 'Observation.ExitCodeKnown := GetExitCodeProcess(Process.hProcess, Observation.ExitCode)', 'TerminateProcess(Process.hProcess, 1)', 'WaitForSingleObject(Process.hProcess, ParentExitTimeoutMS)', 'Observation.ExitObserved := WaitResult = WAIT_OBJECT_0', 'ObserveFailure(Observation)']);
  assert.match(cleanup, /if WaitResult = WAIT_OBJECT_0 then\s+begin\s+Observation\.ExitCodeKnown := GetExitCodeProcess\(Process\.hProcess, Observation\.ExitCode\);[\s\S]*?end\s+else\s+begin\s+TerminateProcess\(Process\.hProcess, 1\)/);
  assert.doesNotMatch(cleanup.slice(cleanup.indexOf('TerminateProcess(Process.hProcess, 1)')), /GetExitCodeProcess|(?:ExitCodeKnown|ExitCode)\s*:=/,
    'forced cleanup must not manufacture or replace the original child exit code');
  const launch = client.split('function LaunchOverlay(').at(-1).split('function TOverlayClient.ClaimCore')[0];
  order(launch, ['LaunchWithHandoff(', 'ChildObservation := Observation', 'ChildObservation.ExitObserved', 'DeleteCreatedBinary(', 'FailedChild := ChildObservation']);
  const remove = client.split('procedure DeleteCreatedBinary(')[1].split('function DownloadVerifiedBinary')[0];
  order(remove, ['SameFileIdentity(Info, CreatedInfo)', 'HashHandleSHA512(Handle) <> SHA512', 'LauncherSetFileInformationByHandle(', 'DispositionAccepted := True', 'CloseHandle(Handle)', 'Handle := CreateFileW(PWideChar(BinaryPath), 0,', 'Observation^.FileRemoved := Error = ERROR_FILE_NOT_FOUND']);
  const start = api.split('function TGameApi.StartOverlayCore(RestrictedPrivileges: Boolean;')[1].split('function TGameApi.RedeemCore')[0];
  order(start, ['TransferClient.AbortChild(', 'FailedChild.ProcessID <> 0', "FLifecycle.ObserveCleanup('O', FailedChild, True)", "FLifecycle.Prepare('O'", "FLifecycle.Submit('O'"]);
});
test('Actual cleanup follows worker join and image reader retirement, before final report', () => {
  const b = licenseSource.split('function RunLicenseClient(const Monitor: ICozyProtectionSession;')[1];
  order(b, ['Protection.StopAndDrain;', 'Worker.Free;', 'Api.RetireImagesForShutdown', 'Context.CleanupOwnImageForShutdown', 'Bootstrap.Close(', "Lifecycle.Submit('B'"]);
  const o = overlay.split('function RunOverlay(const Monitor: ICozyProtectionSession): Integer;')[1];
  order(o, ['Protection.StopMonitoring;', 'Worker.JoinBefore(', 'TOverlayClient.CloseSessionSnapshot(', 'Worker.WaitFor;', 'Protection.StopAndDrain;', 'FreeAndNil(Image)', 'Context.CleanupOwnImageForShutdown', 'Client.ShutdownClose(', "Lifecycle.Submit('O'"]);
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
console.log(`NATIVE_LIFECYCLE_SOURCE_CONTRACTS_PASS ${count}; Windows execution NOT_RUN`);
