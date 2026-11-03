"""Source-level sequencing/ownership checks; NOT a Delphi compile or Windows test."""
from pathlib import Path
import re
import subprocess
root=Path(__file__).resolve().parents[3]
def read(relative):
    # Reuse the strict semantic source loader used by the JS contract tests;
    # it reads actual current constants and verifies map/import ownership.
    loader=root/'Relay Server/tests/fixtures/source/peace.native-string-contract.js'
    code="process.stdout.write(require(process.argv[1]).ReadContractFile(process.argv[2], 'utf8'))"
    return subprocess.check_output(['node','-e',code,str(loader),str(root/relative)],text=True).replace('\r','')
handoff=read('Railway/Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas')
license_session=read('Railway/Cozy.Source/Cozy.License/Cozy.License.Session.pas')
window=read('Railway/Cozy.Source/Cozy.License/Cozy.License.Window.pas')
api=read('Railway/Cozy.Source/Cozy.Platform/Cozy.Api.pas')
overlay=read('Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas')
count=0

def check(name,condition):
    global count
    assert condition,name
    count+=1
    print('PASS',name)

claim=handoff.split('procedure THandoffContext.CompleteClaimAndCleanupCore(',1)[1].split('procedure THandoffContext.CleanupBinaryAfterLicenseCore;',1)[0]
cleanup=handoff.split('procedure THandoffContext.CleanupBinaryAfterLicenseCore;',1)[1].split('function THandoffContext.TakeImageIntegrityCore:',1)[0]
redeem=license_session.split('procedure TLicenseWorker.RedeemPending(',1)[1].split('procedure TLicenseWorker.Execute;',1)[0]
main=license_session.split('function RunLicenseClient: Integer;')[-1].split('\ninitialization')[0]
check('A deletion stays in authenticated handoff', re.search(r'SetFileInfo\(LauncherFile,\s*FileDispositionInfoClass', claim) is not None)
check('B is not unlinked at claim time', 'UnlinkVerifiedOwnImage(' not in claim)
check('The verified B handle is transferred rather than reopened after license', 'FBinaryCleanupFile := BinaryFile;\n    BinaryFile := 0;' in claim and 'OpenSafeImage(' not in cleanup)
check('Live license is checked before O launch and server transfer', redeem.index('LicenseState := FApi.Redeem(BoundaryKey);') < redeem.index('if not LicenseState.IsActive then') < redeem.index('if not FApi.StartOverlay then'))
check('Confirmed transfer terminates B worker without another proof or active unlink', redeem.index('if not FApi.StartOverlay then') < redeem.index('FCommands.Complete(WorkerTransferred)') < redeem.index('Terminate;') and 'CleanupBinaryAfterLicense' not in license_session and 'WorkerActive' not in license_session)
check('B window exits on transfer and joins worker before destroying resources', 'State = WorkerTransferred' in window and main.index('Worker.Free;') < main.index('Api.Free;') < main.index('Context.Free;'))
check('Cleanup is guarded once and preserves nonfatal OS refusal', 'if FBinaryCleanupAttempted then Exit;' in cleanup and 'FBinaryCleanupInfo, False);' in cleanup)
check('Cleanup pins the directory but retains the owner after OS refusal', cleanup.index('PinDirectories(') < cleanup.index('UnlinkVerifiedOwnImage(') < cleanup.index('finally') < cleanup.index('CloseAll(Pins)') and 'Close(FBinaryCleanupFile)' not in cleanup)
check('Integrity owns a separate read file object while the cleanup pin remains held', 'IntegrityFile := OpenSafeImage(FBinaryPath, False, IntegrityInfo, False, True);' in claim and 'TImageIntegrity.Create(IntegrityFile, BinarySHA512, ExpectedCRC64);' in claim and 'TImageIntegrity.Create(BinaryFile,' not in claim)
check('Worker is joined before handoff context can be freed', 'FreeAndNil(Context)' not in main and main.index('Worker.Free;') < main.index('Context.Free;'))
destroy=handoff.split('destructor THandoffContext.Destroy;',1)[1].split('end;',1)[0]
check('Destructor releases both B ownership and uncommitted O parent pins', all(s in destroy for s in ['Close(FBinaryCleanupFile);', 'Close(FParentImage);', 'CloseAll(FParentPins);']))
start=api.split('function TGameApi.StartOverlayCore(RestrictedPrivileges: Boolean): Boolean;',1)[1].split('function TGameApi.RedeemCore(',1)[0]
check('B transfer is committed only after native O ready', start.index('Result := LaunchOverlay(') < start.index('TransferClient.CommitTransfer(') < start.index('FOverlayStarted := True;'))
check('Only a confirmed transfer skips redundant B close after the worker is joined', 'property OverlayTransferred: Boolean read GetOverlayTransferred;' in api and 'try Result := FOverlayStarted; finally TMonitor.Exit(FLock); end;' in api and main.index('Worker.Free;') < main.index('if Api <> nil then Transferred := Api.OverlayTransferred;') < main.index('if (Bootstrap <> nil) and not Transferred then') < main.index('Bootstrap.Close;') < main.index('Api.Free;'))
retire=handoff.split('procedure THandoffContext.CleanupTransferredParentCore;',1)[1].split('procedure THandoffContext.CleanupBinaryAfterLicenseCore;',1)[0]
check('O deletes only an exited process image through matching held and DELETE identities', retire.index('WaitForSingleObject(FParentProcess, 0) = WAIT_OBJECT_0') < retire.index('DeleteFile := OpenSafeImage(') < retire.index('SameIdentity(HeldInfo, DeleteInfo)') < re.search(r'SetFileInfo\(DeleteFile,\s*FileDispositionInfoClass', retire).start())
refresh=overlay.split('procedure TOverlayWorker.Refresh;',1)[1].split('procedure TOverlayWorker.MaintainLease(',1)[0]
renew=overlay.split('procedure TOverlayWorker.RenewLease(',1)[1].split('procedure TOverlayWorker.StartAuthorized;',1)[0]
check('O independently confirms server transfer before B cleanup', renew.index('Lease := FClient.Verify(') < renew.index('TransferConfirmed := FClient.TransferConfirmed;') < renew.index('CleanupParent := ParentExited and FTransferred and not FParentRetirementDone;') < renew.index('if CleanupParent then') < renew.index('FContext.CleanupTransferredParent;'))
check('Full snapshot scheduling remains server-bound and transfer-aware', 'IncludeModules := OverlaySnapshotDue(CozyTick, FLastSnapshotAt, FTransferred,' in refresh and 'FClient.SnapshotDeadlineTick, FLastSnapshotDuration);' in refresh and 'FClient.ReportIntegrity(FContext.Security, FContext.CodeIntegrity, Image,\n    IncludeModules,' in refresh)
ready=overlay.split('procedure TOverlayWorker.FirstFrameReady;',1)[1].split('procedure TOverlayWorker.Refresh;',1)[0]
check('Worker observes readiness only after local handoff completion under the same lock', ready.index('TMonitor.Enter(FLock)') < ready.index('FContext.ConfirmOverlayReady;') < ready.index('FReadyForTransfer := True;') < ready.index('TMonitor.Exit(FLock)'))
check('O transition remains bounded by last authenticated lease', '(CozyTick >= FDeadline)' in overlay and "raise EBootstrap.Create('OVERLAY_TRANSFER_NOT_CONFIRMED')" in renew)
check('Window keeps rendering separate from API ownership and has no auto assignment', 'ImGuiCreate(FWindow, True)' in window and not any(x in window for x in ['TGameApi', 'Bootstrap.Claim', 'Redeem(', 'SERVER_ASSIGNED_V1', 'Vcl.Forms', 'FMX.Forms']))
# These inspect the production unit's lock boundaries and cleanup ordering.
# They intentionally do not simulate a worker and do not claim runtime coverage.
cancel=overlay.split('function TOverlayWorker.RequestCancelled: Boolean;',1)[1].split('procedure TOverlayWorker.FirstFrameReady;',1)[0]
stop=overlay.split('procedure TOverlayWorker.Stop;',1)[1].split('function TOverlayWorker.AwaitingTransfer:',1)[0]
close=overlay.split('function TOverlayWorker.ShouldClose: Boolean;',1)[1].split('procedure TOverlayWorker.Execute;',1)[0]
run=overlay.split('function RunOverlay: Integer;')[-1].split('\ninitialization')[0]
check('Ready event rechecks active authorization while holding its publication lock',
      ready.index('TMonitor.Enter(FLock)') < ready.index('if Terminated or FFailed or (FDeadline = 0)') < ready.index('FContext.ConfirmOverlayReady;')
      and '(CozyTick >= FDeadline)' in ready
      and '(not FReadyForTransfer and not FContext.ParentIsAlive)' in ready)
check('Repeated successful frame callbacks cannot signal or close the ready event twice',
      ready.index('if FReadyForTransfer then Exit;') < ready.index('FContext.ConfirmOverlayReady;'))
check('Stop invalidates authorization under the same lock used to publish ready',
      stop.index('Terminate;') < stop.index('TMonitor.Enter(FLock)') < stop.index('FFailed := True;') < stop.index('FDeadline := 0;') < stop.index('TMonitor.Exit(FLock)'))
check('In-flight report and verification callbacks cancel on sticky failure and expired lease',
      'Result := Terminated or FFailed or' in cancel
      and '((FDeadline <> 0) and (CozyTick >= FDeadline))' in cancel
      and cancel.index('TMonitor.Enter(FLock)') < cancel.index('FFailed := True;') < cancel.index('TMonitor.Exit(FLock)')
      and 'function: Boolean begin Result := RequestCancelled; end);' in renew
      and 'function: Boolean begin Result := RequestCancelled; end' in refresh)
publish=renew[renew.rindex('TMonitor.Enter(FLock);'):]
check('Late lease replies cannot reopen stopped or elapsed authorization',
      publish.index('if Terminated or FFailed or (Deadline <= CozyTick)') < publish.index('FDeadline := Deadline;')
      and '((FDeadline <> 0) and (CozyTick >= FDeadline))' in publish
      and publish.index('FFailed := True;') < publish.index('FDeadline := Deadline;') < publish.index('TMonitor.Exit(FLock)'))
check('UI expiry is sticky and snapshots readiness with its deadline under one lock',
      close.index('TMonitor.Enter(FLock)') < close.index('Result := Terminated or FFailed') < close.index('FFailed := True;') < close.index('TMonitor.Exit(FLock)')
      and 'AwaitingTransfer' not in close)
check('Overlay shutdown joins the worker before closing its authenticated client or context',
      run.index('Worker.Stop;') < run.index('Worker.WaitFor;') < run.index('Worker.Free;') < run.index('Client.ShutdownClose(') < run.index('Context.Free;'))
print(f'License-success source contracts: {count} passed. Static checks only; no Windows deletion or rendering test.')
