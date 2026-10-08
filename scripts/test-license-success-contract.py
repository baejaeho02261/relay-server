"""Source-level sequencing/ownership checks; NOT a Delphi compile or Windows test."""
from pathlib import Path
import re
root=Path(__file__).resolve().parents[2]
handoff=(root/'GameConnect_Win64/Game.Handoff.pas').read_text(encoding='utf-8-sig')
console=(root/'GameConnect_Win64/Game.Console.pas').read_text(encoding='utf-8-sig')
api=(root/'GameConnect_Win64/Game.Api.pas').read_text(encoding='utf-8-sig')
overlay=(root/'GameConnect_Win64/Game.Overlay.pas').read_text(encoding='utf-8-sig')
count=0

def check(name,condition):
    global count
    assert condition,name
    count+=1
    print('PASS',name)

claim=handoff.split('procedure THandoffContext.CompleteClaimAndCleanup(',1)[1].split('procedure THandoffContext.CleanupBinaryAfterLicense;',1)[0]
cleanup=handoff.split('procedure THandoffContext.CleanupBinaryAfterLicense;',1)[1].split('function THandoffContext.TakeImageIntegrity:',1)[0]
redeem=console.split('procedure TIntegrityWorker.RedeemPending(',1)[1].split('procedure TIntegrityWorker.Execute;',1)[0]
main=console.split('function RunGameConsole: Integer;')[-1].split('\ninitialization')[0]
check('A deletion stays in authenticated handoff', 'SetFileInfo(LauncherFile, FileDispositionInfoClass' in claim)
check('B is not unlinked at claim time', 'UnlinkVerifiedOwnImage(' not in claim)
check('The verified B handle is transferred rather than reopened after license', 'FBinaryCleanupFile := BinaryFile;\n    BinaryFile := 0;' in claim and 'OpenSafeImage(' not in cleanup)
check('Live license is checked before O launch and server transfer', redeem.index('LicenseState := FApi.Redeem(Key);') < redeem.index('if not LicenseState.IsActive then') < redeem.index('if not FApi.StartOverlay then'))
check('Confirmed transfer terminates B worker without another proof or active unlink', redeem.index('if not FApi.StartOverlay then') < redeem.index('InterlockedExchange(FState, WorkerTransferred)') < redeem.index('Terminate;') and 'CleanupBinaryAfterLicense' not in console and 'WorkerActive' not in console)
check('B console exits on transfer and joins worker before destroying resources', '(WorkerState = WorkerTransferred)' in console and main.index('Console.Free;') < main.index('Api.Free;') < main.index('Context.Free;'))
check('Cleanup is guarded once and preserves nonfatal OS refusal', 'if FBinaryCleanupAttempted then Exit;' in cleanup and 'FBinaryCleanupInfo, False);' in cleanup)
check('Cleanup pins the directory but retains the owner after OS refusal', cleanup.index('PinDirectories(') < cleanup.index('UnlinkVerifiedOwnImage(') < cleanup.index('finally') < cleanup.index('CloseAll(Pins)') and 'Close(FBinaryCleanupFile)' not in cleanup)
check('Integrity owns a separate read file object while the cleanup pin remains held', 'IntegrityFile := OpenSafeImage(FBinaryPath, False, IntegrityInfo, False, True);' in claim and 'TImageIntegrity.Create(IntegrityFile, BinarySHA512, ExpectedCRC64);' in claim and 'TImageIntegrity.Create(BinaryFile,' not in claim)
check('Worker is joined before handoff context can be freed', 'FreeAndNil(Context)' not in main and main.index('Console.Free;') < main.index('Context.Free;'))
destroy=handoff.split('destructor THandoffContext.Destroy;',1)[1].split('end;',1)[0]
check('Destructor releases both B ownership and uncommitted O parent pins', all(s in destroy for s in ['Close(FBinaryCleanupFile);', 'Close(FParentImage);', 'CloseAll(FParentPins);']))
start=api.split('function TGameApi.StartOverlay: Boolean;',1)[1].split('function TGameApi.Redeem(',1)[0]
check('B transfer is committed only after native O ready', start.index('Result := LaunchOverlay(') < start.index('TransferClient.CommitTransfer(') < start.index('FOverlayStarted := True;'))
check('Only a confirmed transfer skips redundant B close after the worker is joined', 'property OverlayTransferred: Boolean read FOverlayStarted;' in api and main.index('Console.Free;') < main.index('if (Bootstrap <> nil) and ((Api = nil) or not Api.OverlayTransferred) then') < main.index('Bootstrap.Close;') < main.index('Api.Free;'))
retire=handoff.split('procedure THandoffContext.CleanupTransferredParent;',1)[1].split('procedure THandoffContext.CleanupBinaryAfterLicense;',1)[0]
check('O deletes only an exited process image through matching held and DELETE identities', retire.index('WaitForSingleObject(FParentProcess, 0) = WAIT_OBJECT_0') < retire.index('DeleteFile := OpenSafeImage(') < retire.index('SameIdentity(HeldInfo, DeleteInfo)') < retire.index('SetFileInfo(DeleteFile, FileDispositionInfoClass'))
refresh=overlay.split('procedure TOverlayWorker.Refresh;',1)[1].split('procedure TOverlayWorker.StartAuthorized;',1)[0]
check('O independently confirms server transfer before B cleanup', refresh.index('Lease := FClient.Verify(') < refresh.index('if not FClient.TransferConfirmed then') < refresh.index('FContext.CleanupTransferredParent;'))
check('Only immediate post-exit transfer confirmation reuses the server-validated module snapshot', 'ConfirmingTransfer := AwaitingTransfer and not FTransferred and\n    not FContext.ParentIsAlive;' in refresh and 'FClient.ReportIntegrity(FContext.Security, FContext.CodeIntegrity, Image,\n    not ConfirmingTransfer,' in refresh)
ready=overlay.split('procedure TOverlayWorker.FirstFrameReady;',1)[1].split('procedure TOverlayWorker.Refresh;',1)[0]
check('Worker observes readiness only after local handoff completion under the same lock', ready.index('TMonitor.Enter(FLock)') < ready.index('FContext.ConfirmOverlayReady;') < ready.index('FReadyForTransfer := True;') < ready.index('TMonitor.Exit(FLock)'))
check('O transition remains bounded by last authenticated lease', '(TickCount >= FDeadline)' in overlay and "raise EBootstrap.Create('OVERLAY_TRANSFER_NOT_CONFIRMED')" in refresh)
check('No window renderer or automatic assignment marker added', not any(x in console for x in ['CreateWindowEx','Vcl.Forms','FMX.Forms','SERVER_ASSIGNED_V1']))
print(f'License-success source contracts: {count} passed. Static checks only; no Windows deletion or rendering test.')
