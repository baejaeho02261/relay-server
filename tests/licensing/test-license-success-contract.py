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
commands=read('Railway/Cozy.Source/Cozy.License/Cozy.License.Commands.pas')
api=read('Railway/Cozy.Source/Cozy.Platform/Cozy.Api.pas')
overlay=read('Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas')
module_inventory=read('Railway/Cozy.Source/Cozy.Integrity/Cozy.ModuleInventory.pas')
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
check('Live license is checked before O launch and server transfer', redeem.index('LicenseState := FApi.Redeem(BoundaryKey);') < redeem.index('if not LicenseState.IsActive then') < redeem.index('if not FApi.StartOverlay(False,'))
check('Submit has no artificial minimum wait or time-based completion',
      all(token not in license_session+window+commands for token in
          ['WaitForSubmitPresentation', 'LicenseSubmitMinimumMilliseconds', 'AttemptStartedAt', 'FSubmitAt']))
progress=commands.split('procedure TLicenseCommandMailbox.ReportProgress(Value: Integer);',1)[1].split('function TLicenseCommandMailbox.Progress:',1)[0]
completion=commands.split('procedure TLicenseCommandMailbox.Complete(Outcome: Integer);',1)[1].split('procedure TLicenseCommandMailbox.Stop;',1)[0]
check('Worker milestones are monotonic and cannot publish transfer completion',
      'if Value > 99 then Value := 99;' in progress
      and 'if not FStopping and (FState = WorkerBusy) and (Value > FProgress) then' in progress
      and 'FProgress := Value;' in progress
      and 'if Outcome = WorkerTransferred then' in completion
      and 'FState := WorkerTransferred; FProgress := 100; FStopping := True;' in completion)
check('B displays completed worker milestones and keeps API locks away from rendering',
      'FCommands.ReportProgress(40);' in redeem
      and 'procedure(Value: Integer) begin FCommands.ReportProgress(Value); end)' in redeem
      and 'Percent := FProgress();' in window
      and 'ImGuiLicenseScene(FContext, Phase, FKey.Count, Percent / 100)' in window
      and 'function TLicenseWindow.BusyVisual: Boolean;' in window
      and 'Result := Assigned(FState) and (FState() = WorkerBusy);' in window)
check('Only definitive key rejection silently reopens the same B without a timer',
      all("E.Code = '"+code+"'" in redeem for code in ['LICENSE_KEY_INVALID','DESKTOP_KEY_INVALID','DESKTOP_KEY_USED','DESKTOP_EXPIRED','DESKTOP_REVOKED','DESKTOP_RELEASED'])
      and 'if not Terminated and not FCommands.Stopping then\n            FCommands.Complete(WorkerIdle);' in redeem
      and 'else\n          FCommands.Complete(WorkerFailed);' in redeem)
check('Confirmed transfer terminates B worker without another proof or active unlink', redeem.index('if not FApi.StartOverlay(False,') < redeem.index('FCommands.Complete(WorkerTransferred)') < redeem.index('Terminate;') and 'CleanupBinaryAfterLicense' not in license_session and 'WorkerActive' not in license_session)
check('B window exits on transfer and joins worker before destroying resources', 'State = WorkerTransferred' in window and main.index('Worker.Free;') < main.index('Api.Free;') < main.index('Context.Free;'))
check('Cleanup is guarded once and preserves nonfatal OS refusal', 'if FBinaryCleanupAttempted then Exit;' in cleanup and 'FBinaryCleanupInfo, False);' in cleanup)
check('Cleanup pins the directory but retains the owner after OS refusal', cleanup.index('PinDirectories(') < cleanup.index('UnlinkVerifiedOwnImage(') < cleanup.index('finally') < cleanup.index('CloseAll(Pins)') and 'Close(FBinaryCleanupFile)' not in cleanup)
check('Integrity owns a separate read file object while the cleanup pin remains held', 'IntegrityFile := OpenSafeImage(FBinaryPath, False, IntegrityInfo, False, True);' in claim and 'TImageIntegrity.Create(IntegrityFile, BinarySHA512, ExpectedCRC64);' in claim and 'TImageIntegrity.Create(BinaryFile,' not in claim)
check('Worker is joined before handoff context can be freed', 'FreeAndNil(Context)' not in main and main.index('Worker.Free;') < main.index('Context.Free;'))
destroy=handoff.split('destructor THandoffContext.Destroy;',1)[1].split('end;',1)[0]
check('Destructor releases both B ownership and uncommitted O parent pins', all(s in destroy for s in ['Close(FBinaryCleanupFile);', 'Close(FParentImage);', 'CloseAll(FParentPins);']))
start=api.split('function TGameApi.StartOverlayCore(RestrictedPrivileges: Boolean;',1)[1].split('function TGameApi.RedeemCore(',1)[0]
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
modules=api.split('function TGameApi.ReportModulesIfDue: Boolean;',1)[1].split('function TGameApi.ContinueModuleInventoryCore:',1)[0]
retry=modules.split('if (FModuleGenerationRetries < ModuleGenerationRetryLimit)',1)[1].split('FModuleSnapshotID := RequestID;',1)[0]
predicate=module_inventory.split('function ModuleInventoryGenerationRetryable(Snapshot: TJSONObject): Boolean;')[-1].split('function CollectModuleInventoryJSON(',1)[0]
check('An interrupted loader generation is discarded before any server batch and cannot unblock key redemption',
      modules.index('ModuleInventoryGenerationRetryable(FModuleSnapshot)') < modules.index('FModuleSnapshotID := RequestID;') < modules.index('SendIntegrityReport(Payload);')
      and retry.index('FModuleSnapshotCompleted := False;') < retry.index('ClearModuleSnapshot;') < retry.index('Exit(True);')
      and 'FNextModules := NowTick;' in retry)
check('Generation retry is bounded from the first scan, includes cancellation and resets only after server acceptance',
      'ModuleGenerationRetryLimit = 2;' in api and 'ModuleGenerationRetryMilliseconds = 90000;' in api
      and modules.index('if FModuleGenerationRetries = 0 then FModuleGenerationStarted := NowTick;') < modules.index('CollectModuleInventoryJSON(')
      and '(At < FModuleGenerationStarted)' in modules
      and '(At - FModuleGenerationStarted >= ModuleGenerationRetryMilliseconds)' in modules
      and modules.index('SendIntegrityReport(Payload);') < modules.index('FModuleGenerationRetries := 0;'))
check('Generation-only retry cannot hide read failures, code differences, missing digests or one-shot device evidence',
      all(value in predicate for value in ["'TRACKED_CHANGED'", "'PARTIAL'", "'UNVERIFIED_BASELINE'", "'MATCH_LOCAL_FILE'", "'failurePhase'", "'fileSha512', 128", "'codeSha512', 128", "'MEASURED'", "'NO_EXPORTS'", "'SECTION_HASHED'", "'COMPLETE'", "'unknownStart'", "'unreadable'", "'NOT_REQUESTED'"])
      and not any(value in predicate for value in ['.AddPair(', '.RemovePair(', 'Exit(True)']))
budget=api.split('procedure TGameApi.ApplyModuleSnapshotBudget(',1)[1].split('function TGameApi.ReportModulesIfDue:',1)[0]
send=api.split('procedure TGameApi.SendIntegrityReport(',1)[1].split('procedure TGameApi.ReportMeasurementFailure',1)[0]
maintenance=start.split('      MaintainParent :=',1)[1].split('      CheckIntegrityCore;',1)[0]
check('B only maps a completed matching receipt within the unchanged server freshness bound',
      all(value in budget for value in ["Reply.GetValue('snapshotBudget')", 'SnapshotID <> FModuleSnapshotID',
        'ExpiresAt - ServerTime > MaxLeaseMilliseconds', 'Elapsed >= UInt64(Duration)', 'RequireModuleSnapshotLease;',
        'ServerTime < FModuleReceiptServerTime'])
      and send.index('StartedAt := CozyTick;') < send.index('Challenge := PostJSON(')
      and send.index('Reply := PostJSON(') < send.index('ApplyModuleSnapshotBudget(Reply, StartedAt);')
      and "JsonInteger(Payload, 'batchIndex') + 1 =" in send
      and "JsonInteger(Payload, 'batchCount'))" in send)
check('Cached receipt mapping never extends the first monotonic deadline or revives an elapsed window',
      budget.index('RequireModuleSnapshotLease;') < budget.index('if SnapshotID = FModuleReceiptID then')
      and 'if Deadline < FModuleDeadlineTick then FModuleDeadlineTick := Deadline;' in budget
      and '(ServerTime <> FModuleReceiptServerTime)' in budget
      and '(ExpiresAt <> FModuleReceiptExpiresAt)' in budget
      and '(FModuleDeadlineTick <> 0) and (FModuleDeadlineTick <= CozyTick)' in api)
check('B schedules full refresh using observed collection and all batches plus a chunk/renewal reserve',
      'ModuleSnapshotCheckpointReserve = 30000;' in api
      and 'FModuleCycleMilliseconds := NowTick - FModuleGenerationStarted;' in modules
      and 'Reserved := FModuleCycleMilliseconds + ModuleSnapshotCheckpointReserve;' in modules
      and 'FNextModules := FModuleDeadlineTick - Reserved;' in modules
      and '((FModuleDeadlineTick <> 0) and (At >= FModuleDeadlineTick))' in modules)
check('O download drains due snapshots and child wait yields between batches to observe readiness',
      'if BeforeChild then ParentWaitingForChild := True;' in start
      and maintenance.index('repeat') < maintenance.index('then RenewParent();') < maintenance.index('MoreModules := ReportModulesIfDue;') < maintenance.index('until not MoreModules or ParentWaitingForChild;')
      and 'if BeforeChild and (FModuleSnapshot = nil) then FNextModules := 0;' in maintenance
      and 'RequireParentPending();' in maintenance)
check('B progress cannot signal completion until the actual O transfer is acknowledged',
      start.index('TransferClient.CommitTransfer(') < start.index('FOverlayStarted := True;') < start.index('Progress(100)')
      and 'MaintainParent, Progress);' in start)
readiness=api.split('function TGameApi.GetModuleInventoryReadyCore: Boolean;',1)[1].split('function TGameApi.GetOverlayTransferredCore:',1)[0]
check('A fresh completed snapshot allows queued redemption even when the next scan is already due',
      'FModuleSnapshotCompleted and (FModuleSnapshot = nil)' in readiness
      and 'FModuleDeadlineTick - At > ModuleSnapshotCheckpointReserve' in readiness
      and 'FNextModules' not in readiness)
check('Packing retains every row while respecting both payload and escaped signed-envelope byte limits',
      'ModuleBatchMaximum = 16;' in api
      and 'ModulePayloadMaximum = 24576;' in api and 'ModuleEnvelopeMaximum = 32768;' in api
      and 'Payload := CreateModulePayload(255, 256);' in modules
      and 'EncodedMetadataBytes := EncodedStringBytes(Payload.ToJSON);' in modules
      and 'Bytes := EncodedStringBytes(TJSONArray(Modules).Items[I].ToJSON) - 2;' in modules
      and 'SubmitOverhead := IntegritySubmitOverheadBytes;' in modules
      and 'Int64(LargestEncodedModuleBytes + 1) * FModuleBatchSize > ModuleEnvelopeMaximum' in modules
      and 'FModuleBatchCount := (Total + FModuleBatchSize - 1) div FModuleBatchSize;' in modules
      and 'Batch.AddElement(TJSONValue(TJSONArray(Modules).Items[FModuleNextIndex].Clone));' in modules
      and 'Inc(FModuleNextIndex);' in modules
      and 'TEncoding.UTF8.GetByteCount(Text) > ModulePayloadMaximum' in send)
print(f'License-success source contracts: {count} passed. Static checks only; no Windows deletion or rendering test.')
