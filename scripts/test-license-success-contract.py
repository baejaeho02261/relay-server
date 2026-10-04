"""Source-level sequencing/ownership checks; NOT a Delphi compile or Windows test."""
from pathlib import Path
import re
root=Path(__file__).resolve().parents[2]
handoff=(root/'GameConnect_Win64/Game.Handoff.pas').read_text(encoding='utf-8-sig')
console=(root/'GameConnect_Win64/Game.Console.pas').read_text(encoding='utf-8-sig')
launcher=(root/'GameConnect_Win64/Game.Launcher.pas').read_text(encoding='utf-8-sig')
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
check('Authenticated claim keeps A alive and waits for its resource-release acknowledgment',
      'SetFileInfo(LauncherFile, FileDispositionInfoClass' not in claim
      and 'WaitHandles[0] := FHostReadyEvent;' in claim
      and 'HostReadyTimeoutMS) = WAIT_OBJECT_0' in claim)
check('B is not unlinked at claim time', 'UnlinkVerifiedOwnImage(' not in claim)
check('The verified B handle is transferred rather than reopened after license', 'FBinaryCleanupFile := BinaryFile;\n    BinaryFile := 0;' in claim and 'OpenSafeImage(' not in cleanup)
check('License success is checked before cleanup', redeem.index('LicenseState := FApi.Redeem(Key);') < redeem.index('if not LicenseState.IsActive then') < redeem.index('FHandoff.CleanupBinaryAfterLicense'))
check('Server completion precedes cleanup, and its lease is checked before success',
      redeem.index('FApi.CompleteLicense') < redeem.index('FHandoff.CleanupBinaryAfterLicense')
      < redeem.index('GetTickCount64 >= FOverlayGrant.LeaseDeadlineTick')
      < redeem.index('InterlockedExchange(FState, WorkerActive)'))
check('Exactly one license-gated call site exists', console.count('FHandoff.CleanupBinaryAfterLicense')==1)
check('Cleanup is guarded once and preserves nonfatal OS refusal', 'if FBinaryCleanupAttempted then Exit;' in cleanup and 'FBinaryCleanupInfo, False);' in cleanup)
check('Cleanup pins the directory and closes capability on both paths', cleanup.index('PinDirectories(') < cleanup.index('UnlinkVerifiedOwnImage(') < cleanup.index('finally') < cleanup.index('Close(FBinaryCleanupFile)'))
check('Worker is joined before handoff context can be freed', 'FreeAndNil(Context)' not in main and main.index('Console.Free;') < main.index('Context.Free;'))
check('Destructor releases unused cleanup handle', 'destructor THandoffContext.Destroy;\nbegin\n  Close(FBinaryCleanupFile);' in handoff)
check('No window renderer or automatic assignment marker added', not any(x in console for x in ['CreateWindowEx','Vcl.Forms','FMX.Forms','SERVER_ASSIGNED_V1']))
check('B returns to process exit instead of running a message loop after success',
      'RunAuthorizedOverlay' not in console
      and main.index('Api.Free;') < main.index('Context.SendOverlayCapability(')
      < main.index('Context.Free;'))
check('A releases the exact downloaded image pin before B receives its claim payload',
      handoff.index('CloseHandle(DownloadHandle);') < handoff.index('Writer.Bytes := Payload;')
      and 'DownloadHandle := INVALID_HANDLE_VALUE;' in handoff)
check('A self-cleanup preserves its saved image identity after its child is joined',
      'RemoveOwnImage(ExpectedLauncherHash, LauncherImageInfo)' in launcher
      and 'LauncherImageInfo := Config.ImageInfo;' in launcher)
check('The new lifetime contract rejects mixed old/new handoff versions',
      'HandoffVersion = 2;' in handoff and '(SizeOf(TWireHeader) = 100)' in handoff
      and '(Header.Version = HandoffVersion)' in handoff)
read_exact=handoff.split('procedure ReadExact(',1)[1].split('procedure RequirePipeEnd(',1)[0]
check('A rechecks the pipe after observing B exit so a just-written result is not lost',
      read_exact.count('PeekNamedPipe(') >= 2 and 'WatchedProcess' in read_exact)
print(f'License-success source contracts: {count} passed. Static checks only; no Windows deletion or rendering test.')
