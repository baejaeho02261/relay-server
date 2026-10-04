"""Source-level sequencing/ownership checks; NOT a Delphi compile or Windows test."""
from pathlib import Path
import re
root=Path(__file__).resolve().parents[2]
handoff=(root/'GameConnect_Win64/Game.Handoff.pas').read_text(encoding='utf-8-sig')
console=(root/'GameConnect_Win64/Game.Console.pas').read_text(encoding='utf-8-sig')
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
check('License success is checked before cleanup', redeem.index('LicenseState := FApi.Redeem(Key);') < redeem.index('if not LicenseState.IsActive then') < redeem.index('FHandoff.CleanupBinaryAfterLicense'))
check('An expired lease is checked again before WorkerActive',redeem.index('FHandoff.CleanupBinaryAfterLicense') < redeem.rindex('if not LicenseState.IsActive then') < redeem.index('InterlockedExchange(FState, WorkerActive)'))
check('Exactly one license-gated call site exists', console.count('FHandoff.CleanupBinaryAfterLicense')==1)
check('Cleanup is guarded once and preserves nonfatal OS refusal', 'if FBinaryCleanupAttempted then Exit;' in cleanup and 'FBinaryCleanupInfo, False);' in cleanup)
check('Cleanup pins the directory and closes capability on both paths', cleanup.index('PinDirectories(') < cleanup.index('UnlinkVerifiedOwnImage(') < cleanup.index('finally') < cleanup.index('Close(FBinaryCleanupFile)'))
check('Worker is joined before handoff context can be freed', 'FreeAndNil(Context)' not in main and main.index('Console.Free;') < main.index('Context.Free;'))
check('Destructor releases unused cleanup handle', 'destructor THandoffContext.Destroy;\nbegin\n  Close(FBinaryCleanupFile);' in handoff)
check('No window renderer or automatic assignment marker added', not any(x in console for x in ['CreateWindowEx','Vcl.Forms','FMX.Forms','SERVER_ASSIGNED_V1']))
print(f'License-success source contracts: {count} passed. Static checks only; no Windows deletion or rendering test.')
