"""Source sequencing checks only; not Delphi compilation or Windows execution."""
from pathlib import Path

root = Path(__file__).resolve().parents[2] / 'GameConnect_Win64'
read = lambda name: (root / name).read_text(encoding='utf-8-sig')
handoff, console, launcher, api = map(read, (
    'Game.Handoff.pas', 'Game.Console.pas', 'Game.Launcher.pas', 'Game.Api.pas'))
count = 0


def body(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


def check(name, condition):
    global count
    assert condition, name
    count += 1
    print('PASS', name)


claim = body(handoff, 'procedure THandoffContext.CompleteClaimAndCleanup(',
             'procedure THandoffContext.CleanupBinaryAfterLicense;')
cleanup = body(handoff, 'procedure THandoffContext.CleanupBinaryAfterLicense;',
               'function THandoffContext.TakeImageIntegrity:')
redeem = body(console, 'procedure TIntegrityWorker.RedeemPending(',
              'procedure TIntegrityWorker.Execute;')
main = console.rsplit('function RunGameConsole: Integer;', 1)[1]
complete = body(api, 'function TGameApi.CompleteLicense:',
                'procedure TGameApi.TakeIntegrity(')
transfer = body(api, 'procedure TGameApi.TakeIntegrity(', 'function TGameApi.Redeem(')

check('Original A handoff is acknowledged before B waits for A to exit',
      claim.index('SetEvent(FReadyEvent)') <
      claim.index('WaitForSingleObject(FParentProcess, ParentExitTimeoutMS)') <
      claim.index('SetFileInfo(LauncherFile, FileDispositionInfoClass'))
check('Original A never owns an overlay renderer or a license-result reply pipe',
      'RunAuthorizedOverlay' not in launcher and 'RunOverlayPlugin' not in launcher
      and 'WaitForLicenseResult' not in handoff and 'FResultPipe' not in handoff
      and 'Game.Overlay.' not in read('GameLauncher.dpr'))
check('The original v1 handoff ABI is restored',
      'HandoffVersion = 1;' in handoff and '(SizeOf(TWireHeader) = 84)' in handoff
      and '(Header.Version = HandoffVersion)' in handoff)
check('B is not unlinked at claim time and retains its verified cleanup handle',
      'UnlinkVerifiedOwnImage(' not in claim
      and 'FBinaryCleanupFile := BinaryFile;\n    BinaryFile := 0;' in claim
      and 'OpenSafeImage(' not in cleanup)
check('A valid license and server completion precede the one cleanup call',
      redeem.index('LicenseState := FApi.Redeem(Key);') <
      redeem.index('if not LicenseState.IsActive then') <
      redeem.index('FApi.CompleteLicense') <
      redeem.index('FHandoff.CleanupBinaryAfterLicense') <
      redeem.index('InterlockedExchange(FState, WorkerActive)')
      and console.count('FHandoff.CleanupBinaryAfterLicense') == 1)
check('Cleanup pins the exact file, closes its capability, and tolerates only OS refusal',
      'if FBinaryCleanupAttempted then Exit;' in cleanup
      and 'FBinaryCleanupInfo, False);' in cleanup
      and cleanup.index('PinDirectories(') < cleanup.index('UnlinkVerifiedOwnImage(')
      < cleanup.index('finally') < cleanup.index('Close(FBinaryCleanupFile)'))
check('Completed licensing drops tokens and stops further authentication work',
      complete.index('CompleteLicenseSession(') < complete.index('RequestStop;')
      < complete.index('FLicenseCompleted := True;')
      and all(token in complete for token in ('ClearPending;', 'ClearModuleSnapshot;',
          'WipeText(FActivationToken)', 'WipeText(FBootstrapSessionID)',
          'WipeText(FBootstrapSessionToken)')))
check('Only completed sessions may transfer retained integrity ownership',
      'not FLicenseCompleted' in transfer
      and 'InterlockedCompareExchange(FStopRequested, 0, 0) = 0' in transfer
      and all(token in transfer for token in ('FActivationToken <>',
          'FBootstrapSessionID <>', 'FBootstrapSessionToken <>',
          'Image := FImageIntegrity;', 'Code := FCodeIntegrity;',
          'FImageIntegrity := nil;', 'FCodeIntegrity := nil;')))
take = body(console, 'function TConsoleSession.TakeOverlayGrant:',
            'function RunGameConsole: Integer;')
check('B joins its license worker before taking the grant and integrity plans',
      take.index('FWorker.StopAndJoin') < take.index('FWorker.TakeOverlayGrant')
      and main.index('Console.TakeOverlayGrant') < main.index('Api.TakeIntegrity('))
check('The B host begins only after all authentication owners and console are gone',
      all(main.index(token) < main.index('RunOverlayPlugin(') for token in (
          'Console.Free;', 'Api.Free;', 'Bootstrap.Free;', 'FreeAndNil(Context);',
          'if ConsoleAllocated then FreeConsole;'))
      and 'if LicenseCompleted and (Result = 0) and not StopIsRequested then' in main)
check('Retained file/code integrity plans outlive the plugin and are freed once by B',
      main.index('Api.TakeIntegrity(OverlayImage, OverlayCode)') <
      main.index('RunOverlayPlugin(') < main.index('OverlayCode.Free;') <
      main.index('OverlayImage.Free;')
      and main.count('OverlayCode.Free;') == main.count('OverlayImage.Free;') == 1)
check('B hosts the separate plugin with no embedded renderer or A callback',
      'SendOverlayCapability' not in console and 'RunAuthorizedOverlay' not in console
      and 'Game.Overlay.Host' in read('GameConnect.dpr')
      and 'Game.Overlay.Runtime' not in read('GameConnect.dpr'))
check('The original A failure-only self-cleanup remains',
      'RemoveOwnImage(LauncherHash, Config.ImageInfo)' in launcher
      and 'if not HandoffSucceeded then' in launcher)
print(f'License-success source contracts: {count} passed. Static checks only; '
      'Delphi compilation and Windows lifetime/cleanup NOT executed here.')
