"""Source sequencing checks only: not Delphi compilation, ABI or Windows UI tests."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[2] / 'GameConnect_Win64'
read = lambda name: (root / name).read_text(encoding='utf-8-sig')
console = read('Game.Console.pas')
api = read('Game.Api.pas')
completion = read('Game.LicenseCompletion.pas')
data = read('Game.Overlay.Data.pas')
runtime = read('Game.Overlay.Runtime.pas')
count = 0


def body(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


def check(name, condition):
    global count
    assert condition, name
    count += 1
    print('PASS', name)


redeem = body(console, 'procedure TIntegrityWorker.RedeemPending(',
              'procedure TIntegrityWorker.Execute;')
worker = body(console, 'procedure TIntegrityWorker.Execute;',
              'constructor TConsoleSession.Create(')
entry = console.rsplit('function RunGameConsole: Integer;', 1)[1]
take = body(console, 'function TConsoleSession.TakeOverlayGrant:',
            'function RunGameConsole: Integer;')
complete = body(api, 'function TGameApi.CompleteLicense:', 'function TGameApi.Redeem(')
poll = body(runtime, 'procedure TOverlayWorker.Execute;', 'function OverlayWindowProcedure(')
snapshot = body(runtime, 'function TOverlayWorker.Snapshot(', 'procedure TOverlayWorker.Execute;')

check('A successful current license precedes completion and visible authorization',
      redeem.index('FApi.Redeem(Key)') < redeem.index('if not LicenseState.IsActive')
      < redeem.index('FApi.CompleteLicense') < redeem.index('InterlockedExchange(FState, WorkerActive)'))
check('B stops its worker loop immediately after completion and does not renew a license',
      'if State = WorkerActive then Break;' in worker and 'FApi.Verify' not in worker)
check('The grant is taken only after the B worker is joined',
      take.index('FWorker.StopAndJoin') < take.index('FWorker.TakeOverlayGrant'))
check('B authentication owners and console are disposed before the renderer is entered',
      all(entry.index(token) < entry.index('RunAuthorizedOverlay(')
          for token in ('Console.Free;', 'Api.Free;', 'Bootstrap.Free;', 'Context.Free;',
                        'if ConsoleAllocated then FreeConsole;'))
      and 'if LicenseCompleted and (Result = 0) and not StopIsRequested then' in entry)
check('B completion cancels future work and drops activation/bootstrap tokens',
      all(token in complete for token in ('RequireRunning;', 'not FCurrent.IsActive',
          'CompleteLicenseSession(', 'RequestStop;', 'ClearPending;', 'ClearModuleSnapshot;',
          'WipeText(FActivationToken)', 'WipeText(FBootstrapSessionToken)')))
check('A lost completion response retries the same request body with bounded transport budgets',
      completion.count("Body.AddPair('requestId'") == 1
      and completion.index("Body.AddPair('requestId'") < completion.index('for Attempt := 1 to 2')
      and "PostJSON('bootstrap', Body, 8000)" in completion
      and re.search(r'for Attempt := 1 to 2.*StartedAt := (?:Overlay)?GetTickCount64;.*'
                    r"Response := Transport.PostJSON\('bootstrap', Body, 8000\)", completion, re.S))
check('Only bounded exact data fields are accepted, including duplicate-field rejection',
      'Obj.Count <> Length(Names)' in data and 'Matches <> 1' in data
      and "CheckFields(Document, ['schema', 'format', 'title', 'lines', 'theme'])" in data
      and "'GAME-OVERLAY-DATA-1'" in data and 'Lines.Count > 8' in data
      and "TextField(Document, 'title', 1, 120)" in data and 'Length(Value.Value) > 240' in data)
check('The exact document text is SHA-256 checked before JSON display data is parsed',
      data.index('IntegritySHA256Text(DocumentText) <> Result.Document.SHA256')
      < data.index('TJSONObject.ParseJSONValue(DocumentText)'))
check('Network time and validation time count against a bounded monotonic display lease',
      'Duration > 30000' in data and 'Elapsed := NowTick - RequestStarted' in data
      and 'Elapsed >= UInt64(Duration)' in data
      and 'NowTick + UInt64(Duration) - Elapsed' in data)
check('Expiry is latched and an in-flight response cannot revive a closed renderer grant',
      re.search(r'if (?:Overlay)?GetTickCount64 >= FGrant.LeaseDeadlineTick then FValid := False;', snapshot)
      and re.search(r'if (?:Overlay)?GetTickCount64 >= FGrant.LeaseDeadlineTick then FValid := False;', poll)
      and poll.index('if Terminated or not FValid then Break') < poll.index('FGrant := Next'))
check('An independent overlay channel polls and closes with bounded requests',
      "PostJSON('overlay', Body, BudgetMs)" in runtime
      and "Request('poll', 5000)" in poll and "Request('close', 1500)" in poll
      and 'Next.SessionID <> FGrant.SessionID' in poll
      and 'Next.Document.Version < FGrant.Document.Version' in poll)
check('Display closes before bounded network teardown and callback exceptions stay inside Windows boundary',
      runtime.rindex('Window.Free;') < runtime.rindex('Worker.Free;')
      and 'LeaseTimerMilliseconds = 100;' in runtime
      and re.search(r'except\s*(?:\{[^}]*\}\s*)?(?:try\s*)?(?:Overlay)?ShowWindow\(Window, SW_HIDE\)', runtime)
      and 'if Terminated then Exit;' in poll)
new_overlay = completion + data + runtime
check('New overlay data/rendering modules contain no disk writer or executable loader calls',
      not re.search(r'\b(?:LoadLibrary\w*|GetProcAddress|VirtualAlloc\w*|WriteProcessMemory|'
                    r'CreateRemoteThread\w*|CreateProcess\w*|ShellExecute\w*|'
                    r'WriteFile|SaveToFile|TFile\.Write\w*)\s*\(', new_overlay,
                    flags=re.IGNORECASE))
check('A Windows parser probe is provided without claiming it ran on this platform',
      (root / 'tests/OverlayDataProbe.dpr').is_file()
      and (root / 'tests/Build_OverlayProbe_Win64.bat').is_file())
print(f'Overlay native source contracts: {count} passed. Static checks only; '
      'Delphi compilation, Windows ABI, parser probe and real rendering NOT executed here.')
