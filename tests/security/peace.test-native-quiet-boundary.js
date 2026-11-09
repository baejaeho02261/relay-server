'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");

// Source boundaries only: does not execute A/B/O or certify Windows behavior.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const native = path.resolve(__dirname, '../../../Railway');
const read = name => ReadContractFile(path.join(native, name), 'utf8').replaceAll('\r', '');
const stripComments = source => source.replace(/\{[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\n]*/g, '');

test('Production A/B/O reject invalid invocation shapes before startup work and catch failures silently', () => {
  const cases = [
    ['Launcher', /if ParamCount = 0 then/, 'gcrLauncher', 'RunLauncher'],
    ['Client', /if \(ParamCount = 2\) and \(ParamStr\(1\) = '--game-handoff'\) then/, 'gcrConnect', 'RunLicenseClient'],
    ['Overlay', /if \(ParamCount = 2\) and \(ParamStr\(1\) = '--game-overlay'\) then/, 'gcrOverlay', 'RunOverlay'],
  ];
  for (const [name, shape, role, run] of cases) {
    const source = stripComments(read(`Cozy.Projects/Cozy.${name}/Cozy.${name}.dpr`));
    const body = source.slice(source.lastIndexOf('\nbegin\n'));
    assert.match(body, name === 'Launcher' ? /ExitCode := 31000;/ : /ExitCode := 1;/);
    const gate = body.search(shape), seal = body.indexOf('SealApiPointerStorage;');
    const startup = body.indexOf(name === 'Launcher' ? `RequireNativeStartup(${role}, @ExitCode);` : `RequireNativeStartup(${role});`), application = body.indexOf(`ExitCode := ${run};`);
    assert(gate >= 0 && gate < seal && seal < startup && startup < application, name);
    assert.match(body, name === 'Launcher' ? /except\s+end;/ : /except\s+ExitCode := 1;\s+end;/);
    assert.doesNotMatch(body, /MessageBox|ShowMessage|WriteLn|OutputDebugString|WriteConsole/i);
  }
});

test('B owns masked key input outside ImGui and rejects output paths for secrets or exception text', () => {
  const worker = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Session.pas'));
  const window = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Window.pas'));
  const mailbox = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Commands.pas'));
  assert.match(window, /ImGuiLicenseScene\(FContext, Phase, FKey\.Count, Percent \/ 100\)/);
  assert.doesNotMatch(window, /CopyText|ImGuiTextInput|InputText|PWideChar\(.*Key|PAnsiChar\(.*Key/);
  assert.match(window, /Key := FKey; FKey := nil;/);
  assert.match(window, /finally\s+FreeAndNil\(Key\);/);
  assert.match(window, /if FKey <> nil then FKey\.Clear;/);
  assert.match(window, /MaximumKeyCharacters = 100/);
  assert.match(window, /MaximumClipboardCharacters = 4096/);
  assert.match(window, /if not Terminated or \(Value\.Count = 0\)/);
  assert.match(worker, /BoundaryKey := Key\.CopyText;/);
  assert.match(worker, /FreeAndNil\(Key\);\s+try LicenseState := FApi\.Redeem\(BoundaryKey\);\s+finally WipeText\(BoundaryKey\); end;/);
  assert.match(mailbox, /FPending := Key; Key := nil;/);
  assert.match(mailbox, /else if not FStopping then/);
  assert.match(mailbox, /FreeAndNil\(FPending\)/);
  for (const source of [worker, window, mailbox]) {
    assert.doesNotMatch(source, /AllocConsole|FreeConsole|SetConsole|ReadConsole|WriteConsole|WriteLn|OutputDebugString|MessageBox|ShowMessage|CozyUserErrorText/i);
    assert.doesNotMatch(source, /WriteAllText|SaveToFile|SetClipboardData|EmptyClipboard|FPendingKey: string|QueuedKey: string/i);
  }
  for (const name of ['Cozy.Console.pas', 'Cozy.Console.Commands.pas'])
    assert.equal(fs.existsSync(path.join(native, 'Cozy.Source/Cozy.Application', name)), false);
  assert.match(window, /State = WorkerFailed/);
  assert.match(window, /State = WorkerTransferred/);
});

test('Legacy error formatter returns no visible text, including unknown errors', () => {
  const source = stripComments(read('Cozy.Source/Cozy.Application/Cozy.UserErrors.pas'));
  const format = source.slice(source.lastIndexOf('function CozyUserErrorText('));
  assert.match(format, /begin\s+Result := '';\s+end;\s+end\./);
  assert.doesNotMatch(format, /case\s|CP-\d|\.Message/);
});

test('B authorizes after hidden GPU initialization, presents before input and joins before GPU/API retirement', () => {
  const source = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Session.pas'));
  const window = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Window.pas'));
  const entry = source.slice(source.lastIndexOf('function RunLicenseClient: Integer;'));
  assert(entry.indexOf('Context.CompleteClaimAndCleanup(') < entry.indexOf('RunLicenseWindow('));
  assert(entry.includes('Worker.StartChecks;'));
  assert(!entry.includes('Api.CheckIntegrity;'), 'initial measurement must run in the worker');
  const execute = source.split('procedure TLicenseWorker.Execute;')[1].split('function RunLicenseClient: Integer;')[0];
  assert.match(execute, /FApi\.CheckIntegrity;[\s\S]*?if FWatch <> nil then FWatch\.Start;[\s\S]*?InterlockedExchange\(FInitializationSucceeded, 1\);/);
  assert.match(execute, /finally\s+if FInitializedEvent <> 0 then SetEvent\(FInitializedEvent\);\s+end;\s+while/);
  const start = source.split('procedure TLicenseWorker.StartChecks;')[1].split('procedure TLicenseWorker.RequestStop;')[0];
  assert(start.includes('WaitForSingleObject(FInitializedEvent, 45000)'));
  assert(start.includes('InterlockedCompareExchange(FInitializationSucceeded, 0, 0) = 0'));
  const workerDestroy = source.split('destructor TLicenseWorker.Destroy;')[1].split('function TLicenseWorker.')[0];
  assert(workerDestroy.indexOf('inherited Destroy;') < workerDestroy.indexOf('FCommands.Free;'));
  assert(execute.includes('if FCommands <> nil then FCommands.Stop;'));


  const create = window.split('constructor TLicenseWindow.Create(')[1].split('destructor TLicenseWindow.Destroy;')[0];
  assert(create.indexOf('ImGuiCreate(FWindow, True)') < create.indexOf('SetMitigationGpuIdentity(ImGuiGpuIdentity(FContext))'));
  const run = window.split('function TLicenseWindow.Run(')[1].split('function RunLicenseWindow(')[0];
  assert(run.indexOf('BeforeShow();') < run.indexOf('ApiShowWindow(FWindow, SW_SHOW)'));
  assert.match(window, /FShown and FFocused and FVisibleFrame and \(FElapsed >= 0\.45\)/);
  assert.match(window, /FVisibleFrame := Presented = IMGUI_PRESENT_VISIBLE/);
  assert.match(window, /if Presented <> IMGUI_PRESENT_VISIBLE then Exit;/);
  const destroy = window.split('destructor TLicenseWindow.Destroy;')[1].split('procedure TLicenseWindow.RequireOwner;')[0];
  assert(destroy.indexOf('ApiShowWindow(FWindow, SW_HIDE)') < destroy.indexOf('FJoinWorker()'));
  assert(destroy.indexOf('FJoinWorker()') < destroy.indexOf('ImGuiDestroy(FContext)'));
  assert.match(entry, /begin\s+ShutdownGuard\.ArmAfter\(15000\);\s+Worker\.RequestStop;\s+end,/);
  assert.match(entry, /begin Worker\.StopAndJoin; end\)/);
  assert.match(run, /if FState\(\) = WorkerTransferred then Result := 0/);
  assert.match(entry, /if Api <> nil then Transferred := Api\.OverlayTransferred;\s+if Api <> nil then Api\.FlushNHWReports;\s+if Watch <> nil then SecurityStopped := SecurityStopped or Watch\.Confirmed;\s+if \(Api <> nil\) and SecurityStopped then Api\.FinishNHWStop;\s+if SecurityStopped then Result := 1\s+else if Transferred then Result := 0;/);
  assert.match(entry, /Watch\.RequestStop;\s+Watch\.StopChildObservers;\s+SecurityStopped := Watch\.Confirmed;/);
  assert(entry.indexOf('Worker.Free;') < entry.indexOf('Watch.RequestStop;'));
  assert(entry.indexOf('Watch.RequestStop;') < entry.indexOf('Api.FinishNHWStop;'));
  assert(entry.indexOf('Watch.StopChildObservers;') < entry.indexOf('Context.CleanupOwnImageForShutdown;'));
  assert(entry.indexOf('Api.FinishNHWStop;') < entry.indexOf('Api.RetireImagesForShutdown;'));
  assert(entry.indexOf('Context.CleanupOwnImageForShutdown;') < entry.indexOf('Watch.Free;'));
  assert(entry.indexOf('Bootstrap.Close;') < entry.indexOf('Watch.Free;'));
  assert(entry.indexOf('Api.Free;') < entry.indexOf('Watch.Free;'));
  assert(entry.indexOf('Worker.Free;') < entry.indexOf('Api.Free;'));
  assert(entry.indexOf('Worker.Free;') < entry.indexOf('Context.Free;'));
});
