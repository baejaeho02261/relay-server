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
    ['Launcher', /if ParamCount = 0 then/, 'gcrLauncher', 'RunLauncher', 'ntsLauncher'],
    ['Client', /if \(ParamCount = 2\) and \(ParamStr\(1\) = '--game-handoff'\) then/, 'gcrConnect', 'RunLicenseClient', 'ntsClient'],
    ['Overlay', /if \(ParamCount = 2\) and \(ParamStr\(1\) = '--game-overlay'\) then/, 'gcrOverlay', 'RunOverlay', 'ntsOverlay'],
  ];
  for (const [name, shape, role, run, traceScope] of cases) {
    const source = stripComments(read(`Cozy.Projects/Cozy.${name}/Cozy.${name}.dpr`));
    const body = source.slice(source.lastIndexOf('\nbegin\n'));
    assert.match(body, /ExitCode := 31000;/);
    const gate = body.search(shape), seal = body.indexOf('SealApiPointerStorage;');
    const diagnostic = name === 'Client' ? ', @ExitCode' : '';
    const startup = body.indexOf(`RequireNativeStartup(${role}, @ExitCode);`), application = body.indexOf(`ExitCode := ${run}(TCozyNHWMonitor.Create(${traceScope})${diagnostic});`);
    assert(gate >= 0 && gate < seal && seal < startup && startup < application, name);
    assert.match(body, /except\s+end;/);
    assert.doesNotMatch(body, /MessageBox|ShowMessage|WriteLn|OutputDebugString|WriteConsole/i);
  }
});

test('B keeps the owned key private across focus changes and wipes its bounded frame copies', () => {
  const worker = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Session.pas'));
  const window = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Window.pas'));
  const mailbox = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Commands.pas'));
  const paint = window.split('procedure TLicenseWindow.Paint;')[1].split('function TLicenseWindow.Message(')[0];
  assert.match(paint, /if not FResetKeySequence and\s+\(Phase in \[0, 1, 2, LicensePhaseRejectScan, LicensePhaseRejected\]\) then\s+KeyCharacters := FKey\.Count;\s+if \(KeyCharacters > 0\) and WindowInputEnabled then\s+begin[\s\S]*?RevealedKey := FKey\.CopyText;\s+Actions := ImGuiLicenseSceneReveal\(FContext, ScenePhase, Length\(RevealedKey\),\s+Progress, PWideChar\(RevealedKey\), Length\(RevealedKey\)\);\s+finally\s+WipeBoundaryText\(RevealedKey\);\s+end;\s+end\s+else\s+Actions := ImGuiLicenseSceneReveal\(FContext, ScenePhase, KeyCharacters, Progress, nil, 0\);/);
  assert(paint.indexOf('WipeBoundaryText(RevealedKey);') < paint.indexOf('ImGuiEndCanvas(FContext);'));
  const cancel = window.split('procedure TLicenseWindow.CancelInput;')[1].split('procedure TLicenseWindow.ClearKey;')[0];
  assert.doesNotMatch(cancel, /FKey|ClearKey/);
  assert.match(window, /procedure TLicenseWindow\.Close;[\s\S]*?FClosing := True;\s+ClearKey;/);
  assert.doesNotMatch(window, /ImGuiTextInput|PAnsiChar\(.*Key/);
  assert.match(window, /Key.AppendBuffer\(FKey\);\s+FRedemptionPending := FSubmit\(Key\);/);
  assert.match(window, /finally\s+FreeAndNil\(Key\);/);
  assert.match(window, /if FKey <> nil then FKey\.Clear;/);
  assert.match(window, /MaximumKeyCharacters = 100/);
  assert.match(window, /MaximumClipboardCharacters = 4096/);
  assert.match(window, /if Last = Limit then Exit;/);
  assert.match(window, /else if Count <> 64 then Exit;/);
  assert.match(worker, /BoundaryKey := Key\.CopyText;/);
  assert.match(worker, /FreeAndNil\(Key\);\s+try\s+LicenseState := FApi\.Redeem\(BoundaryKey,\s+procedure\(Value: Integer\) begin FCommands\.ReportProgress\(Value\); end\);\s+finally WipeText\(BoundaryKey\); end;/);
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

test('NHW enforces only an authenticated and schema-valid Relay termination receipt', () => {
  const source = stripComments(read('Cozy.Source/Cozy.Protection/Cozy.NHW.Monitor.pas'));
  const capture = source.split('procedure TCozyNHWMonitor.Capture(')[1].split('procedure TCozyNHWMonitor.LatchTermination;')[0];
  assert.match(capture, /FPending := FPending \+ NewKinds;/);
  assert.match(capture, /FPendingConfirmed := FPendingConfirmed \+ \(Confirmed \* FPending\);/);
  assert.match(capture, /NowTick >= FReportAgainAt\[Kind\]/);
  assert.doesNotMatch(capture, /LatchTermination|FProtectiveStop|StopMonitoring|FStopHandler/);
  const report = source.split('procedure TCozyNHWMonitor.ReportInBackground;')[1];
  assert.match(report, /for Attempt := 1 to 2 do[\s\S]*?Transport\.PostJSON\('bootstrap', Body, AttemptBudget\)/);
  assert(report.indexOf('RequestID := BootstrapRequestID;') < report.indexOf('for Attempt := 1 to 2 do'));
  assert.match(report, /if not TJSONBool\(OK\)\.AsBoolean then Break;[\s\S]*?ValidateProtocolDocument\('nhwReport', Data\);\s+if TJSONBool\(Data\.GetValue\('terminate'\)\)\.AsBoolean then\s+begin\s+LatchTermination;/);
  assert.equal((source.match(/\bLatchTermination;/g) || []).length, 3);
  const latch = source.split('procedure TCozyNHWMonitor.LatchTermination;')[1].split('procedure TCozyNHWMonitor.ReportInBackground;')[0];
  assert.match(latch, /TInterlocked\.CompareExchange\(FProtectiveStop, 1, 0\) <> 0 then Exit;/);
  assert.match(latch, /StopMonitoring;\s+if Assigned\(StopHandler\) then/);
  assert.doesNotMatch(source, /WriteConsole|WriteLn|OutputDebugString|MessageBox|ShowMessage/i);
});

test('NHW corroborates only the scoped kinds in a fresh complete own-process frame', () => {
  const directory = 'Cozy.Source/Cozy.Protection/';
  const control = stripComments(read(directory + 'Cozy.NHW.FalsePositiveControl.pas'));
  const engine = stripComments(read(directory + 'Cozy.NHW.Engine.pas'));
  const monitor = stripComments(read(directory + 'Cozy.NHW.Monitor.pas'));
  const catalog = require('../../contracts/native-monitor/peace.nhw-detections-v1.json').detections;
  const declarations = control.split('const\n')[1].split('\ntype')[0];
  const affected = new Set(declarations.match(/\bdk\w+/g));
  assert.deepEqual(catalog.filter(({symbol}) => affected.has(symbol)).map(({id}) => id),
    [1, 9, 10, 13, 14, 15, 38, 58, 65, 66, 69, 70, 79, 80, 150, 167]);
  const rule = control.slice(control.lastIndexOf('function CorroborateNHWObservations(')).split('function IsV60Signal(')[0];
  assert.match(rule, /if not OwnCompleteFrame then Exit;[\s\S]*?if not ExecutionImpact and not \(dkWriteIntegrity in VerifiedImpact\) then Exit;/);
  assert.match(rule, /if ExecutionImpact then Result := Result \+ \(Observed \* NHWCorroboratedThreadKinds\);/);
  assert.match(rule, /if \(Observed \* \[dkTokenChange, dkDacl\]\) <> \[\] then\s+Result := Result \+ \(Observed \* NHWCorroboratedTokenKinds\);/);
  const cycle = engine.split('procedure RecordCycleEvidence;')[1].split('procedure FinalizeSamplingAndReport;')[0];
  assert.match(cycle, /Confirmed := \[\];\s+if Embedded and \(not NewMonitorBaseline\) and StableTarget and\s+\(LivePID = WinCurrentProcessId\) then[\s\S]*?\(dkWriteIntegrity in Detected\) and not WriteGuard\.ObservationFailed[\s\S]*?SensorConsensus\.Last\.Corroborated[\s\S]*?if CorrelationCoverageValid and Unified\.CurrentComplete and\s+\(Unified\.PrimaryRootCount >= 2\) then\s+Confirmed := Confirmed \+ CorroborateNHWObservations\(True, Detected, Confirmed\);/);
  const capture = monitor.split('procedure TCozyNHWMonitor.Capture(')[1].split('procedure TCozyNHWMonitor.LatchTermination;')[0];
  assert.match(capture, /Kind in \(Confirmed \* NHWCorroborationKinds\)\) and\s+\(NowTick >= FConfirmedAgainAt\[Kind\]\) then\s+begin\s+Include\(NewKinds, Kind\);/);
  assert(capture.indexOf('FConfirmedAgainAt[Kind]') < capture.indexOf('NowTick >= FReportAgainAt[Kind]'));
});

test('each role owns a distinct bounded optional NHW kernel logger during handoff', () => {
  const directory = 'Cozy.Source/Cozy.Protection/';
  const etw = read(directory + 'Cozy.NHW.ETW.pas');
  const engine = stripComments(read(directory + 'Cozy.NHW.Engine.pas'));
  const monitor = stripComments(read(directory + 'Cozy.NHW.Monitor.pas'));
  assert.match(monitor, /RunEmbedded\(FSensorStop, TraceScope,/);
  assert.match(engine, /KernelTrace := TETWMonitor\.Create\(TraceScope\);/);
  const names = etw.match(/TRACE_NAMES: array\[TNHWTraceScope\] of string = \(([\s\S]*?)\);/)[1];
  assert.equal(new Set(names.match(/'[^']+'/g)).size, 4);
  const roleGuids = ['LAUNCHER', 'CLIENT', 'OVERLAY'].map(role => {
    const scope = role[0] + role.slice(1).toLowerCase();
    assert.ok(etw.includes(`nts${scope}: FTraceGuid := GUID_${role};`));
    return etw.match(new RegExp(`GUID_${role}: TGUID = '([^']+)';`))[1];
  });
  assert.equal(new Set(roleGuids).size, 3);
  assert.match(etw, /FTraceName := TRACE_NAMES\[Scope\]/);
  assert.match(etw, /Props\^\.Wnode\.Guid := FTraceGuid;/);
  assert.match(etw, /EtwStartTrace\(FSession, PWideChar\(FTraceName\), Props\)[\s\S]*FLogger\.LoggerName := PWideChar\(FTraceName\)/);
  assert.match(etw, /if FSession <> 0 then[\s\S]*EtwControlTrace\(FSession, nil,\s*PEtwTraceProperties\(@FTraceProps\[0\]\), ETW_TRACE_CONTROL_STOP\)/);
});

test('B authorizes after hidden GPU initialization, presents before input and joins before GPU/API retirement', () => {
  const source = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Session.pas'));
  const window = stripComments(read('Cozy.Source/Cozy.License/Cozy.License.Window.pas'));
  const entry = source.slice(source.lastIndexOf('function RunLicenseClient(const Monitor: ICozyProtectionSession;'));
  assert(entry.indexOf('Context.CompleteClaimAndCleanup(') < entry.indexOf('RunLicenseWindow('));
  assert(entry.indexOf('Api.CheckIntegrity;') < entry.indexOf('Worker.StartChecks;'));
  const create = window.split('constructor TLicenseWindow.Create(')[1].split('destructor TLicenseWindow.Destroy;')[0];
  assert(create.indexOf('ImGuiCreate(FWindow, True)') < create.indexOf('SetMitigationGpuIdentity(ImGuiGpuIdentity(FContext))'));
  const run = window.split('function TLicenseWindow.Run(')[1].split('function RunLicenseWindow(')[0];
  assert(run.indexOf('BeforeShow();') < run.indexOf('ApiShowWindow(FWindow, SW_SHOW)'));
  const windowInput = window.split('function TLicenseWindow.WindowInputEnabled: Boolean;')[1].split('function TLicenseWindow.SceneInputEnabled: Boolean;')[0];
  assert.match(windowInput, /Result := not FClosing and FShown and FFocused and FVisibleFrame and\s+not FMinimized and not FResizePending;/);
  const sceneInput = window.split('function TLicenseWindow.SceneInputEnabled: Boolean;')[1].split('function TLicenseWindow.DragThresholdReached(')[0];
  assert.match(sceneInput, /if not WindowInputEnabled or FRedemptionPending or \(FOutcomePhase <> 0\) or\s+not Assigned\(FState\) then Exit;/);
  assert.match(sceneInput, /Result := State = WorkerIdle;/);
  assert.match(window, /FVisibleFrame := FShown and \(Presented = IMGUI_PRESENT_VISIBLE\)/);
  assert.match(window, /if not FVisibleFrame then\s+begin\s+CancelInput;\s+Exit;\s+end;/);
  const destroy = window.split('destructor TLicenseWindow.Destroy;')[1].split('procedure TLicenseWindow.RequireOwner;')[0];
  assert(destroy.indexOf('ApiShowWindow(FWindow, SW_HIDE)') < destroy.indexOf('FJoinWorker()'));
  assert(destroy.indexOf('FJoinWorker()') < destroy.indexOf('ImGuiDestroy(FContext)'));
  assert.match(entry, /begin Worker\.RequestStop; end,/);
  assert.match(entry, /begin Worker\.StopAndJoin; end,\s+function: Boolean\s+begin Result := Worker\.RequestLaunch; end,\s+Session\.ThemeIndex\)/);
  assert.match(run, /if FPresentationComplete and \(FState\(\) = WorkerTransferred\) then Result := 0/);
  assert.match(entry, /if Api <> nil then Transferred := Api\.OverlayTransferred;\s+if \(Result = 0\) and not Transferred then Result := 1;/);
  assert.doesNotMatch(entry, /if Transferred then Result := 0;/);
  assert(entry.indexOf('Worker.Free;') < entry.indexOf('Api.Free;'));
  assert(entry.indexOf('Worker.Free;') < entry.indexOf('Context.Free;'));
});
