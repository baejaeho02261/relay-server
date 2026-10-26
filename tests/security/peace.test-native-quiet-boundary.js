'use strict';

// Source boundaries only: does not execute A/B/O or certify Windows behavior.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const native = path.resolve(__dirname, '../../../Railway');
const read = name => fs.readFileSync(path.join(native, name), 'utf8').replaceAll('\r', '');
const stripComments = source => source.replace(/\{[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\n]*/g, '');

test('Production A/B/O reject invalid invocation shapes before startup work and catch failures silently', () => {
  const cases = [
    ['Launcher', /if ParamCount = 0 then/, 'gcrLauncher', 'RunLauncher'],
    ['Client', /if \(ParamCount = 2\) and \(ParamStr\(1\) = '--game-handoff'\) then/, 'gcrConnect', 'RunGameConsole'],
    ['Overlay', /if \(ParamCount = 2\) and \(ParamStr\(1\) = '--game-overlay'\) then/, 'gcrOverlay', 'RunOverlay'],
  ];
  for (const [name, shape, role, run] of cases) {
    const source = stripComments(read(`Cozy.Projects/Cozy.${name}/Cozy.${name}.dpr`));
    const body = source.slice(source.lastIndexOf('\nbegin\n'));
    assert.match(body, /ExitCode := 1;/);
    const gate = body.search(shape), seal = body.indexOf('SealApiPointerStorage;');
    const startup = body.indexOf(`RequireNativeStartup(${role});`), application = body.indexOf(`ExitCode := ${run};`);
    assert(gate >= 0 && gate < seal && seal < startup && startup < application, name);
    assert.match(body, /except\s+ExitCode := 1;\s+end;/);
    assert.doesNotMatch(body, /MessageBox|ShowMessage|WriteLn|OutputDebugString|WriteConsole/i);
  }
});

test('B renders masked input only and has no path for failure text to reach its output', () => {
  const source = stripComments(read('Cozy.Source/Cozy.Application/Cozy.Console.pas'));
  const render = source.split('procedure TConsoleSession.RenderInput(')[1].split('procedure TConsoleSession.Tick;')[0];
  const tick = source.split('procedure TConsoleSession.Tick;')[1].split('function TConsoleSession.ReadKey(')[0];
  assert.match(render, /Display := StringOfChar\('\*', Length\(Value\)\);/);
  assert.doesNotMatch(render, /Display := Value|WriteText\(Value\)/);
  assert.equal((source.match(/\bWriteText\(Display\);/g) || []).length, 1);
  assert.doesNotMatch(tick, /WriteText|WriteConsole|CozyUserErrorText|\.Message/);
  assert.doesNotMatch(source, /FNotice|CozyUserErrorText|OutputDebugString|MessageBox|ShowMessage/i);
  assert.match(tick, /WorkerState = WorkerFailed/);
  assert.match(tick, /WorkerState = WorkerTransferred/);
  assert.match(source, /finally\s+WipeText\(Key\);/);
});

test('Legacy error formatter returns no visible text, including unknown errors', () => {
  const source = stripComments(read('Cozy.Source/Cozy.Application/Cozy.UserErrors.pas'));
  const format = source.slice(source.lastIndexOf('function CozyUserErrorText('));
  assert.match(format, /begin\s+Result := '';\s+end;\s+end\./);
  assert.doesNotMatch(format, /case\s|CP-\d|\.Message/);
});

test('Input remains behind real handoff and cleanup stays before resource release', () => {
  const source = stripComments(read('Cozy.Source/Cozy.Application/Cozy.Console.pas'));
  const entry = source.slice(source.lastIndexOf('function RunGameConsole: Integer;'));
  assert(entry.indexOf('Context.CompleteClaimAndCleanup(') < entry.indexOf('if not AllocConsole'));
  assert(entry.indexOf('Api.CheckIntegrity;') < entry.indexOf('if not AllocConsole'));
  assert(entry.indexOf('Console.Free;') < entry.indexOf('Api.Free;'));
  assert(entry.indexOf('Console.Free;') < entry.indexOf('Context.Free;'));
  assert.doesNotMatch(source, /WriteAllText|SaveToFile|SetClipboardData|EmptyClipboard/i);
});
