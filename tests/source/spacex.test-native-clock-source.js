'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/spacex.native-string-contract");
// Source contracts only. Arithmetic is executed separately by ClockMathProbe.
// Actual Win64 QPC, suspend/resume, cancellation scheduling and A/B/O: NOT_RUN.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const root = path.resolve(__dirname, '../../../Desktop');
const read = p => ReadContractFile(path.join(root, p), 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
const clock = read('SpaceX.Source/SpaceX.Platform/SpaceX.Clock.pas');
const impl = clock.slice(clock.indexOf('\nimplementation\n'));
const wait = impl.slice(impl.indexOf('function SpaceXWaitForDelay('), impl.indexOf('procedure SpaceXPause('));
function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? files(path.join(dir, e.name)) : [path.join(dir, e.name)]);
}
test('owned production timing has one clock domain and no Sleep/GetTickCount calls', () => {
  for (const file of files(path.join(root, 'SpaceX.Source')).filter(p => p.endsWith('.pas'))) {
    const src = ReadContractFile(file, 'utf8');
    assert.doesNotMatch(src, /\b(?:GetTickCount(?:64)?|Sleep)\s*\(/, path.relative(root, file));
    assert.doesNotMatch(src, /BindApiPointer\([^\n]*(?:HASH_GetTickCount64|HASH_Sleep)/, path.relative(root, file));
  }
});
test('documented clock exports bind canonical addresses before pointer sealing', () => {
  const expected = ['CloseHandle', 'CreateEventW', 'GetLastError', 'QueryPerformanceCounter', 'QueryPerformanceFrequency', 'SetLastError', 'WaitForSingleObject'];
  assert.deepEqual([...clock.matchAll(/BindApiPointer\(ClockSlot_(\w+), RequireClockApi\('(\w+)'\)\)/g)].map(m => {
    assert.equal(m[1], m[2]); return m[1];
  }).sort(), expected);
  assert.match(clock, /Winapi\.Windows\.GetModuleHandleW\('kernel32\.dll'\)/);
  assert.match(clock, /Winapi\.Windows\.GetProcAddress\(Module, Name\)/);
  assert.match(clock, /uses Winapi\.Windows, SpaceX\.Api\.Pointer, SpaceX\.Platform\.ExportResolver, SpaceX\.Clock\.Math;/);
  assert.doesNotMatch(clock, /FreeLibrary|RDTSC|NtDelayExecution|RequireProcAddressHash|TStopwatch/);
});
test('delay cancellation is checked before expiry; every wait has a bounded recheck', () => {
  const cancelAt = wait.indexOf('if Assigned(Cancelled) and Cancelled() then Exit(False);');
  const remainingAt = wait.indexOf('SpaceXDeadlineRemaining(At, Deadline, 100)');
  const waitAt = wait.indexOf('Status := Wait(Handle, Slice);');
  assert.ok(cancelAt >= 0 && cancelAt < remainingAt && remainingAt < waitAt);
  assert.match(wait, /if Slice = 0 then Exit\(True\)/);
  assert.match(wait, /Status <> WAIT_TIMEOUT/);
  assert.match(wait, /finally WriteError\(SavedError\); end;/);
  assert.match(clock, /Deadline := SpaceXDeadlineAfter\(SpaceXTick, Milliseconds\)/);
});
test('copied worker clock callbacks share the production deadline domain', () => {
  for (const file of ['SpaceX.Identity/SpaceX.DeviceSignals.pas', 'SpaceX.Integrity/SpaceX.Measurement.pas']) {
    const src = read('SpaceX.Source/' + file);
    assert.match(src, /TSpaceXClockRead/);
    assert.match(src, /:= @SpaceXTick;/);
    assert.doesNotMatch(src, /Slot_Tick|TApiGetTickCount64/);
  }
});
test('worker join fallback borrows a wait handle before worker context ownership begins', () => {
  const src = read('SpaceX.Source/SpaceX.Crypto/SpaceX.Hashes.Workers.pas');
  const run = src.slice(src.indexOf('procedure ExecuteBlake3WorkersCancellable(', src.indexOf('\nimplementation')));
  assert.match(src, /Wait\(DelayHandle, 1\)/);
  assert.ok(run.indexOf('DelayHandle := THandle(SpaceXClockDelayHandle);') < run.indexOf('Handles[I] := Create('));
  assert.ok(run.indexOf('JoinWorker(Handles[I]') < run.lastIndexOf('FillChar(Workers'));
  assert.doesNotMatch(src, /Close\(DelayHandle\)|ReleaseHandle\(DelayHandle/);
});
test('absolute deadlines in internal handoff/socket probes use the shared clock', () => {
  for (const file of ['SpaceX.Handoff/SpaceX.HandoffPipeContracts.inc', 'SpaceX.Handoff/SpaceX.HandoffProcessContracts.inc', 'SpaceX.Network/SpaceX.RelaySocketContracts.inc']) {
    const src = read('SpaceX.Tests/' + file);
    assert.match(src, /SpaceXTick/);
    assert.doesNotMatch(src, /GetTickCount/);
  }
});
