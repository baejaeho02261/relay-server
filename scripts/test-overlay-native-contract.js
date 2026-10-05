"use strict";
// Static release/ownership contracts. This does NOT compile or execute Delphi.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = path.resolve(__dirname, '../../GameConnect_Win64');
const read = file => fs.readFileSync(path.join(base, file), 'utf8');
const b = read('Game.Console.pas');
const entry = b.slice(b.lastIndexOf('function RunGameConsole: Integer;'));
const sequence = ['FreeAndNil(Console);', 'OfferData := Api.PrepareOverlay;',
  'DownloadOverlayBinary(', 'Bootstrap.OverlayFinish(', 'OverlayTransferred := True;',
  'FreeAndNil(Api);', 'FreeAndNil(Bootstrap);', 'Context.PrepareForNextHandoff;',
  'OverlayStarted := LaunchWithHandoff('];
let after = -1;
for (const step of sequence) {
  const at = entry.indexOf(step, after + 1);
  assert.ok(at > after, 'Missing or reordered B ownership boundary: ' + step);
  after = at;
}
assert.ok(b.includes('if State = WorkerActive then Break;'));
assert.ok(!b.includes('if FAuthenticated and not FStop then WaitForWorker(False)'));
const o = read('Game.Overlay.pas');
for (const required of ['THandoffContext.ReceiveFromCommandLine',
  'Bootstrap.OverlayClaim(', 'Context.CompleteClaimAndCleanup(',
  'FApi.CheckIntegrity;', 'FApi.ContinueModuleInventory', 'FApi.VerifyOverlay',
  'Worker.Free;', 'Bootstrap.Close;', 'RunOverlaySurface(@AwaitSurfaceSession',
  'Not intended for actual use.']) {
  assert.ok(o.includes(required), 'O contract missing: ' + required);
}
assert.ok(!/\b(?:Vcl|FMX)\./i.test(o));
const surface = read('Game.Overlay.Surface.pas');
assert.ok(surface.includes('AwaitReady(Context)'));
assert.ok(!/RegisterHotKey|UnregisterHotKey|GetAsyncKeyState|WM_HOTKEY|CloseChordPressed/.test(o + surface));
assert.ok(!/\b(?:ReadProcessMemory|WriteProcessMemory|CreateRemoteThread)\s*\(/i.test(o));
const api = read('Game.Api.pas');
assert.ok(api.includes("Body.AddPair('stage', FStage)"));
assert.ok(api.includes("const Stage: string = 'B'"));
assert.ok(api.includes("GAME-OVERLAY-FINISH-V1"));
assert.ok(api.includes("GAME-OVERLAY-CLAIM-V1"));
const bootstrap = read('Game.Bootstrap.pas');
assert.ok(bootstrap.includes("(Action = 'overlayClaim') then MaxAttempts := 2"));
assert.ok(bootstrap.includes("if FOverlaySession then Data := Post('overlayClose', Body)"));
for (const ext of ['dpr', 'dproj', 'manifest', 'rc']) {
  assert.ok(fs.existsSync(path.join(base, 'GameOverlay.' + ext)));
}
assert.ok(fs.existsSync(path.join(base, 'GameOverlayResources.res')));
console.log('Overlay native ownership/protocol source contracts passed (Windows build/runtime still required).');
