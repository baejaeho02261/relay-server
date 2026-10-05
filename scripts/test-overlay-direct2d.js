'use strict';
// Source contracts only: a Win64 Delphi build and desktop rendering remain required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../GameConnect_Win64');
const file = path.join(root, 'Game.Overlay.Surface.pas');
const bytes = fs.readFileSync(file);
const source = bytes.toString('utf8');
const code = source.replace(/\{[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\n]*/g, '');
let checks = 0;
function check(name, fn) { fn(); checks++; console.log(`PASS ${name}`); }
check('Pascal encoding is UTF-8 BOM and CRLF', () => {
  assert.equal(bytes.subarray(0, 3).toString('hex'), 'efbbbf');
  assert.equal(source.replace(/\r\n/g, '').includes('\n'), false);
});
check('educational scope is explicit', () => {
  assert.match(source, /Educational demonstration only\. Not intended for actual use\./);
});
check('Direct2D and DirectWrite use the native Delphi unit', () => {
  assert.match(code, /Winapi\.D2D1/i);
  assert.match(code, /D2D1CreateFactory/);
  assert.match(code, /DWriteCreateFactory/);
  assert.doesNotMatch(code, /\b(?:Vcl|FMX)\.|\bTCanvas\b|Winapi\.DWrite/i);
});
check('no keyboard polling, hotkeys, hooks or keyboard event handlers', () => {
  assert.doesNotMatch(code, /\b(?:RegisterHotKey|UnregisterHotKey|GetAsyncKeyState|GetKeyState|SetWindowsHookEx\w*|TranslateAccelerator\w*)\b/i);
  assert.doesNotMatch(code, /\bWM_(?:HOTKEY|KEY\w*|SYSKEY\w*|CHAR|SYSCHAR)\b/);
});
check('opaque borderless native window without click-through', () => {
  assert.match(code, /CreateWindowExW\([\s\S]*?WS_POPUP/);
  assert.doesNotMatch(code, /\b(?:WS_CAPTION|WS_BORDER|WS_THICKFRAME|WS_EX_TRANSPARENT|WS_EX_LAYERED|SetLayeredWindowAttributes)\b/);
  assert.match(code, /pixelFormat\.alphaMode := D2D1_ALPHA_MODE_IGNORE/);
  assert.match(code, /Black := Color\(0, 0, 0\);\s*Mask[\s\S]*?Target\.Clear\(Black\)/);
});
check('exactly three named checkbox selection flags', () => {
  assert.match(code, /OptionCount = 3;/);
  assert.match(code, /\('Option 1', 'Option 2', 'Option 3'\)/);
  assert.match(code, /function OverlaySelectionMask: Cardinal;/);
  assert.match(code, /WM_LBUTTONUP:[\s\S]*?xor \(LongInt\(1\) shl Index\)/);
});
check('no GDI drawing or extra native controls', () => {
  assert.doesNotMatch(code, /\b(?:FillRect|FrameRect|TextOut\w*|DrawText(?:A|W)?|CreateFont\w*|CreatePen|CreateSolidBrush|BitBlt|StretchBlt|RoundRect|CreateDialog\w*)\s*\(/i);
  assert.equal((code.match(/CreateWindowExW\s*\(/g) || []).length, 1);
});
check('render target and label layouts are cached', () => {
  assert.match(code, /if State\.Target <> nil then Exit;/);
  assert.match(code, /State\.WriteFactory\.CreateTextLayout/);
  assert.match(code, /State\.Target\.DrawTextLayout/);
  const paint = code.slice(code.indexOf('procedure PaintSurface'), code.indexOf('procedure GetSurfaceBounds'));
  assert.doesNotMatch(paint, /CreateTextFormat|CreateTextLayout|CreateSolidColorBrush/);
});
check('device-loss handling releases target-owned brushes and bounds retries', () => {
  assert.match(code, /State\.Brush := nil;\s*State\.Target := nil;/);
  assert.match(code, /State\.RetryCount > RetryLimit/);
  assert.match(code, /Status = D2DERR_RECREATE_TARGET/);
});
check('DPI conversion and primary work area are explicit', () => {
  assert.match(code, /SPI_GETWORKAREA/);
  assert.match(code, /GetDpiForWindow/);
  assert.match(code, /WM_DPICHANGED/);
  assert.match(code, /96\.0 \/ State\.Dpi/);
});
check('hidden renderer initializes before worker authorization and visibility', () => {
  const run = code.slice(code.lastIndexOf('function RunOverlaySurface'));
  const create = run.indexOf('CreateTextResources(State)');
  const draw = run.indexOf('PaintSurface(State)');
  const ready = run.indexOf('AwaitReady(Context)');
  const visible = run.indexOf('ShowWindow(State.Window');
  assert.ok(create >= 0 && draw > create && ready > draw && visible > ready);
  assert.match(run, /if not AwaitReady\(Context\) or not IsAlive\(Context\) then Exit;/);
});
check('expired authorization returns failure and timer performs no idle redraw', () => {
  const timer = code.slice(code.indexOf('WM_TIMER:'), code.indexOf('WM_CLOSE:'));
  assert.match(timer, /not State\.IsAlive\(State\.Context\)[\s\S]*?State\.Failed := True;\s*DestroyWindow/);
  assert.match(timer, /else if State\.RetryPending/);
  assert.doesNotMatch(timer, /Game\.Api|VerifyOverlay|CheckIntegrity|BeginDraw|PaintSurface/);
});
check('native window callback catches exceptions before dispatcher boundary', () => {
  const proc = code.slice(code.indexOf('function SurfaceWindowProc'), code.lastIndexOf('function RunOverlaySurface'));
  assert.match(proc, /except\s*State\.Failed := True;\s*PostQuitMessage\(1\);/);
});
console.log(`Direct2D overlay source contracts: ${checks} passed (native execution not tested).`);
