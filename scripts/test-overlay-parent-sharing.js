'use strict';
// Sharing regression for the native B -> O handoff. This models the Windows
// bidirectional CreateFile sharing rule; it does not replace a Windows run.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const handoff = fs.readFileSync(path.join(__dirname, '../../GameConnect_Win64/Game.Handoff.pas'), 'utf8');
const integrity = fs.readFileSync(path.join(__dirname, '../../GameConnect_Win64/Game.Integrity.pas'), 'utf8');
const consoleSource = fs.readFileSync(path.join(__dirname, '../../GameConnect_Win64/Game.Console.pas'), 'utf8');
const overlay = fs.readFileSync(path.join(__dirname, '../../GameConnect_Win64/Game.Overlay.pas'), 'utf8');
const openSafeImage = handoff.slice(handoff.indexOf('function OpenSafeImage('), handoff.indexOf('function SameIdentity('));
const READ = 1, WRITE = 2, DELETE = 4;
let checks = 0;
function check(name, fn) { fn(); checks++; console.log('PASS ' + name); }
function file(access, share) { return { access, share }; }
function canOpen(existing, next) {
  return existing.every(old => (next.access & ~old.share) === 0 && (old.access & ~next.share) === 0);
}
function safeImage(deletePermission = false, parentDeletePin = false) {
  assert.equal(deletePermission && parentDeletePin, false, 'parent sharing must never request DELETE');
  return file(READ | (deletePermission ? DELETE : 0), READ | (parentDeletePin ? DELETE : 0));
}
const bCleanup = safeImage(true);
// Integrity keeps a distinct read-only file object so closing the cleanup owner
// is its final file-object close. The cleanup owner remains the strict pin.
const bIntegrity = safeImage(false, true);
const bPins = [bCleanup, bIntegrity];

check('Native helper keeps default READ sharing and requires a read-only parent opt-in', () => {
  assert.match(openSafeImage, /AllowReadFallback: Boolean = False;\s*AllowPinnedDeleteRead: Boolean = False/);
  assert.match(openSafeImage, /Check\(not \(DeletePermission and AllowPinnedDeleteRead\)/);
  assert.match(openSafeImage, /Access := GENERIC_READ;/);
  assert.match(openSafeImage, /if DeletePermission then\s*Access := Access or DeleteAccess;/);
  assert.match(openSafeImage, /ShareMode := FILE_SHARE_READ;/);
  assert.match(openSafeImage, /if AllowPinnedDeleteRead then ShareMode := ShareMode or FILE_SHARE_DELETE;/);
  assert.doesNotMatch(openSafeImage, /FILE_SHARE_WRITE/);
  assert.equal((openSafeImage.match(/CreateFileW\(PWideChar\(Path\), (?:Access|GENERIC_READ), ShareMode,/g) || []).length, 2);
  assert.throws(() => safeImage(true, true), /parent sharing must never request DELETE/);
});

check('Three B-parent readers and the independent B integrity reader alone opt in', () => {
  const calls = [...handoff.matchAll(/:= OpenSafeImage\(([^;]+)\);/g)].map(match => match[1].trim());
  const optedIn = calls.filter(call => call.split(',').length === 5).sort();
  assert.deepEqual(optedIn, [
    'FBinaryPath, False, IntegrityInfo, False, True',
    'FLauncherPath, False, ParentInfo, False, True',
    'LauncherPath, False, LauncherInfo, False, PreserveParent',
    'Result.FLauncherPath, False, Info, False, OverlayRole'
  ].sort());
  assert(calls.includes('FBinaryPath, True, FinalBinaryInfo, True'));
  for (const call of calls.filter(call => !optedIn.includes(call))) assert(call.split(',').length <= 4);
  assert.match(handoff, /FBinaryCleanupFile := BinaryFile;/);
  assert.match(handoff, /FImageIntegrity := TImageIntegrity\.Create\(IntegrityFile, BinarySHA512, ExpectedCRC64\)/);
  assert.match(integrity, /DuplicateHandle\(GetCurrentProcess, Handle, GetCurrentProcess,\s*@FHandle, 0, False, DUPLICATE_SAME_ACCESS\)/);
});

check('Regression reproduced: original parent read conflicts with both retained B pins', () => {
  assert.equal(canOpen([bCleanup], safeImage()), false);
  assert.equal(canOpen(bPins, safeImage()), false);
  // Reproducing the former duplicate ownership: closing just one reference
  // would leave the DELETE file object and its sharing conflict alive.
  const originalIntegrityDuplicate = { ...bCleanup };
  assert.equal(canOpen([originalIntegrityDuplicate], safeImage()), false);
});

check('B parent readers coexist with cleanup and integrity pins throughout O handoff', () => {
  const parentReader = safeImage(false, true);
  assert.equal(canOpen(bPins, parentReader), true);
  assert.equal(canOpen([...bPins, parentReader], parentReader), true);
  assert.equal(canOpen([...bPins, parentReader, parentReader], parentReader), true);
});

check('Existing B pins still deny new write, delete, rename and replacement access', () => {
  const pins = [...bPins, safeImage(false, true)];
  for (const access of [WRITE, DELETE, WRITE | DELETE, READ | WRITE, READ | DELETE]) {
    // Even an attacker offering every share flag cannot override B's old pins.
    assert.equal(canOpen(pins, file(access, READ | WRITE | DELETE)), false);
  }
  assert.equal(canOpen([bCleanup, bIntegrity], file(DELETE, READ | WRITE | DELETE)), false);
  assert.equal(canOpen(pins, safeImage(false, true)), true);
});

check('A to B normal path and OS read-only fallback retain compatible strict pins', () => {
  const normalA = safeImage();
  assert.equal(canOpen([normalA], safeImage()), true);
  assert.equal(canOpen([normalA], file(WRITE, READ | WRITE | DELETE)), false);
  assert.equal(canOpen([normalA], file(DELETE, READ | WRITE | DELETE)), false);
  const fallbackB = safeImage();
  assert.equal(canOpen([fallbackB], safeImage(false, true)), true);
  assert.equal(canOpen([fallbackB, safeImage(false, true)], file(DELETE, READ | WRITE | DELETE)), false);
});

check('B cleanup follows authorized visible O readiness and retains same-handle identity checks', () => {
  const redeem = consoleSource.slice(consoleSource.indexOf('procedure TIntegrityWorker.RedeemPending'), consoleSource.indexOf('procedure TIntegrityWorker.Execute'));
  assert(redeem.indexOf('if not FApi.StartOverlay then') < redeem.indexOf('FHandoff.CleanupBinaryAfterLicense'));
  assert.match(handoff, /UnlinkVerifiedOwnImage\(FBinaryCleanupFile, FBinaryPath, BinarySHA512,\s*FBinaryCleanupInfo, False\)/);
  const complete = handoff.slice(handoff.indexOf('procedure THandoffContext.CompleteOverlayClaim'), handoff.indexOf('procedure THandoffContext.ConfirmOverlayReady'));
  assert.match(complete, /SameText\(HashHandle\(ParentFile\), LauncherSHA512\)/);
  assert.match(complete, /ParentInfo\.dwVolumeSerialNumber = FLauncherVolume/);
  assert.match(complete, /ParentInfo\.nFileIndexHigh = FLauncherIndexHigh/);
  assert.match(complete, /ParentInfo\.nFileIndexLow = FLauncherIndexLow/);
  assert.match(complete, /Close\(ParentFile\);/);
  assert(overlay.indexOf('Worker.StartAuthorized;') < overlay.indexOf('Result := RunOverlayUI('));
  assert(overlay.indexOf('Result := RunOverlayUI(') < overlay.indexOf('Context.ConfirmOverlayReady;'));
});

check('B owns distinct cleanup and integrity file objects without dropping its strict pin', () => {
  const claim = handoff.slice(handoff.indexOf('procedure THandoffContext.CompleteClaimAndCleanup('), handoff.indexOf('function THandoffContext.ParentIsAlive:'));
  const ownerOpen = claim.indexOf('BinaryFile := OpenSafeImage(FBinaryPath, True, FinalBinaryInfo, True);');
  const readerOpen = claim.indexOf('IntegrityFile := OpenSafeImage(FBinaryPath, False, IntegrityInfo, False, True);');
  const transfer = claim.indexOf('FBinaryCleanupFile := BinaryFile;');
  assert(ownerOpen >= 0 && ownerOpen < readerOpen && readerOpen < transfer);
  assert.doesNotMatch(claim.slice(ownerOpen, transfer), /Close\(BinaryFile\)/);
  assert.match(claim, /SameIdentity\(FinalBinaryInfo, IntegrityInfo\) and\s*SameText\(HashHandle\(IntegrityFile\), BinarySHA512\)/);
  assert.match(claim, /TImageIntegrity\.Create\(IntegrityFile, BinarySHA512, ExpectedCRC64\);\s*Close\(IntegrityFile\);/);
  assert.doesNotMatch(claim, /TImageIntegrity\.Create\(BinaryFile/);
  assert.equal(canOpen([bCleanup], bIntegrity), true);
  // A DuplicateHandle reference keeps FILE_OBJECT cleanup from occurring;
  // a second CreateFile object does not retain the deletion owner's object.
  const oldObject = { handles: 2 }, ownerObject = { handles: 1 }, readerObject = { handles: 1 };
  const closeFinalObjectHandle = object => --object.handles === 0;
  assert.equal(closeFinalObjectHandle(oldObject), false);
  assert.equal(closeFinalObjectHandle(ownerObject), true);
  assert.equal(readerObject.handles, 1);
});

check('Successful unlink closes its owner while OS refusal retains the strict owner pin', () => {
  const unlinkStart = handoff.indexOf('procedure UnlinkVerifiedOwnImage(');
  const unlink = handoff.slice(unlinkStart, handoff.indexOf('procedure RemoveOwnImage(', unlinkStart));
  const cleanup = handoff.slice(handoff.indexOf('procedure THandoffContext.CleanupBinaryAfterLicense;'), handoff.indexOf('function THandoffContext.TakeImageIntegrity:'));
  assert(unlink.indexOf('if not SetFileInfo(') < unlink.indexOf('    Exit;'));
  assert(unlink.indexOf('    Exit;') < unlink.indexOf('  Close(Handle);'));
  assert.doesNotMatch(cleanup, /Close\(FBinaryCleanupFile\)/);
  assert.match(handoff, /destructor THandoffContext\.Destroy;\s*begin\s*Close\(FBinaryCleanupFile\);/);
  assert.equal(canOpen([bCleanup, bIntegrity], file(DELETE, READ | WRITE | DELETE)), false);
  assert.equal(canOpen([bCleanup, bIntegrity], file(WRITE, READ | WRITE | DELETE)), false);
  // If Windows denied DELETE access initially, retaining the original read
  // owner still prevents delete/rename even though the reader shares delete.
  assert.equal(canOpen([safeImage(), bIntegrity], file(DELETE, READ | WRITE | DELETE)), false);
});

console.log(`${checks} overlay parent sharing checks passed (model/source contracts; Windows runtime not executed).`);
