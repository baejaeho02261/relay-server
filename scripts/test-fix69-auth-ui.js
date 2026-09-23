'use strict';
// Architecture gates for the native authorization UI. These do not compile Delphi.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const dir = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const read = name => fs.readFileSync(path.join(dir, name), 'utf8').replace(/^\uFEFF/, '').replace(/\r/g, '');
const routine = (s, name) => {
  const rows = [...s.matchAll(/^(?:procedure|function)\s+([\w.]+)/gm)];
  const i = rows.findIndex(row => row[1] === name);
  assert.ok(i >= 0, name);
  return s.slice(rows[i].index, rows[i + 1]?.index ?? s.length);
};
const ui = read('MoaPlayApp.Ui.inc');
const steps = read('MoaPlayApp.AuthSteps.inc');
const permissions = read('MoaPlayApp.Permissions.inc');
const device = read('MoaPlayDeviceInfo.pas');
const startup = read('MoaPlayApp.Lifecycle.Startup.inc');
const notification = read('MoaPlayApp.Lifecycle.Notifications.inc');
const support = read('MoaPlayApp.Support.Permissions.inc');
const qr = read('MoaPlayApp.Protocol.Qr.inc');
const splash = read('MoaPlayApp.Splash.inc');
assert.match(ui, /FRoot\.Align := TAlignLayout\.Client/);
assert.doesNotMatch(ui, /Min\(480,.*ClientWidth|FRoot\.SetBounds/);
assert.match(routine(splash, 'TMoaPlayForm.UpdateSplash'), /FSplashPanel\.Visible := False/);
assert.doesNotMatch(startup, /GetTimeStamp < FSplashMinUntil|RequestNotificationPermissionOnce/);
assert.doesNotMatch(routine(support, 'TMoaPlayForm.UpdateAutomaticPermissions'), /RequestNotificationPermissionOnce|RequestSupportPhonePermission|RequestRequiredRuntimePermissions/);
assert.doesNotMatch(notification, /FNotifier\.RequestPermission/);
assert.doesNotMatch(qr, /RequestNotificationPermissionOnce/);
const retry = routine(permissions, 'TMoaPlayForm.PermissionRetryClick');
assert.match(retry, /not FPermissionPanel\.Visible then Exit/);
assert.match(retry, /SupportPhonePermissionPending/);
assert.equal((retry.match(/RequestRequiredRuntimePermissions;/g) || []).length, 1);
const batch = routine(device.slice(device.indexOf('implementation')), 'RequestRequiredRuntimePermissions');
// Explicit SDK branches avoid requesting unavailable platform permissions.
assert.match(batch, /SDK_INT < 26[\s\S]*READ_PHONE_STATE/);
assert.match(batch, /SDK_INT < 29[\s\S]*READ_PHONE_NUMBERS[\s\S]*READ_PHONE_STATE/);
assert.match(batch, /SDK_INT >= 33[\s\S]*POST_NOTIFICATIONS/);
assert.match(batch, /RequestResult\.Complete/);
assert.doesNotMatch(batch, /Self\.|TMoaPlayForm|FPermissionPanel/);
assert.match(steps, /FAuthStepLines\[I\]\.SetBounds/);
assert.match(steps, /FAuthDetailMode := 1/);
assert.match(steps, /FAuthDetailMode := 2/);
assert.match(qr, /FQrPanel\.Visible := FAuthDetailMode = 1/);
assert.match(routine(ui, 'TMoaPlayForm.ShowBiometricPanel'), /FBiometricPanel\.Visible := FAuthDetailMode = 2/);
assert.match(steps, /MemberTestEnterClick\(Sender\)/);
assert.match(steps, /if not PermissionsReady then Exit/);
assert.doesNotMatch(steps, /(?:LicenseAuthenticated|BiometricAuthenticated|FMemberTestGranted|FPermissionsServerGranted)\s*:=\s*True/i);
assert.match(routine(steps, 'TMoaPlayForm.CloseAuthDetail'), /FAuthDetailMode := 0/);
assert.match(routine(ui, 'TMoaPlayForm.SetCurrentScreen'), /if not FAuthStepsPanel\.Visible then[\s\S]*FAuthDetailBack\.Visible := False/);
assert.match(routine(steps, 'TMoaPlayForm.UpdateAuthSteps'), /if not AuthSurface or FReinstallBlocked or FReinstallProbe/);
const methods = read('MoaPlayApp.Methods.inc');
for (const name of ['BuildAuthStepsUI', 'ResizeAuthStepsUI', 'UpdateAuthSteps', 'AuthStepClick', 'AuthContinueClick', 'AuthDetailBackClick', 'CloseAuthDetail']) {
  assert.match(methods, new RegExp('(?:procedure|function)\\s+' + name + '\\b'));
  assert.match(steps, new RegExp('(?:procedure|function)\\s+TMoaPlayForm\\.' + name + '\\b'));
}
for (const name of ['MoaPlayApp.AuthSteps.inc', 'MoaPlayApp.Ui.inc', 'MoaPlayApp.Permissions.inc', 'MoaPlayDeviceInfo.pas']) {
  const b = fs.readFileSync(path.join(dir, name));
  assert.equal(b.subarray(0, 3).toString('hex'), 'efbbbf');
  assert.doesNotMatch(b.toString('utf8'), /(?<!\r)\n/);
}
console.log('FIX69 auth UI PASS: one user-owned permission batch, SDK branches, persistent steps, opt-in details/back, unchanged server gates, no startup progress/delay, full client width. Delphi/device execution not performed.');
