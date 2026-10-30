'use strict';

// Cross-language data and source-boundary checks; NOT Delphi or Windows execution.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const policy = require('../../services/artifacts/peace.server-policy-protection');
const native = path.resolve(__dirname, '../../../Railway');
const read = name => fs.readFileSync(path.join(native, name), 'utf8').replaceAll('\r', '');
const engine = read('Cozy.Source/Cozy.Protection/Cozy.Protection.Engine.pas');
const launcher = read('Cozy.Source/Cozy.Application/Cozy.Launcher.pas');
const bootstrap = read('Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas');
const keyless = read('Cozy.Source/Cozy.Application/Cozy.KeylessBootstrap.pas');

test('Native initialized V2 slot is byte-identical to server public-only slot', () => {
  const include = read('Cozy.Source/Cozy.Protection/Cozy.Protection.Slot.inc');
  const bytes = Buffer.from([...include.matchAll(/\$([A-F0-9]{2})/g)].map(x => parseInt(x[1], 16)));
  assert.equal(bytes.length, 4096);
  assert.deepEqual(bytes, policy.CreateUnsealedSlot());
  assert.equal(crypto.createHash('sha512').update(bytes).digest('hex'),
    '2e0fa1e4d95750cab4b3e67512f5c53b7771432d5e67807ec21ed024ec7afc8beb02d14374d3a3521501db04c5f62a1abaf3c7f13e5521d835bb0788ced2f2ff');
  assert(bytes.subarray(40, 4080).every(x => x === 0));
});

test('Production parser has no VM interpreter or embedded-key decryption path', () => {
  assert.doesNotMatch(engine, /HandoffDecrypt|ConfigurationKey|ClientKey|OpenProgram|ExecuteFunction|EvaluateCozyProtection|CozyVmEvaluateBytecode/);
  assert.match(engine, /U16\(Slot, 16\) <> 2/);
  assert.match(engine, /for I := 136 to SlotTrailerAt - 1 do/);
  assert.match(engine, /'COZY-SERVER-POLICY-ID-V2' \+ #10/);
  assert.match(engine, /ExpectedID <> Result\.PolicyID/);
  assert.match(engine, /Digest := DeviceSHA256\(Bytes\)/);
  const reference = read('Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas');
  assert.match(reference, /function CozyVmEvaluateBytecode/);
  for (const name of ['Launcher', 'Client', 'Overlay']) {
    assert.doesNotMatch(read(`Cozy.Projects/Cozy.${name}/Cozy.${name}.dpr`), /VmReference/);
  }
});

test('A parses only public V3 fields with no launcher ticket or decrypt fallback', () => {
  assert.match(launcher, /Bytes := ReadVerifiedIssuedAConfig\(Handle, FileSize\(Info\)\)/);
  assert.ok(launcher.indexOf('ReadVerifiedIssuedAConfig(Handle') < launcher.indexOf('Result := ParsePublicConfig(Bytes)'));
  assert.match(launcher, /BinaryConfigMarker: AnsiString = 'COZYACF3'/);
  assert.match(launcher, /U16\(8\) <> 3/);
  assert.match(launcher, /ExpiryBytes := Field\(8, 8, 8\)/);
  assert.match(launcher, /if FieldCount = 9 then PinStateBytes := Field\(9, 1, 6144\)/);
  assert.match(launcher, /Result := ParsePublicConfig\(Bytes\)/);
  assert.doesNotMatch(launcher, /LauncherTicket|TicketBytes|CozyProtectionDecryptConfig|COZYACF2|COZYA2CONFIG/);
  assert.match(launcher, /Client\.BeginKeylessFlow\(/);
});

test('Native proof reconstructs the frozen canonical and bounds all approval waiting', () => {
  assert.match(keyless, /ApprovalBudgetMs = 300000/);
  assert.match(keyless, /RequestBudgetMs = 10000/);
  assert.match(keyless, /PollMilliseconds = 2000/);
  assert.match(keyless, /Clock := TStopwatch\.StartNew/);
  assert.match(keyless, /Left := ApprovalBudgetMs - ElapsedMs/);
  assert.match(keyless, /if Assigned\(Cancelled\) and Cancelled\(\)/);
  const expected = keyless.split("Expected := 'COZY-KEYLESS-BOOTSTRAP-V1'")[1].split('ValidateKeylessBinding(Canonical, Expected)')[0];
  const order = ['ChallengeID', 'Nonce', 'RequestID', 'LauncherID', 'LauncherSHA512', 'LauncherCRC64',
    'CodeSHA512', 'CodeCRC64', 'Security.MachineID', 'Security.DeviceID', 'PersistentKeyID', 'ProviderKind',
    'IntToStr(Epoch)', 'IntToStr(Revision)', 'IntToStr(ExpiresAt)'];
  let previous = -1;
  for (const value of order) { const at = expected.indexOf(value, previous + 1); assert(at > previous, value); previous = at; }
  assert(keyless.indexOf('ValidateKeylessBinding(Canonical, Expected);') < keyless.indexOf('AppSignature := Security.Sign(Canonical)'));
  assert.match(keyless, /PersistentSignature := Key\.Sign\(Canonical\)/);
  assert.match(keyless, /TPersistentDeviceKey\.Create\(Namespace, ProviderKind = 'PLATFORM'\)/);
  assert.doesNotMatch(keyless, /SaveToFile|WriteAllText|WriteAllBytes|TRegistry|ShellExecute|OutputDebugString|MessageBox/);
});

test('Approval is followed by new code measurement and atomic server begin, not a local grant', () => {
  const begin = bootstrap.split('function TBootstrapClient.BeginKeylessFlowCore(')[1].split('function TBootstrapClient.ChunkCore(')[0];
  const markers = ['WaitForKeylessApproval(', 'CurrentCode := CodeIntegrity.MeasureNow(',
    "raise EBootstrap.Create('COZY_KEYLESS_IMAGE_CHANGED')", "Data := Post('beginKeyless', Body)", 'EnsureDeviceIdentity('];
  let previous = -1;
  for (const value of markers) { const at = begin.indexOf(value, previous + 1); assert(at > previous, value); previous = at; }
  assert.doesNotMatch(bootstrap, /LauncherTicket|Post\('begin',/);
  assert.match(begin, /if \(Result\.FlowID <> ''\) and \(Result\.DownloadTicket <> ''\) then\s+try\s+AbortFlowCore\(Result\);/);
  assert.doesNotMatch(begin, /\bAbortFlow\(/);
  assert.match(begin, /Result\.ClearSecrets;\s+Result := Default\(TBootstrapFlow\);\s+FFlowStarted := 0;\s+raise;/);
});


test('Native actual approval path rechecks post-response cancellation and uses bounded jitter hints', () => {
  assert.match(keyless,/MinimumPollMilliseconds = 1000/);
  assert.match(keyless,/MaximumPollMilliseconds = 5000/);
  assert.match(keyless,/if Reply.GetValue\('pollAfterMs'\) <> nil then Hint := Number\(Reply, 'pollAfterMs'\)/);
  assert.match(keyless,/if Hint < MinimumPollMilliseconds then Hint := MinimumPollMilliseconds/);
  assert.match(keyless,/if Hint > MaximumPollMilliseconds then Hint := MaximumPollMilliseconds/);
  assert.match(keyless,/Cancelled\(\) then CancellationSeen := True/);
  const exchange=keyless.split('  function Exchange(Request: TJSONObject): TJSONObject;')[1].split('  function Proof(')[0];
  assert.match(exchange,/Transport.PostJSON\('bootstrap', Request, Remaining\);\s+Remaining;/);
  assert.match(keyless,/Status := ValidateKeylessDecision\(Reply, ChallengeID, ExpiresAt,/);
  assert.match(keyless,/if Left > 100 then Left := 100;\s+if Left > Budget then Left := Budget;/);
  const probe=read('Cozy.Tests/Cozy.Identity/Cozy.KeylessApprovalProbe.dpr');
  for(const name of ['ValidateKeylessBinding','ValidateKeylessDecision','KeylessApprovalRemaining'])assert(probe.includes(name+'('),name);
  assert(probe.includes('late approved after cancellation'));
  assert(probe.includes('other issued A challenge'));
  // This verifies wiring and probe coverage only, not Delphi execution.
});
