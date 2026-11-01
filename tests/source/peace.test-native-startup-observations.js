'use strict';
// Source-contract evidence only. Windows role fixtures must actually be built
// and executed before reporting any native startup gate as PASS.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../../Railway');
const available = fs.existsSync(root);
const read = name => available ? fs.readFileSync(path.join(root, name), 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n') : '';
const startup = read('Cozy.Source/Cozy.Application/Cozy.Startup.pas');
const gate = startup.split('procedure RequireNativeStartup(Role: TGameComponentRole; FailureStage: PInteger);')[1] || '';
const capture = startup.split('function CaptureNativeStartupObservation(Role: TGameComponentRole): TNativeStartupObservation;').at(-1).split('function NativeStartupObservationComplete')[0];
const publish = (startup.split('procedure PublishStartupObservation')[1] || '').split('procedure SetApiContract')[0];
const checks = {skip: !available};
const roles = [['Cozy.Launcher', 'gcrLauncher', 'RunLauncher'], ['Cozy.Client', 'gcrConnect', 'RunGameConsole'], ['Cozy.Overlay', 'gcrOverlay', 'RunOverlay']];

test('actual product local gates retain their matching role before application work', checks, () => {
  for (const [name, role, run] of roles) {
    const source = read(`Cozy.Projects/${name}/${name}.dpr`);
    const body = source.slice(source.lastIndexOf('\nbegin\n'));
    const start = body.indexOf(`RequireNativeStartup(${role}`);
    assert(start >= 0 && start < body.indexOf(`ExitCode := ${run};`), name);
    assert.equal((body.match(/RequireNativeStartup\(/g) || []).length, 1);
    assert.doesNotMatch(body, /CaptureNativeStartupObservation|PublishStartupObservation|Writeln|WriteLn/);
  }
});

test('only successfully completed ABI/seal/API/resource/algorithm checks set flags', checks, () => {
  const ordered = [
    "Stage(31004);", "if not Win64ApiLayoutValid then", "STARTUP_ABI_INVALID", "Include(Observation.CompletedChecks, nscAbi);",
    "Stage(31005);", "if not ApiPointerStorageIsSealed then", "STARTUP_API_BINDINGS_INCOMPLETE", "Include(Observation.CompletedChecks, nscSealedPointers);",
    "Stage(31006);", "ValidateRoleApis(Role);", "Include(Observation.CompletedChecks, nscRoleApis);",
    "Stage(31007);", "ValidateRoleResources(Role);", "Include(Observation.CompletedChecks, nscRoleResources);",
    "Stage(31008);", "if not StartupAlgorithmsValid then", "STARTUP_ALGORITHM_SELF_TEST_FAILED", "Include(Observation.CompletedChecks, nscAlgorithms);",
    "Observation.FailureStage := 0; Observation.State := nssPassed;", "finally PublishStartupObservation(Observation); end;"
  ];
  let previous = -1;
  for (const token of ordered) { const next = gate.indexOf(token); assert(next > previous, token); previous = next; }
  assert.match(gate, /Observation := Default\(TNativeStartupObservation\);[\s\S]*Observation.State := nssFailed;/);
  assert.doesNotMatch(gate, /CaptureNativeStartupObservation|NativeStartupObservationComplete|except/);
});

test('observation uses one private atomic POD publication with no telemetry allocation', checks, () => {
  const publicPart = startup.split('\nimplementation\n')[0];
  assert.doesNotMatch(publicPart, /StartupObservations:|PublishStartupObservation/);
  assert.match(startup, /StartupObservations: array\[TGameComponentRole\] of Int64;/);
  assert.match(publish, /TInterlocked.Exchange\(StartupObservations\[Value.Role\], EncodedState\);/);
  assert.match(capture, /TInterlocked.CompareExchange\(StartupObservations\[Role\], Int64\(0\), Int64\(0\)\)/);
  assert.doesNotMatch(publish, /TMonitor|\.Create|GetMem|SetLength|WriteFile|\.Sign\(|PostJSON|Writeln|WriteLn/);
  assert.match(capture, /Result.CompletedChecks := \[\];/);
});

test('standalone algorithms cannot report unexecuted roles or incomplete local gates as PASS', checks, () => {
  const source = read('Cozy.Tests/Cozy.Startup/Cozy.StartupProbe.dpr');
  assert.match(source, /if not StartupAlgorithmsValid then/);
  assert.match(source, /STARTUP_API_BINDINGS_INCOMPLETE/);
  assert.match(source, /STARTUP_ROLE_API_CONTRACT_MISMATCH/);
  assert.match(source, /Observation.CompletedChecks = \[nscAbi\]/);
  assert.match(source, /Observation.CompletedChecks = \[nscAbi, nscSealedPointers\]/);
  assert.match(source, /CheckNotRun\(gcrConnect\); CheckNotRun\(gcrOverlay\);/);
  assert.match(source, /standalone A=FAILED, B\/O=NOT_RUN/);
  assert.match(source, /server authorization is NOT_RUN/);
});

function mappings(source) {
  return [...source.matchAll(/\b(Cozy\.[A-Za-z0-9_.]+)\s+in\s+'([^']+)'/g)].map(m => [m[1].toLowerCase(), m[2].toLowerCase()]).sort((a, b) => a[0].localeCompare(b[0]));
}
for (const [name, role] of roles) test(`${role} isolated fixture has exact product unit maps and original resources`, checks, () => {
  const product = read(`Cozy.Projects/${name}/${name}.dpr`);
  const fixturePath = `Cozy.Tests/Cozy.Startup/${name}StartupProbe.dpr`;
  const fixture = read(fixturePath);
  assert.deepEqual(mappings(fixture), mappings(product));
  for (const [, relative] of mappings(fixture)) {
    // Windows file names are case-insensitive; resolve against actual case from the DPR.
    assert(relative.startsWith('..\\..\\cozy.source\\'));
  }
  const expectedResource = path.resolve(root, `Cozy.Projects/${name}/${name}Resources.res`);
  const resource = fixture.match(/\{\$R '([^']+)'\}/)[1].replace(/\\/g, '/');
  assert.equal(path.resolve(root, path.dirname(fixturePath), resource), expectedResource);
  assert(fs.existsSync(expectedResource));
  assert.match(fixture, /\{\$IFNDEF GAME_STARTUP_ROLE_PROBE\}/);
  assert.doesNotMatch(fixture, /DEFINE GAME_APPLICATION_BUILD|ExitCode := RunLauncher|ExitCode := RunGameConsole|ExitCode := RunOverlay|RequireCozyProtection\(/);
  assert(fixture.includes(`RunStartupRoleProbe(${role});`));
  assert.match(read(`Cozy.Tests/Cozy.Startup/${name}StartupProbe.dproj`), /<TestOnlyDefine>GAME_STARTUP_ROLE_PROBE<\/TestOnlyDefine>/);
  const contract = read('Cozy.Tests/Cozy.Startup/Cozy.StartupRoleProbeContracts.inc');
  assert(contract.indexOf('SealApiPointerStorage;') < contract.indexOf('RequireNativeStartup(Role);'));
  assert(contract.indexOf('RequireNativeStartup(Role);') < contract.indexOf('NativeStartupObservationComplete(Observation), \'STARTUP_ROLE_GATE_INCOMPLETE\''));
  assert.match(contract, /STARTUP_OTHER_ROLE_NOT_RUN/);
});

test('source binding generator reviews every conditional and preserves native NOT_RUN scope', checks, () => {
  const generator = read('Cozy.Tests/Cozy.Startup/Cozy.generate-startup-contracts.py');
  assert.match(generator, /PRODUCTION_DISABLED = \{/);
  for (const define of ['COZY_HASH_WORKER_TESTS','GAME_DEVICE_SECURITY_TESTS','GAME_STARTUP_ROLE_PROBE','GAME_TRANSPORT_TESTS']) assert(generator.includes(`'${define}'`));
  assert.doesNotMatch(generator, /re\.fullmatch\(r'GAME_\.\*/);
  assert.match(generator, /raise ValueError\('Unknown production conditional '/);
  assert.match(read('Cozy.Tests/Cozy.Startup/Cozy.test-startup-contracts.py'), /Unknown production conditional GAME_UNREVIEWED_PROBE/);
});
