'use strict';
// Source/lifetime wiring evidence only, never a replacement for Win64 probes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const railway = path.resolve(__dirname, '../../../Railway');
const read = file => fs.readFileSync(path.join(railway, file), 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
const own = read('Cozy.Source/Cozy.Integrity/Cozy.OwnMeasurement.pas');
const runtime = read('Cozy.Source/Cozy.Integrity/Cozy.OwnedRuntime.pas');
function routine(source, name) {
  const start = source.indexOf(name);
  assert.ok(start >= 0, name);
  const next = source.slice(start + name.length).search(/\n(?:procedure|function|constructor|destructor) /);
  return source.slice(start, next < 0 ? undefined : start + name.length + next);
}
assert.match(own, /OwnMeasurementContract = 'GAME-OWN-MEASUREMENT-BUNDLE-V3'/);
assert.match(own, /Bundle.Count <> 11/);
assert.match(own, /not OwnedRuntimeComplete\(Bundle.GetValue\('ownedGraph'\)\)/);
assert.match(own, /RuntimeBefore := Runtime.Capture/);
assert.match(own, /RuntimeAfter := Runtime.Capture/);
assert.match(own, /GraphBefore := CaptureApiPointerGraph/);
assert.match(own, /GraphAfter := CaptureApiPointerGraph/);
assert.match(own, /Code.MeasureBundle\(CodeDigest, CrcLayers, Budget\)/);
assert.match(own, /Coverage := 'PARTIAL'; Stable := False; GraphMeasured := False/);
assert.match(own, /FreeAndNil\(CrcLayers\); FreeAndNil\(RuntimeGraph\)/);
assert.match(own, /RuntimeGraph := OwnedRuntimeFailure\(RuntimeProfile, RuntimeReason\)/);
assert.match(own, /Allocation\/serialization failure[\s\S]*?Status:=msReadError;ImageDigest:=Default\(TImageDigest\)/);
assert.match(runtime, /FBindings\[I\]=Items\[I\]/);
assert.match(runtime, /Result.Nodes\[I-1\].Alive,'RUNTIME_OBJECT_RETIRED'/);
assert.match(runtime, /Inc\(S.Nodes\[I\].Generation\); AddChange\(Changes,Id,pcReregister\)/);
assert.match(runtime, /FHistory.Accept\(S,Changes\)/);
assert.doesNotMatch(runtime, /ReadProcessMemory|VirtualQuery|NtReadVirtualMemory|PByte\(.*FBindings|NativeUInt\(.*FBindings/);
for (const [file, cls, profile, image] of [
  ['Cozy.Application/Cozy.Bootstrap.pas', 'TBootstrapClient', 'rpBootstrapClient', 'FOwnImage'],
  ['Cozy.Platform/Cozy.Api.pas', 'TGameApi', 'rpLicenseApi', 'FImageIntegrity'],
  ['Cozy.Overlay/Cozy.Overlay.Client.pas', 'TOverlayClient', 'rpOverlayClient', 'FOwnImage'],
]) {
  const source = read('Cozy.Source/' + file);
  const constructor = routine(source, 'constructor ' + cls + '.Create');
  assert.ok(constructor.indexOf('FTransport := TConnectTransport.Create') < constructor.indexOf('FRuntimeGraph :='), cls + ' registers actual constructed transport');
  assert.ok(constructor.includes(`TCozyOwnedRuntimeGraph.Create(${profile}, Self, FGate, FTransport)`));
  const destroy = routine(source, 'destructor ' + cls + '.Destroy');
  assert.ok(destroy.indexOf('FGate.CloseAndWait') < destroy.indexOf('FRuntimeGraph.Close'), cls + ' drains active calls before retirement');
  assert.ok(destroy.indexOf('FRuntimeGraph.Close') < destroy.indexOf('FTransport.Free'), cls + ' retires while dependencies remain alive');
  const capture = routine(source, 'function ' + cls + '.OwnRuntime');
  assert.ok(capture.includes(`FRuntimeGraph.BindDependencies(Security, ${image}, CodeIntegrity)`));
  assert.match(capture, /CozyRuntimeBindings\(Self, FGate, FTransport, Security,/);
  assert.ok(capture.includes(image + ', CodeIntegrity)'));
  assert.ok((source.match(/OwnRuntime\(/g) || []).length >= 5, cls + ' forwards runtime scope to report, authority and server operation');
}
const api = read('Cozy.Source/Cozy.Platform/Cozy.Api.pas');
const retire = routine(api, 'procedure TGameApi.RetireImagesForShutdown');
assert.ok(retire.indexOf('RetireDependency(5)') < retire.indexOf('FreeAndNil(FImageIntegrity)'));
assert.ok(retire.indexOf('RetireDependency(6)') < retire.indexOf('FreeAndNil(FCodeIntegrity)'));
const overlayClient = read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas');
const retireOverlay = routine(overlayClient, 'procedure TOverlayClient.RetireOwnImageForShutdown');
assert.ok(retireOverlay.indexOf('FGate.CloseAndWait') < retireOverlay.indexOf('RetireDependency(5)'));
assert.match(retireOverlay, /finally FOwnImage := nil; end;/);
const overlay = read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas');
assert.ok(overlay.indexOf('Client.RetireOwnImageForShutdown') < overlay.indexOf('FreeAndNil(Image)'));
assert.match(read('Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas'), /CurrentImage, Code, CrcLayers, MeasurementState, Runtime\)/);
assert.match(read('Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas'), /end, OwnImage, Runtime\)/);
const completion = read('Cozy.Tests/Cozy.Integrity/Cozy.MeasurementCompletionProbe.dpr');
assert.match(completion, /for Fault:=omfFile to omfDeadline/);
assert.match(completion, /SINGLE_STAGE_FAILURE_CLEARS_ALL_DIGESTS/);
assert.match(completion, /SINGLE_STAGE_FAILURE_CLEARS_GRAPH_DIGESTS/);
assert.match(completion, /REAL_PRE_CANCELLED_BUDGET/);
assert.match(read('Cozy.Source/Cozy.Configuration/Cozy.Metadata.inc'), /\{\$IFDEF GAME_APPLICATION_BUILD\}[\s\S]*?\{\$IFDEF GAME_OWN_MEASUREMENT_TESTS\}\s+\{\$MESSAGE FATAL/);
const probe = read('Cozy.Tests/Cozy.Integrity/Cozy.OwnedRuntimeProbe.dpr');
for (const invariant of ['ACTUAL_FIELD_REPLACEMENT_REJECTED', 'FAILED_BIND_LEAVES_HISTORY_UNCHANGED', 'RETIRED_OBJECT_DISTINGUISHED', 'EXPLICIT_REREGISTRATION_ADVANCES_GENERATION', 'MID_MEASUREMENT_GENERATION_CHANGE_REJECTED', 'CLOSED_OWNER_CANNOT_MEASURE']) assert.ok(probe.includes(invariant));
console.log('OWN RUNTIME WIRING PASS: real client registration/retirement, strict V3 completion and failure disposal; native Windows compilation/execution NOT_RUN');
