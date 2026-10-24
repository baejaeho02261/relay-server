'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// STATIC source contracts only. A separate .dpr is provided for an actual
// Windows/Delphi run. Never report these tests as a native executable result.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const native=name=>fs.readFileSync(path.resolve(MODULE_RESOURCE_ROOT,'../../Railway',name),'utf8').replace(/\r/g,'');
const own=native("Cozy.Source/Cozy.Integrity/Cozy.OwnMeasurement.pas");
test('native source: enum default and wire name are NOT_MEASURED',()=>{const s=native("Cozy.Source/Cozy.Integrity/Cozy.Measurement.pas");assert.match(s,/TMeasurementStatus\s*=\s*\(msNotMeasured,\s*msMeasured/);assert.match(s,/msNotMeasured: Result := 'NOT_MEASURED'/);});
test('native source: collector clears outputs before invoking measurement clock',()=>{const body=own.slice(own.lastIndexOf('function CollectOwnMeasurement'));assert(body.indexOf('Status := msNotMeasured')<body.indexOf('Started := MeasurementTick'));assert(body.indexOf('ImageDigest := Default')<body.indexOf('Started := MeasurementTick'));assert.match(body,/if Status = msMeasured then Coverage := 'FULL'[\s\S]*ImageDigest := Default/);});
test('native source: completion requires bounded digests, exact role names and complete metadata',()=>{for(const name of ['ecma182','nvme','jones','xz','we','iso','crc32c','crc16_arc','crc8_smbus'])assert(own.includes("'"+name+"'"));for(const fragment of ['DigestsComplete','Bundle.Count <> 9','Finished - Started > 60000',"IsText('coverage', 'FULL')", "GetValue('imageStable')"] )assert(own.includes(fragment));});
for(const [file,status]of [["Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas",'MeasurementState'],["Cozy.Source/Cozy.Platform/Cozy.Api.pas",'Status'],["Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas",'Failure'],["Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas",'Failure']])test('native source: '+file+' resets and checks collection result',()=>{const s=native(file),pos=s.indexOf('Bundle := CollectOwnMeasurement(');assert(pos>=0);const before=s.slice(Math.max(0,pos-400),pos),after=s.slice(pos,pos+1500);assert(before.includes(status+' := msNotMeasured'));assert(after.includes('OwnMeasurementComplete('));assert(after.includes('msCoverageInsufficient'));});
test('native source: unmodified managed record clearing uses Default, not unsafe FillChar',()=>{assert(!/FillChar\((ImageDigest|CodeDigest|Image|Code)/.test(own));assert.match(own,/function HexDigest/);});
test('native source: IDE probe exists, no production build test-hook enabled',()=>{const p=native("Cozy.Tests/Cozy.Integrity/Cozy.MeasurementCompletionProbe.dpr");assert(p.includes('DEFAULT_MUST_BE_NOT_MEASURED'));assert(!p.includes('DEFINE GAME_PRODUCT_FAULTS'));for(const name of ["Cozy.Projects/Cozy.Client/Cozy.Client.dproj","Cozy.Projects/Cozy.Launcher/Cozy.Launcher.dproj","Cozy.Projects/Cozy.Overlay/Cozy.Overlay.dproj"]){const full=path.resolve(MODULE_RESOURCE_ROOT,'../../Railway',name);if(fs.existsSync(full))assert(!fs.readFileSync(full,'utf8').includes('GAME_PRODUCT_FAULTS'));}});

// Regression for 2026-10-18 A abort: compare the producer and consumer, not
// only the presence of fail-closed keywords. Native execution remains separate.
const codeIntegrity=native("Cozy.Source/Cozy.Integrity/Cozy.CodeIntegrity.pas");
const allRoles=own.slice(own.indexOf('function AllRolesMeasured'),own.indexOf('function OwnMeasurementComplete',own.indexOf('implementation')));
const layerProducer=codeIntegrity.slice(codeIntegrity.indexOf('function TCodeIntegrity.MeasureCrcLayersCore'),codeIntegrity.indexOf('function TCodeIntegrity.MeasureNowCore'));
test('CRC producer and completion gate agree on string wire version CRC-LAYERS-V1',()=>{
 assert.match(layerProducer,/AddPair\('version', 'CRC-LAYERS-V1'\)/);
 assert.match(allRoles,/Value := Layers.GetValue\('version'\);[\s\S]*if not \(Value is TJSONString\) or \(Value.Value <> 'CRC-LAYERS-V1'\) then Exit;/);
 assert.doesNotMatch(allRoles,/Value is TJSONNumber/);
 assert.match(allRoles,/Layers.Count <> 10/);
 assert.match(allRoles,/Value.Value <> 'measured'/);
});
test('own bundle numeric version remains distinct from CRC string version',()=>{
 const check=own.slice(own.indexOf('function OwnMeasurementComplete',own.indexOf('implementation')),own.lastIndexOf('function CollectOwnMeasurement'));
 assert.match(check,/Value := Bundle.GetValue\('version'\);\s*if not \(Value is TJSONNumber\) or \(Value.Value <> '1'\) then Exit;/);
});
test('server accepts producer CRC wire version and rejects numeric or unknown versions',()=>{
 const crc=require("../../services/runtime/peace.desktop-crc-policy");
 const layers=require("../../services/integrity/peace.desktop-integrity").CodeImage(require("../fixtures/runtime/peace.crc-test-fixture").crcTestFixture()).crcLayers;
 assert.equal(layers.version,'CRC-LAYERS-V1');assert.equal(crc.Validate(layers),true);assert.equal(crc.Compare(layers,layers).complete,true);
 for(const version of [1,'1','CRC-LAYERS-V2',null])assert.equal(crc.Validate({...layers,version}),false);
});
test('server still rejects incomplete CRC roles as completed own measurement',()=>{
 const contract=require("../../services/integrity/peace.measurement-plan-contract");
 const layers=require("../../services/integrity/peace.desktop-integrity").CodeImage(require("../fixtures/runtime/peace.crc-test-fixture").crcTestFixture()).crcLayers;
 const meta={contract:contract.OWN_CONTRACT,version:1,startedTick:100,finishedTick:200,coverage:'FULL',fileStatus:'MEASURED',codeStatus:'MEASURED',crcStatus:'MEASURED',imageStable:true};
 assert.equal(contract.ValidateOwnMetadata(meta,'MEASURED',layers),true);
 for(const role of Object.keys(layers).filter(k=>k!=='version')){
  const bad=structuredClone(layers),previous=bad[role];
  bad[role]={algorithm:previous.algorithm,role:previous.role,status:'failed',reason:'READ_ERROR'};
  assert.equal(contract.ValidateOwnMetadata(meta,'MEASURED',bad),false,role);
  delete bad[role];assert.equal(contract.ValidateOwnMetadata(meta,'MEASURED',bad),false,role+' missing');
 }
});
test('Windows probe tests a positive live bundle and wrong-type/incomplete negatives',()=>{
 const probe=native("Cozy.Tests/Cozy.Integrity/Cozy.MeasurementCompletionProbe.dpr");
 for(const marker of ['LIVE_OWN_BUNDLE_MUST_COMPLETE','CRC_NUMERIC_VERSION_MUST_FAIL','CRC_STRING_ONE_MUST_FAIL','CRC_UNKNOWN_VERSION_MUST_FAIL','ALL_NINE_ROLE_FAILURES_MUST_FAIL','FAILED_PLAN_MUST_CLEAR_PREVIOUS_DIGESTS'])assert(probe.includes(marker));
 assert(probe.includes('TCodeIntegrity.Create(Input.Handle)'));assert(probe.includes('CollectOwnMeasurement(ImagePlan, CodePlan'));
});
