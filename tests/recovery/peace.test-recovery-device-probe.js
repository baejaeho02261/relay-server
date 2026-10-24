'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Source/build boundary contracts. This suite does not execute Windows, CNG,
// TPM or Delphi and must never be imported as native execution evidence.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(MODULE_RESOURCE_ROOT,'../..'),read=name=>fs.readFileSync(path.join(root,name),'utf8').replace(/^\uFEFF/,'').replace(/\r\n/g,'\n');
const key=read("Railway/Cozy.Source/Cozy.Identity/Cozy.DeviceKey.pas"),probe=read("Railway/Cozy.Tests/Cozy.Identity/Cozy.RecoveryDeviceProbe.dpr"),project=read("Railway/Cozy.Tests/Cozy.Identity/Cozy.RecoveryDeviceProbe.dproj"),metadata=read("Railway/Cozy.Source/Cozy.Configuration/Cozy.Metadata.inc");
const noComments=text=>text.replace(/\{(?!\$)[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\n]*/g,'');
let checks=0;
function test(fn){fn();checks++;}
function section(text,start,end){const from=text.indexOf(start),to=text.indexOf(end,from+start.length);assert(from>=0&&to>from,'missing bounded source section');return noComments(text.slice(from,to));}
test(()=>{
 assert.match(project,/<TestOnlyDefine>GAME_RECOVERY_DEVICE_PROBE<\/TestOnlyDefine>/);
 assert.match(project,/<Import Project="\.\.\\Cozy\.Build\\Cozy\.ManualProbe\.props"/);
 assert.match(probe,/\{\$IFNDEF GAME_RECOVERY_DEVICE_PROBE\}[\s\S]*?\{\$MESSAGE FATAL/);
 assert.match(probe,/\{\$IFDEF GAME_APPLICATION_BUILD\}[\s\S]*?\{\$MESSAGE FATAL/);
 for(const flag of ['GAME_RECOVERY_DEVICE_PROBE','GAME_DEVICE_KEY_PROBE'])assert(metadata.includes('{$IFDEF '+flag+'}'));
 for(const role of ["Cozy.Launcher","Cozy.Client","Cozy.Overlay"])assert(!read('Railway/Cozy.Projects/'+role+'/'+role+'.dproj').includes('GAME_RECOVERY_DEVICE_PROBE'));
 const group=read("Railway/Cozy.Tests/Cozy.Build/Cozy.ManualNativeTests.groupproj");assert(group.includes('Projects Include="..\\Cozy.Identity\\Cozy.RecoveryDeviceProbe.dproj"'));assert(group.includes(';Cozy.RecoveryDeviceProbe;'));
});
test(()=>{
 const ctor=section(key,'constructor TPersistentDeviceKey.OpenRecoveryProbe','function TPersistentDeviceKey.RecoveryProviderImplementation');
 assert(ctor.includes("FRecoveryKeyName:='cozy.Client.Device.V2.'+Namespace"));
 assert(ctor.includes("TCreateKey(DecodeApiPointer(CreateKeySlot))(FProvider,FKey,'RSA',PWideChar(FRecoveryKeyName),0,0)"));
 assert(!ctor.includes('NteExists'));assert(!ctor.includes('OpenNamedKey('));
 const existing=ctor.slice(ctor.indexOf(' end else begin'));assert(existing.includes('TOpenKey(DecodeApiPointer(OpenKeySlot))'));assert(!existing.includes('TCreateKey('));
 assert(ctor.indexOf('FRecoveryOwned:=True')>ctor.indexOf('Check(TCreateKey'));
 assert.match(ctor,/if FKey=0 then Invalid;\s*FRecoveryOwned:=True/);
});
test(()=>{
 const ctor=section(key,'constructor TPersistentDeviceKey.OpenRecoveryProbe','function TPersistentDeviceKey.RecoveryProviderImplementation');
 assert(ctor.includes("'Microsoft Platform Crypto Provider'"));assert(ctor.includes("'Microsoft Software Key Storage Provider'"));
 assert(ctor.includes("PropertyDword(FProvider,'Impl Type')"));assert(ctor.includes("PropertyDword(FProvider,'PCP_PLATFORM_TYPE')<>2"));
 assert(ctor.includes('(ImplFlags and 1)=0'));assert(ctor.includes('(ImplFlags and 2)=0'));
 assert(ctor.includes("SetDword(FKey,'Export Policy',0)"));assert(ctor.includes('if not ProbePrivateExportBlocked then'));
 const publicLoad=section(key,'procedure TPersistentDeviceKey.LoadPublicKey','constructor TPersistentDeviceKey.Create');
 assert(publicLoad.includes("PropertyDword(FKey,'Export Policy')<>0"));assert(publicLoad.includes("'RSAPUBLICBLOB'"));assert(!publicLoad.includes("'RSAPRIVATEBLOB'"));
});
test(()=>{
 const deletion=section(key,'procedure TPersistentDeviceKey.DeleteRecoveryProbeKey','{$IFDEF GAME_DEVICE_IDENTITY_PROBE}\n{$I ..\\..\\Cozy.Tests\\Cozy.Identity\\Cozy.DeviceKeyContracts.inc}');
 assert(deletion.indexOf('if not FRecoveryOwned or (FKey=0)')<deletion.indexOf('Check(TDelete('));
 assert(deletion.includes('FKey:=0;FRecoveryOwned:=False;'));
 assert(deletion.includes('Status:=TOpenKey('));assert(deletion.includes('RECOVERY_PROBE_KEY_STILL_PRESENT'));
 assert(deletion.includes('(Cardinal(Status)<>NteBadKeyset) and (Cardinal(Status)<>NteNotFound)'));
 const destructor=section(key,'destructor TPersistentDeviceKey.Destroy','function TPersistentDeviceKey.SignCore');
 assert(destructor.includes('if FRecoveryOwned and (FKey<>0) then'));
 assert(!noComments(probe).includes('Original.Delete'));assert(!noComments(probe).includes('Reopened.Delete'));
});
test(()=>{
 assert(probe.includes('Original := TPersistentDeviceKey.OpenRecoveryProbe(OriginalNamespace, Platform, False)'));
 assert(probe.includes('Original.PublicKey <> ExpectedPublicKey'));
 assert(probe.includes('ReplacementNamespace = OriginalNamespace'));
 assert(probe.includes('Replacement := TPersistentDeviceKey.OpenRecoveryProbe(ReplacementNamespace, Platform, True)'));
 assert(probe.includes('Replacement.PublicKey = ExpectedPublicKey'));
 assert(probe.includes('Reopened := TPersistentDeviceKey.OpenRecoveryProbe(OriginalNamespace, Platform, False)'));
 assert(probe.includes('Reopened.PublicKey <> ExpectedPublicKey'));
 assert(probe.includes("Answer.AddPair('originalKeyStillPresent', TJSONTrue.Create)"));
 assert(!probe.includes("AddPair('originalKeyDeleted', TJSONTrue.Create)"));
});
test(()=>{
 const run=section(probe,'procedure Run;','function SafeError');
 assert(run.indexOf('Replacement.DeleteRecoveryProbeKey;')<run.indexOf('DeletedReplacement := True;'));
 assert(run.includes("except CleanupStatus := 'FAILED'"));
 assert(run.includes("CleanupStatus := 'CONSTRUCTION_FAILED_UNKNOWN'"));
 assert(run.includes('if CreatedReplacement then Fail('));
 assert(run.includes('Key.CreateEvidence(Nonce)'));assert(run.includes('Key.Activate(Activation)'));assert(run.includes('Key.Sign(Canonical)'));
 assert(probe.includes("Answer.AddPair('hardwareAttested', TJSONFalse.Create)"));
});
test(()=>{
 assert(probe.includes('ParamCount <> 0'));assert(probe.includes('Length(Line) >= 32768'));
 assert(probe.includes('ParseProtocolObject(Line, 32768)'));assert(probe.includes('Count > 256'));
 assert(probe.includes("Number(Request, 'requestId') <> Count"));
 assert(probe.includes("Number(Request, 'version') <> 1"));
 assert(probe.includes("Fail('RECOVERY_PROBE_FIELD_INVALID')"));
 assert(probe.includes("Canonical := Text(Request, 'canonical', 16384)"));
 assert(probe.includes("Domain <> 'GAME-DEVICE-IDENTITY-V2'"));
 assert(probe.includes("Domain <> 'GAME-DEVICE-ACTIVATION-V2'"));
 assert(probe.includes("Domain <> 'GAME-RECOVERY-DRILL-ORIGINAL-V1'"));
 assert(probe.includes("Fail('RECOVERY_PROBE_RUN_BINDING_INVALID')"));
 assert(!noComments(probe).match(/NCryptImportKey|RSAPRIVATEBLOB|CreateFile|WriteAllText|ParamStr/));
});
test(()=>{
 assert(probe.includes('SealApiPointerStorage'));assert(probe.includes('if not ApiPointerStorageIsSealed'));
 assert(probe.includes("Error.AddPair('ok', TJSONFalse.Create)"));assert(probe.includes('ExitCode := 1'));
 assert(probe.includes('WipeText(Activation); WipeText(Secret)'));
 assert(probe.includes("Flush(System.Output)"));
});
console.log(JSON.stringify({suite:'RECOVERY_DEVICE_PROBE_SOURCE_CONTRACTS',checks,status:'PASS',nativeBuild:'NOT_RUN',windowsExecuted:false,hardwareAttested:false}));
