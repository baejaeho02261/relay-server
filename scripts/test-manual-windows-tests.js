'use strict';
// Portable tooling contracts only: never claims a Windows executable ran here.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const t=require('../tools/manual-windows-tests'),root=path.resolve(__dirname,'../..');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'game-manual-contract-'));let checks=0;
const test=fn=>{fn();checks++;},save=(name,value)=>fs.writeFileSync(path.join(dir,name),JSON.stringify(value));
try{
 const valid={version:1,probeDirectory:dir,probes:{},artifacts:{},releaseVersion:'1.0.0',runIntegration:false};
 test(()=>assert.equal(t.Config(valid),valid));
 test(()=>assert.throws(()=>t.Config({...valid,privateKey:'secret'}),/MANUAL_INPUT_INVALID/));
 test(()=>assert.throws(()=>t.Config({...valid,probeDirectory:'relative'}),/ABSOLUTE_REQUIRED/));
 test(()=>assert.throws(()=>t.Config({...valid,probes:{unknown:path.join(dir,'x.exe')}}),/PROBE_PATH_INVALID/));
 test(()=>assert.throws(()=>t.Config({...valid,artifacts:{C:path.join(dir,'x.exe')}}),/ARTIFACT_PATH_INVALID/));
 test(()=>assert.throws(()=>t.Config({...valid,runIntegration:'true'}),/MANUAL_INPUT_INVALID/));
 test(()=>assert.throws(()=>t.Pe64(Buffer.alloc(256)),/PE_INVALID/));
 const pe=Buffer.alloc(512);pe.writeUInt16LE(0x5a4d,0);pe.writeUInt32LE(0x80,0x3c);pe.writeUInt32LE(0x4550,0x80);pe.writeUInt16LE(0x8664,0x84);pe.writeUInt16LE(0x20b,0x98);
 test(()=>t.Pe64(pe));
 const src=path.join(dir,'source.exe'),copy=path.join(dir,'copy.exe');fs.writeFileSync(src,pe);
 let row;test(()=>{row=t.Snapshot(src,copy);assert.match(row.beforeSha512,/^[a-f0-9]{128}$/);assert.equal(t.FinishHash(row).unchanged,true);});
 test(()=>{const changed=Buffer.from(pe);changed[300]=1;fs.writeFileSync(src,changed);assert.equal(t.FinishHash(row).unchanged,false);});
 test(()=>assert.equal(t.Evaluate({validator:'pass'},1,'PASS').outcome,'FAIL'));
 test(()=>assert.equal(t.Evaluate({validator:'pass'},0,'').outcome,'FAIL'));
 test(()=>assert.equal(t.Evaluate({validator:'pass'},0,'PASS first\nFAIL second').outcome,'FAIL'));
 test(()=>assert.equal(t.Evaluate({validator:'pass'},0,'PASS\nSKIP no privilege').outcome,'PARTIAL'));
 test(()=>assert.equal(t.Evaluate({validator:'hash-reference'},0,'{"status":"PASS","actualNativeExecuted":false}').outcome,'FAIL'));
 test(()=>assert.equal(t.Evaluate({validator:'hash-reference'},0,'{"status":"PASS","actualNativeExecuted":true}').outcome,'FAIL'));
 test(()=>{const r={status:'PASS',actualNativeExecuted:true,scope:'WINDOWS_PASCAL_WITH_EXPORTS',exportComparison:'PASS',hashCases:100,crcCases:100,exportCases:4,auxiliaryPeRangeComparison:'NOT_RUN'};assert.equal(t.Evaluate({validator:'hash-reference'},0,JSON.stringify(r)).outcome,'PASS');for(const k of ['exportComparison','exportCases','scope']){const bad={...r};delete bad[k];assert.equal(t.Evaluate({validator:'hash-reference'},0,JSON.stringify(bad)).outcome,'FAIL');}});
 test(()=>{const r={status:'PASS',cases:46,nativeExecutions:48,selectedRangeComparison:'PASS',nativeMappedImageComparison:'PASS',nativeDiskComparison:'PASS',independentRoles:require('./compare-native-crc-pe').ROLES};assert.equal(t.Evaluate({validator:'crc-pe-reference'},0,JSON.stringify(r)).outcome,'PASS');assert.equal(t.Evaluate({validator:'crc-pe-reference'},0,JSON.stringify({...r,nativeMappedImageComparison:'NOT_RUN'})).outcome,'FAIL');assert.equal(t.Evaluate({validator:'crc-pe-reference'},0,JSON.stringify({...r,independentRoles:Array(9).fill('ecma182')})).outcome,'FAIL');});
 test(()=>{
  // Serialized-result validation only: these objects are not execution evidence.
  const roles=require('./compare-native-crc-pe').ROLES,coverage=Object.fromEntries(roles.map(role=>[role,'measured'])),sha='a'.repeat(128);
  const stage={validator:'crc-pe-reference',requireFinalArtifacts:true,finalArtifactSha512:{}},r={status:'PASS',cases:46,nativeExecutions:48,selectedRangeComparison:'PASS',nativeMappedImageComparison:'PASS',nativeDiskComparison:'PASS',independentRoles:roles,finalArtifactComparison:'NOT_RUN',inputsUnchanged:true,inputs:{probe:{unchanged:true}},finalArtifacts:{}};
  assert.equal(t.Evaluate(stage,0,JSON.stringify(r)).outcome,'PARTIAL');
  for(const role of ['A','B','O']){stage.finalArtifactSha512[role]=sha;r.inputs[role]={beforeSha512:sha,unchanged:true};r.finalArtifacts[role]={selectionRole:role,coverage:{...coverage},nativeDiskComparison:'PASS'};}
  r.finalArtifactComparison='PASS';assert.equal(t.Evaluate(stage,0,JSON.stringify(r)).outcome,'PASS');
  for(const mutate of [x=>x.inputs.A.beforeSha512='b'.repeat(128),x=>x.inputs.probe.unchanged=false,x=>x.inputs.B.unchanged=false,x=>x.finalArtifacts.O.coverage.jones='unavailable',x=>delete x.finalArtifacts.A,x=>x.finalArtifactComparison='NOT_RUN']){const bad=structuredClone(r);mutate(bad);assert.equal(t.Evaluate(stage,0,JSON.stringify(bad)).outcome,'FAIL');}
 });
 test(()=>assert.equal(t.Evaluate({validator:'pe-reference'},0,'{"status":"PASS","nativeExecuted":false,"suite":"PE_CORPUS_V1"}').outcome,'FAIL'));
 test(()=>assert.equal(t.Evaluate({validator:'state-reference'},0,'{"status":"PASS","nativeExecuted":true}').outcome,'PASS'));
 test(()=>{const stage={validator:'independent-crc-reference'},result={status:'PASS',nativeCrcPrimitiveOutcome:'PASS',nativeCrcPrimitiveCompared:true,nativeCrcConstantsCompared:true};assert.equal(t.Evaluate(stage,0,JSON.stringify(result)).outcome,'PASS');for(const k of ['nativeCrcPrimitiveOutcome','nativeCrcPrimitiveCompared','nativeCrcConstantsCompared']){const bad={...result};delete bad[k];assert.equal(t.Evaluate(stage,0,JSON.stringify(bad)).outcome,'FAIL');}});
 test(()=>assert.throws(()=>t.Config({...valid,collectHardwareSignals:'true'}),/MANUAL_INPUT_INVALID/));
 test(()=>assert.equal(t.Evaluate({validator:'state'},0,'{"status":"PASS","stateChecks":35,"scheduleChecks":512,"observedTransitionMasks":[18,20,24,16,32,0],"gpuExecuted":false}').outcome,'FAIL'));
 test(()=>assert.equal(t.Evaluate({validator:'state'},0,'{"status":"PASS","stateChecks":36,"scheduleChecks":512,"observedTransitionMasks":[18,20,24,16,32,0],"gpuExecuted":false}').outcome,'PASS'));
 test(()=>assert.equal(t.Evaluate({validator:'abi-reference'},0,'{"match":true,"nativeExecuted":true,"fieldCount":103}').outcome,'FAIL'));
 test(()=>assert.throws(()=>t.Evaluate({validator:'abi'},0,'PASS'),/ABI_OUTPUT_FORMAT/));
 test(()=>assert.equal(t.Evaluate({validator:'integration'},0,'PASS',{outcome:'PASS'}).outcome,'FAIL'));
 const integration={outcome:'PASS',ready:true,licenseConsumed:true,overlayFirstFrame:true,parentTransferred:true,parentExited:true,parentFilesDeleted:true,overlayClosed:true,serverSessionClosed:true};
 test(()=>assert.equal(t.Evaluate({validator:'integration'},0,'',integration).outcome,'PASS'));
 const run=path.join(dir,'run'),priv=path.join(dir,'private');for(const p of [run,priv]){fs.mkdirSync(p);fs.writeFileSync(path.join(p,'ci-owned-marker'),'test');}
 const conf=path.join(dir,'input.json');fs.writeFileSync(conf,JSON.stringify(valid));
 let plan;test(()=>{plan=t.Prepare(conf,run,priv,process.execPath,'pwsh',false);assert(plan.stages.filter(x=>x.id!=='probe-build-output-contracts').every(x=>x.skip));assert.equal(plan.stages.find(x=>x.id==='probe-build-output-contracts').skip,undefined);assert.equal(plan.kind,'MANUAL_EXECUTION');assert.equal(plan.stages.find(x=>x.id==='abo-integration').skip,'OPERATOR_DID_NOT_SELECT_ISOLATED_ABO_EXECUTION');});
 test(()=>{
  const run2=path.join(dir,'run-finals'),priv2=path.join(dir,'private-finals');for(const p of [run2,priv2]){fs.mkdirSync(p);fs.writeFileSync(path.join(p,'ci-owned-marker'),'test');}
  const input=path.join(dir,'input-finals.json'),artifacts=Object.fromEntries(['A','B','O'].map(role=>[role,src]));
  fs.writeFileSync(input,JSON.stringify({...valid,probes:{CrcPeProbe:src},artifacts}));
  const p=t.Prepare(input,run2,priv2,process.execPath,'pwsh',false),stage=p.stages.find(x=>x.id==='independent-crc-pe');
  assert.equal(stage.skip,undefined);assert.equal(stage.requireFinalArtifacts,true);
  for(const role of ['A','B','O']){assert(stage.args.includes('--'+role.toLowerCase()));assert(stage.args.includes(p.inputs[role].executedCopy));assert.equal(stage.finalArtifactSha512[role],p.inputs[role].beforeSha512);assert.equal(t.FinishHash(p.inputs[role]).unchanged,true);}
  assert.equal(p.stages.find(x=>x.id==='abo-integration').skip,'OPERATOR_DID_NOT_SELECT_ISOLATED_ABO_EXECUTION');
 });
 fs.writeFileSync(path.join(run,'execution.json'),JSON.stringify({startedAt:'TEST',environment:{platform:'portable-test'},stages:[]}));
 test(()=>{const r=t.Finalize(run,path.join(dir,'result.json'));assert.equal(r.outcome,'INCOMPLETE');assert.equal(r.nativeBuild,'NOT_RUN');assert.equal(r.ciEvidenceCreated,false);assert.equal(r.hardwareAttested,false);assert.equal(r.publicationApproval,false);assert(r.stages.every(x=>x.outcome==='NOT_RUN'));});
 test(()=>{const p=JSON.parse(fs.readFileSync(path.join(run,'plan.json'),'utf8'));p.stages[p.stages.length-1].preparationError='MANUAL_ABO_RELEASE_BUILD_REQUIRED';fs.writeFileSync(path.join(run,'plan.json'),JSON.stringify(p));const r=t.Finalize(run,path.join(dir,'invalid-final-result.json'));assert.equal(r.outcome,'FAIL');assert.equal(r.stages.at(-1).outcome,'FAIL');});
 test(()=>{
  // Synthetic Windows-shaped report checks serialization only, not execution.
  const p=JSON.parse(fs.readFileSync(path.join(run,'plan.json'),'utf8'));
  p.environment={nodePlatform:'win32',nodeArchitecture:'x64'};
  p.inputs={A:row,B:row,O:row};
  fs.writeFileSync(path.join(run,'plan.json'),JSON.stringify(p));
  fs.writeFileSync(path.join(run,'execution.json'),JSON.stringify({startedAt:'2026-01-01T00:00:00.1234567Z',environment:{},stages:[]}));
  const first=t.Finalize(run,path.join(dir,'windows-shaped-1.json')),second=t.Finalize(run,path.join(dir,'windows-shaped-2.json'));
  assert.notEqual(first.publicVerificationFile,second.publicVerificationFile);
  const exported=JSON.parse(fs.readFileSync(first.publicVerificationFile,'utf8'));
  assert.equal(exported.startedAt,'2026-01-01T00:00:00.123Z');
  assert.equal(exported.publicationApproval,false);assert.equal(exported.hardwareAttested,false);
  assert(!JSON.stringify(exported).includes(dir));assert(!Object.hasOwn(first.environment,'nodePath'));assert(!first.stages.some(stage=>Object.hasOwn(stage,'log')));assert(!Object.hasOwn(first.inputs.A,'source'));assert(!Object.hasOwn(first.inputs.A,'executedCopy'));assert.equal(exported.stages.length,require('../services/desktopManualVerification').CURRENT_STAGES.length);
 });
 test(()=>{const ps=fs.readFileSync(path.join(root,'GameWeb/tools/manual-windows-tests.ps1'),'utf8'),bat=fs.readFileSync(path.join(root,'GameWeb/tools/Run_Manual_Windows_Tests.bat'),'utf8');assert(!/dcc64\.exe|msbuild\.exe|ci-evidence\.json|Run_Windows_CI/i.test(ps+bat));assert(ps.includes('WindowsJob]::Start'));assert(ps.includes('Get-CiEnvironment'));assert(ps.includes('MANUAL_PRIVATE_FIXTURE_CLEANUP_FAILED'));});
 test(()=>{const props=fs.readFileSync(path.join(root,'GameConnect_Win64/tests/manual-ide/ManualProbe.props'),'utf8');assert(props.includes('units\\$(ProjectName)\\$(Platform)\\$(Config)'));assert(!props.includes('GAME_APPLICATION_BUILD'));for(const name of t.PROBES.filter(x=>!['NativeAbiSdkProbe','OverlayGpuFaultProbe'].includes(x)))assert(fs.existsSync(path.join(root,'GameConnect_Win64/tests/manual-ide',name+'.dproj')),name);});
 console.log(JSON.stringify({suite:'MANUAL_WINDOWS_TOOL_CONTRACTS',checks,status:'PASS',windowsExecuted:false,nativeBuild:'NOT_RUN',ciEvidenceCreated:false}));
}finally{fs.rmSync(dir,{recursive:true,force:true});}
