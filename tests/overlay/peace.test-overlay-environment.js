'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const assert=require('node:assert/strict'),{Validate,Evaluate}=require("../../tools/overlay/peace.overlay-environment");
const nonce='1'.repeat(64),yes={physicalMonitors:true,unmodifiedRealInput:true,visualPositionAndHitAlignment:true};
function Measurement(){
 const rows=[];let clears=0;
 function add(msg=0,wp=0,dpi=96,monitor='0000000000000001',extra={}){const before=clears;if([8,0x2e0,0x7e,0x2b1].includes(msg))clears++;rows.push({kind:'message',seq:rows.length,tick:rows.length*100,msg,wparam:wp,dpi,windowDpi:dpi,monitor,left:0,top:0,right:320*dpi/96,bottom:160*dpi/96,workLeft:0,workTop:0,workRight:1920,workBottom:1080,clearCount:clears,clearBefore:before,dragging:false,buttonTracking:false,captureOwned:false,sessionPaused:false,sessionRegistered:true,suggestedMatches:true,...extra});}
 add();add(0x201,0,96,undefined,{x:40,y:60,hostButtonHit:true,captureOwned:true,buttonTracking:true});add(0x202,0,96,undefined,{x:40,y:60,hostButtonHit:true});add(0x201,0,96,undefined,{x:10,y:10,hostButtonHit:false,captureOwned:true,dragging:true});add(8);
 add(0x2e0,0,144,'0000000000000002');add(0x201,0,144,'0000000000000002',{x:60,y:90,hostButtonHit:true,captureOwned:true,buttonTracking:true});add(0x202,0,144,'0000000000000002',{x:60,y:90,hostButtonHit:true});add(0x201,0,144,'0000000000000002',{x:10,y:10,hostButtonHit:false,captureOwned:true,dragging:true});add(8,0,144,'0000000000000002');
 add(0x2b1,3,144,'0000000000000002');add(0x2b1,4,144,'0000000000000002',{sessionPaused:true});add(0x2b1,1,144,'0000000000000002');
 return {version:1,kind:'OVERLAY_ENVIRONMENT_MEASUREMENT',mode:'INTERACTIVE_WINDOW_MESSAGES',nonce,syntheticMessages:false,hardwareAttested:false,operatorFinished:true,events:rows};
}
const r=Measurement();assert.equal(Evaluate(r,yes,nonce).outcome,'PASS');assert.equal(Evaluate(r,{...yes,physicalMonitors:false},nonce).outcome,'INCOMPLETE');
assert.equal(Evaluate({...r,operatorFinished:false},yes,nonce).outcome,'INCOMPLETE');
assert.equal(Evaluate({...r,events:r.events.filter(x=>x.msg!==0x2b1).map((x,i)=>({...x,seq:i}))},yes,nonce).stages[2].outcome,'NOT_RUN');
for(const mutate of [x=>x.events[1].hostButtonHit=false,x=>x.events[4].captureOwned=true,x=>x.events[4].clearBefore=x.events[4].clearCount,x=>x.events[5].suggestedMatches=false,x=>x.events[5].windowDpi=96,x=>x.events[11].sessionPaused=false,x=>x.events[12].left=-2000]){const x=structuredClone(r);mutate(x);assert.equal(Evaluate(x,yes,nonce).outcome,'FAIL');}
assert.throws(()=>Validate({...r,syntheticMessages:true},nonce),/MEASUREMENT_INVALID/);assert.throws(()=>Validate(r,'2'.repeat(64)),/MEASUREMENT_INVALID/);
const invalid=structuredClone(r);invalid.events[2].seq=0;assert.throws(()=>Validate(invalid,nonce),/ROW_INVALID/);
const local=structuredClone(r);for(const e of local.events){e.monitor='0000000000000001';e.dpi=96;e.windowDpi=96;if(e.x===60){e.x=40;e.y=60;}}
assert.equal(Evaluate(local,yes,nonce).stages[0].outcome,'NOT_RUN');assert.equal(Evaluate(local,yes,nonce).stages[1].outcome,'NOT_RUN');
const unavailable=structuredClone(r);unavailable.events=unavailable.events.filter(x=>x.msg!==0x2b1).map((x,i)=>({...x,seq:i,sessionRegistered:false}));assert.equal(Evaluate(unavailable,yes,nonce).outcome,'INCOMPLETE');assert.equal(Evaluate(unavailable,yes,nonce).stages[2].outcome,'NOT_RUN');
const delayed=structuredClone(r);delayed.events[0].sessionRegistered=false;assert.equal(Evaluate(delayed,yes,nonce).outcome,'PASS');
const fs=require('node:fs'),path=require('node:path'),renderer=fs.readFileSync(path.join(MODULE_RESOURCE_ROOT,"../../Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas"),'utf8');
assert.doesNotMatch(renderer,/OVERLAY_SESSION_NOTIFY_FAILED/);
assert.match(renderer,/OptionalSystemProcAddressHash64\('wtsapi32\.dll', HASH_WTSRegisterSessionNotification\)/);
assert.doesNotMatch(renderer,/(?<!OptionalSystem)RequireProcAddressHash64\('wtsapi32\.dll'/);
const registration=renderer.slice(renderer.indexOf('procedure TOverlayWindow.TryRegisterSession;'),renderer.indexOf('procedure TOverlayWindow.UnregisterSession;'));
assert.match(registration,/FSessionRegistrationAttempts >= SessionRegistrationLimit/);assert.match(registration,/At - FSessionRegistrationTick < SessionRegistrationIntervalMS/);assert.match(registration,/not Slot_WTSRegisterSessionNotification.IsBound/);assert.match(registration,/not Slot_WTSUnRegisterSessionNotification.IsBound/);
assert.match(renderer,/SessionRegistrationLimit = 30/);assert.match(renderer,/SessionRegistrationIntervalMS = 1000/);assert.doesNotMatch(registration,/\b(?:Sleep|WaitForSingleObject|WaitForMultipleObjects)\s*\(/i);
assert.match(renderer,/if not AuthorityValid then Break;\s*TryRegisterSession;\s*ApiTranslateMessage/);
// Exercise the complete orchestration with an isolated synthetic child and
// temporary files. No Windows/GPU/physical measurement is claimed by this test.
const vm=require('node:vm'),os=require('node:os'),crypto=require('node:crypto');
const toolFile=path.join(MODULE_RESOURCE_ROOT,"../tools/overlay/peace.overlay-environment.js"),tool=fs.readFileSync(toolFile,'utf8'),toolRequire=require('node:module').createRequire(toolFile);
function RunHarness({measurement=Measurement(),afterSpawn,onConfirmation,error}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'overlay-environment-contract-'));
 try{
  const home=path.join(root,'Relay Server/tools');fs.mkdirSync(home,{recursive:true});
  const inputs=['Relay Server/maintenance/source-manifest.json',"Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas","Railway/Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr","Railway/Cozy.Projects/Cozy.Overlay/Cozy.Overlay.manifest"];
  for(const file of inputs){fs.mkdirSync(path.dirname(path.join(root,file)),{recursive:true});fs.writeFileSync(path.join(root,file),'original '+file);}
  const sourceHashes=Object.fromEntries(inputs.map(file=>[file,crypto.createHash('sha512').update(fs.readFileSync(path.join(root,file))).digest('hex')]));
  const probe=path.join(root,'cozy.OverlayEnvironmentProbe.exe'),pe=Buffer.alloc(512);
  pe.writeUInt16LE(0x5a4d,0);pe.writeUInt32LE(128,0x3c);pe.writeUInt32LE(0x4550,128);pe.writeUInt16LE(0x8664,132);pe.writeUInt16LE(0x20b,152);fs.writeFileSync(probe,pe);
  let input=Buffer.from('YES\nYES\nYES\n'),confirmed=false,spawned=0,copy;
  const fakeFs={...fs,readSync(fd,buffer,offset,length,position){
   if(fd!==0)return fs.readSync(fd,buffer,offset,length,position);
   if(!confirmed){confirmed=true;if(onConfirmation)onConfirmation({root,inputs,probe,copy});}
   if(!input.length)return 0;buffer[offset]=input[0];input=input.subarray(1);return 1;
  }};
  const fakeChild={spawnSync(exe,args){spawned++;copy=exe;assert.equal(args[0],'--interactive');
   fs.writeFileSync(args[2],JSON.stringify({...measurement,nonce:args[4]}));
   if(afterSpawn)afterSpawn({root,inputs,probe,copy});return {status:0,stdout:'synthetic child fixture\n',stderr:''};
  }};
  const fakeProcess={platform:'win32',arch:'x64',stdout:{write(){}},exitCode:undefined};
  const context={module:{exports:{}},require(name){if(name==='node:fs')return fakeFs;if(name==='node:child_process')return fakeChild;return toolRequire(name);},__dirname:path.join(home,'overlay'),__filename:path.join(home,'overlay','peace.overlay-environment.js'),Buffer,process:fakeProcess,console:{log(){},error(){}}};
  vm.runInNewContext(tool,context,{filename:'peace.overlay-environment.js'});
  if(error){assert.throws(()=>context.module.exports.Run(probe),error);assert.equal(fs.readdirSync(home).filter(f=>f.endsWith('.json')).length,0,'changed inputs must not produce a verification report');return;}
  const report=context.module.exports.Run(probe);
  assert.equal(spawned,1);assert.equal(report.sourceInputsUnchanged,true);assert.equal(report.probeUnchanged,true);
  assert.equal(report.sourceManifestSha512,sourceHashes[inputs[0]]);
  for(const file of inputs.slice(1))assert.equal(report.sourceFiles[file],sourceHashes[file]);
  assert.equal(report.hardwareAttested,false);assert.equal(Object.hasOwn(report,'ciEvidenceCreated'),false);assert.equal(report.publicationApproval,false);
  assert.equal(fs.readdirSync(home).filter(f=>f.endsWith('.json')).length,1);
  return {outcome:report.outcome,exitCode:fakeProcess.exitCode};
 }finally{fs.rmSync(root,{recursive:true,force:true});}
}
assert.deepEqual(RunHarness(),{outcome:'PASS',exitCode:0});
assert.deepEqual(RunHarness({measurement:{...Measurement(),operatorFinished:false}}),{outcome:'INCOMPLETE',exitCode:2});
const broken=Measurement();broken.events[4].captureOwned=true;
assert.deepEqual(RunHarness({measurement:broken}),{outcome:'FAIL',exitCode:1});
for(const index of [0,1,2,3])RunHarness({afterSpawn:({root,inputs})=>fs.appendFileSync(path.join(root,inputs[index]),' changed'),error:/OVERLAY_ENVIRONMENT_SOURCE_INPUTS_CHANGED/});
RunHarness({onConfirmation:({root,inputs})=>fs.unlinkSync(path.join(root,inputs[1])),error:/OVERLAY_ENVIRONMENT_SOURCE_INPUTS_CHANGED/});
RunHarness({onConfirmation:({probe})=>fs.appendFileSync(probe,' changed'),error:/OVERLAY_ENVIRONMENT_PROBE_CHANGED/});
RunHarness({onConfirmation:({copy})=>fs.unlinkSync(copy),error:/OVERLAY_ENVIRONMENT_PROBE_CHANGED/});
console.log('PASS overlay environment telemetry and orchestration contracts: DPI/hit-test/capture/RDP, exit status, before/after source/probe binding; actual Windows/GPU/physical checks NOT_RUN');
