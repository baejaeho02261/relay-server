'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Operator measurements of the real test renderer, never CI/publication evidence.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process'),os=require('node:os');
const ROOT=path.resolve(MODULE_RESOURCE_ROOT,'../..');
const hash=bytes=>crypto.createHash('sha512').update(bytes).digest('hex');
function Read(file,max=16*1024*1024){const fd=fs.openSync(file,'r');try{const s=fs.fstatSync(fd);if(!s.isFile()||s.size<1||s.size>max)throw Error('OVERLAY_ENVIRONMENT_FILE_SIZE');return fs.readFileSync(fd);}finally{fs.closeSync(fd);}}
function Json(file){return JSON.parse(Read(file).toString('utf8').replace(/^\uFEFF/,''));}
function SourceSnapshot(){
 return {sourceManifestSha512:hash(Read(path.join(ROOT,'Relay Server/maintenance/source-manifest.json'))),sourceFiles:Object.fromEntries(["Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas","Railway/Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr","Railway/Cozy.Projects/Cozy.Overlay/Cozy.Overlay.manifest"].map(f=>[f,hash(Read(path.join(ROOT,f)))]))};
}
function Validate(raw,nonce){
 if(!raw||raw.version!==1||raw.kind!=='OVERLAY_ENVIRONMENT_MEASUREMENT'||raw.mode!=='INTERACTIVE_WINDOW_MESSAGES'||raw.nonce!==nonce||raw.syntheticMessages!==false||raw.hardwareAttested!==false||typeof raw.operatorFinished!=='boolean'||!Array.isArray(raw.events)||raw.events.length<1||raw.events.length>16000)throw Error('OVERLAY_ENVIRONMENT_MEASUREMENT_INVALID');
 let tick=-1,clears=-1;
 const bools=['dragging','buttonTracking','captureOwned','sessionPaused','sessionRegistered','suggestedMatches'];
 for(const [i,r] of raw.events.entries()){
  if(r.seq!==i||!Number.isSafeInteger(r.tick)||r.tick<tick||r.tick>1800000||!Number.isSafeInteger(r.msg)||!Number.isSafeInteger(r.wparam)||!Number.isSafeInteger(r.dpi)||r.dpi<48||r.dpi>768||!Number.isSafeInteger(r.windowDpi)||r.windowDpi<48||r.windowDpi>768||!Number.isSafeInteger(r.clearCount)||r.clearCount<clears||!Number.isSafeInteger(r.clearBefore)||r.clearBefore<0||r.clearBefore>r.clearCount||!/^[0-9A-F]{16}$/.test(r.monitor)||r.monitor==='0000000000000000'||bools.some(k=>typeof r[k]!=='boolean'))throw Error('OVERLAY_ENVIRONMENT_ROW_INVALID');
  for(const k of ['left','top','right','bottom','workLeft','workTop','workRight','workBottom'])if(!Number.isSafeInteger(r[k])||Math.abs(r[k])>1000000)throw Error('OVERLAY_ENVIRONMENT_RECT_INVALID');
  if(r.right<=r.left||r.bottom<=r.top||r.workRight<=r.workLeft||r.workBottom<=r.workTop)throw Error('OVERLAY_ENVIRONMENT_RECT_INVALID');
  if([0x201,0x202].includes(r.msg)&&(!Number.isInteger(r.x)||!Number.isInteger(r.y)||typeof r.hostButtonHit!=='boolean'))throw Error('OVERLAY_ENVIRONMENT_POINTER_INVALID');
  tick=r.tick;clears=r.clearCount;
 }
 return raw;
}
function Evaluate(raw,confirmation,nonce){
 Validate(raw,nonce);
 const errors=[],rows=raw.events;
 const inside=r=>r.left>=r.workLeft&&r.top>=r.workTop&&r.left<r.workRight&&r.top<r.workBottom;
 for(const r of rows){
  if(r.msg===0x2b1&&!r.sessionRegistered)errors.push('SESSION_MESSAGE_WITHOUT_NOTIFICATION_REGISTRATION');
  if(r.dpi!==r.windowDpi)errors.push('WINDOW_DPI_READBACK_MISMATCH');
  if([0x201,0x202].includes(r.msg)){
   const expected=r.x>=32*r.dpi/96&&r.x<288*r.dpi/96&&r.y>=52*r.dpi/96&&r.y<96*r.dpi/96;
   if(r.hostButtonHit!==expected)errors.push('INDEPENDENT_HIT_TEST_MISMATCH');
   if(r.msg===0x201&&!r.sessionPaused&&(!r.captureOwned||r.buttonTracking!==expected||r.dragging===expected))errors.push('POINTER_CAPTURE_STATE_MISMATCH');
  }
  const reset=r.msg===8||r.msg===0x2e0||r.msg===0x7e||r.msg===0x2b1;
  if(reset&&(r.clearCount<=r.clearBefore||r.dragging||r.buttonTracking||r.captureOwned))errors.push('INPUT_NOT_CLEARED_AFTER_TRANSITION');
  if(r.msg===0x2e0&&!r.suggestedMatches)errors.push('DPI_SUGGESTED_RECT_MISMATCH');
  if(r.msg===0x2b1&&[1,3,8].includes(r.wparam)&&(!inside(r)||r.sessionPaused))errors.push('SESSION_RESUME_POSITION_OR_STATE_INVALID');
  if(r.msg===0x2b1&&[2,4,6,7].includes(r.wparam)&&!r.sessionPaused)errors.push('SESSION_DISCONNECT_NOT_PAUSED');
 }
 // Physical monitor claims are limited to pre-RDP local samples and explicit
 // operator confirmation. HMONITOR counts alone do not prove physical hardware.
 const firstRemote=rows.findIndex(r=>r.msg===0x2b1&&[3,4].includes(r.wparam));
 const local=firstRemote<0?rows:rows.slice(0,firstRemote);
 const monitors=new Set(local.map(r=>r.monitor)),dpis=new Set(local.map(r=>r.dpi));
 const pointerMonitors=new Set(local.filter(r=>r.msg===0x201&&r.hostButtonHit).map(r=>r.monitor));
 const dragMonitors=new Set(local.filter(r=>r.msg===0x201&&!r.hostButtonHit&&r.dragging).map(r=>r.monitor));
 const didFocus=rows.some(r=>r.msg===8),didDpi=local.some(r=>r.msg===0x2e0&&r.suggestedMatches);
 let disconnected=-1,resumed=false;
 for(const [i,r] of rows.entries()){if(r.msg===0x2b1&&r.wparam===4)disconnected=i;else if(disconnected>=0&&r.msg===0x2b1&&[1,3].includes(r.wparam)&&i>disconnected)resumed=true;}
 const confirmed=confirmation?.physicalMonitors===true&&confirmation?.unmodifiedRealInput===true&&confirmation?.visualPositionAndHitAlignment===true;
 const complete=raw.operatorFinished&&confirmed;
 const registrationVerified=rows.some(r=>r.sessionRegistered)&&rows.filter(r=>r.msg===0x2b1).every(r=>r.sessionRegistered);
 const result=(id,ok,reason)=>({id,outcome:errors.length?'FAIL':complete&&ok?'PASS':'NOT_RUN',...(!complete||!ok?{reason}:{})});
 const stages=[
  result('physical-dpi-multi-monitor',monitors.size>=2&&pointerMonitors.size>=2&&dragMonitors.size>=2&&didFocus,'TWO_LOCAL_PHYSICAL_MONITORS_WITH_REAL_BUTTON_DRAG_FOCUS_CHECKS_REQUIRED'),
  result('mixed-dpi-monitor-move',monitors.size>=2&&dpis.size>=2&&didDpi&&didFocus,'TWO_DISTINCT_LOCAL_DPI_VALUES_AND_OS_DPI_CHANGE_REQUIRED'),
  result('rdp-disconnect-reconnect',resumed&&didFocus&&registrationVerified,'WTS_REGISTRATION_AND_REAL_REMOTE_DISCONNECT_THEN_CONNECT_OF_SAME_SESSION_REQUIRED')
 ];
 return {version:1,kind:'OVERLAY_ENVIRONMENT_VERIFICATION',evidenceType:'OPERATOR_RECORDED_LOCAL_MEASUREMENT',outcome:errors.length?'FAIL':stages.every(x=>x.outcome==='PASS')?'PASS':'INCOMPLETE',stages,errors:[...new Set(errors)],measured:{events:rows.length,localMonitors:monitors.size,localDpis:[...dpis].sort((a,b)=>a-b),buttonMonitors:pointerMonitors.size,dragMonitors:dragMonitors.size,remoteDisconnectThenResume:resumed},confirmation,hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false,scope:'Local operator observations plus independently checked renderer telemetry; prebuilt probe source/build identity is not attested.'};
}
function Ask(prompt){process.stdout.write(prompt+' [YES / NO]: ');let s='',b=Buffer.alloc(1);while(fs.readSync(0,b,0,1,null)){const c=b.toString();if(c==='\n')break;if(c!=='\r')s+=c;if(s.length>256)throw Error('OVERLAY_ENVIRONMENT_INPUT_TOO_LONG');}return s.trim().toUpperCase()==='YES';}
function Run(probe){
 if(process.platform!=='win32'||process.arch!=='x64')throw Error('OVERLAY_ENVIRONMENT_WINDOWS_X64_REQUIRED');
 if(!path.isAbsolute(probe))throw Error('OVERLAY_ENVIRONMENT_ABSOLUTE_PROBE_REQUIRED');
 const bytes=Read(probe,128*1024*1024);if(bytes.length<256||bytes.readUInt16LE(0)!==0x5a4d)throw Error('OVERLAY_ENVIRONMENT_WIN64_PE_REQUIRED');const pe=bytes.readUInt32LE(0x3c);if(pe>bytes.length-26||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664||bytes.readUInt16LE(pe+24)!==0x20b)throw Error('OVERLAY_ENVIRONMENT_WIN64_PE_REQUIRED');
 // Bind observations to the files selected before the interactive run. This
 // detects changed inputs; it does not attest how the prebuilt EXE was built.
 const sourceBefore=SourceSnapshot();
 const nonce=crypto.randomBytes(32).toString('hex'),runId='overlay-environment-'+new Date().toISOString().replace(/[:.]/g,'-')+'-'+nonce.slice(0,8),dir=path.join(MODULE_RESOURCE_ROOT,'overlay-environment-runs',runId);fs.mkdirSync(dir,{recursive:true});
 const copy=path.join(dir,'cozy.OverlayEnvironmentProbe.exe'),rawFile=path.join(dir,'measurement.json'),log=path.join(dir,'probe.log');fs.writeFileSync(copy,bytes,{flag:'wx'});
 const startedAt=new Date().toISOString();
 console.log('Build tests/cozy.manual-ide/cozy.OverlayEnvironmentProbe.dproj in RAD Studio Win64 Release first.');
 console.log('This workflow needs real local monitors with DIFFERENT scale settings and real RDP reconnect. No CI is required.');
 console.log('Window: click inside Injection, drag black background on EACH monitor, switch focus while holding input.');
 console.log('Perform the local monitor tests BEFORE connecting RDP. Return to same session. Release F6 for checkpoint, F10 to finish.');
 const child=cp.spawnSync(copy,['--interactive','--output',rawFile,'--nonce',nonce],{encoding:'utf8',timeout:31*60*1000,maxBuffer:8*1024*1024,windowsHide:false});fs.writeFileSync(log,(child.stdout||'')+(child.stderr||''),{flag:'wx'});
 if(child.error||child.status!==0||!fs.existsSync(rawFile))throw Error('OVERLAY_ENVIRONMENT_PROBE_FAILED_SEE_'+runId);
 const confirmation={physicalMonitors:Ask('Were at least TWO actual physical monitors used before RDP'),unmodifiedRealInput:Ask('Were real mouse/focus/RDP transitions used, without injected messages or simulated monitors'),visualPositionAndHitAlignment:Ask('Was the window visible on-screen with correct button/drag hit alignment and no stuck input after EVERY transition')};
 const raw=Json(rawFile),report=Evaluate(raw,confirmation,nonce);
 // Include the confirmation interval in both before/after input checks.
 let unchanged=false,sourceUnchanged=false;
 try{unchanged=hash(Read(probe,128*1024*1024))===hash(bytes)&&hash(Read(copy,128*1024*1024))===hash(bytes);}catch(_){}
 try{sourceUnchanged=JSON.stringify(SourceSnapshot())===JSON.stringify(sourceBefore);}catch(_){}
 if(!unchanged)throw Error('OVERLAY_ENVIRONMENT_PROBE_CHANGED');
 if(!sourceUnchanged)throw Error('OVERLAY_ENVIRONMENT_SOURCE_INPUTS_CHANGED');
 report.runId=runId;report.startedAt=startedAt;report.finishedAt=new Date().toISOString();report.platform='win32';report.architecture='x64';report.windowsRelease=os.release();report.buildProvenance='IDE_PREBUILT_INPUTS_NOT_ATTESTED';report.probeSha512=hash(bytes);report.measurementSha512=hash(Read(rawFile));report.probeUnchanged=unchanged;
 report.sourceManifestSha512=sourceBefore.sourceManifestSha512;report.sourceFiles=sourceBefore.sourceFiles;report.sourceInputsUnchanged=sourceUnchanged;
 const reportFile=path.join(MODULE_RESOURCE_ROOT,runId+'.json');fs.writeFileSync(reportFile,JSON.stringify(report,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({outcome:report.outcome,reportFile,measurementFile:rawFile,stages:report.stages,ciEvidenceCreated:false},null,2));process.exitCode=report.outcome==='PASS'?0:report.outcome==='INCOMPLETE'?2:1;return report;
}
if(require.main===module){try{const [action,probe]=process.argv.slice(2);if(action!=='run'||!probe||process.argv.length!==4)throw Error('Usage: node peace.overlay-environment.js run "ABSOLUTE_cozy.OverlayEnvironmentProbe.exe"');Run(probe);}catch(e){console.error(e.message);process.exitCode=1;}}
module.exports={Validate,Evaluate,Run};
