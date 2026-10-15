'use strict';
// Runs existing IDE-built probes only. Does not build A/B/O, request keys,
// create CI evidence or change a server/process outside these test children.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),cp=require('node:child_process');
const contract=require('../services/desktopMitigationCompatibility'),read=require('./manual-release-check').read;
const hash=b=>crypto.createHash('sha512').update(b).digest('hex');
function Pe64(b){if(b.length<256||b.readUInt16LE(0)!==0x5a4d)throw Error('MITIGATION_WIN64_PE_REQUIRED');const pe=b.readUInt32LE(60);if(pe>b.length-26||b.readUInt32LE(pe)!==0x4550||b.readUInt16LE(pe+4)!==0x8664||b.readUInt16LE(pe+24)!==0x20b)throw Error('MITIGATION_WIN64_PE_REQUIRED');}
function ParseNative(log,mode,scope){
 const rows=log.split(/\r?\n/).filter(x=>x.startsWith('{'));if(rows.length!==1)throw Error('MITIGATION_NATIVE_REPORT_INVALID');
 const r=require('../services/strictJson').Parse(rows[0],{maxBytes:16384,maxNodes:2048,maxDepth:8});return contract.NativeResult(r,mode,scope);
}
function Execute(exe,probeSha512,mode,componentScope,{spawn=cp.spawnSync}={}){
 if(!exe)return {row:{mode,componentScope,probeSha512:null,executed:false,exitCode:null,status:'NOT_RUN',reason:'PROBE_MISSING',logSha512:hash('PROBE_MISSING\n'),result:null},log:'PROBE_MISSING\n'};
 const args=['--report',...(mode==='prohibit'?['--prohibit']:[])];
 const r=spawn(exe,args,{encoding:'utf8',timeout:25000,maxBuffer:1024*1024,windowsHide:false,shell:false});
 const log=String(r.stdout||'')+String(r.stderr||'')+(r.error?'\nPROBE_EXECUTION_FAILED\n':'');
 let result=null,reason='';try{result=ParseNative(log,mode,componentScope);}catch(_){reason='NATIVE_REPORT_INVALID';}
 if(r.error)reason='PROBE_EXECUTION_FAILED';
 else if(result?.policyReadback==='PASS'&&(componentScope==='AB'||result.renderer==='PASS')&&/^\s*(?:FAIL(?:ED)?\b|ERROR(?:\b|:))/m.test(log))reason='NATIVE_COMPATIBILITY_FAILURE';
 const code=Number.isInteger(r.status)?r.status<0?r.status>>>0:r.status:null;
 const row={mode,componentScope,probeSha512,executed:true,exitCode:code,status:'FAIL',reason,logSha512:hash(log),result};
 row.status=contract.Outcome(row);if(row.status==='PASS')row.reason='';else if(!row.reason)row.reason='NATIVE_COMPATIBILITY_FAILURE';
 return {row,log};
}
function Snapshot(file,destination){const b=read(file);Pe64(b);fs.writeFileSync(destination,b,{flag:'wx',mode:0o700});return{file,destination,sha512:hash(b)};}
function Unchanged(s){try{return hash(read(s.file))===s.sha512&&hash(read(s.destination))===s.sha512;}catch(_){return false;}}
async function Select(args,home){
 if(args.length!==0&&args.length!==5)throw Error('MITIGATION_ARGUMENTS_INVALID');
 if(args.length)return args.map(x=>path.resolve(x));
 const rl=require('node:readline').createInterface({input:process.stdin,output:process.stdout});
 // readline's callback is a value rather than an error-first callback.
 const question=text=>new Promise(resolve=>rl.question(text,resolve));
 try{
  console.log('IDE probe folder: '+path.resolve(home,'../../GameConnect_Win64/tests/manual-ide/bin'));
  const selections=[];for(const label of ['A final EXE','B final EXE','O final EXE','ProcessMitigationProfileProbe.exe','OverlayMitigationProbe.exe']){const value=(await question(label+' absolute path: ')).trim().replace(/^"(.*)"$/,'$1');if(!value||!path.isAbsolute(value))throw Error('MITIGATION_ABSOLUTE_PATH_REQUIRED');selections.push(value);}return selections;
 }finally{rl.close();}
}
async function Main(args,home=__dirname){
 if(process.platform!=='win32'||process.arch!=='x64')throw Error('MITIGATION_ACTUAL_WINDOWS_X64_REQUIRED');
 if(args.includes('--help')){console.log('Run_Mitigation_Compatibility.bat [A.exe B.exe O.exe ProcessMitigationProfileProbe.exe OverlayMitigationProbe.exe]');return;}
 const files=await Select(args,home),startedAt=new Date().toISOString(),runId='mitigation-'+startedAt.replace(/[:.]/g,'-')+'-'+crypto.randomBytes(4).toString('hex');
 const source=require('./manual-release-check').inventory(home).sourceManifestSha512;
 const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'Game-Mitigation-'));let snapshots=[];
 try{
  const artifacts={},probes={},roles=['A','B','O'];
  for(const [i,role]of roles.entries()){
   const s=Snapshot(files[i],path.join(scratch,role+'.exe'));snapshots.push(s);if(require('../services/peBuildConfiguration').HasProductFaultMarker(read(s.destination)))throw Error('SECURITY_TEST_BUILD_NOT_PUBLISHABLE');if(require('../services/peBuildConfiguration').ReadBuildConfiguration(read(s.destination)).configuration!=='RELEASE')throw Error('MITIGATION_FINAL_RELEASE_REQUIRED');artifacts[role]={sha512:s.sha512,unchanged:true};
  }
  const native={};for(const [i,scope]of ['AB','O'].entries()){
   const file=files[i+3];if(!fs.existsSync(file)){probes[scope]={sha512:null,unchanged:false};continue;}
   const s=Snapshot(file,path.join(scratch,scope==='O'?'OverlayMitigationProbe.exe':'ProcessMitigationProfileProbe.exe'));snapshots.push(s);native[scope]=s;probes[scope]={sha512:s.sha512,unchanged:true};
  }
  const rows=[];for(const mode of ['observe','prohibit'])for(const scope of ['AB','O']){
   console.log('Running '+scope+' / '+mode+' in a new test process...');const s=native[scope],r=Execute(s?.destination,s?.sha512,mode,scope);rows.push(r.row);
   fs.writeFileSync(path.join(home,runId+'-'+scope+'-'+mode+'.log'),r.log,{flag:'wx',mode:0o600});console.log(r.row.status+': '+scope+' / '+mode);
  }
  for(const [i,role]of roles.entries())artifacts[role].unchanged=Unchanged(snapshots[i]);
  for(const scope of ['AB','O'])if(native[scope])probes[scope].unchanged=Unchanged(native[scope]);
  let sourceManifestUnchanged=false;try{sourceManifestUnchanged=require('./manual-release-check').inventory(home).sourceManifestSha512===source;}catch(_){sourceManifestUnchanged=false;}
  const report=contract.ValidateReport({version:1,kind:'MITIGATION_COMPATIBILITY_OBSERVATION',runId,startedAt,finishedAt:new Date().toISOString(),platform:'win32',architecture:'x64',sourceManifestSha512:source,sourceManifestUnchanged,artifacts,probes,rows,windowsExecuted:rows.some(row=>row.result!==null),hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false,scope:'LINKED_RELEASE_UNITS_ONLY_NOT_PRODUCT_WORKFLOW'});
  const out=path.join(home,runId+'.json');fs.writeFileSync(out,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});console.log('Compatibility report: '+out);
  console.log('Only linked policy/renderer probes ran. Full product workflow, hardware attestation, CI and publication authorization were not created.');
  if(!sourceManifestUnchanged||Object.values(artifacts).some(x=>!x.unchanged)||Object.values(probes).some(x=>x.sha512!==null&&!x.unchanged)||rows.some(x=>x.status==='FAIL'))process.exitCode=1;
  return report;
 }finally{fs.rmSync(scratch,{recursive:true,force:true});}
}
if(require.main===module)Main(process.argv.slice(2)).catch(e=>{console.error('ERROR: '+(/^[A-Z0-9_]+$/.test(e.message)?e.message:'MITIGATION_COMPATIBILITY_FAILED'));process.exitCode=1;});
module.exports={Execute,ParseNative,Pe64,Main};
