'use strict';
// Test suite orchestration, not a source of signed deployment PASS. The caller
// must use a disposable test environment with the locked package versions.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const TESTS=["test-completion-protocol-6-10.js", "test-completion-measurement-6-10.js", "test-completion-artifacts-6-10.js", "test-completion-pin-6-10.js", "test-hardening-protocol.js", "test-hardening-work-queue.js", "test-hardening-measurement.js", "test-hardening-pe-corpus.js", "test-review-corrections.js", "test-independent-contracts-14.js", "test-extended-hashes.js", "test-crc-layers.js", "test-desktop-pe-exports.js", "test-desktop-integrity-policy.js", "test-desktop-integrity-reports.js", "test-connect-tls.js", "test-desktop-connect.js", "test-overlay-imgui.js", "test-overlay-transfer.js", "test-native-code-contract.js", "test-security-native-contract.js", "test-windows-ci.js", "test-web-ui-cache.js"];
function Classify(result,log){if(result.status===0&&!result.error)return'PASS';if(/Cannot find module|MODULE_NOT_FOUND|Could not locate the bindings file/.test(log))return'BLOCKED_DEPENDENCY';if(log.includes('DESKTOP_WRITER_LOCK_UNAVAILABLE'))return'BLOCKED_NATIVE_LOCK';if(result.error?.code==='ETIMEDOUT')return'TIMEOUT';return'FAIL';}
function Main(directory){
 const root=path.resolve(__dirname,'..'),out=fs.realpathSync(directory||path.join(root,'tools'));
 if(!fs.statSync(out).isDirectory())throw Error('SERVER_CONTRACT_OUTPUT_INVALID');
 const id=new Date().toISOString().replace(/[-:.]/g,'')+'-'+crypto.randomBytes(6).toString('hex');
 const prefix='server-contracts-6-10-'+id,logs=path.join(out,prefix+'-logs'),file=path.join(out,prefix+'.json');
 fs.mkdirSync(logs,{mode:0o700});
 const summary={version:1,scope:'SERVER_AND_SOURCE_CONTRACTS_6_TO_10',generatedAt:new Date().toISOString(),node:process.version,requiredEngine:require('../package.json').engines.node,platform:process.platform,architecture:process.arch,windowsProductBuildExecuted:false,physicalWindowsIntegrationExecuted:false,signedCiEvidence:false,suites:[]};
 fs.writeFileSync(file,JSON.stringify(summary,null,2)+'\n',{flag:'wx',mode:0o600});
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'game-contract-suite-6-10-'));
 try{
  for(const name of TESTS){
   const started=new Date().toISOString(),p=spawnSync(process.execPath,[path.join(__dirname,name)],{cwd:root,encoding:'utf8',timeout:120000,maxBuffer:16*1024*1024,env:{...process.env,DATA_DIR:temporary,HA_ENABLED:'0',DESKTOP_RECOVERY_WITNESS_DIR:'',DESKTOP_RECOVERY_WITNESS_REQUIRED:'0'}});
   const log=(p.stdout||'')+(p.stderr||'')+(p.error?'\n'+p.error.stack:'');const logName=name.replace(/\.js$/,'.log');fs.writeFileSync(path.join(logs,logName),log,{flag:'wx',mode:0o600});
   const row={name,status:Classify(p,log),exitCode:p.status,signal:p.signal||null,started,finished:new Date().toISOString(),log:prefix+'-logs/'+logName,sha512:crypto.createHash('sha512').update(log).digest('hex')};
   summary.suites.push(row);fs.writeFileSync(file,JSON.stringify(summary,null,2)+'\n');console.log(row.status+' '+name);
  }
 }finally{fs.rmSync(temporary,{recursive:true,force:true});summary.finishedAt=new Date().toISOString();summary.counts=Object.fromEntries(['PASS','BLOCKED_DEPENDENCY','BLOCKED_NATIVE_LOCK','TIMEOUT','FAIL'].map(status=>[status,summary.suites.filter(x=>x.status===status).length]));summary.outcome=summary.suites.length===TESTS.length&&summary.suites.every(x=>x.status==='PASS')?'PASS':'INCOMPLETE';fs.writeFileSync(file,JSON.stringify(summary,null,2)+'\n');}
 console.log('SERVER_CONTRACT_RESULTS '+file);console.log(JSON.stringify(summary.counts));return summary.outcome==='PASS'?0:1;
}
if(require.main===module){try{if(process.argv.length>3)throw Error('SERVER_CONTRACT_ARGUMENTS_INVALID');process.exitCode=Main(process.argv[2]);}catch(e){console.error(e.message);process.exitCode=1;}}
module.exports={TESTS,Classify};
