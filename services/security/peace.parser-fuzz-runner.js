'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const cp=require('node:child_process'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const TARGETS=Object.freeze(['strict-json','webauthn-cbor','pe64-export','custom-package','packing-pe']);
const FILES=['../maintenance/source-manifest.json',"../tools/security/peace.parser-fuzz-child.js","security/peace.parser-fuzz-runner.js","security/peace.parser-fuzz-cases.js","protocol/peace.strict-json.js","authentication/peace.passkey-auth-data.js","artifacts/peace.pe-preflight.js","artifacts/peace.desktop-pe-exports.js","artifacts/peace.custom-package-format.js","artifacts/peace.desktop-packing-protocol.js","integrity/peace.desktop-integrity.js","cryptography/peace.extended-hashes.js"];
function Hash(b){return crypto.createHash('sha512').update(b).digest('hex');}
function Validate(o){if(!o||Object.getPrototypeOf(o)!==Object.prototype||Object.keys(o).some(k=>!['seed','iterations'].includes(k))||!Number.isInteger(o.seed)||o.seed<0||o.seed>0xffffffff||!Number.isInteger(o.iterations)||o.iterations<1||o.iterations>1024)throw Error('FUZZ_INPUT_INVALID');return o;}
function Identity(){return Object.fromEntries(FILES.map(f=>[f,Hash(fs.readFileSync(path.join(MODULE_RESOURCE_ROOT,f)))]));}
function One(target,o,{deadlineMs=7000}={}){return new Promise(resolve=>{const at=Date.now(),env=require('./peace.service-isolation').ChildEnvironment();env.NODE_ENV='test';let child,done=false,result=null,output=0,timer;
 function finish(reason){if(done)return;done=true;clearTimeout(timer);resolve(reason?{target,status:'FAIL',error:reason,elapsedMs:Date.now()-at}:{...result,elapsedMs:Date.now()-at});}
 try{child=cp.spawn(process.execPath,['--max-old-space-size=128','--stack-size=1024',path.join(MODULE_RESOURCE_ROOT,"../tools/security/peace.parser-fuzz-child.js"),target,String(o.seed),String(o.iterations)],{cwd:path.resolve(MODULE_RESOURCE_ROOT,'..'),env,stdio:['ignore','pipe','pipe','ipc'],windowsHide:true,shell:false});
  timer=setTimeout(()=>{child.kill('SIGKILL');},deadlineMs);timer.unref();
  const drain=b=>{output+=b.length;if(output>32768)child.kill('SIGKILL');};child.stdout.on('data',drain);child.stderr.on('data',drain);
  child.on('message',m=>{if(result||!m||typeof m!=='object'||Array.isArray(m)||Buffer.byteLength(JSON.stringify(m))>32768){child.kill('SIGKILL');return;}result=m;});child.on('error',()=>finish('FUZZ_SPAWN_FAILED'));child.on('exit',(code,signal)=>{if(signal)finish(output>32768?'FUZZ_OUTPUT_LIMIT':'FUZZ_TIMEOUT_OR_TERMINATED');else if(code!==0||!result||result.target!==target||!['PASS','FAIL'].includes(result.status))finish('FUZZ_CHILD_FAILED');else finish();});
 }catch(_){finish('FUZZ_SPAWN_FAILED');}
});}
async function Run(options){const o=Validate(options),sources=Identity(),startedAt=Date.now(),results=[];for(const target of TARGETS)results.push(await One(target,o));const after=Identity(),sourceChanged=JSON.stringify(sources)!==JSON.stringify(after);return {version:1,kind:'BOUNDED_MUTATION_PARSER_TEST',seed:o.seed,iterationsPerTarget:o.iterations,mutatorVersion:1,startedAt,finishedAt:Date.now(),status:sourceChanged||results.some(r=>r.status!=='PASS')?'FAIL':'PASS',sourceChanged,sources,runtime:process.version,platform:process.platform,scope:'SYNTHETIC_INPUTS_PURE_SERVER_PARSERS',coverageGuided:false,windowsProductExecuted:false,productionCredentialsPassed:false,results};}
module.exports={Run,One,Validate,Identity,TARGETS};
