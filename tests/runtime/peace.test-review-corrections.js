'use strict';
const sourceLayout=require('../fixtures/source/peace.project-layout');
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Focused executable regressions. Private lexical state is exposed ONLY inside
// a test-owned module instance; no production exports, DB or locks are weakened.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os');
const path=require('node:path'),crypto=require('node:crypto'),Module=require('node:module');
const {PassThrough}=require('node:stream');
const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'game-review-corrections-'));
process.env.DATA_DIR=temporary;process.env.HA_ENABLED='0';
const root=path.resolve(MODULE_RESOURCE_ROOT,'..'),native=path.resolve(root,'../Railway');
const work=require("../../services/runtime/peace.desktop-work-queue");
let groups=0;
async function check(name,fn){await fn();groups++;console.log('PASS '+name);}
function isolated(relative,names=[],overrides={}){
 const filename=path.join(root,relative),loaded=new Module(filename,module);
 loaded.filename=filename;loaded.paths=Module._nodeModulePaths(path.dirname(filename));
 const real=Module.createRequire(filename);
 loaded.require=sourceLayout.MockRequire(filename,overrides);
 loaded._compile(fs.readFileSync(filename,'utf8')+'\nmodule.exports.__probe={'+names.join(',')+'};\n',filename);
 return loaded.exports;
}
const pair=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const identity={privateKey:pair.privateKey,keyId:'a'.repeat(64)};
function frame(clear='{"operation":"execute","body":{"action":"verify"}}',requestId=crypto.randomUUID()){
 const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12);
 const aad=Buffer.from('GAME-CONNECT-4\nREQUEST\n'+requestId+'\n'+identity.keyId);
 const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(aad);
 const ciphertext=Buffer.concat([cipher.update(Buffer.from(clear)),cipher.final()]);
 const wrappedKey=crypto.publicEncrypt({key:pair.publicKey,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key);
 key.fill(0);return {v:1,keyId:identity.keyId,requestId,wrappedKey:wrappedKey.toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
}
function connect(queue=work){return isolated("services/network/peace.desktop-connect.js",['Open','seen','pendingReplays'],{'./peace.connect-transport-key':{Resolve:id=>{if(id!==identity.keyId)throw Error('CONNECT_PIN_MISMATCH');return identity;}},"../runtime/peace.desktop-work-queue":queue});}
async function body(bytes,max=131072,split=0){const req=new PassThrough(),promise=require("../../web/http/peace.read-json-body").ReadJsonBody(req,max);if(split){req.write(bytes.subarray(0,split));req.end(bytes.subarray(split));}else req.end(bytes);return promise;}
(async()=>{
 try{
  await check('Replay: real RSA/GCM and strict-JSON failures release reservations; same ID can retry',async()=>{
   const c=connect().__probe,good=frame(),bad={...good,tag:Buffer.alloc(16).toString('base64')};
   await assert.rejects(c.Open(bad,10000));assert.equal(c.seen.size,0);assert.equal(c.pendingReplays.size,0);
   const opened=await c.Open(good,10000);assert.equal(opened.payload.operation,'execute');opened.key.fill(0);
   assert.equal(c.pendingReplays.size,0);assert.equal(c.seen.size,1);
   await assert.rejects(c.Open(good,10000),/CONNECT_REPLAY/);
   const duplicate=frame('{"operation":"execute","operation":"challenge","body":{}}');
   await assert.rejects(c.Open(duplicate,10000));assert.equal(c.pendingReplays.size,0);assert(!c.seen.has(duplicate.requestId));
   // RSA failure also releases, independently of GCM failure.
   const rsa=frame();rsa.wrappedKey=Buffer.alloc(256).toString('base64');
   await assert.rejects(c.Open(rsa,10000));assert.equal(c.pendingReplays.size,0);assert(!c.seen.has(rsa.requestId));
  });
  await check('Replay: 12032 failed queue admissions cannot exhaust the 12000-ID store',async()=>{
   let calls=0;const c=connect({auth:{run:async()=>{calls++;throw Error(calls%2?'WORK_QUEUE_BUSY':'WORK_DEADLINE');}}}).__probe;
   const input=frame();
   for(let i=0;i<12032;i++)await assert.rejects(c.Open({...input,requestId:crypto.randomUUID()},10000),/WORK_QUEUE_BUSY|WORK_DEADLINE/);
   assert.equal(calls,12032);assert.equal(c.pendingReplays.size,0);assert.equal(c.seen.size,0);
  });
  await check('Replay: concurrent duplicates blocked; authenticated denial remains blocked; returned key copy survives wiping',async()=>{
   let resolve;const returnedKey=Buffer.alloc(32,9),q={auth:{run:()=>new Promise(r=>{resolve=r;})}};
   const c=connect(q).__probe,input=frame(),pending=c.Open(input,10000);
   assert.equal(c.pendingReplays.size,1);await assert.rejects(c.Open(input,10000),/CONNECT_REPLAY/);
   resolve({key:returnedKey,payload:{operation:'execute',body:{action:'verify'}}});
   const opened=await pending;assert(returnedKey.every(v=>v===0));assert(opened.key.every(v=>v===9));opened.key.fill(0);
   assert.equal(c.pendingReplays.size,0);assert.equal(c.seen.size,1);
   // Business authorization is downstream: successful decryption is never undone.
   await assert.rejects(c.Open(input,10000),/CONNECT_REPLAY/);
  });
  await check('Admin JSON: nested/escaped duplicate fields, invalid UTF-8 and unsafe integers rejected',async()=>{
   for(const text of ['{"a":1,"a":2}','{"a":{"b":1,"b":2}}','{"a":1,"\\u0061":2}','{"n":9007199254740992}','{"__proto__":{}}','{"s":"\\ud800"}','[]','null'])await assert.rejects(body(Buffer.from(text)),/INVALID_JSON/);
   await assert.rejects(body(Buffer.from([123,34,97,34,58,34,0xc0,0xaf,34,125])),/INVALID_JSON/);
   const bytes=Buffer.from('{"이름":"테스트 😀","nested":{"ok":true}}');
   assert.equal((await body(bytes,131072,3)).이름,'테스트 😀');assert.deepEqual(await body(Buffer.alloc(0)),{});
   await assert.rejects(body(Buffer.from('{"a":1}'),4),/BODY_TOO_LARGE/);
   const aborted=new PassThrough(),cancelled=require("../../web/http/peace.read-json-body").ReadJsonBody(aborted);
   aborted.emit('aborted');await assert.rejects(cancelled,/BODY_ABORTED/);aborted.destroy();
   const failed=new PassThrough(),fault=require("../../web/http/peace.read-json-body").ReadJsonBody(failed);failed.destroy(Error('READ_FAULT'));await assert.rejects(fault,/^Error: BODY_READ_FAILED$/);
  });
  await check('License nested JSON: duplicates rejected without changing the signed raw-payload SHA-512',()=>{
   const parse=isolated("services/licensing/peace.desktop-licenses.js",['Payload']).__probe.Payload;
   const input={activationToken:'a'.repeat(64),appVersion:'1.0',machineId:'B'.repeat(64),binarySha512:'c'.repeat(128),binaryCrc64:'D'.repeat(16),codeSha512:'e'.repeat(128),codeCrc64:'F'.repeat(16)};
   const raw=JSON.stringify(input,null,2),parsed=parse({action:'verify',payloadJSON:raw});assert.deepEqual(parsed.payload,input);
   assert.equal(parsed.payloadHash,crypto.createHash('sha512').update(raw).digest('hex'));
   const bad=raw.slice(0,-1)+',"appVersion":"2.0"}';assert.throws(()=>parse({action:'verify',payloadJSON:bad}),/INPUT_INVALID/);
   assert.throws(()=>parse({action:'verify',payloadJSON:raw.slice(0,-1)+',"app\\u0056ersion":"2.0"}'}),/INPUT_INVALID/);
  });
  await check('Own measurement: all six failure states survive validation, storage and authority evaluation',()=>{
   const reports=require("../../services/integrity/peace.desktop-integrity-reports"),authority=require("../../services/security/peace.desktop-security-authority");
   const failures=require("../../services/integrity/peace.measurement-status").failures;
   assert.deepEqual(failures,['NOT_MEASURED','READ_ERROR','FILE_CHANGED','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED']);
   for(const status of failures){
    const payload=reports.Payload(JSON.stringify({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status}}));assert.equal(payload.own.status,status);
    const value=authority.Payload(JSON.stringify({version:1,hashVersion:3,measurement:status,fileSha512:'',fileCrc64:'',codeSha512:'',codeCrc64:'',codeXxh3_128:'',codeBlake3:'',apiSealed:true,apiSlots:1,dynamicCode:'ALLOWED',cfg:'DISABLED'}));
    const decision=authority.Evaluate(value,{hashVersion:3},{},{});assert.equal(decision.status,'INDETERMINATE');assert.equal(decision.reason,status==='READ_ERROR'?'MEASUREMENT_UNAVAILABLE':status);
    const row=reports.Record({stage:'A',status:'CLIENT_DIAGNOSTIC',check:'OWN_CODE',reason:decision.reason,measurementStatus:status});assert.equal(row.measurementStatus,status);assert.equal(row.attested,false);
   }
   const stored=JSON.parse(fs.readFileSync(reports.FILE,'utf8')).data.records;assert.deepEqual(stored.map(r=>r.measurementStatus),failures);
   assert.deepEqual(reports.List().items.map(r=>r.measurementStatus).sort(),[...failures].sort());
   assert.throws(()=>reports.Payload('{"version":1,"hashVersion":3,"check":"OWN_IMAGE","reason":"PERIODIC","own":{"status":"MEASURED"}}'),/INTEGRITY_REPORT_INVALID/);
   assert.throws(()=>reports.Payload('{"version":1,"hashVersion":3,"check":"OWN_IMAGE","reason":"PERIODIC","own":{"status":"MADE_UP"}}'),/INTEGRITY_REPORT_INVALID/);
  });
  await check('Signed diagnostic submission: real signature/receipt/store preserves failure and invalidates; auth context isolated',()=>{
   const invalidations=[],row={id:'FLOW_TEST',sessionId:'SESSION_TEST',reportContextId:'CONTEXT_TEST',stage:'A',machineId:'A'.repeat(64),publicKey:require("../../services/network/peace.connect-transport-key").PublicBlob(pair.publicKey).toString('base64'),integrityArtifact:{id:'ARTIFACT_TEST'}};
   const reports=isolated("services/integrity/peace.desktop-integrity-reports.js",['Challenge','Submit'],{
    "../bootstrap/peace.desktop-bootstrap":{AuthenticateIntegrityReport:()=>row},
    "../security/peace.desktop-security-authority":{UsesAuthority:()=>true,Policy:()=>({revision:1}),Invalidate:(_row,stage,reason)=>invalidations.push({stage,reason})},
    "../security/peace.desktop-security-operations":{Revision:()=>1},"../licensing/peace.desktop-licenses":{ParseKey:()=>({key:pair.publicKey})}
   });
   const common={stage:'A',sessionId:'CONTEXT_TEST',sessionToken:'TEST_ONLY_TOKEN',machineId:row.machineId};
   for(const status of require("../../services/integrity/peace.measurement-status").failures){
    const challenge=reports.__probe.Challenge({...common,action:'challenge'}),payload=JSON.stringify({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'MEASUREMENT_FAILED',own:{status}});
    const signature=crypto.sign('sha256',Buffer.from(reports.Canonical(row.reportContextId,challenge,payload)),{key:pair.privateKey,padding:crypto.constants.RSA_PKCS1_PADDING}).toString('base64');
    const request={...common,action:'submit',reportId:challenge.reportId,payload,signature},reply=reports.__probe.Submit(request);
    assert.equal(reply.accepted,true);assert.equal(reply.status,'CLIENT_DIAGNOSTIC');assert.equal(reply.terminate,false);
    assert.equal(Object.hasOwn(reply,'leaseExpiresAt'),false);assert.deepEqual(reports.__probe.Submit(request),reply);
   }
   assert.equal(invalidations.length,6);assert(invalidations.every(x=>x.stage==='A'));
   const statuses=reports.List({sessionId:'SESSION_TEST'}).items.map(x=>x.measurementStatus).sort();assert.deepEqual(statuses,[...require("../../services/integrity/peace.measurement-status").failures].sort());
  });
  await check('PE upload: real worker malformed-PE response keeps desktopError/status/code',async()=>{
   await assert.rejects(require("../../services/artifacts/peace.desktop-pe-cache").Prepare(Buffer.alloc(512)),error=>error.desktopError===true&&error.status===400&&error.message==='BOOTSTRAP_PE_INVALID');
  });
  await check('PE upload: queue busy/deadline/internal failures keep distinct HTTP error classifications',async()=>{
   for(const [input,code,status] of [['WORK_QUEUE_BUSY','BOOTSTRAP_UPLOAD_BUSY',429],['WORK_DEADLINE','BOOTSTRAP_UPLOAD_TIMEOUT',408],['WORKER_EXITED','BOOTSTRAP_PE_ANALYSIS_FAILED',503]]){
    const cache=isolated("services/artifacts/peace.desktop-pe-cache.js",[],{"../runtime/peace.desktop-work-queue":{pe:{run:async()=>{throw Error(input);}}}});
    await assert.rejects(cache.Prepare(Buffer.alloc(512)),e=>e.desktopError===true&&e.message===code&&e.status===status);
   }
  });
  await check('Upload route: actual stream and PE worker return PE_INVALID, never INPUT_INVALID (auth/response adapters isolated)',async()=>{
   let response;
   const routes=isolated("web/routes/bootstrap/peace.desktop-bootstrap-routes.js",[],{
    "../../http/peace.api-context":{RequireAdmin:()=>true,Json:(_r,status,body)=>{response={status,body};},ApiError:(_r,status,error)=>{response={status,body:{error}};}},
    "../../authentication/peace.web-auth":{ValidateCsrf:()=>true},"../../../services/network/peace.ha-coordinator":{CanAcceptTraffic:()=>true},"../../../services/authentication/peace.desktop-admin-guard":{CheckSession:()=>({ok:true})}
   });
   const req=new PassThrough();req.headers={'content-type':'application/octet-stream','content-length':'512'};
   const pathname='/api/desktop/bootstrap/artifacts',url=new URL('http://unit.test'+pathname+'?component=O&version=1.0&fileName=cozy.Overlay.exe');
   const handled=routes.HandleUpload({method:'POST',pathname,url,req,res:{},session:{id:'unit',role:'ADMIN'}});
   req.end(Buffer.alloc(512));assert.equal(await handled,true);assert.equal(response.status,400);assert.equal(response.body.error,'BOOTSTRAP_PE_INVALID');
  });
  await check('Renewal metric: challenge successes excluded; actual failed/successful renewals counted exactly once',()=>{
   const before=work.Snapshot().renewal;
   for(let i=0;i<100;i++){assert.equal(work.RecordRenewal('challenge','verify',true),false);assert.equal(work.RecordRenewal('challenge','overlayVerify',true),false);}
   assert.equal(work.RecordRenewal('bootstrap','overlayChallenge',true),false);
   assert.equal(work.RecordRenewal('execute','verify',false),true);assert.equal(work.RecordRenewal('bootstrap','overlayVerify',true),true);
   const after=work.Snapshot().renewal;assert.equal(after.attempted-before.attempted,2);assert.equal(after.failed-before.failed,1);assert.equal(after.failureRatio,.5);
  });
  await check('A/B/O source contracts: five module metadata fields and typed failure propagation remain connected',()=>{
   for(const file of ["Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas","Cozy.Source/Cozy.Platform/Cozy.Api.pas","Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas"]){
    const source=fs.readFileSync(path.join(native,file),'utf8');
    for(const name of ['measurementPlanVersion','measurementStartedTick','measurementFinishedTick','moduleGenerationStable','coverage'])assert(source.includes("'"+name+"'"),file+': '+name);
    assert(source.includes('MeasurementStatusName'),file);assert(source.includes('MeasurementFailureStatus'),file);
   }
   const probe=fs.readFileSync(path.join(native,"Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr"),'utf8');
   assert.match(probe,/on E: EInvalidOpException do[\s\S]*OVERLAY_STATE_TRANSITION/);
   assert.match(probe,/on E: EInvalidOpException do[\s\S]*OVERLAY_LEASE_EXPIRED/);
   assert.match(probe,/on E: EImageIntegrity do/); // reparse test must retain its actual exception.
   const resource=fs.readFileSync(path.join(native,"Cozy.Projects/Cozy.Overlay/Cozy.OverlayResources.res"));let at=0,manifests=[];
   function identifier(pos,end){const first=resource.readUInt16LE(pos);pos+=2;if(first===65535)return {id:resource.readUInt16LE(pos),next:pos+2};let v=first;while(v){assert(pos+2<=end);v=resource.readUInt16LE(pos);pos+=2;}return {id:null,next:pos};}
   while(at<resource.length){assert(at+8<=resource.length);const size=resource.readUInt32LE(at),header=resource.readUInt32LE(at+4),end=at+header;assert(header>=32&&end+size<=resource.length);const type=identifier(at+8,end),name=identifier(type.next,end);if(type.id===24&&name.id===1)manifests.push(resource.subarray(end,end+size));at=(end+size+3)&~3;}
   assert.equal(manifests.length,1);assert.deepEqual(manifests[0],fs.readFileSync(path.join(native,"Cozy.Projects/Cozy.Overlay/Cozy.Overlay.manifest")));assert(manifests[0].includes(Buffer.from('PerMonitorV2, PerMonitor')));
   const version=fs.readFileSync(path.join(native,"Cozy.ImGui/Cozy.Vendor/Cozy.Core/Cozy.imgui.h"),'utf8').match(/^#define IMGUI_VERSION\s+"([^"]+)"/m)[1];
   assert.equal(require("../../contracts/runtime/dependency-provenance-v1.json").imguiVersion,version);
   assert.equal(require("../../setup/releases/release-manifest-spec.example.json").toolchain.imgui,version);
  });
  console.log(`REVIEW CORRECTIONS PASS: ${groups} groups. Windows/Delphi, real sockets/auth/SQLite, GPU and actual EXE not executed here.`);
 }finally{await Promise.all([work.auth,work.pe,work.proof,work.renewalProof,work.tpmAttestation].map(q=>q.close()));fs.rmSync(temporary,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
