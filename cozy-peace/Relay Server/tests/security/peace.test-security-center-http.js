'use strict';
require("../runtime/peace.test-owned-directory").Main(__filename,'action-approval-http-',async tmp=>{
// Real HTTP dispatcher, session/CSRF/password and ES256 assertion validation.
// Native authority storage is isolated in memory, not presented as SQLite E2E.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict'),http=require('node:http');
Object.assign(process.env,{DATA_DIR:tmp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'test-only-action-password',VIEWER_SECRET:'test-only-viewer',WEB_ADMIN_TRANSPORT:'proxy',WEB_ADMIN_TRUSTED_PROXIES:'127.0.0.1/32,::1/128',WEB_ADMIN_REQUIRE_HTTPS:'1',WEB_ADMIN_SECURE_COOKIE:'1',WEBAUTHN_RP_ID:'localhost',WEBAUTHN_ORIGIN:'https://localhost',WEB_ADMIN_LOGIN_IP_MAX:'1000',WEB_ADMIN_LOGIN_ROLE_MAX:'1000'});
require("../../core/peace.utilities.js").EnsureDirs();
const f=require("../fixtures/runtime/peace.next123-fixture").Fixture(),c=f.cohort();f.active(c);
function swap(name,value){const file=require('../fixtures/source/peace.project-layout').RelayFile(path.posix.basename(name));require(file);require.cache[file].exports=value;}
swap("../services/bootstrap/peace.desktop-bootstrap-store",f.store);swap("../services/storage/peace.desktop-operation-audit",{...f.audit,RecordAccess:()=>null});swap("../services/artifacts/peace.desktop-release-safety",f.safety);
swap("../services/integrity/peace.desktop-integrity-reports",{Policy:()=>({revision:1}),Baselines:()=>({items:[]})});
swap("../storage/snapshots/peace.database.js",{...require("../../storage/snapshots/peace.database.js"),SaveDatabase:()=>true});
const state=require("../../core/peace.runtime-state"),wire=require("../fixtures/authentication/peace.passkey-wire-fixture"),web=require("../../web/authentication/peace.web-auth");
const {RequestHandler}=require("../../web/http/peace.web-server");let server,checks=0;
const prefix='/api/desktop/bootstrap/security-center/';
const test=async(name,fn)=>{await fn();checks++;console.log('PASS '+name);};
function call(route,body,actor,headers={}){return new Promise((resolve,reject)=>{const bytes=body===undefined?null:Buffer.from(JSON.stringify(body));const r=http.request({host:'127.0.0.1',port:server.address().port,path:route,method:bytes?'POST':'GET',headers:{Host:'localhost','X-Forwarded-Proto':'https',...(actor?{Cookie:actor.cookie,'X-CSRF-Token':actor.csrf}:{}),...(bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{}),...headers}},s=>{let b='';s.on('data',x=>b+=x);s.on('end',()=>{try{resolve({status:s.statusCode,data:JSON.parse(b),headers:s.headers});}catch(e){reject(e);}});});r.setTimeout(5000,()=>r.destroy(Error('TEST_TIMEOUT')));r.on('error',reject);r.end(bytes);});}
async function login(role='admin'){const r=await call('/api/login',{role,password:role==='admin'?process.env.ADMIN_SECRET:process.env.VIEWER_SECRET});assert.equal(r.status,200,JSON.stringify(r.data));return {cookie:r.headers['set-cookie'][0].split(';')[0],csrf:r.data.csrf};}
async function pending(actor,route,body){const r=await call(route,body,actor);assert.equal(r.status,428,JSON.stringify(r.data));assert.equal(r.data.error,'ADMIN_ACTION_REQUIRED');return r.data.action;}
async function password(actor,a,p=process.env.ADMIN_SECRET){return call('/api/session/reauthenticate',{password:p,actionId:a.id},actor);}

swap("../services/bootstrap/peace.desktop-bootstrap",{...require("../../services/bootstrap/peace.desktop-bootstrap"),...f.boot,Initialize:()=>f.db,AssertSecurityAvailable:()=>{}});

async function approved(actor,route,body){const a=await pending(actor,route,body);assert.equal((await password(actor,a)).status,200);return {a,response:await call(route,body,actor,{'X-Admin-Action':a.id})};}
async function job(actor,kind,id){for(let i=0;i<200;i++){const r=await call(prefix+kind+'/'+id,undefined,actor);assert.equal(r.status,200,JSON.stringify(r.data));if(r.data.job.status!=='RUNNING')return r.data.job;await new Promise(r=>setTimeout(r,20));}throw Error('TEST_JOB_TIMEOUT');}
try{
 server=http.createServer((q,s)=>Promise.resolve(RequestHandler(q,s)).catch(e=>{s.statusCode=500;s.end(JSON.stringify({error:e.message}));}));await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const admin=await login(),viewer=await login('viewer'),center=prefix.slice(0,-1),body={seed:42,iterations:32};
 await test('security center GET rejects anonymous and viewer',async()=>{assert.equal((await call(center)).status,401);assert.equal((await call(center,undefined,viewer)).status,403);});
 await test('GET reports NOT_RUN without triggering expensive work',async()=>{const r=await call(center,undefined,admin);assert.equal(r.status,200,JSON.stringify(r.data));assert.equal(r.data.parserTests.status,'NOT_RUN');assert.equal(r.data.resources.active,0);assert.equal(r.data.exposureGate.productionActivation,true);});
 await test('missing CSRF cannot start parser job',async()=>assert.equal((await call(prefix+'parser-tests',body,admin,{'X-CSRF-Token':''})).data.error,'CSRF_FAILED'));
 let a;
 await test('fresh login does not replace action-specific approval',async()=>{a=await pending(admin,prefix+'parser-tests',body);assert.equal(a.summary.seed,42);assert.equal(require("../../services/security/peace.server-security-center").Status().parserTests.status,'NOT_RUN');});
 await test('proof for one workload cannot approve changed iteration count',async()=>{assert.equal((await password(admin,a)).status,200);const r=await call(prefix+'parser-tests',{seed:42,iterations:64},admin,{'X-Admin-Action':a.id});assert.equal(r.data.error,'ADMIN_ACTION_CHANGED');});
 let fuzz;
 await test('approved HTTP request runs real bounded parser children',async()=>{const x=await approved(admin,prefix+'parser-tests',body);assert.equal(x.response.status,202,JSON.stringify(x.response.data));fuzz=await job(admin,'parser-tests',x.response.data.result.id);assert.equal(fuzz.status,'PASS',JSON.stringify(fuzz));assert.equal(fuzz.result.results.length,5);assert.equal(fuzz.result.windowsProductExecuted,false);assert.equal((await call(prefix+'parser-tests',body,admin,{'X-Admin-Action':x.a.id})).data.error,'ADMIN_ACTION_INVALID');});
 await test('arbitrary command/target is rejected after approval without execution',async()=>{const r=await approved(admin,prefix+'parser-tests',{...body,command:'DONT_RUN'});assert.equal(r.response.data.error,'FUZZ_INPUT_INVALID');});
 await test('finished report endpoint rejects fabricated IDs',async()=>assert.equal((await call(prefix+'parser-tests/'+'0'.repeat(32),undefined,admin)).status,404));
 await test('approved candidate scan uses exact existing artifact bytes and actual worker',async()=>{const x=await approved(admin,prefix+'artifact-scan',{artifactIds:[c.rows[0].id]});assert.equal(x.response.status,202,JSON.stringify(x.response.data));const r=await job(admin,'artifact-scan',x.response.data.result.id);assert.equal(r.status,'PASS',JSON.stringify(r));assert.equal(r.results[0].sha512,c.rows[0].sha512);});
 await test('client cannot supply filesystem path to scanner',async()=>{const x=await approved(admin,prefix+'artifact-scan',{artifactIds:[c.rows[0].id],path:'/etc/passwd'});assert.equal(x.response.data.error,'EXPOSURE_SELECTION_INVALID');});
 const detect=require("../../services/security/peace.security-detection");detect.Record('EXPOSURE_BLOCKED',{subject:'synthetic-fixture',reason:'ARTIFACT_EXPOSURE_BLOCKED'});const alert=detect.Status().alerts.find(x=>x.kind==='EXPOSURE_BLOCKED');
 await test('incident response requires exact action approval',async()=>{const r=await approved(admin,prefix+'respond',{alertId:alert.id,action:'ACKNOWLEDGE',reason:'OPERATOR_REVIEW'});assert.equal(r.response.status,200,JSON.stringify(r.response.data));assert.equal(r.response.data.result.status,'ACKNOWLEDGED');});
 await test('approved hold blocks new expensive jobs without changing active A/B/O',async()=>{const original=JSON.stringify(f.db.active),r=await approved(admin,prefix+'respond',{alertId:alert.id,action:'HOLD_BACKGROUND',reason:'OPERATOR_REVIEW'});assert.equal(r.response.status,200,JSON.stringify(r.response.data));assert(require("../../services/runtime/peace.server-resource-budget").Snapshot().holdRemainingMs>0);const attempted=await approved(admin,prefix+'parser-tests',body);assert.equal(attempted.response.data.error,'RESOURCE_BACKGROUND_HELD');assert.equal(JSON.stringify(f.db.active),original);});
 await test('release hold restores new job admission, never grants licenses',async()=>{const r=await approved(admin,prefix+'respond',{alertId:alert.id,action:'RELEASE_BACKGROUND',reason:'OPERATOR_REVIEW'});assert.equal(r.response.status,200,JSON.stringify(r.response.data));assert.equal(require("../../services/runtime/peace.server-resource-budget").Snapshot().holdRemainingMs,0);});
 await test('audit append failure prevents unlogged response',async()=>{const original=require("../../storage/audit/peace.audit.js").LogEvent,before=detect.Status().alerts.find(x=>x.id===alert.id).status;require("../../storage/audit/peace.audit.js").LogEvent=()=>({ok:false});try{assert.throws(()=>detect.Respond({alertId:alert.id,action:'RESOLVE',reason:'OPERATOR_REVIEW'},'TEST'),/AUDIT_FAILED/);assert.equal(detect.Status().alerts.find(x=>x.id===alert.id).status,before);}finally{require("../../storage/audit/peace.audit.js").LogEvent=original;}});
 await test('authentication failures reach detector without storing supplied password',async()=>{const secret='FAKE-WRONG-PASSWORD-NOT-A-CREDENTIAL';for(let i=0;i<8;i++)assert.equal((await call('/api/login',{role:'admin',password:secret})).status,401);assert(detect.Status().alerts.some(x=>x.kind==='AUTH_FAILURE'));assert(!JSON.stringify(detect.Status()).includes(secret));});
 console.log('Security center HTTP: '+checks+' passed; real HTTP/crypto/workers, isolated authority store. Not SQLite/Windows/physical passkey.');
 }catch(e){console.error('[TEST_PRIMARY_FAILURE]',e);process.exitCode=1;}finally{
 // Stop new background work, drain owned resources, then let the child exit.
 // The parent owns directory removal; lifetime SQLite locks are never weakened.
 const errors=[];
 for(const close of [
  ()=>require("../../services/security/peace.server-security-center").Stop(),
  async()=>{if(server)await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));},
  ()=>require("../../services/runtime/peace.desktop-work-queue").pe.close()
 ])try{await close();}catch(e){errors.push(e);console.error('[TEST_TEARDOWN_FAILED] '+e.stack);}
 if(errors.length)process.exitCode=1;
}
});
