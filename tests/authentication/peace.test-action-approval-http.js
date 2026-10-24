'use strict';
// Real HTTP dispatcher, session/CSRF/password and ES256 assertion validation.
// Native authority storage is isolated in memory, not presented as SQLite E2E.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict'),http=require('node:http');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'action-approval-http-'));
Object.assign(process.env,{DATA_DIR:tmp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'test-only-action-password',VIEWER_SECRET:'test-only-viewer',WEB_ADMIN_TRANSPORT:'proxy',WEB_ADMIN_TRUSTED_PROXIES:'127.0.0.1/32,::1/128',WEB_ADMIN_REQUIRE_HTTPS:'1',WEB_ADMIN_SECURE_COOKIE:'1',WEBAUTHN_RP_ID:'localhost',WEBAUTHN_ORIGIN:'https://localhost',WEB_ADMIN_LOGIN_IP_MAX:'1000',WEB_ADMIN_LOGIN_ROLE_MAX:'1000'});
require("../../core/peace.utilities.js").EnsureDirs();
const f=require("../fixtures/runtime/peace.next123-fixture").Fixture(),c=f.cohort();f.active(c);
function swap(name,value){const file=require('../fixtures/source/peace.project-layout').RelayFile(path.posix.basename(name));require(file);require.cache[file].exports=value;}
swap("../services/bootstrap/peace.desktop-bootstrap-store",f.store);swap("../services/storage/peace.desktop-operation-audit",f.audit);swap("../services/artifacts/peace.desktop-release-safety",f.safety);
swap("../services/integrity/peace.desktop-integrity-reports",{Policy:()=>({revision:1}),Baselines:()=>({items:[]})});
swap("../storage/snapshots/peace.database.js",{...require("../../storage/snapshots/peace.database.js"),SaveDatabase:()=>true});
const state=require("../../core/peace.runtime-state"),wire=require("../fixtures/authentication/peace.passkey-wire-fixture"),web=require("../../web/authentication/peace.web-auth");
const {RequestHandler}=require("../../web/http/peace.web-server");let server,checks=0;
const prefix='/api/desktop/bootstrap/security-operations/';
const test=async(name,fn)=>{await fn();checks++;console.log('PASS '+name);};
function call(route,body,actor,headers={}){return new Promise((resolve,reject)=>{const bytes=body===undefined?null:Buffer.from(JSON.stringify(body));const r=http.request({host:'127.0.0.1',port:server.address().port,path:route,method:bytes?'POST':'GET',headers:{Host:'localhost','X-Forwarded-Proto':'https',...(actor?{Cookie:actor.cookie,'X-CSRF-Token':actor.csrf}:{}),...(bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{}),...headers}},s=>{let b='';s.on('data',x=>b+=x);s.on('end',()=>{try{resolve({status:s.statusCode,data:JSON.parse(b),headers:s.headers});}catch(e){reject(e);}});});r.setTimeout(5000,()=>r.destroy(Error('TEST_TIMEOUT')));r.on('error',reject);r.end(bytes);});}
async function login(role='admin'){const r=await call('/api/login',{role,password:role==='admin'?process.env.ADMIN_SECRET:process.env.VIEWER_SECRET});assert.equal(r.status,200,JSON.stringify(r.data));return {cookie:r.headers['set-cookie'][0].split(';')[0],csrf:r.data.csrf};}
async function pending(actor,route,body){const r=await call(route,body,actor);assert.equal(r.status,428,JSON.stringify(r.data));assert.equal(r.data.error,'ADMIN_ACTION_REQUIRED');return r.data.action;}
async function password(actor,a,p=process.env.ADMIN_SECRET){return call('/api/session/reauthenticate',{password:p,actionId:a.id},actor);}
(async()=>{try{
 server=http.createServer((q,s)=>Promise.resolve(RequestHandler(q,s)).catch(e=>{s.statusCode=500;s.end(JSON.stringify({error:e.message}));}));await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const admin=await login(),second=await login(),viewer=await login('viewer');const route=prefix+'baseline-pin';const body={expectedRevision:0,expectedOperationsRevision:0,expectedPolicyRevision:0,manifestId:c.id,note:'HTTP test only'};
 await test('critical action still requires admin and CSRF',async()=>{assert.equal((await call(route,body)).status,401);assert.equal((await call(route,body,viewer)).status,403);assert.equal((await call(route,body,admin,{'X-CSRF-Token':''})).data.error,'CSRF_FAILED');});
 let a;
 await test('fresh password login alone cannot perform a mutation',async()=>{a=await pending(admin,route,body);assert.equal(a.summary.manifestId,c.id);assert.equal(a.storage,'SERVER_MEMORY_ONLY');assert.equal(f.safety.State().baseline,null);});
 await test('unapproved action cannot be used and is burned',async()=>{assert.equal((await call(route,body,admin,{'X-Admin-Action':a.id})).data.error,'ADMIN_ACTION_NOT_APPROVED');a=await pending(admin,route,body);});
 await test('wrong password cannot approve action',async()=>{assert.equal((await password(admin,a,'wrong')).data.error,'REAUTH_FAILED');assert.equal((await password(admin,a)).data.error,'ADMIN_ACTION_INVALID');a=await pending(admin,route,body);});
 await test('session binding rejects a second valid admin session',async()=>{assert.equal((await password(second,a)).data.error,'ADMIN_ACTION_INVALID');assert.equal((await password(admin,a)).status,200);});
 await test('changed body rejected even with correct password',async()=>{const r=await call(route,{...body,note:'different'},admin,{'X-Admin-Action':a.id});assert.equal(r.data.error,'ADMIN_ACTION_CHANGED');assert.equal(f.safety.State().baseline,null);});
 await test('approval cannot be repurposed to a different endpoint',async()=>{a=await pending(admin,route,body);assert.equal((await password(admin,a)).status,200);assert.equal((await call(prefix+'retire-cohort',body,admin,{'X-Admin-Action':a.id})).data.error,'ADMIN_ACTION_CHANGED');});
 await test('server policy change after reauth rejects exact body',async()=>{a=await pending(admin,route,body);assert.equal((await password(admin,a)).status,200);f.db.securityAuthorityPolicy.revision++;assert.equal((await call(route,body,admin,{'X-Admin-Action':a.id})).data.error,'ADMIN_ACTION_POLICY_CHANGED');f.db.securityAuthorityPolicy.revision--;});
 await test('exact password approved action commits once',async()=>{a=await pending(admin,route,body);assert.equal((await password(admin,a)).status,200);const r=await call(route,body,admin,{'X-Admin-Action':a.id});assert.equal(r.status,200,JSON.stringify(r.data));assert.equal(f.safety.State().baseline.manifestId,c.id);assert.equal((await call(route,body,admin,{'X-Admin-Action':a.id})).data.error,'ADMIN_ACTION_INVALID');});
 await test('subsequent important mutation asks its own confirmation',async()=>{const next=await pending(admin,prefix+'retire-cohort',{expectedRevision:1,manifestId:c.id,reason:'second action only'});assert.notEqual(a.id,next.id);});
 // Synthetic authenticator; actual WebAuthn parsing/signature validation.
 const pk=require("../../services/authentication/peace.passkey-auth"),req={headers:{host:'localhost','x-forwarded-proto':'https'},socket:{remoteAddress:'127.0.0.1'}};
 const managed=web.Authenticate({headers:{...req.headers,cookie:admin.cookie},socket:req.socket});
 const crypto=require('node:crypto'),keys=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const begin=pk.RegistrationBegin(managed,req);const registration=wire.Registration('localhost',keys.publicKey);const finish=pk.RegistrationFinish(managed,req,{...registration,challengeId:begin.challengeId,clientDataJSON:wire.b64(JSON.stringify({type:'webauthn.create',challenge:begin.publicKey.challenge,origin:'https://localhost'})),name:'synthetic test key'});assert(finish.ok,JSON.stringify(finish));
 await test('passkey assertion is bound to a pending action',async()=>{
  const b={expectedRevision:1,manifestId:c.id,reason:'fixture retirement'},action=await pending(admin,prefix+'retire-cohort',b);
  const r=await call('/api/session/reauthenticate/passkey/begin',{actionId:action.id},admin);assert.equal(r.status,200,JSON.stringify(r.data));
  const clientData=Buffer.from(JSON.stringify({type:'webauthn.get',challenge:r.data.publicKey.challenge,origin:'https://localhost'})),auth=wire.Auth('localhost',1,5);
  const assertion={challengeId:r.data.challengeId,credentialId:registration.credentialId,clientDataJSON:wire.b64(clientData),authenticatorData:wire.b64(auth),signature:wire.b64(crypto.sign('sha256',Buffer.concat([auth,crypto.createHash('sha256').update(clientData).digest()]),keys.privateKey))};const signed=await call('/api/session/reauthenticate/passkey/finish',{...assertion,actionId:action.id},admin);
  assert.equal(signed.status,200,JSON.stringify(signed.data));const done=await call(prefix+'retire-cohort',b,admin,{'X-Admin-Action':action.id});assert.equal(done.status,200,JSON.stringify(done.data));
 });
 await test('revocation tombstone survives restoration of old credential record',()=>{const cred=state.production.passkeyCredentials.get(finish.credential.id),old={...cred};assert(pk.Revoke(cred.id,'TEST').ok);state.production.passkeyCredentials.set(cred.id,old);assert.equal(pk.LoginBegin('admin',req).reason,'PASSKEY_NOT_REGISTERED');assert(require("../../services/authentication/peace.admin-credential-revocations").At(cred.id)>0);});
 console.log('Action approval HTTP: '+checks+' passed; physical authenticator, Windows and real SQLite are not exercised.');
 }catch(e){console.error(e.stack);process.exitCode=1;}finally{if(server)await new Promise(r=>server.close(r));fs.rmSync(tmp,{recursive:true,force:true});}})();
