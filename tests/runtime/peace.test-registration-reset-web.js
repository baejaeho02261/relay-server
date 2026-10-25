'use strict';
// Actual production HTTP dispatcher, password/action-bound authorization,
// SQLite and an independent witness. Only disposable synthetic PE data is used;
// this never executes native binaries, contacts production or approves releases.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const crypto=require('node:crypto'),http=require('node:http'),net=require('node:net');
const {spawn,spawnSync}=require('node:child_process');
const ROOT=path.resolve(__dirname,'../..'),ENTRY=path.join(ROOT,'peace.relay-server.js');
const ROUTE='/api/desktop/bootstrap/security-operations/registration-reset',SCOPE='ABO_LICENSES_ISSUANCE_OPERATIONS_V1';
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const modules=Object.fromEntries(Object.entries({
 utilities:'../../core/peace.utilities',database:'../../storage/snapshots/peace.database',sqlite:'../../storage/sqlite/peace.sqlite-database',
 store:'../../services/bootstrap/peace.desktop-bootstrap-store',bootstrap:'../../services/bootstrap/peace.desktop-bootstrap',
 licenses:'../../services/licensing/peace.desktop-licenses',fixture:'../fixtures/bootstrap/peace.desktop-bootstrap-fixture',
 state:'../../core/peace.runtime-state',workspace:'../../services/operations/peace.desktop-workspace-store',
 machine:'../../services/devices/peace.desktop-machine-policy',integrity:'../../services/integrity/peace.desktop-integrity-reports',
 witness:'../../services/recovery/peace.recovery-witness-file',reset:'../../services/operations/peace.registration-reset',auxiliary:'../../services/operations/peace.registration-reset-stores',
 operations:'../../services/security/peace.desktop-security-operations',audit:'../../services/storage/peace.desktop-operation-audit',
 web:'../../web/authentication/peace.web-auth',passkey:'../../services/authentication/peace.passkey-auth',wire:'../fixtures/authentication/peace.passkey-wire-fixture'
}).map(([name,file])=>[name,require.resolve(file)]));
async function freePort(){const server=net.createServer();await new Promise((resolve,reject)=>server.listen(0,'127.0.0.1',resolve).once('error',reject));const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;}
async function within(promise,ms){let timer;try{return await Promise.race([promise,new Promise(resolve=>{timer=setTimeout(()=>resolve({timeout:true}),ms);})]);}finally{clearTimeout(timer);}}
function script(env,body){
 const result=spawnSync(process.execPath,['-e','const M='+JSON.stringify(modules)+';'+body],{cwd:ROOT,env,encoding:'utf8',timeout:30000,maxBuffer:1024*1024});
 assert.equal(result.error,undefined,result.error?.message);assert.equal(result.status,0,result.stderr+'\n'+result.stdout);
 const start=result.stdout.lastIndexOf('WEB_RESET_TEST:');assert.ok(start>=0,result.stdout);return JSON.parse(result.stdout.slice(start+15));
}
const SNAPSHOT=`
 const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
 require(M.utilities).EnsureDirs();require(M.database).LoadDatabase();const b=require(M.store).Load(),l=require(M.licenses).DB(),state=require(M.state);
 const hash=bytes=>crypto.createHash('sha512').update(bytes).digest('hex'),root=process.env.DATA_DIR;
 function files(dir){return fs.existsSync(dir)?fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?files(path.join(dir,e.name)):[path.join(dir,e.name)]):[];}
 const names=['connect-transport-key.pem','connect-transport-key.id','connect-tls.sha256','desktop-key-purposes.json','desktop-key-purposes.initialized','desktop-license-journal.key','desktop-machine-policy/authority.key','desktop-integrity-reports/authority.key','fixture-custom-package.key',...files(path.join(root,'connect-tls')).map(file=>path.relative(root,file))];
 const keys=Object.fromEntries(names.map(name=>[name,hash(fs.readFileSync(path.join(root,name)))]));
 const value={counts:require(M.reset).Counts(),related:require(M.auxiliary).Counts(),
 keys,secrets:{bootstrap:hash(b.secret),license:hash(l.signingSecret)},passkeys:Object.fromEntries(state.production.passkeyCredentials),
 artifactFiles:Object.keys(b.artifacts).map(id=>require(M.store).ArtifactPath(id)),reset:b.registrationResetJob||null,operations:require(M.operations).State(),
 witness:JSON.parse(fs.readFileSync(path.join(process.env.DESKTOP_RECOVERY_WITNESS_DIR,'witness.json'))).body};
 value.keys.witness=hash(fs.readFileSync(path.join(process.env.DESKTOP_RECOVERY_WITNESS_DIR,'witness.key')));
 require(M.sqlite).Close();console.log('WEB_RESET_TEST:'+JSON.stringify(value));`;

(async()=>{
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'peace-web-reset-'));fs.chmodSync(temporary,0o700);
 const data=path.join(temporary,'data'),witness=path.join(temporary,'witness');fs.mkdirSync(data,{mode:0o700});fs.mkdirSync(witness,{mode:0o700});
 const customKey=path.join(data,'fixture-custom-package.key');fs.writeFileSync(customKey,crypto.randomBytes(32),{mode:0o600});
 const port=await freePort(),tcp=await freePort(),children=new Set();
 const env={...process.env,DATA_DIR:data,NODE_ENV:'production',HA_ENABLED:'0',STORAGE_ENGINE:'sqlite',PORT:String(port),WEB_ADMIN_PORT:String(port),CONNECT_TCP_PORT:String(tcp),CONNECT_TCP_HOST:'127.0.0.1',HEALTH_PORT:'0',WEB_ADMIN_TRANSPORT:'railway',WEB_ADMIN_RAILWAY_EDGE_ONLY:'1',WEB_ADMIN_HOST:'0.0.0.0',WEB_ADMIN_REQUIRE_HTTPS:'1',WEB_ADMIN_SECURE_COOKIE:'1',WEB_ADMIN_TRUSTED_PROXIES:'',RAILWAY_PROJECT_ID:'11111111-1111-4111-8111-111111111111',RAILWAY_ENVIRONMENT_ID:'22222222-2222-4222-8222-222222222222',RAILWAY_SERVICE_ID:'33333333-3333-4333-8333-333333333333',WEBAUTHN_RP_ID:'admin.example.test',WEBAUTHN_ORIGIN:'https://admin.example.test',ADMIN_SECRET:crypto.randomBytes(48).toString('base64url'),VIEWER_SECRET:crypto.randomBytes(48).toString('base64url'),DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:String(tcp),GAME_CUSTOM_PACKAGE_KEY_FILE:customKey,WEB_ADMIN_LOGIN_IP_MAX:'1000',WEB_ADMIN_LOGIN_ROLE_MAX:'1000'};
 for(const name of Object.keys(env))if(name.startsWith('DESKTOP_RECOVERY_WITNESS_')||name.startsWith('COZY_REGISTRATION_RESET_')||name.startsWith('CONNECT_TLS_'))delete env[name];
 const ingress={Host:'admin.example.test','X-Forwarded-Host':'admin.example.test','X-Forwarded-Proto':'https','X-Railway-Request-Id':'synthetic-reset-http','X-Real-IP':'127.0.0.1',Origin:'https://admin.example.test'};
 function call(route,body,actor,headers={}){return new Promise((resolve,reject)=>{const bytes=body===undefined?null:Buffer.from(JSON.stringify(body));const request=http.request({host:'127.0.0.1',port,path:route,method:bytes?'POST':'GET',headers:{...ingress,...(actor?{Cookie:actor.cookie,'X-CSRF-Token':actor.csrf}:{}),...(bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{}),...headers}},response=>{let text='';response.on('data',part=>text+=part);response.on('end',()=>{try{resolve({status:response.statusCode,data:JSON.parse(text),headers:response.headers});}catch(error){reject(error);}});});request.setTimeout(5000,()=>request.destroy(Error('WEB_RESET_TEST_HTTP_TIMEOUT')));request.once('error',reject);request.end(bytes);});}
 async function login(role='admin'){const response=await call('/api/login',{role,password:role==='admin'?env.ADMIN_SECRET:env.VIEWER_SECRET});assert.equal(response.status,200,JSON.stringify(response.data));return {cookie:response.headers['set-cookie'][0].split(';')[0],csrf:response.data.csrf};}
 async function approve(actor,body){const pending=await call(ROUTE,body,actor);assert.equal(pending.status,428,JSON.stringify(pending.data));assert.equal(pending.data.error,'ADMIN_ACTION_REQUIRED');const approved=await call('/api/session/reauthenticate',{password:env.ADMIN_SECRET,actionId:pending.data.action.id},actor);assert.equal(approved.status,200,JSON.stringify(approved.data));return pending.data.action.id;}
 async function start(){
  let logs='',exited=false;const child=spawn(process.execPath,[ENTRY],{cwd:ROOT,env,stdio:['ignore','pipe','pipe']});children.add(child);
  const capture=bytes=>{logs=(logs+bytes.toString()).slice(-80000);};child.stdout.on('data',capture);child.stderr.on('data',capture);
  const ended=new Promise(resolve=>child.once('exit',(code,signal)=>{exited=true;children.delete(child);resolve({code,signal});}));
  const began=Date.now();let ready=false;while(Date.now()-began<22000&&!exited){try{if((await call('/readyz')).status===200){ready=true;break;}}catch{}await delay(60);}
  assert.ok(ready,'server did not become ready: '+logs);
  return {get logs(){return logs;},async resetExit(){const outcome=await within(ended,12000);assert.ok(!outcome.timeout,'reset did not drain and exit: '+logs);assert.equal(outcome.code,1,logs);await assert.rejects(call('/readyz'));},async stop(){if(exited)return;child.kill('SIGTERM');const outcome=await within(ended,11000);assert.ok(!outcome.timeout,'shutdown timeout: '+logs);assert.equal(outcome.code,0,logs);}};
 }
 try{
  script(env,`
   const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');require(M.utilities).EnsureDirs();require(M.database).LoadDatabase();
   const b=require(M.bootstrap),f=require(M.fixture),l=require(M.licenses),s=require(M.state);
   for(const role of ['A','B','O'])b.Publish(role,'80.0.0',f.PE(role));
   const license=l.Create({requestId:crypto.randomUUID(),label:'synthetic web reset'},'RESET_TEST').license;f.Begin(f.Device());
   require(M.workspace).Atomic(value=>{value.metadata[license.id]={note:'synthetic reset',tags:['fixture'],revision:1};});
   const req={headers:${JSON.stringify(Object.fromEntries(Object.entries(ingress).map(([k,v])=>[k.toLowerCase(),v])))},socket:{remoteAddress:'127.0.0.1'}};
   const web=require(M.web),pk=require(M.passkey),wire=require(M.wire),session=web.Login(req,'admin',process.env.ADMIN_SECRET).session;
   if(!session)throw Error('SYNTHETIC_LOGIN_FAILED');const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),begin=pk.RegistrationBegin(session,req),registration=wire.Registration('admin.example.test',pair.publicKey);
   const enrolled=pk.RegistrationFinish(session,req,{...registration,challengeId:begin.challengeId,clientDataJSON:wire.b64(JSON.stringify({type:'webauthn.create',challenge:begin.publicKey.challenge,origin:'https://admin.example.test'})),name:'synthetic reset credential'});
   if(!enrolled.ok)throw Error(JSON.stringify(enrolled));
   require(M.audit).Run('SYNTHETIC_RESET_POLICY','RESET_TEST',{},db=>{const ops=require(M.operations).State();ops.requireCozyProtection=true;ops.requirePackingEvidence=true;ops.requireBuildContract=true;ops.requireTestEvidence=true;ops.releaseGovernance.requireManifest=true;ops.releaseGovernance.minimumSecurityVersion=4;require(M.operations).ValidateState(ops);db.securityOperations=ops;});
   require(M.machine).Load();require(M.integrity).Policy();if(!require(M.database).SaveDatabase())throw Error('FIXTURE_SAVE_FAILED');
   const head=file=>JSON.parse(fs.readFileSync(file)).body.current;
   new(require(M.witness).WitnessFile)(${JSON.stringify(witness)}).enroll({DESKTOP_JOURNAL:head(path.join(process.env.DATA_DIR,'desktop-license-journal.jsonl.head')),DESKTOP_MACHINE_POLICY:head(path.join(process.env.DATA_DIR,'desktop-machine-policy/journal.jsonl.head')),DESKTOP_BOOTSTRAP:head(path.join(process.env.DATA_DIR,'desktop-bootstrap/authority.json.head')),DESKTOP_INTEGRITY:head(require(M.integrity).FILE+'.head')});
   require(M.sqlite).Close();console.log('WEB_RESET_TEST:'+JSON.stringify({seeded:true}));`);
  env.DESKTOP_RECOVERY_WITNESS_DIR=witness;env.DESKTOP_RECOVERY_WITNESS_REQUIRED='1';
  const before=script(env,SNAPSHOT);assert.equal(before.counts.artifacts,3);assert.equal(before.counts.licenses,1);assert.ok(before.counts.issuedLaunchers>0);assert.equal(Object.keys(before.passkeys).length,1);
  const first=await start(),admin=await login(),viewer=await login('viewer'),other=await login();
  assert.equal((await call(ROUTE)).status,401);assert.equal((await call(ROUTE,undefined,viewer)).status,403);
  const initial=await call(ROUTE,undefined,admin);assert.equal(initial.status,200,JSON.stringify(initial.data));assert.deepEqual(initial.data.counts,before.counts);assert.equal(initial.data.operation,null);
  const id=crypto.randomBytes(32).toString('hex'),body={requestId:id,scope:SCOPE,confirmation:'전체 초기화',expectedEpoch:initial.data.epoch};
  assert.equal((await call(ROUTE,body)).status,401);assert.equal((await call(ROUTE,body,viewer)).status,403);
  assert.equal((await call(ROUTE,body,admin,{'X-CSRF-Token':''})).data.error,'CSRF_FAILED');
  const pending=await call(ROUTE,body,admin);assert.equal(pending.status,428,JSON.stringify(pending.data));assert.equal(pending.data.error,'ADMIN_ACTION_REQUIRED');assert.equal((await call(ROUTE,undefined,admin)).data.operation,null,'merely requesting approval must not enqueue a reset');
  const action=pending.data.action;
  assert.equal((await call('/api/session/reauthenticate',{password:env.ADMIN_SECRET,actionId:action.id},other)).data.error,'ADMIN_ACTION_INVALID','another valid admin session cannot approve this reset');
  assert.equal((await call('/api/session/reauthenticate',{password:env.ADMIN_SECRET,actionId:action.id},admin)).status,200);
  assert.equal((await call(ROUTE,{...body,expectedEpoch:body.expectedEpoch+1},admin,{'X-Admin-Action':action.id})).data.error,'ADMIN_ACTION_CHANGED','approved reset body is immutable');
  const wrong={...body,confirmation:'초기화'},wrongAction=await approve(admin,wrong);const wrongResult=await call(ROUTE,wrong,admin,{'X-Admin-Action':wrongAction});assert.equal(wrongResult.status,400,JSON.stringify(wrongResult.data));assert.equal((await call(ROUTE,undefined,admin)).data.operation,null);
  const stale={...body,expectedEpoch:body.expectedEpoch+1},staleAction=await approve(admin,stale);const staleResult=await call(ROUTE,stale,admin,{'X-Admin-Action':staleAction});assert.equal(staleResult.status,409,JSON.stringify(staleResult.data));
  const authorized=await approve(admin,body),queued=await call(ROUTE,body,admin,{'X-Admin-Action':authorized});assert.equal(queued.status,202,JSON.stringify(queued.data));assert.equal(queued.data.operation.id,id);assert.equal(queued.data.restartRequired,true);await first.resetExit();
  const resumed=await start();assert.match(resumed.logs,/REGISTRATION_RESET_COMPLETE/);assert.ok(resumed.logs.indexOf('REGISTRATION_RESET_COMPLETE')<resumed.logs.indexOf('CONNECT_TLS_LISTENER_READY'));
  const reconnected=await login(),complete=await call(ROUTE+'?requestId='+id,undefined,reconnected);assert.equal(complete.status,200,JSON.stringify(complete.data));assert.equal(complete.data.operation.id,id);assert.equal(complete.data.operation.status,'COMPLETE');assert.ok(Object.values(complete.data.counts).every(value=>value===0));
  assert.equal((await call('/api/session',undefined,admin)).status,401,'restart must invalidate previous in-memory sessions');await resumed.stop();
  const after=script(env,SNAPSHOT);assert.ok(Object.values(after.counts).every(value=>value===0));assert.deepEqual(after.keys,before.keys);assert.deepEqual(after.secrets,before.secrets);assert.deepEqual(after.passkeys,before.passkeys);
  for(const [store,fields]of Object.entries({machine:['bindings','receipts'],integrity:['records','baselines','observations'],workspace:['metadata','jobs','receipts','releaseNotes']}))for(const field of fields)assert.equal(after.related[store][field],0,'related registration data must be empty: '+store+'.'+field);
  for(const flag of ['requireCozyProtection','requirePackingEvidence','requireBuildContract','requireTestEvidence'])assert.equal(after.operations[flag],true,'enabled security policy must remain enabled: '+flag);assert.equal(after.operations.releaseGovernance.minimumSecurityVersion,4);
  for(const file of before.artifactFiles)assert.equal(fs.existsSync(file),false,'owned registration EXE must be removed');
  for(const domain of ['DESKTOP_BOOTSTRAP','DESKTOP_JOURNAL','DESKTOP_MACHINE_POLICY','DESKTOP_INTEGRITY'])assert.ok(after.witness.heads[domain].current.seq>before.witness.heads[domain].current.seq,'witness must advance '+domain);
  assert.equal(after.witness.installationId,before.witness.installationId);
  script(env,`require(M.utilities).EnsureDirs();require(M.database).LoadDatabase();require(M.licenses).Create({requestId:require('node:crypto').randomUUID(),label:'created after web reset'},'RESET_TEST');if(!require(M.database).SaveDatabase())throw Error('FIXTURE_SAVE_FAILED');require(M.sqlite).Close();console.log('WEB_RESET_TEST:'+JSON.stringify({created:true}));`);
  const replayed=await start(),newAdmin=await login(),current=await call(ROUTE,undefined,newAdmin);assert.equal(current.data.counts.licenses,1);
  const retryBody={...body,expectedEpoch:current.data.epoch},retryAction=await approve(newAdmin,retryBody),retry=await call(ROUTE,retryBody,newAdmin,{'X-Admin-Action':retryAction});
  assert.ok([200,202,409].includes(retry.status),JSON.stringify(retry.data));
  // A spent request ID may report the original completion or refuse replay,
  // but it must never delete registrations created after its first reset.
  await delay(300);assert.equal((await call(ROUTE,undefined,newAdmin)).data.counts.licenses,1);await replayed.stop();assert.equal(script(env,SNAPSHOT).counts.licenses,1);
  console.log('PASS web reset: real HTTP/SQLite/witness, admin+CSRF+one-use exact action, restart resume, file cleanup, keys/passkeys/floors preserved and spent request replay');
 }finally{
  for(const child of children){const ended=new Promise(resolve=>child.once('exit',resolve));child.kill('SIGKILL');await ended;}
  fs.rmSync(temporary,{recursive:true,force:true});
 }
})().catch(error=>{console.error(error.stack||error.message);process.exitCode=1;});
