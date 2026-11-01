'use strict';
// Real signatures and durable isolated authority store; synthetic PE fixtures
// are never executed and create no Windows or production approval evidence.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),child=require('node:child_process');
if(process.argv[2]!=='--keyring-child'){
 test('issued A generations preserve exact bytes and revoke durable authority',{timeout:60000},()=>{
  const owned=fs.mkdtempSync(path.join(os.tmpdir(),'peace-issued-keyring-')),env={...process.env,COZY_KEYRING_TEST_DIR:owned};delete env.NODE_TEST_CONTEXT;
  try{const result=child.spawnSync(process.execPath,['--test-reporter=tap',__filename,'--keyring-child'],{env,encoding:'utf8',timeout:50000,maxBuffer:4*1024*1024,windowsHide:true});
   if(result.stdout)process.stdout.write(result.stdout);assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr||result.stdout);
   assert.match(result.stdout,/# tests 9\b/);assert.match(result.stdout,/# pass 9\b/);
  }finally{fs.rmSync(owned,{recursive:true,force:true});}
 });
}else{
 const owned=process.env.COZY_KEYRING_TEST_DIR;assert.ok(path.isAbsolute(owned)&&path.basename(owned).startsWith('peace-issued-keyring-'));
 Object.assign(process.env,{DATA_DIR:owned,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131',ADMIN_SECRET:'keyring-test-only-admin',VIEWER_SECRET:'keyring-test-only-viewer',WEB_ADMIN_TRANSPORT:'proxy',WEB_ADMIN_TRUSTED_PROXIES:'127.0.0.1/32,::1/128',WEB_ADMIN_REQUIRE_HTTPS:'1',WEB_ADMIN_SECURE_COOKIE:'1',WEBAUTHN_RP_ID:'localhost',WEBAUTHN_ORIGIN:'https://localhost',WEB_ADMIN_LOGIN_IP_MAX:'1000',WEB_ADMIN_LOGIN_ROLE_MAX:'1000'});
 delete process.env.DESKTOP_ISSUED_A_SIGNING_KEYS_JSON;console.log=()=>{};
 require('../../core/peace.utilities').EnsureDirs();require('../../services/network/peace.connect-tls').Public();
 const signing=require('../../services/bootstrap/peace.issued-a-signing'),ring=require('../../services/bootstrap/peace.issued-a-keyring');
 const store=require('../../services/bootstrap/peace.desktop-bootstrap-store'),fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');
 const boot=require('../../services/bootstrap/peace.desktop-bootstrap'),keytool=require('../../tools/security/peace.issued-a-signing-key');
 const templates=fixture.CurrentCohort(),oldId=templates.issuerKeyId,oldPrivate=process.env[signing.ENV];
 const request={requestId:crypto.randomUUID(),label:'same immutable issuance'},issued=boot.IssueLauncher(request,'TEST'),oldBytes=boot.LauncherBytes(issued.launcherId);
 const oldReceipt=structuredClone(store.Load().launchers[issued.launcherId].finalIssuedSignature),config=fixture.Config(oldBytes);
 const activeIssue=boot.IssueLauncher({requestId:crypto.randomUUID()},'TEST'),active=fixture.BeginIssued(fixture.Device(),activeIssue);
 const pair=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537}),identity=signing.PublicIdentity(pair.publicKey),newId=identity.keyId;
 const encoded=Buffer.from(pair.privateKey.export({type:'pkcs8',format:'pem'})).toString('base64');
 const newTemplate=require('../fixtures/bootstrap/peace.issued-a-fixture').WithAnchor(fixture.PE('A','new key exact template'),pair.publicKey);
 const reject=(fn,code)=>assert.throws(fn,{message:code});let newMade;
 test('status is read-only, public and legacy behavior unchanged until initialization',()=>{
  const before=JSON.stringify(store.Load());const view=ring.Status();assert.equal(view.managed,false);assert.equal(view.revision,0);assert.equal(view.legacyKeyId,oldId);
  assert.equal(JSON.stringify(store.Load()),before);assert.equal(view.privateMaterialIncluded,false);assert.equal(view.offlineRevocation,false);
  const text=JSON.stringify(view);assert.equal(text.includes(oldPrivate),false);assert.equal(text.includes('PRIVATE KEY'),false);
  assert.equal(boot.IssueLauncher(request,'TEST').launcherId,issued.launcherId);assert.deepEqual(boot.LauncherBytes(issued.launcherId),oldBytes);
  process.env[signing.KEYS_ENV]=JSON.stringify({[newId]:encoded});reject(()=>signing.Create(newTemplate,config),'ISSUED_A_KEYRING_REQUIRED');
  delete process.env[signing.ENV];reject(()=>signing.Create(newTemplate,config),'ISSUED_A_KEYRING_REQUIRED');process.env[signing.ENV]=oldPrivate;
  const initialized=ring.Mutate({action:'initialize',expectedRevision:0},'TEST');assert.equal(initialized.status.revision,1);assert.equal(initialized.status.keys[0].state,'ACTIVE');
 });
 test('new public generation matches private possession, exact template and key purpose',()=>{
  reject(()=>ring.Mutate({action:'register',expectedRevision:0,publicKey:keytool.PublicJSON(identity)},'TEST'),'ISSUED_A_KEYRING_CONFLICT');
  reject(()=>ring.Mutate({action:'register',expectedRevision:1,publicKey:{...keytool.PublicJSON(identity),privateKey:encoded}},'TEST'),'ISSUED_A_PUBLIC_JSON_INVALID');
  const registered=ring.Mutate({action:'register',expectedRevision:1,publicKey:keytool.PublicJSON(identity)},'TEST');assert.equal(registered.status.revision,2);
  assert.deepEqual(registered.status.keys.map(r=>r.state),['ACTIVE','ACTIVE']);assert.equal(registered.status.keys.find(r=>r.keyId===newId).generation,2);
  newMade=signing.Create(newTemplate,config);assert.equal(newMade.receipt.keyId,newId);assert.equal(signing.Create(templates.outputs.A.bytes,config).receipt.keyId,oldId);
  assert.equal(signing.VerifyFinal(newMade.bytes,{expectedTemplateSha512:fixture.sha512(newTemplate),expectedKeyId:newId}).keyId,newId);
  reject(()=>signing.VerifyFinal(newMade.bytes,{expectedTemplateSha512:fixture.sha512(newTemplate),expectedKeyId:oldId}),'ISSUED_A_TRUST_CONTEXT_MISMATCH');
  assert.equal(JSON.stringify(store.Load().issuedAKeyring).includes(encoded),false);
  const before=JSON.stringify(store.Load().issuedAKeyring);process.env[signing.KEYS_ENV]=JSON.stringify({[oldId]:encoded});
  reject(()=>signing.Create(newTemplate,config),'ISSUED_A_SIGNING_KEY_INVALID');assert.equal(JSON.stringify(store.Load().issuedAKeyring),before);
  process.env[signing.KEYS_ENV]=JSON.stringify({[newId]:encoded});
  const conflict=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),conflictId=signing.PublicIdentity(conflict.publicKey);
  require('../../services/security/peace.desktop-key-purposes').Reserve(conflict.publicKey,'SERVER_TRANSPORT');
  process.env[signing.KEYS_ENV]=JSON.stringify({[newId]:encoded,[conflictId.keyId]:Buffer.from(conflict.privateKey.export({type:'pkcs8',format:'pem'})).toString('base64')});
  reject(()=>ring.Mutate({action:'register',expectedRevision:2,publicKey:keytool.PublicJSON(conflictId)},'TEST'),'SECURITY_KEY_PURPOSE_CONFLICT');
  process.env[signing.KEYS_ENV]=JSON.stringify({[newId]:encoded});
 });
 test('retiring forbids fresh signatures but keeps exact retry and download without old private key',()=>{
  ring.Mutate({action:'state',expectedRevision:2,keyId:oldId,state:'RETIRING'},'TEST');delete process.env[signing.ENV];
  assert.equal(signing.Readiness(templates.outputs.A.bytes).reason,'ISSUED_A_SIGNING_KEY_RETIRING');
  reject(()=>boot.IssueLauncher({requestId:crypto.randomUUID()},'TEST'),'ISSUED_A_SIGNING_KEY_RETIRING');
  assert.equal(boot.IssueLauncher(request,'TEST').launcherId,issued.launcherId);assert.deepEqual(boot.LauncherBytes(issued.launcherId),oldBytes);
  assert.deepEqual(store.Load().launchers[issued.launcherId].finalIssuedSignature,oldReceipt);
  assert.deepEqual(signing.Materialize(newTemplate,newMade.receipt),newMade.bytes);
  assert.doesNotThrow(()=>ring.AssertLauncher(store.Load().launchers[activeIssue.launcherId]));
  reject(()=>ring.Mutate({action:'state',expectedRevision:3,keyId:oldId,state:'ACTIVE'},'TEST'),'ISSUED_A_KEYRING_INPUT_INVALID');
 });
 test('revocation closes live authority and unused A atomically without rewriting old signatures',()=>{
  const before=structuredClone(store.Load().launchers[issued.launcherId].finalIssuedSignature);
  const changed=ring.Mutate({action:'state',expectedRevision:3,keyId:oldId,state:'REVOKED'},'TEST');assert.equal(changed.status.revision,4);
  assert.equal(store.Load().launchers[issued.launcherId].status,'REVOKED');assert.equal(store.Load().flows[active.begin.flowId].status,'REVOKED');assert.equal(store.Load().launchers[activeIssue.launcherId].status,'REVOKED');
  assert.equal(store.Load().launchers[issued.launcherId].profile,undefined);assert.deepEqual(store.Load().launchers[issued.launcherId].finalIssuedSignature,before);
  reject(()=>signing.Materialize(templates.outputs.A.bytes,oldReceipt),'ISSUED_A_SIGNING_KEY_REVOKED');
  assert.throws(()=>boot.LauncherBytes(issued.launcherId));assert.throws(()=>fixture.Download(active.begin));
  reject(()=>ring.Mutate({action:'state',expectedRevision:4,keyId:oldId,state:'RETIRING'},'TEST'),'ISSUED_A_KEY_REVOKED_IRREVERSIBLE');
  // The unchanged offline V1 verifier proves bytes, not current server policy.
  assert.equal(signing.VerifyFinal(oldBytes,{expectedTemplateSha512:oldReceipt.templateSha512,expectedKeyId:oldId}).keyId,oldId);
  process.env[signing.ENV]=oldPrivate;assert.equal(signing.Readiness(templates.outputs.A.bytes).reason,'ISSUED_A_SIGNING_KEY_REVOKED');
 });
 test('server environment removal and process restart cannot resurrect revoked generation',()=>{
  const copy=fs.mkdtempSync(path.join(os.tmpdir(),'peace-keyring-restart-'));try{
   fs.cpSync(owned,copy,{recursive:true});const env={...process.env,DATA_DIR:copy};delete env[signing.ENV];delete env[signing.KEYS_ENV];delete env.NODE_TEST_CONTEXT;
   const script=`const r=require(process.argv[1]);const s=r.Status();if(s.revision!==4)throw Error('revision');try{r.AssertUse(process.argv[2]);throw Error('accepted');}catch(e){if(e.message!=='ISSUED_A_SIGNING_KEY_REVOKED')throw e;}process.stdout.write('persisted-revocation');`;
   const out=child.spawnSync(process.execPath,['-e',script,require.resolve('../../services/bootstrap/peace.issued-a-keyring'),oldId],{env,encoding:'utf8',timeout:10000});
   assert.equal(out.status,0,out.stderr);assert.equal(out.stdout,'persisted-revocation');
  }finally{fs.rmSync(copy,{recursive:true,force:true});}
 });
 test('stored ring validates bounded unique generations and irreversible public state',()=>{
  const current=structuredClone(store.Load().issuedAKeyring);assert.equal(ring.ValidateState(current),current);
  for(const change of [s=>s.revision=0,s=>s.nextGeneration++,s=>s.keys[newId].generation=s.keys[oldId].generation,s=>s.keys[oldId].state='active',s=>s.keys[oldId].privateKey='forbidden',s=>s.keys[oldId].changedAt=0]){
   const invalid=structuredClone(current);change(invalid);reject(()=>ring.ValidateState(invalid),'ISSUED_A_KEYRING_STORAGE_INVALID');
  }
  reject(()=>ring.AssertUse('f'.repeat(64)),'ISSUED_A_SIGNING_KEY_UNKNOWN');
 });
 test('keypool rejects duplicate identity, duplicate JSON keys and invalid declared identity',()=>{
  for(const input of [JSON.stringify({[oldId]:oldPrivate}),`{"${newId}":"${encoded}","${newId}":"${encoded}"}`,JSON.stringify({['f'.repeat(64)]:encoded})]){
   process.env[signing.KEYS_ENV]=input;reject(()=>signing.ConfiguredPublic(),'ISSUED_A_SIGNING_KEY_INVALID');
  }
  process.env[signing.KEYS_ENV]=JSON.stringify({[newId]:encoded});assert.equal(signing.ConfiguredPublic().length,2);
 });
 test('migration imports historical receipt keys as verify-only without old private material',()=>{
  const separate=fs.mkdtempSync(path.join(os.tmpdir(),'peace-keyring-history-'));try{
   const env={...process.env,DATA_DIR:separate};delete env[signing.ENV];delete env[signing.KEYS_ENV];delete env.NODE_TEST_CONTEXT;
   const script=`console.log=()=>{};const assert=require('node:assert/strict');require(process.argv[1]).EnsureDirs();require(process.argv[2]).Public();const f=require(process.argv[3]),b=require(process.argv[4]),s=require(process.argv[5]),r=require(process.argv[6]),store=require(process.argv[7]);const old=f.CurrentCohort(),issue=b.IssueLauncher({requestId:require('node:crypto').randomUUID()},'TEST'),bytes=b.LauncherBytes(issue.launcherId),row=structuredClone(store.Load().launchers[issue.launcherId]);const next=f.CurrentCohort({rotateIssuer:true,version:'81.0.0'});const out=r.Mutate({action:'initialize',expectedRevision:0},'TEST');assert.equal(out.status.keys.find(k=>k.keyId===old.issuerKeyId).state,'RETIRING');assert.equal(out.status.keys.find(k=>k.keyId===old.issuerKeyId).privateKeyConfigured,false);assert.equal(out.status.keys.find(k=>k.keyId===next.issuerKeyId).state,'ACTIVE');assert.deepEqual(s.Materialize(old.outputs.A.bytes,row.finalIssuedSignature,row),bytes);process.stdout.write('legacy-import-preserved');`;
   const out=child.spawnSync(process.execPath,['-e',script,require.resolve('../../core/peace.utilities'),require.resolve('../../services/network/peace.connect-tls'),require.resolve('../../tests/fixtures/bootstrap/peace.desktop-bootstrap-fixture'),require.resolve('../../services/bootstrap/peace.desktop-bootstrap'),require.resolve('../../services/bootstrap/peace.issued-a-signing'),require.resolve('../../services/bootstrap/peace.issued-a-keyring'),require.resolve('../../services/bootstrap/peace.desktop-bootstrap-store')],{env,encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
   assert.equal(out.status,0,out.stderr);assert.equal(out.stdout,'legacy-import-preserved');
  }finally{fs.rmSync(separate,{recursive:true,force:true});}
 });
 test('HTTP key administration requires admin, CSRF and exact one-use action approval',async()=>{
  const http=require('node:http'),{RequestHandler}=require('../../web/http/peace.web-server');
  const server=http.createServer((req,res)=>Promise.resolve(RequestHandler(req,res)).catch(e=>{res.statusCode=500;res.end(JSON.stringify({error:e.message}));}));
  const call=(url,body,actor,headers={})=>new Promise((resolve,reject)=>{
   const bytes=body===undefined?null:Buffer.from(JSON.stringify(body)),req=http.request({host:'127.0.0.1',port:server.address().port,path:url,method:bytes?'POST':'GET',headers:{Host:'localhost','X-Forwarded-Proto':'https',...(actor?{Cookie:actor.cookie,'X-CSRF-Token':actor.csrf}:{}),...(bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{}),...headers}},res=>{let data='';res.on('data',b=>data+=b);res.on('end',()=>{try{resolve({status:res.statusCode,data:JSON.parse(data),headers:res.headers});}catch(error){reject(error);}});});
   req.on('error',reject);req.setTimeout(5000,()=>req.destroy(Error('TEST_TIMEOUT')));req.end(bytes);
  });
  try{
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
   async function login(role){const out=await call('/api/login',{role,password:role==='admin'?process.env.ADMIN_SECRET:process.env.VIEWER_SECRET});assert.equal(out.status,200);return {cookie:out.headers['set-cookie'][0].split(';')[0],csrf:out.data.csrf};}
   const admin=await login('admin'),viewer=await login('viewer'),url='/api/desktop/bootstrap/security-operations/issued-a-keys',body={action:'state',expectedRevision:4,keyId:newId,state:'RETIRING'};
   assert.equal((await call(url)).status,401);assert.equal((await call(url,undefined,viewer)).status,403);
   const status=await call(url,undefined,admin);assert.equal(status.status,200);assert.equal(status.data.revision,4);assert.equal(status.data.privateMaterialIncluded,false);
   assert.equal((await call(url,body,viewer)).status,403);assert.equal((await call(url,body,admin,{'X-CSRF-Token':''})).data.error,'CSRF_FAILED');
   const pending=await call(url,body,admin);assert.equal(pending.status,428);assert.equal(pending.data.error,'ADMIN_ACTION_REQUIRED');assert.equal(ring.State().revision,4);
   assert.equal((await call('/api/session/reauthenticate',{password:process.env.ADMIN_SECRET,actionId:pending.data.action.id},admin)).status,200);
   const result=await call(url,body,admin,{'X-Admin-Action':pending.data.action.id});assert.equal(result.status,200,JSON.stringify(result.data));assert.equal(result.data.status.revision,5);
   assert.equal((await call(url,body,admin,{'X-Admin-Action':pending.data.action.id})).data.error,'ADMIN_ACTION_INVALID');assert.equal(ring.State().revision,5);
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 });
}
