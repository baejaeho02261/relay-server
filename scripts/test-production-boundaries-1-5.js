'use strict';
// Production guard/session, route dispatch, receipt and governance code is run.
// The route tests use a real loopback HTTP socket and a test-owned in-memory
// authority store/audit/file reader. They are NOT the complete web server,
// SQLite durability, a native PE test or a real Windows CI PASS.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs');
const path=require('node:path'),os=require('node:os'),http=require('node:http'),vm=require('node:vm'),Module=require('node:module');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-boundaries-1-5-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-ADMIN-1-5',VIEWER_SECRET:'SYNTHETIC-VIEWER-1-5',OPERATOR_SECRET:'SYNTHETIC-OPERATOR-1-5',WEB_ADMIN_TRUSTED_PROXIES:'127.0.0.1/32',DESKTOP_ADMIN_REAUTH_REQUIRED:'0',WEB_ADMIN_LOGIN_IP_MAX:'10000',WEB_ADMIN_LOGIN_ROLE_MAX:'10000',WEB_ADMIN_LOGIN_GLOBAL_MAX:'10000'});
require('../core/utils').EnsureDirs();
const web=require('../web/webAuth'),guard=require('../services/desktopAdminGuard');
const deadline=require('../services/desktopDeadline'),protocol=require('../services/desktopRequestProtocol'),delegation=require('../services/desktopHandoffDelegation');
const prov=require('../services/desktopReleaseProvenance');
const realNow=Date.now,root=path.resolve(__dirname,'..');
let checks=0,server,db,ops,simulatedReadFailure='',simulatedDebugBuild='',failBeforeCommit=false,commits=0;
const test=(name,run)=>{run();checks++;console.log('PASS '+name);};
const atest=async(name,run)=>{await run();checks++;console.log('PASS '+name);};
const reject=(fn,code)=>assert.throws(fn,e=>e.message===code,code);
const sha=x=>crypto.createHash('sha512').update(x).digest('hex');
const mutationRoot='/api/desktop/bootstrap/security-operations';
const request=()=>({headers:{},socket:{remoteAddress:'127.0.0.1',encrypted:true}});
function WithClock(wall,tick,run){
 const {performance}=require('node:perf_hooks'),old=Object.getOwnPropertyDescriptor(performance,'now');
 Date.now=()=>wall;Object.defineProperty(performance,'now',{configurable:true,value:()=>tick});
 try{return run();}finally{Date.now=realNow;if(old)Object.defineProperty(performance,'now',old);else delete performance.now;}
}
const policy={version:1,revision:7,trustedReleaseKeys:[]};
const audit={LogEvent:()=>({ok:true}),WriteHealth:()=>({status:'HEALTHY'})};
const store={Load:()=>db,Atomic:mutate=>{
 const next=structuredClone(db);const result=mutate(next);
 if(failBeforeCommit)throw Error('SYNTHETIC_BEFORE_COMMIT');
 ops.ValidateState(next.securityOperations);db=next;commits++;return result;
}};
const authority={Policy:()=>structuredClone(policy),ArtifactReason:()=>'',InvalidateAll:()=>{}};
const bootstrap={ReadArtifactBytes:row=>{
 if(row.id===simulatedReadFailure){const e=Error('BOOTSTRAP_ARTIFACT_INVALID');e.desktopError=true;e.status=409;throw e;}
 // File/hash verification remains mocked in this governance fixture. Return
 // structurally valid synthetic PE bytes for the real configuration gate.
 return row.id===simulatedDebugBuild?require('./test-pe-build-configuration').Fixture(['GAME_BUILD_DEBUG_V1']):require('./desktop-bootstrap-fixture').PE(row.component);
}};
const productionFiles=['services/desktopSecurityOperations.js','web/routes/desktopSecurityRoutes.js'];
const loaded=new Map(),mocks=new Map([
 [path.join(root,'services/desktopBootstrapStore.js'),store],
 [path.join(root,'services/desktopSecurityAuthority.js'),authority],
 [path.join(root,'services/desktopBootstrap.js'),bootstrap],
 [path.join(root,'storage/audit.js'),audit],
 [path.join(root,'services/desktopOperationAudit.js'),{Run:(_kind,_actor,_details,mutate)=>store.Atomic(mutate)}],
 [path.join(root,'services/desktopKeyPurposes.js'),{Reserve(){},Assert(){},Summary:()=>({scope:'TEST_MEMORY_ONLY'})}],
 [path.join(root,'services/haCoordinator.js'),{CanAcceptTraffic:()=>true}],
 [path.join(root,'web/apiContext.js'),{
   Json(res,status,value){res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(value));},
   ApiError(res,status,reason){res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify({ok:false,reason}));}
 }]
]);
function load(file){
 file=path.resolve(root,file);if(mocks.has(file))return mocks.get(file);if(loaded.has(file))return loaded.get(file).exports;
 if(!productionFiles.includes(path.relative(root,file).split(path.sep).join('/')))return require(file);
 const module={exports:{}},base=Module.createRequire(file);loaded.set(file,module);
 const local=name=>{const target=base.resolve(name);return mocks.has(target)?mocks.get(target):productionFiles.some(x=>path.join(root,x)===target)?load(target):base(name);};
 vm.runInThisContext(Module.wrap(fs.readFileSync(file,'utf8')),{filename:file})(module.exports,local,module,file,path.dirname(file));
 return module.exports;
}
function artifact(component,n){return{id:(n*10+'ABO'.indexOf(component)+1).toString(16).padStart(24,'0').toUpperCase(),component,version:'100.'+n,sha512:sha(component+n),protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,authorityVersion:1,measurementPlanVersion:1,tlsPinVersion:1};}
const first=Object.fromEntries(['A','B','O'].map(k=>[k,artifact(k,1)])),second=Object.fromEntries(['A','B','O'].map(k=>[k,artifact(k,2)]));
const selected=c=>({aId:c.A.id,bId:c.B.id,oId:c.O.id});
const activation=c=>({expectedRevision:ops.Revision(),expectedPolicyRevision:policy.revision,...selected(c)});
function manifest(c,n){return{version:1,releaseName:'SYNTHETIC-NOT-WINDOWS-'+n,securityVersion:n,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,sourceManifestSha512:'1'.repeat(128),policySha512:prov.PolicyDigest(policy),toolchain:{delphi:'NOT_RUN',cpp:'NOT_RUN',windowsSdk:'NOT_RUN',imgui:'SYNTHETIC'},artifacts:Object.fromEntries(['A','B','O'].map(k=>[k,c[k].sha512]))};}
function key(){const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');return{privateKey,publicKey:publicKey.export({type:'spki',format:'pem'}).toString(),keyId:prov.KeyId(publicKey)};}
const oldKey=key(),newKey=key();let issued=realNow();
function addKey(k){return ops.SetCiSigner({expectedRevision:ops.Revision(),keyId:k.keyId,publicKey:k.publicKey,notBefore:realNow()-60000,notAfter:realNow()+3600000,state:'ACTIVE'},'SYNTHETIC');}
function envelope(k,m,result='PASS'){
 const statement={version:1,purpose:prov.CI_DOMAIN,manifestId:prov.ManifestId(m),runId:'SYNTHETIC-UNIT-NOT-A-REAL-CI-RUN-'+(++issued),issuedAt:issued,nativeBuild:result,apiProbe:result,integration:result,logsSha512:'2'.repeat(128)};
 return{keyId:k.keyId,statement,signature:crypto.sign(null,Buffer.from(prov.Canonical(statement)),k.privateKey).toString('base64')};
}
function record(k,m,result='PASS'){return ops.RecordCiEvidence({expectedRevision:ops.Revision(),envelope:envelope(k,m,result)},'SYNTHETIC');}
function call(route,body,session,csrf=true){
 return new Promise((resolve,rejectPromise)=>{
  const bytes=body===undefined?null:Buffer.from(JSON.stringify(body));
  const req=http.request({host:'127.0.0.1',port:server.address().port,path:mutationRoot+'/'+route,method:bytes?'POST':'GET',headers:{'X-Forwarded-Proto':'https',...(bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{}),...(session?{Cookie:web.COOKIE_NAME+'='+session.token,'X-CSRF-Token':csrf?session.csrf:'wrong'}:{})}},res=>{
   let text='';res.on('data',x=>text+=x);res.on('end',()=>{try{resolve({status:res.statusCode,body:JSON.parse(text)});}catch(e){rejectPromise(e);}});
  });req.on('error',rejectPromise);req.setTimeout(5000,()=>req.destroy(Error('TEST_HTTP_TIMEOUT')));req.end(bytes);
 });
}
(async()=>{try{
 test('1.4 critical floor cannot be disabled by an unset/zero legacy environment flag',()=>{
  const paths=['security-authority','integrity-policy','module-baselines',...['controls','contracts','signers','rollout','test-evidence','activate','enable-all','release-governance','ci-signers','ci-evidence','recovery/prepare','recovery/apply'].map(x=>'security-operations/'+x)];
  for(const flag of ['', '0','1']){process.env.DESKTOP_ADMIN_REAUTH_REQUIRED=flag;for(const p of paths)assert(guard.ReauthenticationRequired('/api/desktop/bootstrap/'+p),p);}
  process.env.DESKTOP_ADMIN_REAUTH_REQUIRED='0';assert.equal(guard.Status().criticalReauthenticationMandatory,true);
 });
 test('1.4 read-only previews/candidates/planning are not silently made critical mutations',()=>{
  for(const action of ['plan-release','release-manifests','preview-pair','preview-rollout','preview-enable-all'])assert.equal(guard.ReauthenticationRequired(mutationRoot+'/'+action),false,action);
  assert.equal(guard.ReauthenticationRequired('/api/desktop/bootstrap/artifacts'),false);
  for(const method of ['GET','HEAD','OPTIONS'])assert.equal(guard.ReauthenticationRequired(mutationRoot+'/activate',method),false);
  process.env.DESKTOP_ADMIN_REAUTH_REQUIRED='1';assert(guard.ReauthenticationRequired(mutationRoot+'/plan-release'));process.env.DESKTOP_ADMIN_REAUTH_REQUIRED='0';
 });
 test('1.4 ordinary session activity does not renew recent authentication',()=>{
  const s=web.Login(request(),'admin',process.env.ADMIN_SECRET).session,start=realNow();Date.now=()=>start+web.REAUTH_MS;
  try{const req={...request(),headers:{cookie:web.COOKIE_NAME+'='+s.token}};assert.equal(web.Authenticate(req),s);assert.equal(guard.CheckSession(s,mutationRoot+'/activate').reason,'ADMIN_REAUTH_REQUIRED');assert.equal(guard.CheckSession(s,mutationRoot+'/preview-pair').ok,true);
   assert.equal(web.Reauthenticate(request(),s,'wrong').ok,false);assert.equal(guard.CheckSession(s,mutationRoot+'/activate').reason,'ADMIN_REAUTH_REQUIRED');
   assert.equal(web.Reauthenticate(request(),s,process.env.ADMIN_SECRET).ok,true);assert.equal(guard.CheckSession(s,mutationRoot+'/activate').ok,true);
  }finally{Date.now=realNow;web.RevokeSession(s.id);}
 });
 test('1.5 credential change/revocation invalidates a previously fresh capability',()=>{
  const s=web.Login(request(),'admin',process.env.ADMIN_SECRET).session;assert.equal(guard.CheckSession(s,mutationRoot+'/activate').ok,true);
  const secret=process.env.ADMIN_SECRET;process.env.ADMIN_SECRET=secret+'-CHANGED';try{assert.equal(guard.CheckSession(s,mutationRoot+'/activate').reason,'ADMIN_SESSION_EXPIRED');}finally{process.env.ADMIN_SECRET=secret;}
 });
 test('2.1 exact wall/monotonic expiry rejects even after wall-clock rollback',()=>{
  for(const ms of [1,5000,15000,30000])WithClock(1000000,500,()=>{
   const d=deadline.After(ms);assert.equal(deadline.Expired(d,{wall:d.expiresAt-1,tick:d.deadline-1}),false);
   assert(deadline.Expired(d,{wall:d.expiresAt,tick:500}));assert(deadline.Expired(d,{wall:1,tick:d.deadline}));
  });
 });
 test('2.2 purpose fingerprints are disjoint for every catalog entry',()=>{
  const names=Object.keys(protocol.catalog),values=names.map(name=>protocol.Fingerprint(name,{requestId:'same-request',payload:'same'}));assert.equal(new Set(values).size,names.length);
  reject(()=>protocol.Resolve('security','redeem'),'SECURITY_INPUT_INVALID');reject(()=>protocol.Resolve('report','claim'),'INTEGRITY_REPORT_INVALID');
 });
 test('2.3 repeated put keeps the first result, metadata and deadline',()=>{
  const r=protocol.CreateReceipts({ttlMs:100,max:2}),b={id:1};
  WithClock(1000,10,()=>r.put('x','authority.submit',b,{lease:1099},{scope:'ORIGINAL'}));
  WithClock(1099,109,()=>{r.put('x','authority.submit',b,{lease:999999},{scope:'CHANGED'});assert.deepEqual(r.get('x','authority.submit',b),{response:{lease:1099},meta:{scope:'ORIGINAL'}});});
  WithClock(1100,110,()=>assert.equal(r.get('x','authority.submit',b),null));
 });
 test('2.3 same receipt ID with changed body/purpose cannot overwrite a committed result',()=>{
  const r=protocol.CreateReceipts();r.put('x','report.submit',{x:1},{ok:true},{});
  for(const method of ['get','put']){reject(()=>r[method]('x','report.submit',{x:2},{ok:false},{}),'REQUEST_ID_REUSED');reject(()=>r[method]('x','authority.submit',{x:1},{ok:false},{}),'REQUEST_ID_REUSED');}
  assert.deepEqual(r.get('x','report.submit',{x:1}).response,{ok:true});
 });
 test('2.3 failed receipt serialization cannot evict a live unrelated result',()=>{
  const r=protocol.CreateReceipts({max:1});r.put('x','authority.submit',{x:1},{ok:true},{});
  assert.throws(()=>r.put('y','authority.submit',{x:2},{callback(){}},{}));assert.equal(r.get('x','authority.submit',{x:1}).response.ok,true);
  const detached=r.get('x','authority.submit',{x:1});detached.response.ok=false;assert.equal(r.get('x','authority.submit',{x:1}).response.ok,true);
 });
 test('2.3 receipt limits/options and monotonic cleanup are fail-closed',()=>{
  for(const options of [{max:0},{ttlMs:0},{max:NaN},{ttlMs:1.1}])reject(()=>protocol.CreateReceipts(options),'DESKTOP_RECEIPT_OPTIONS_INVALID');
  const r=protocol.CreateReceipts({ttlMs:100});WithClock(1000,0,()=>r.put('x','report.submit',{},'ok',{}));WithClock(1,100,()=>assert.equal(r.get('x','report.submit',{}),null));
 });
 test('3.1/3.2 V3 delegation canonical separates parent grant, child claim and B/O role',()=>{
  const parent=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),child=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),nonce='A'.repeat(64),id='B'.repeat(64),canonical='server session / build / expiry';
  const messages=['DELEGATION','CLAIM'].flatMap(kind=>['B','O'].map(role=>delegation.Canonical(kind,role,canonical,id,nonce)));
  assert.equal(new Set(messages).size,4);const signed=crypto.sign('RSA-SHA512',Buffer.from(messages[0]),parent.privateKey);
  assert(crypto.verify('RSA-SHA512',Buffer.from(messages[0]),parent.publicKey,signed));
  for(const message of messages.slice(1))assert.equal(crypto.verify('RSA-SHA512',Buffer.from(message),parent.publicKey,signed),false);
  assert.equal(crypto.verify('RSA-SHA512',Buffer.from(messages[0]),child.publicKey,signed),false);
  assert.notEqual(delegation.Canonical('DELEGATION','B',canonical+'changed',id,nonce),messages[0]);
 });
 ops=load('services/desktopSecurityOperations.js');
 db={revision:0,artifacts:Object.fromEntries([...Object.values(first),...Object.values(second)].map(x=>[x.id,structuredClone(x)])),active:{A:first.A.id,B:first.B.id,O:first.O.id},securityOperations:ops.Defaults()};
 const routes=load('web/routes/desktopSecurityRoutes.js');
 server=http.createServer(async(req,res)=>{
  try{const bytes=[];for await(const part of req)bytes.push(part);const body=bytes.length?require('../services/strictJson').Parse(Buffer.concat(bytes)):{};
   const handled=await routes.Handle({method:req.method,pathname:new URL(req.url,'http://localhost').pathname,body,req,res,session:web.Authenticate(req,false)});
   if(!handled){res.writeHead(404);res.end('{}');}
  }catch(e){if(!res.headersSent)res.writeHead(e.status||400,{'Content-Type':'application/json'});res.end(JSON.stringify({ok:false,reason:e.message}));}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const admin=web.Login(request(),'admin',process.env.ADMIN_SECRET).session,viewer=web.Login(request(),'viewer',process.env.VIEWER_SECRET).session;
 await atest('1.6 production route rejects anonymous/viewer even when called without outer dispatcher',async()=>{
  for(const session of [null,viewer])for(const action of ['activate','ci-signers','release-governance','recovery/prepare','recovery/apply']){const before=JSON.stringify(db);const out=await call(action,activation(first),session);assert.equal(out.status,403,action);assert.equal(JSON.stringify(db),before);}
 });
 await atest('1.4 production route rejects stale reauthentication while preview remains readable',async()=>{
  const start=realNow();Date.now=()=>start+web.REAUTH_MS;
  try{const before=JSON.stringify(db);assert.equal((await call('activate',activation(first),admin)).body.reason,'ADMIN_REAUTH_REQUIRED');
   const preview=await call('preview-pair',selected(first),admin);assert.equal(preview.status,200);assert.equal(preview.body.preview.eligible,false);assert.equal(JSON.stringify(db),before);
  }finally{Date.now=realNow;}
 });
 await atest('1.6 production route still rejects bad CSRF before mutation',async()=>{
  const before=JSON.stringify(db);assert.equal((await call('activate',activation(first),admin,false)).body.reason,'CSRF_FAILED');assert.equal(JSON.stringify(db),before);
 });
 test('4.1/4.2 publication floor is strict even for a stored legacy false/false/0 state',()=>{
  const before=JSON.stringify(db),status=ops.ProductionStatus();assert.equal(status.legacyRuntimePolicy,true);assert.equal(status.requirements.requireManifest,true);assert.equal(status.requirements.requireCiEvidence,false);assert.equal(status.requirements.minimumSecurityVersion,1);
  assert.equal(ops.PreviewPair(selected(first)).eligible,true);assert.equal(ops.PreviewProductionPair(selected(first)).eligible,false);assert.equal(JSON.stringify(db),before);
 });
 await atest('4.1 activation HTTP route cannot opt into the internal CI/legacy compatibility mode',async()=>{
  const before=JSON.stringify(db);assert.equal((await call('activate',activation(first),admin)).body.reason,'SECURITY_RELEASE_MANIFEST_REQUIRED');
  assert.equal((await call('activate',{...activation(first),production:false},admin)).body.reason,'SECURITY_OPERATIONS_INVALID');assert.equal(JSON.stringify(db),before);
 });
 await atest('4.1/4.2/4.5 publication policy HTTP route cannot lower the mandatory floor',async()=>{
  for(const patch of [{requireManifest:false},{requireCiEvidence:true},{minimumSecurityVersion:0}]){
   const before=JSON.stringify(db),out=await call('release-governance',{expectedRevision:ops.Revision(),...patch},admin);
   assert.equal(out.body.reason,'SECURITY_PUBLICATION_REQUIREMENTS_REQUIRED');assert.equal(JSON.stringify(db),before);
  }
 });
 const m1=manifest(first,1),m2=manifest(second,2);
 test('4.1 a planned manifest is not a registered production cohort',()=>{
  ops.PlanReleaseManifest({expectedRevision:ops.Revision(),manifest:m1},'SYNTHETIC');
  assert(ops.PreviewProductionPair(selected(first)).reasons.includes('SECURITY_RELEASE_MANIFEST_NOT_REGISTERED'));
  // Simulate the declaration attached by Stage for this in-memory artifact fixture.
  for(const row of Object.values(first))db.artifacts[row.id].deploymentManifestId=prov.ManifestId(m1);
  ops.RecordReleaseManifest({expectedRevision:ops.Revision(),manifest:m1},'SYNTHETIC');
 });
 test('4.2 manual publication has no fabricated CI result or required operator PASS',()=>{
  const view=ops.PreviewProductionPair(selected(first));assert.equal(view.eligible,true);assert.equal(view.release.ciVerification,'NOT_PROVIDED');assert.equal(view.release.ciOutcomes,null);assert.deepEqual(ops.State().releaseGovernance.ciKeys,{});assert.deepEqual(ops.State().releaseGovernance.ciEvidence,{});
  ops.RecordEvidence({expectedRevision:ops.Revision(),...selected(first),report:{version:1,aSha512:first.A.sha512,bSha512:first.B.sha512,oSha512:first.O.sha512,sourceManifestSha512:m1.sourceManifestSha512,logsSha512:'2'.repeat(128),nativeBuild:'PASS',apiProbe:'PASS',integration:'PASS',note:'SYNTHETIC UNIT FIXTURE; NOT WINDOWS'}},'SYNTHETIC');
  assert.equal(ops.PreviewProductionPair(selected(first)).release.ciOutcomes,null);
 });
 test('4.2 optional signed CI FAIL/NOT_RUN stays accurately reported in manual mode',()=>{
  addKey(oldKey);addKey(newKey);for(const result of ['FAIL','NOT_RUN']){record(oldKey,m1,result);const view=ops.PreviewProductionPair(selected(first));assert.equal(view.eligible,true);assert.equal(view.release.ciOutcomes.nativeBuild,result);}
  record(oldKey,m1);assert.equal(ops.PreviewProductionPair(selected(first)).eligible,true);
 });
 test('4.3 changed purpose or tampered statement fails signature validation',()=>{
  const e=envelope(oldKey,m1);e.statement.logsSha512='9'.repeat(128);reject(()=>ops.RecordCiEvidence({expectedRevision:ops.Revision(),envelope:e},'SYNTHETIC'),'SECURITY_CI_SIGNATURE_INVALID');
  e.statement.purpose='GAME-RELEASE-APPROVAL-V2';reject(()=>ops.RecordCiEvidence({expectedRevision:ops.Revision(),envelope:e},'SYNTHETIC'),'SECURITY_CI_EVIDENCE_INVALID');
 });
 test('4.1 failed final artifact re-read leaves policy and active cohort unchanged',()=>{
  const before=JSON.stringify(db);simulatedReadFailure=first.B.id;try{reject(()=>ops.ActivateProductionPair(activation(first),'SYNTHETIC'),'BOOTSTRAP_ARTIFACT_INVALID');}finally{simulatedReadFailure='';}assert.equal(JSON.stringify(db),before);
 });
 test('4.1 explicit Debug in any role cannot activate and leaves the cohort unchanged',()=>{
  for(const row of Object.values(first)){
   const before=JSON.stringify(db);simulatedDebugBuild=row.id;
   try{reject(()=>ops.ActivateProductionPair(activation(first),'SYNTHETIC'),'SECURITY_DEBUG_BUILD_NOT_PUBLISHABLE');}
   finally{simulatedDebugBuild='';}
   assert.equal(JSON.stringify(db),before);
  }
 });
 test('2.4/4.1 failure before store commit leaves both active pointer and runtime floor unchanged',()=>{
  const before=JSON.stringify(db);failBeforeCommit=true;try{reject(()=>ops.ActivateProductionPair(activation(first),'SYNTHETIC'),'SYNTHETIC_BEFORE_COMMIT');}finally{failBeforeCommit=false;}assert.equal(JSON.stringify(db),before);
 });
 await atest('4.1/4.2 activation route commits verified cohort and strict runtime policy together',async()=>{
  const before=commits,out=await call('activate',activation(first),admin);assert.equal(out.status,200,JSON.stringify(out.body));assert.equal(commits,before+1);
  assert.equal(ops.State().releaseGovernance.requireManifest,true);assert.equal(ops.State().releaseGovernance.requireCiEvidence,false);assert.equal(ops.State().releaseGovernance.minimumSecurityVersion,1);
  assert.equal(ops.State().activations.at(-1).manifestId,prov.ManifestId(m1));assert.equal(ops.ProductionStatus().legacyRuntimePolicy,false);
 });
 test('4.4 retiring a CI key preserves earlier verified proof but rejects new records',()=>{
  ops.SetCiSigner({expectedRevision:ops.Revision(),keyId:oldKey.keyId,state:'RETIRING'},'SYNTHETIC');assert.equal(ops.PreviewProductionPair(selected(first)).eligible,true);reject(()=>record(oldKey,m1),'SECURITY_CI_SIGNER_NOT_ACTIVE');
  record(newKey,m1);ops.SetCiSigner({expectedRevision:ops.Revision(),keyId:oldKey.keyId,state:'REVOKED'},'SYNTHETIC');assert.equal(ops.PreviewProductionPair(selected(first)).eligible,true);
  reject(()=>ops.SetCiSigner({expectedRevision:ops.Revision(),keyId:oldKey.keyId,state:'ACTIVE'},'SYNTHETIC'),'SECURITY_CI_SIGNER_REVOKE_FINAL');
 });
 test('4.6 valid signed release A cannot be mixed with another release O',()=>{
  ops.RecordReleaseManifest({expectedRevision:ops.Revision(),manifest:m2},'SYNTHETIC');record(newKey,m2);
  const body={...selected(first),oId:second.O.id};assert(ops.PreviewProductionPair(body).reasons.includes('SECURITY_RELEASE_MIXED_MANIFEST'));
  const before=JSON.stringify(db);reject(()=>ops.ActivateProductionPair({...activation(first),...body},'SYNTHETIC'),'SECURITY_RELEASE_MIXED_MANIFEST');assert.equal(JSON.stringify(db),before);
 });
 test('4.5 security floor remains monotonic and applies to emergency recovery too',()=>{
  ops.ActivateProductionPair(activation(second),'SYNTHETIC');ops.SetProductionGovernance({expectedRevision:ops.Revision(),minimumSecurityVersion:2},'SYNTHETIC');
  reject(()=>ops.ActivateProductionPair(activation(first),'SYNTHETIC'),'SECURITY_RELEASE_DOWNGRADE');reject(()=>ops.SetProductionGovernance({expectedRevision:ops.Revision(),minimumSecurityVersion:1},'SYNTHETIC'),'SECURITY_RELEASE_FLOOR_IRREVERSIBLE');
  reject(()=>ops.PrepareProductionRecovery({...activation(first),requestId:'synthetic-recovery-01',reason:'SYNTHETIC'},'SYNTHETIC'),'SECURITY_RELEASE_DOWNGRADE');
 });
 await atest('4.5 recovery HTTP route cannot use legacy compatibility to evade production checks',async()=>{
  const out=await call('recovery/prepare',{...activation(first),requestId:'synthetic-recovery-02',reason:'SYNTHETIC'},admin);assert.equal(out.body.reason,'SECURITY_RELEASE_DOWNGRADE');
 });
 test('4.4 optional CI signer revocation invalidates evidence without inventing PASS',()=>{
  ops.SetCiSigner({expectedRevision:ops.Revision(),keyId:newKey.keyId,state:'REVOKED'},'SYNTHETIC');
  ops.RequireRuntimePair(second.A,second.B,second.O);const view=ops.PreviewProductionPair(selected(second));assert.equal(view.eligible,true);assert.equal(view.release.ciVerification,'INVALID_OR_REVOKED');assert.equal(view.release.ciOutcomes,null);
 });
 test('1.5 logout blocks a delayed direct route mutation even with the old CSRF token',()=>{
  web.RevokeSession(admin.id);assert.equal(guard.CheckSession(admin,mutationRoot+'/activate').reason,'ADMIN_SESSION_EXPIRED');
 });
 console.log(JSON.stringify({scope:'PRODUCTION_CODE_WITH_IN_MEMORY_STORE_AND_ROUTE_ADAPTER',groups:checks,fullWebServer:false,nativeDatabase:false,windowsExecuted:false,syntheticSignaturesAreNotCiEvidence:true}));
}finally{Date.now=realNow;if(server)await new Promise(resolve=>server.close(resolve));web.RevokeAllSessions();fs.rmSync(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
