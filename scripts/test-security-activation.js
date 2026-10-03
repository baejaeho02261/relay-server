'use strict';
// Generated keys and synthetic PE images only. Tests server enforcement; does
// not claim to run Delphi, a physical authenticator or a Windows CFG process.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs');
const os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-activation-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',WEBAUTHN_RP_ID:'localhost',WEBAUTHN_ORIGIN:'https://localhost',DESKTOP_SECURITY_STEP_UP_REQUIRED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../core/utils').EnsureDirs();
const state=require('../core/state'),store=require('../services/desktopBootstrapStore');
const auth=require('../services/desktopSecurityAuthority'),ops=require('../services/desktopSecurityOperations');
const guard=require('../services/desktopAdminGuard'),dual=require('../services/privilegedApproval');
const activation=require('../services/desktopSecurityActivation'),boot=require('../services/desktopBootstrap');
const audit=require('../storage/audit'),passkey=require('../services/passkeyAuth'),fixture=require('./desktop-bootstrap-fixture');
const req={headers:{host:'localhost','x-forwarded-proto':'https'},socket:{encrypted:true}};
const alice={id:'activation-alice',role:'admin'},alice2={id:'activation-alice2',role:'admin'},bob={id:'activation-bob',role:'admin'};
const B64=x=>Buffer.from(x).toString('base64url');
const clientData=(type,challenge)=>B64(Buffer.from(JSON.stringify({type,challenge,origin:'https://localhost',crossOrigin:false})));
function authData(counter){const b=Buffer.alloc(37);crypto.createHash('sha256').update('localhost').digest().copy(b);b[32]=5;b.writeUInt32BE(counter,33);return b;}
function register(s){
 const start=passkey.RegistrationBegin(s,req);assert.equal(start.ok,true);
 const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),credentialId=B64(crypto.randomBytes(32));
 const out=passkey.RegistrationFinish(s,req,{challengeId:start.challengeId,credentialId,clientDataJSON:clientData('webauthn.create',start.publicKey.challenge),authenticatorData:B64(authData(0)),publicKeySpki:B64(pair.publicKey.export({type:'spki',format:'der'})),name:'Activation test'});
 assert.equal(out.ok,true,out.reason);return{...pair,credentialId,id:out.credential.id,counter:0};
}
function verify(s,key){
 const start=guard.Begin(s,req),client=clientData('webauthn.get',start.publicKey.challenge),ad=authData(++key.counter);
 const out=guard.Finish(s,req,{challengeId:start.challengeId,credentialId:key.credentialId,clientDataJSON:client,authenticatorData:B64(ad),signature:B64(crypto.sign('sha256',Buffer.concat([ad,crypto.createHash('sha256').update(Buffer.from(client,'base64url')).digest()]),key.privateKey))});
 assert.equal(out.ok,true,out.reason);
}
let count=0,a,b,keys=[],releaseKey,contexts,device;
const test=(name,fn)=>{fn();console.log('PASS '+name);count++;};
const reject=(fn,code)=>assert.throws(fn,e=>e.message===code,code);
const has=(view,code)=>view.issues.some(x=>x.code===code);
const bytes=()=>fs.readFileSync(path.join(temp,'desktop-bootstrap/authority.json'));
const view=(profile='SERVER')=>activation.Preview(profile,alice);
function signed(component,version,cfg=false){
 const data=fixture.PE(component,auth.DOMAIN+' activation '+version);
 if(cfg){const opt=data.readUInt32LE(0x3c)+24,lc=768;data.writeUInt16LE(data.readUInt16LE(opt+70)|0x4000,opt+70);data.writeUInt32LE(0x1100,opt+112+80);data.writeUInt32LE(148,opt+116+80);data.writeUInt32LE(148,lc);data.writeBigUInt64LE(1n,lc+136);data.writeUInt32LE(0x500,lc+144);}
 const keyId=crypto.createHash('sha256').update(releaseKey.publicKey.export({type:'spki',format:'der'})).digest('hex');
 const signature=crypto.sign(null,Buffer.from(auth.ReleaseCanonical(component,version,fixture.sha256(data))),releaseKey.privateKey).toString('base64');
 return ops.Stage(component,version,data,{keyId,signature},'TEST');
}
const contract={version:1,evidenceVersion:1,minApiSlots:60,maxApiSlots:62,requiredChecks:['ownImage','apiStorage','mitigations']};
function contracts(){for(const r of[a,b])ops.SetContract({expectedRevision:ops.Revision(),artifactId:r.id,contract},'TEST');}
function report(outcome='PASS'){
 ops.RecordEvidence({expectedRevision:ops.Revision(),aId:a.id,bId:b.id,report:{version:1,aSha256:a.sha256,bSha256:b.sha256,sourceManifestSha256:'1'.repeat(64),logsSha256:'2'.repeat(64),nativeBuild:'PASS',apiProbe:'PASS',integration:outcome,note:'SYNTHETIC SERVER REGRESSION RECORD. Not a Windows test.'}},'TEST');
}
function publishPair(){ops.ActivatePair({expectedRevision:ops.Revision(),expectedPolicyRevision:auth.Policy().revision,aId:a.id,bId:b.id},'TEST');}
function observe(ctx,patch={}){
 const c=auth.Execute(ctx),baseline=boot.AuthenticateIntegrityReport(ctx).integrityArtifact;
 const value={version:1,measurement:'MEASURED',fileSha256:baseline.sha256,fileCrc64:baseline.crc64,codeSha256:baseline.codeSha256,codeCrc64:baseline.codeCrc64,apiSealed:true,apiSlots:60,dynamicCode:'ALLOWED',cfg:'DISABLED',...patch};
 const payload=JSON.stringify(value);return auth.Execute({...ctx,action:'submit',challengeId:c.challengeId,payload,signature:fixture.Sign(device,auth.Canonical(ctx,c,payload))});
}
function session(patch={}){
 device=fixture.Device();const start=fixture.Begin(device);fixture.Download(start.begin);
 const ac={action:'challenge',stage:'A',sessionId:start.begin.flowId,sessionToken:start.begin.downloadTicket,machineId:device.machineId,intent:'finish',binding:auth.Binding(start.begin.flowId,start.begin.release.sha256)};
 assert.equal(observe(ac,patch).status,'PASS');
 const out=fixture.Claim(device,start.begin,fixture.Finish(device,start.begin));
 const bc={action:'challenge',stage:'B',sessionId:out.sessionId,sessionToken:out.sessionToken,machineId:device.machineId,intent:'verify',binding:auth.Binding(crypto.randomUUID(),fixture.sha256('activation-test'))};
 assert.equal(observe(bc,patch).status,'PASS');return[ac,bc];
}
function permit(plan){
 verify(alice,keys[0]);verify(bob,keys[2]);
 const request=guard.Authorize(alice,'POST',activation.PATH,plan,'');assert.equal(request.reason,'DUAL_APPROVAL_REQUIRED',JSON.stringify(request));
 const approved=dual.Approve(request.ticketId,bob);assert.equal(approved.ok,true,approved.reason);
 const result=guard.Authorize(alice,'POST',activation.PATH,plan,request.ticketId);assert.equal(result.ok,true,result.reason);return result.ticket;
}
try{
 test('No activation marker and no silent strict-default migration',()=>{assert.equal(activation.AdminEnforced(),false);assert.equal(activation.Status().serverEnabled,false);assert.equal(store.Load().securityActivation,undefined);});
 test('Non-admin and unknown profile are rejected',()=>{reject(()=>activation.Preview('ALL',{role:'viewer'}),'ADMIN_REQUIRED');reject(()=>activation.Preview('FALLBACK',alice),'SECURITY_ACTIVATION_PROFILE_INVALID');});
 test('First readiness check is read-only and reports real missing prerequisites',()=>{const before=bytes(),v=view();assert.equal(v.ready,false);for(const c of['SECURITY_ADMIN_STEP_UP_REQUIRED','SECURITY_ADMIN_IDENTITY_REQUIRED','SECURITY_SECOND_OPERATOR_REQUIRED','SECURITY_ACTIVE_PAIR_REQUIRED'])assert.ok(has(v,c),c);assert.deepEqual(bytes(),before);});
 test('Actual passkey service verifies generated operator assertions',()=>{keys=[register(alice),register(alice2),register(bob)];process.env.DESKTOP_APPROVER_IDENTITIES_JSON=JSON.stringify({[keys[0].id]:'operator-a',[keys[1].id]:'operator-a',[keys[2].id]:'operator-b'});for(const[s,k]of[[alice,keys[0]],[alice2,keys[1]],[bob,keys[2]]])verify(s,k);assert.equal(guard.Status().provisionedPrincipalCount,2);});
 test('Two sessions of one operator do not satisfy two-person readiness',()=>{const old=process.env.DESKTOP_APPROVER_IDENTITIES_JSON;process.env.DESKTOP_APPROVER_IDENTITIES_JSON=JSON.stringify({[keys[0].id]:'operator-a',[keys[1].id]:'operator-a'});assert.ok(has(view(),'SECURITY_SECOND_OPERATOR_REQUIRED'));process.env.DESKTOP_APPROVER_IDENTITIES_JSON=old;});
 test('Unsigned current releases cannot be made trusted by enable-all',()=>{a=boot.Publish('A','1.0.0',fixture.PE('A',auth.DOMAIN));b=boot.Publish('B','1.0.0',fixture.PE('B',auth.DOMAIN));assert.ok(has(view(),'SECURITY_RELEASE_SIGNATURE'));assert.equal(auth.Policy().trustedReleaseKeys.length,0);});
 test('Trusted detached signatures use existing verified publication flow',()=>{releaseKey=crypto.generateKeyPairSync('ed25519');const keyId=crypto.createHash('sha256').update(releaseKey.publicKey.export({type:'spki',format:'der'})).digest('hex');auth.SetPolicy({expectedRevision:auth.Policy().revision,trustedReleaseKeys:[{keyId,publicKey:releaseKey.publicKey.export({type:'spki',format:'pem'}).toString()}]},'TEST');a=signed('A','1.0.1');b=signed('B','1.0.1');publishPair();assert.equal(has(view(),'SECURITY_RELEASE_SIGNATURE'),false);});
 test('Build contracts are required; no slot count is inferred',()=>{assert.ok(has(view(),'SECURITY_BUILD_CONTRACT_REQUIRED'));assert.deepEqual(ops.State().contracts,{});contracts();assert.equal(has(view(),'SECURITY_BUILD_CONTRACT_REQUIRED'),false);});
 test('Missing, NOT_RUN and FAIL evidence cannot auto become PASS',()=>{assert.ok(has(view(),'SECURITY_TEST_EVIDENCE_REQUIRED'));for(const result of['NOT_RUN','FAIL']){report(result);assert.ok(has(view(),'SECURITY_TEST_EVIDENCE_REQUIRED'));assert.equal(ops.State().pairEvidence[ops.PairKey(a,b)].integration,result);}report();assert.equal(has(view(),'SECURITY_TEST_EVIDENCE_REQUIRED'),false);});
 test('Real challenge/signature measurement is needed after boot',()=>{assert.ok(has(view(),'SECURITY_RECENT_OBSERVATION_REQUIRED'));contexts=session();assert.equal(view().ready,true,JSON.stringify(view().issues));});
 test('Latest readonly-storage failure blocks activation',()=>{observe(contexts[1],{apiSealed:false});assert.ok(has(view(),'SECURITY_TARGET_OBSERVATION_FAILED'));observe(contexts[1]);assert.equal(view().ready,true);});
 test('Build-specific slot mismatch blocks activation even when nonzero',()=>{observe(contexts[1],{apiSlots:1});assert.ok(has(view(),'SECURITY_TARGET_OBSERVATION_FAILED'));observe(contexts[1]);});
 test('ALL never falls back when CFG metadata or runtime protection is missing',()=>{const v=view('ALL');assert.equal(v.ready,false);assert.ok(has(v,'SECURITY_CFG_BUILD_REQUIRED'));assert.equal(v.plan.profile,'ALL');assert.equal(v.target.policy.requireCfg,true);assert.equal(v.target.policy.dynamicCode,'prohibit');});
 test('SERVER is an explicit scope, preserving existing Windows policy',()=>{const v=view();assert.equal(v.ready,true);assert.equal(v.target.policy.requireCfg,auth.Policy().requireCfg);assert.equal(v.target.policy.dynamicCode,auth.Policy().dynamicCode);});
 test('Preview never changes data, policies, keys or current active pair',()=>{const before=bytes();view();view('ALL');assert.deepEqual(bytes(),before);});
 test('Missing, extra and client-chosen target overrides are rejected',()=>{const p=view().plan;reject(()=>activation.CheckRequest({...p,requireCfg:false},alice),'SECURITY_ACTIVATION_INPUT_INVALID');const short={...p};delete short.aSha256;reject(()=>activation.CheckRequest(short,alice),'SECURITY_ACTIVATION_INPUT_INVALID');});
 test('Stale policy/operations/activation revisions are rejected',()=>{const p=view().plan;for(const[k,c]of[['expectedPolicyRevision','SECURITY_POLICY_CONFLICT'],['expectedOperationsRevision','SECURITY_OPERATIONS_CONFLICT'],['expectedActivationRevision','SECURITY_ACTIVATION_CONFLICT']])reject(()=>activation.CheckRequest({...p,[k]:p[k]+1},alice),c);});
 test('Activation binds the exact active A/B identities and hashes',()=>{const p=view().plan;reject(()=>activation.CheckRequest({...p,aSha256:'f'.repeat(64)},alice),'SECURITY_ACTIVE_PAIR_CHANGED');reject(()=>activation.CheckRequest({...p,bId:a.id},alice),'SECURITY_ACTIVE_PAIR_CHANGED');});
 test('First activation requires dual approval even when global dual is off',()=>{assert.equal(state.production.deploymentManifest.dualApprovalRequired===true,false);assert.equal(dual.Required(activation.PATH),true);const p=view().plan,out=guard.Authorize(alice,'POST',activation.PATH,p);assert.equal(out.reason,'DUAL_APPROVAL_REQUIRED');assert.equal(dual.Approve(out.ticketId,alice).reason,'SECOND_ADMIN_SESSION_REQUIRED');assert.equal(dual.Approve(out.ticketId,alice2).reason,'SECOND_ADMIN_IDENTITY_REQUIRED');});
 test('No direct activation without a consumed server-side approval',()=>{reject(()=>activation.Apply(view().plan,alice),'SECURITY_ACTIVATION_APPROVAL_REQUIRED');reject(()=>activation.Apply(view().plan,alice,{status:'CONSUMED'}),'SECURITY_ACTIVATION_APPROVAL_REQUIRED');});
 test('Exact target settings appear in second-operator approval summary',()=>{const out=guard.Summary(activation.PATH,view('ALL').plan);assert.equal(out.activationTargets.requireTestEvidence,true);assert.equal(out.activationTargets.windows,'dynamicCode=prohibit; requireCfg=true');assert.ok(!JSON.stringify(out).includes('PUBLIC KEY'));});
 let plan,ticket;
 test('Revoked approving key invalidates a consumed capability before apply',()=>{plan=view().plan;ticket=permit(plan);const cred=state.production.passkeyCredentials.get(keys[2].id);cred.revokedAt=Date.now();reject(()=>activation.Apply(plan,alice,ticket),'SECURITY_ACTIVATION_APPROVAL_REQUIRED');cred.revokedAt=0;});
 test('Audit fsync failure leaves policy and activation marker unchanged',()=>{plan=view().plan;ticket=permit(plan);const before=bytes(),original=fs.fsyncSync;fs.fsyncSync=()=>{throw Object.assign(Error('injected'),{code:'ENOSPC'});};try{reject(()=>activation.Apply(plan,alice,ticket),'SECURITY_AUDIT_UNAVAILABLE');}finally{fs.fsyncSync=original;}assert.deepEqual(bytes(),before);assert.equal(activation.AdminEnforced(),false);assert.equal(audit.LogEvent('TEST_RECOVERY','synthetic failure injection ended',{durable:true}).ok,true);});
 test('Atomic store rename failure cannot partially enable policies or admin gate',()=>{plan=view().plan;ticket=permit(plan);const before=bytes(),old=fs.renameSync;fs.renameSync=(src,dst)=>{if(dst===path.join(temp,'desktop-bootstrap/authority.json'))throw Error('INJECTED_RENAME_FAILURE');return old(src,dst);};try{reject(()=>activation.Apply(plan,alice,ticket),'INJECTED_RENAME_FAILURE');}finally{fs.renameSync=old;}assert.deepEqual(bytes(),before);assert.equal(activation.AdminEnforced(),false);});
 test('SERVER enables all seven server controls in one authority commit',()=>{plan=view().plan;ticket=permit(plan);const before=structuredClone(store.Load()),oldRev=before.revision,out=activation.Apply(plan,alice,ticket);assert.equal(out.activated,true);assert.equal(out.current.serverEnabled,true);assert.equal(out.current.allEnabled,false);assert.equal(guard.Status().stepUpRequired,true);assert.equal(guard.Status().dualApprovalRequired,true);assert.equal(store.Load().revision,oldRev+1);for(const k of['secret','artifacts','active','launchers','flows','issueReceipts'])assert.deepEqual(store.Load()[k],before[k],k);assert.equal(state.production.deploymentManifest.dualApprovalRequired===true,false);});
 test('Admin enforcement persists outside the legacy global toggle',()=>{for(const p of['/api/desktop/bootstrap/security-authority','/api/desktop/bootstrap/artifacts','/api/desktop/bootstrap/security-operations/controls','/api/production/dual-policy'])assert.equal(dual.Required(p),true);assert.equal(dual.Required('/api/system/service/stop'),false);assert.equal(guard.CheckSession({id:'password',role:'admin'}).reason,'SECURITY_ADMIN_STEP_UP_REQUIRED');});
 test('Activation cannot replay after policy revisions change',()=>{reject(()=>activation.Apply(plan,alice,ticket),'SECURITY_POLICY_CONFLICT');});
 test('Durable settings reload in a separate server process',()=>{const code="const a=require('./services/desktopSecurityActivation');if(!a.AdminEnforced()||!a.Status().serverEnabled)process.exit(3);console.log('RELOADED')";const p=child.spawnSync(process.execPath,['-e',code],{cwd:path.resolve(__dirname,'..'),env:process.env,encoding:'utf8'});assert.equal(p.status,0,p.stderr);assert.match(p.stdout,/RELOADED/);});
 test('Malformed persisted activation records are rejected',()=>{const r=activation.Record();for(const bad of[{...r,adminEnforced:false},{...r,approvedBy:r.activatedBy},{...r,unknown:true},{...r,revision:0}])reject(()=>activation.ValidateRecord(bad),'SECURITY_ACTIVATION_STORAGE_INVALID');});
 test('Observed values are not copied into contracts or manufactured test records',()=>{const before=ops.State();view('ALL');assert.deepEqual(ops.State(),before);});
 test('Supported ALL path uses real signature/measurement services with synthetic CFG fixtures',()=>{a=signed('A','1.0.2',true);b=signed('B','1.0.2',true);contracts();report();publishPair();contexts=session({dynamicCode:'PROHIBITED',cfg:'ENABLED'});assert.equal(view('ALL').ready,true,JSON.stringify(view('ALL').issues));});
 test('ALL activation enables Windows requirements as well as server requirements',()=>{const p=view('ALL').plan,t=permit(p),out=activation.Apply(p,alice,t);assert.equal(out.current.allEnabled,true);assert.equal(auth.Policy().dynamicCode,'prohibit');assert.equal(auth.Policy().requireCfg,true);assert.equal(ops.State().rollout.enabled,false);});
 test('ALL status reflects subsequent explicit policy edits rather than an old success flag',()=>{auth.SetPolicy({expectedRevision:auth.Policy().revision,mode:'observe'},'TEST_INTERNAL');assert.equal(activation.Status().allEnabled,false);assert.equal(activation.Status().serverEnabled,false);assert.equal(activation.AdminEnforced(),true);});
 console.log(`Activation regression: ${count} passed (server services, generated signatures, synthetic PE; no Windows/browser execution)`);
}finally{fs.rmSync(temp,{recursive:true,force:true});}
