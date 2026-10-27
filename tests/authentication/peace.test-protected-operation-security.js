'use strict';
// Production handlers, bounded synthetic files and isolated persistence.
// Never connects to an operating server, downloads a real EXE or alters keys.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {Isolated}=require("../fixtures/protocol/peace.completion-6-10-fixture"),protocol=require("../../services/protocol/peace.desktop-request-protocol");
const {DeviceRate}=require("../../services/runtime/peace.desktop-request-rate");
const digest=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>{const e=Error(code);e.desktopError=true;e.status=403;throw e;};
function BootFixture(){
 const at=Date.now(),id=crypto.randomBytes(12).toString('hex'),bytes=Buffer.from('SYNTHETIC_ARTIFACT_DATA_ONLY');
 const make=role=>({id:role,component:role,sha512:'a'.repeat(128),crc64:'A'.repeat(16),codeSha512:'b'.repeat(128),codeCrc64:'B'.repeat(16),size:bytes.length});
 const row={id,sessionId:'SESSION',launcherId:'L',releaseId:'B',overlayReleaseId:'O',status:'STARTED',createdAt:at-1000,expiresAt:at+60000,sessionExpiresAt:at+60000,claimedAt:at-1000,deviceId:'DEVICE',machineId:'MACHINE',downloadHash:digest('DOWNLOAD_SECRET'),sessionHash:digest('SESSION_SECRET'),chunkOffsets:[]};
 const db={launchers:{L:{id:'L',artifactId:'A',status:'AVAILABLE',issuedAt:at-1000,expiresAt:at+60000}},artifacts:{A:make('A'),B:make('B'),O:make('O')},flows:{[id]:row}},state={serviceEnabled:true,maintenanceMode:false};
 const calls={artifacts:[],fresh:0,writes:0,read:0};const revoked=new Set();let afterRead=()=>{},afterWrite=()=>{},fresh=true;
 const api=Isolated("services/bootstrap/peace.desktop-bootstrap.js",['Chunk','RequireFlowPair'],{
  './peace.desktop-bootstrap-store':{Load:()=>db,ArtifactPath:()=>'/synthetic',AfterCommit:fn=>fn()},"../../config/peace.runtime-configuration":{HA_ENABLED:false},"../../core/peace.runtime-state":state,
  'node:fs':{constants:{O_RDONLY:0,O_NOFOLLOW:0},openSync:()=>1,closeSync(){},fstatSync:()=>({isFile:()=>true,size:bytes.length}),readSync(_fd,b,offset,count,pos){bytes.copy(b,offset,pos,pos+count);calls.read++;afterRead();return count;}},
  "../storage/peace.desktop-operation-audit":{Run(_kind,_actor,_meta,fn){calls.writes++;fn(db);afterWrite();}},"../network/peace.ha-coordinator":{CanAcceptTraffic:()=>true},
  "../recovery/peace.desktop-recovery":{Assert(){}},"../devices/peace.desktop-device-registry":{AssertMachineAllowed(){}},"../devices/peace.desktop-machine-policy":{Validate:x=>x,AssertAllowed(){}},
  './peace.desktop-handoff-delegation':{RequirePair:()=>3,Version:()=>3,Parent:r=>r},
  "../security/peace.desktop-security-operations":{RequireRuntimePair(){}},"../security/peace.desktop-security-authority":{RequireArtifact(a){if(!a||revoked.has(a.id))fail('SECURITY_RELEASE_REVOKED');calls.artifacts.push(a.id);},RequireFresh(){calls.fresh++;if(!fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');}},
  "../devices/peace.desktop-device-identity":{AssertSession(){}},"../integrity/peace.desktop-integrity-reports":{RequireSnapshot(){},Record(){}},"../../storage/audit/peace.audit.js":{LogEvent(){}}
 });
 const body={action:'chunk',flowId:id,downloadTicket:'DOWNLOAD_SECRET',offset:0};
 const options={machineId:row.machineId,binarySha512:db.artifacts.B.sha512,binaryCrc64:db.artifacts.B.crc64,codeSha512:db.artifacts.B.codeSha512,codeCrc64:db.artifacts.B.codeCrc64,securityIntent:'verify',securityBinding:'SERVER_BOUND'};
 return {api,row,db,body,bytes,state,calls,revoked,options,onRead:fn=>afterRead=fn,onWrite:fn=>afterWrite=fn,denyFresh:()=>fresh=false};
}
for(const part of ['A','B','O'])test('bootstrap runtime pair rechecks revoked '+part,()=>{const f=BootFixture();f.revoked.add(part);assert.throws(()=>f.api.__probe.RequireFlowPair(f.row),/RELEASE_REVOKED/);});
test('bootstrap chunk valid capability and exact retry return same bytes without another receipt',()=>{const f=BootFixture(),a=f.api.Execute(f.body),b=f.api.Execute(f.body);assert.equal(a.data,f.bytes.toString('base64'));assert.deepEqual(a,b);assert.equal(f.calls.writes,1);assert(f.calls.artifacts.length>=12);});
test('wrong download ticket fails before artifact read',()=>{const f=BootFixture();assert.throws(()=>f.api.Execute({...f.body,downloadTicket:'OTHER'}),/FLOW_INVALID/);assert.equal(f.calls.read,0);});
test('chunk read crossing expiry does not create receipt or return bytes',()=>{const f=BootFixture();f.onRead(()=>f.row.expiresAt=Date.now()-1);assert.throws(()=>f.api.__probe.Chunk(f.body),/EXPIRED/);assert.equal(f.calls.writes,0);});
test('chunk artifact revoked during read is rejected before acknowledgement',()=>{const f=BootFixture();f.onRead(()=>f.revoked.add('B'));assert.throws(()=>f.api.__probe.Chunk(f.body),/RELEASE_REVOKED/);assert.equal(f.calls.writes,0);});
test('service disable during durable receipt prevents response',()=>{const f=BootFixture();f.onWrite(()=>f.state.maintenanceMode=true);assert.throws(()=>f.api.Execute(f.body),/SERVICE_DISABLED/);});
test('B Gate needs current observation even with matching supplied hashes',()=>{const f=BootFixture();f.row.status='CLAIMED';f.api.Gate(f.row.sessionId,'SESSION_SECRET',f.row.deviceId,f.options);f.denyFresh();assert.throws(()=>f.api.Gate(f.row.sessionId,'SESSION_SECRET',f.row.deviceId,f.options),/FRESH_OBSERVATION_REQUIRED/);assert.equal(f.calls.fresh,2);});
test('B Gate rejects wrong credentials, device or file hash',()=>{const f=BootFixture();f.row.status='CLAIMED';for(const [token,device,options]of [['WRONG',f.row.deviceId,f.options],['SESSION_SECRET','OTHER',f.options],['SESSION_SECRET',f.row.deviceId,{...f.options,binarySha512:'c'.repeat(128)}]])assert.throws(()=>f.api.Gate(f.row.sessionId,token,device,options));});
test('client normal flag cannot skip chunk field checking; unknown action denied',()=>{const f=BootFixture();assert.throws(()=>f.api.Execute({...f.body,normal:true}),/INPUT_INVALID/);assert.throws(()=>f.api.Execute({action:'overlayGrant'}),/INPUT_INVALID/);});
function OverlayFixture(){
 const at=Date.now(),bytes=Buffer.from('SYNTHETIC_OVERLAY'),keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
 const parent={id:'P',sessionId:'A'.repeat(24),launcherId:'L',releaseId:'B',overlayReleaseId:'O',licenseId:'LICENSE',deviceId:'PARENT_DEVICE',status:'CLAIMED',claimedAt:at-1000,sessionExpiresAt:at+60000};
 const row={id:crypto.randomBytes(12).toString('hex').toUpperCase(),sessionId:crypto.randomBytes(12).toString('hex').toUpperCase(),parentFlowId:parent.id,parentSessionId:parent.sessionId,releaseId:'O',licenseId:'LICENSE',parentDeviceId:parent.deviceId,deviceId:'CHILD_DEVICE',machineId:'MACHINE',status:'PREPARED',createdAt:at-1000,expiresAt:at+60000,claimedAt:at-1000,authorizedAt:at-10,sessionExpiresAt:at+60000,ticketHash:digest('TICKET'),sessionHash:digest('TOKEN'),chunkOffsets:[]};
 const artifact=id=>({id,component:id,sha512:'a'.repeat(128),crc64:'A'.repeat(16),codeSha512:'b'.repeat(128),codeCrc64:'B'.repeat(16),size:bytes.length});
 const license={id:'LICENSE',consumed:true,status:'USED',deviceId:parent.deviceId,bootstrapSessionId:parent.sessionId,expiresAt:at+120000};
 const db={flows:{P:parent},launchers:{L:{artifactId:'A'}},artifacts:{A:artifact('A'),B:artifact('B'),O:artifact('O')},overlays:{[row.id]:row}};
 let afterRead=()=>{},beforeWrite=()=>{},fresh=true;const calls={fresh:0,writes:0,artifacts:[]},revoked=new Set();
 const boot={Fail:fail,EnsureSecurityAvailable(){},AssertSecurityAvailable(){},EqualHash:(v,h)=>digest(v)===h,AssertFlowLifetime(p){if(p.sessionExpiresAt<=Date.now())fail('BOOTSTRAP_EXPIRED');},SessionAuthenticated(id,token){if(id!==parent.sessionId||token!=='PARENT_TOKEN')fail('BOOTSTRAP_SESSION_INVALID');return parent;},Verify(_row,canonical,signature){if(!crypto.verify('sha256',Buffer.from(canonical),keys.publicKey,Buffer.from(signature,'base64')))fail('BOOTSTRAP_PROOF_INVALID');},RetireFlow(){},CheckFile(a,h,c){if(a.sha512!==h||a.crc64!==c)fail('HASH_MISMATCH');}};
 const authority={RequireArtifact(a){if(!a||revoked.has(a.id))fail('SECURITY_RELEASE_REVOKED');calls.artifacts.push(a.id);},Binding:(id,h)=>id+'|'+h,RequireFresh(){calls.fresh++;if(!fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');},RenewalIdentity(){if(!fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');return {id:'CURRENT_OBSERVATION',expiresAt:Date.now()+30000};}};
 const api=Isolated("services/overlay/peace.desktop-overlay.js",['Chunk','Commit','Verify'],{
  "../bootstrap/peace.desktop-bootstrap":boot,"../bootstrap/peace.desktop-bootstrap-store":{Load:()=>db,ArtifactPath:()=>'/synthetic'},"../../config/peace.runtime-configuration":{},
  "../bootstrap/peace.desktop-handoff-delegation":{Parent:r=>({deviceId:r.parentDeviceId}),Version:()=>3},
  'node:fs':{constants:{O_RDONLY:0,O_NOFOLLOW:0},openSync:()=>1,closeSync(){},fstatSync:()=>({isFile:()=>true,size:bytes.length}),readSync(_fd,b,offset,count,pos){bytes.copy(b,offset,pos,pos+count);afterRead();return count;}},
  "../recovery/peace.desktop-recovery":{Assert(){}},"../devices/peace.desktop-device-registry":{AssertMachineAllowed(){}},"../devices/peace.desktop-machine-policy":{AssertAllowed(){}},"../licensing/peace.desktop-licenses":{DB:()=>({licenses:{LICENSE:license}})},
  "../security/peace.desktop-security-authority":authority,"../security/peace.desktop-security-operations":{RequireRuntimePair(){}},"../devices/peace.desktop-device-identity":{AssertSession(){}},"../integrity/peace.desktop-integrity-reports":{RequireSnapshot(){}},
  "../storage/peace.desktop-operation-audit":{Run(_kind,_actor,_meta,fn){beforeWrite();calls.writes++;return fn(db);}},"../../storage/audit/peace.audit.js":{LogEvent(){}}
 });
 const chunk={action:'overlayChunk',overlayId:row.id,overlayTicket:'TICKET',offset:0};
 const commit={action:'overlayCommit',handoffVersion:1,sessionId:parent.sessionId,sessionToken:'PARENT_TOKEN',overlayId:row.id,signature:crypto.sign('sha256',Buffer.from(['GAME-OVERLAY-TRANSFER-V1',parent.sessionId,row.id].join('\n')),keys.privateKey).toString('base64')};
 const verify={action:'overlayVerify',sessionId:row.sessionId,sessionToken:'TOKEN',machineId:row.machineId,binarySha512:db.artifacts.O.sha512,binaryCrc64:db.artifacts.O.crc64,codeSha512:db.artifacts.O.codeSha512,codeCrc64:db.artifacts.O.codeCrc64};
 return {api,row,parent,license,chunk,commit,verify,bytes,calls,revoked,onRead:fn=>afterRead=fn,beforeWrite:fn=>beforeWrite=fn,denyFresh:()=>fresh=false};
}
test('O chunk retains capability authorization and exact bytes',()=>{const f=OverlayFixture();assert.equal(f.api.__probe.Chunk(f.chunk).data,f.bytes.toString('base64'));assert.equal(f.calls.writes,1);assert(f.calls.artifacts.includes('A')&&f.calls.artifacts.includes('B'));});
for(const kind of ['expiry','license','artifact'])test('O chunk rechecks '+kind+' after file read',()=>{const f=OverlayFixture();f.onRead(()=>{if(kind==='expiry')f.row.expiresAt=Date.now()-1;if(kind==='license')f.license.releasedAt=Date.now();if(kind==='artifact')f.revoked.add('B');});assert.throws(()=>f.api.__probe.Chunk(f.chunk),/EXPIRED|ACTIVATION_INVALID|RELEASE_REVOKED/);assert.equal(f.calls.writes,0);});
test('O verify requires live authority and exact repeat does not extend lease',()=>{const f=OverlayFixture();f.row.status='CLAIMED';const a=f.api.__probe.Verify(f.verify),expiry=f.row.sessionExpiresAt;assert.deepEqual(f.api.__probe.Verify(f.verify),a);assert.equal(f.row.sessionExpiresAt,expiry);f.denyFresh();assert.throws(()=>f.api.__probe.Verify(f.verify),/FRESH_OBSERVATION_REQUIRED/);});
test('O transfer requires fresh O observation despite recent authorizedAt',()=>{const f=OverlayFixture();f.row.status='CLAIMED';f.denyFresh();assert.throws(()=>f.api.__probe.Commit(f.commit),/FRESH_OBSERVATION_REQUIRED/);assert.equal(f.parent.status,'CLAIMED');assert.equal(f.calls.writes,0);});
test('O transfer rechecks observation inside commit before mutating parent',()=>{const f=OverlayFixture();f.row.status='CLAIMED';f.beforeWrite(()=>f.denyFresh());assert.throws(()=>f.api.__probe.Commit(f.commit),/FRESH_OBSERVATION_REQUIRED/);assert.equal(f.parent.status,'CLAIMED');assert.equal(f.row.transferVersion,undefined);});
test('valid O transfer still succeeds with actual RSA signature and current authority',()=>{const f=OverlayFixture();f.row.status='CLAIMED';assert.equal(f.api.__probe.Commit(f.commit).status,'TRANSFERRED');assert.equal(f.parent.status,'CLOSED');assert.equal(f.calls.fresh,2);});
test('purpose catalog rejects cross-domain and unknown operations',()=>{for(const [op,action]of [['security','redeem'],['device','submit'],['report','verify'],['bootstrap',{}],['execute','permit'],['other','verify']])assert.throws(()=>protocol.Resolve(op,action));for(const [op,action]of [['bootstrap','chunk'],['bootstrap','finish'],['bootstrap','claim'],['bootstrap','overlayVerify'],['bootstrap','overlayCommit'],['execute','redeem'],['execute','verify'],['execute','overlay'],['security','challenge'],['security','submit'],['device','complete']])assert(protocol.Resolve(op,action).domain);});
test('device rate limit: rejected requests do not extend window or exhaust another device',()=>{let clock=0;const r=new DeviceRate({clock:()=>clock,limit:2,windowMs:100,capacity:2});r.Take('A');r.Take('A');for(let i=0;i<10;i++)assert.throws(()=>r.Take('A'),/RATE_LIMIT/);r.Take('B');assert.equal(r.entries.get('A').until,100);clock=100;r.Take('A');assert.equal(r.entries.get('A').count,1);});
test('device rate bounded storage and no partial insertion on capacity denial',()=>{let clock=0;const r=new DeviceRate({clock:()=>clock,capacity:1,windowMs:100});r.Take('A');assert.throws(()=>r.Take('B'),/RATE_LIMIT/);assert.equal(r.entries.size,1);clock=100;r.Take('B');assert.equal(r.entries.size,1);for(const invalid of ['',null,'a'.repeat(101)])assert.throws(()=>r.Take(invalid));});
test('encrypted dispatcher with deviceId reaches real handler selection (missing Rate regression)',async()=>{
 let runs=0,revoked=false;const e=()=>{if(revoked)fail('SECURITY_RELEASE_REVOKED');return {authorized:true};};
 const api=Isolated("services/network/peace.desktop-connect.js",['Dispatch'],{
  "../licensing/peace.desktop-licenses":{Fail:fail,messages:{},Challenge:e,Execute:e},'./peace.connect-transport-key':{},"../runtime/peace.desktop-work-queue":{IsRenewal:()=>false},
  './peace.desktop-tls-pin-transition':{Offer:()=>null},'./peace.desktop-transport-rotation':{AssertUse(){}},"../integrity/peace.desktop-proof-work":{Prepare:()=>[],Run:async(_jobs,fn)=>{runs++;return fn();}},"../runtime/peace.desktop-runtime-diagnostics":{Record(){}}
 });
 // Shape-only dummy credentials reach the isolated business stubs; no real proof claim.
 const fixture=require('../fixtures/protocol/peace.packet-schema-cases.json').cases.find(p=>p.operation==='execute'&&p.body.action==='verify');
 const opened={keyId:'KEY',payload:structuredClone(fixture)};
 assert.equal((await api.__probe.Dispatch(opened,Infinity)).ok,true);assert.equal(runs,1);revoked=true;assert.equal((await api.__probe.Dispatch(opened,Infinity)).error,'SECURITY_RELEASE_REVOKED');opened.payload.body.action='unknown';assert.equal((await api.__probe.Dispatch(opened,Infinity)).ok,false);assert.equal(runs,2);
});

test('SERVER update bearer URL rechecks actual HMAC, expiry and current catalog enablement',()=>{
 const id='D'.repeat(24),secret='TEST_ONLY_'.repeat(8),current={type:'SERVER',artifactId:id,enabled:true};
 const state={releaseCatalog:new Map([['SERVER:STABLE',current]])};
 const manager=Isolated("services/artifacts/peace.release-manager.js",[],{
  "../../config/peace.runtime-configuration":{DATA_DIR:'/isolated',UPDATE_BASE_URL:''},"../../core/peace.runtime-state":state,"../../identity/peace.identity-manager":{},"../../core/peace.utilities.js":{},
  fs:{mkdirSync(){},readFileSync:()=>secret}
 });
 const u=new URL(manager.SignedDownload(id),'https://test.invalid');const exp=u.searchParams.get('exp'),sig=u.searchParams.get('sig');
 assert(manager.VerifyDownload(id,exp,sig));assert(!manager.VerifyDownload(id,exp,'0'.repeat(64)));
 current.enabled=false;assert(!manager.VerifyDownload(id,exp,sig));current.enabled=true;
 const expired=String(Date.now()-1),expiredSig=crypto.createHmac('sha256',secret).update(id+'|'+expired).digest('hex');assert(!manager.VerifyDownload(id,expired,expiredSig));
 state.releaseCatalog.clear();assert(!manager.VerifyDownload(id,exp,sig));
});
