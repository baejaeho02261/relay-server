'use strict';
// Real authority/parser/CRC logic and RSA signatures. Only identity, policy
// persistence, audit and surrounding services are isolated; no live user data.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {Isolated}=require("../fixtures/protocol/peace.completion-6-10-fixture");
const contract=require("../../services/integrity/peace.measurement-plan-contract");
const baseline=require("../../services/integrity/peace.desktop-integrity").CodeImage(require("../fixtures/runtime/peace.crc-test-fixture").crcTestFixture());
const keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
function Fixture(mode='enforce'){
 const artifact={id:'BUILD-B',component:'B',version:'1.0',authorityVersion:1,hashVersion:3,ownMeasurementVersion:1,sha512:'a'.repeat(128),crc64:'A'.repeat(16),codeSha512:baseline.sha512,codeCrc64:baseline.crc64,codeXxh3_128:baseline.xxh3_128,codeBlake3:baseline.blake3,crcLayers:structuredClone(baseline.crcLayers)};
 const row={id:'FLOW',sessionId:'SESSION',releaseId:artifact.id,machineId:'A'.repeat(64),publicKey:'ISOLATED_PUBLIC_KEY',integrityArtifact:artifact};
 const db={artifacts:{[artifact.id]:artifact},launchers:{}};let operationsRevision=1,enabled=true,revoked=0;
 const fail=code=>{const e=Error(code);e.desktopError=true;throw e;};
 const ops={PointerGraphSlots:()=>10,EffectivePolicy:p=>p,Revision:()=>operationsRevision,ArtifactReason:()=>'',EvaluateContract:()=>null};
 const auth=Isolated("services/security/peace.desktop-security-authority.js",['pending','decisions','receipts'],{
  "../bootstrap/peace.desktop-bootstrap-store":{Load:()=>db},"../../storage/audit/peace.audit.js":{LogEvent(){}},'./peace.desktop-security-operations':ops,
  "../bootstrap/peace.desktop-bootstrap":{Revoke(id){assert.equal(id,row.sessionId);revoked++;},EnsureSecurityAvailable(){if(!enabled)fail('SERVICE_DISABLED');},AuthenticateIntegrityReport(body){if(body.sessionId!==row.sessionId||body.sessionToken!=='SESSION_SECRET'||body.machineId!==row.machineId)fail('SESSION_INVALID');return row;}},
  "../devices/peace.desktop-device-identity":{AssertSession(){}},'./peace.desktop-mitigation-profiles':{Select:()=>undefined,RequireCurrent(){},Check:()=>''},
  "../licensing/peace.desktop-licenses":{ParseKey:()=>({key:keys.publicKey})},"../integrity/peace.desktop-proof-work":{Verify:(_pub,text,signature)=>crypto.verify('sha256',Buffer.from(text),keys.publicKey,Buffer.from(signature,'base64'))}
 });
 db.securityAuthorityPolicy={...auth.Defaults(),mode};
 const body={action:'challenge',stage:'B',sessionId:row.sessionId,sessionToken:'SESSION_SECRET',machineId:row.machineId,intent:'verify',binding:auth.Binding('OP','HASH')};
 function Value(){return {version:1,hashVersion:3,measurement:'MEASURED',fileSha512:artifact.sha512,fileCrc64:artifact.crc64,codeSha512:artifact.codeSha512,codeCrc64:artifact.codeCrc64,codeXxh3_128:artifact.codeXxh3_128,codeBlake3:artifact.codeBlake3,crcLayers:structuredClone(artifact.crcLayers),apiSealed:true,apiSlots:10,dynamicCode:'ALLOWED',cfg:'DISABLED',ownMeasurement:{contract:contract.OWN_CONTRACT,version:1,startedTick:10,finishedTick:20,coverage:'FULL',fileStatus:'MEASURED',codeStatus:'MEASURED',crcStatus:'MEASURED',imageStable:true}};}
 function Signed(c,v=Value(),b=body){const payload=JSON.stringify(v);return {...b,action:'submit',challengeId:c.challengeId,payload,signature:crypto.sign('sha256',Buffer.from(auth.Canonical(b,c,payload)),keys.privateKey).toString('base64')};}
 function Observe(v=Value(),b=body){const c=auth.Execute(b),signed=Signed(c,v,b);return {response:auth.Execute(signed),signed};}
 const Fresh=(b=body)=>auth.RequireFresh(row,'B',b.intent,b.binding);
 return {auth,db,artifact,row,body,Value,Signed,Observe,Fresh,revoked:()=>revoked,setOps:()=>operationsRevision++,disable:()=>enabled=false};
}
test('FULL bundle with complete CRC passes actual RSA submit and fresh guard',()=>{const f=Fixture(),{response,signed}=f.Observe();assert.equal(response.proceed,true);assert.equal(response.status,'PASS');f.Fresh();assert.deepEqual(f.auth.Execute(signed),response);assert.equal(Object.keys(response).length,8);});
for(const mode of ['enforce','observe']){
 test(mode+': no observation cannot authorize',()=>{const f=Fixture(mode);assert.throws(()=>f.Fresh(),/FRESH_OBSERVATION_REQUIRED/);});
 for(const status of ['NOT_MEASURED','READ_ERROR','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED'])test(mode+': '+status+' cannot inherit prior PASS',()=>{
  const f=Fixture(mode);f.Observe();f.Fresh();const v=f.Value();v.measurement=status;for(const k of ['fileSha512','fileCrc64','codeSha512','codeCrc64','codeXxh3_128','codeBlake3'])v[k]='';delete v.crcLayers;Object.assign(v.ownMeasurement,{coverage:'PARTIAL',fileStatus:status,codeStatus:'NOT_MEASURED',crcStatus:'NOT_MEASURED',imageStable:false});
  assert.equal(f.Observe(v).response.proceed,false);assert.throws(()=>f.Fresh(),/MEASUREMENT_INCOMPLETE/);
 });
}
test('admitted replacement challenge removes prior decision and prior signed receipt immediately',()=>{const f=Fixture(),old=f.Observe();f.auth.Execute(f.body);assert.throws(()=>f.Fresh(),/FRESH_OBSERVATION_REQUIRED/);assert.throws(()=>f.auth.Execute(old.signed),/CHALLENGE_INVALID/);});
test('replacement does not invalidate unrelated operation binding',()=>{const f=Fixture();f.Observe();f.auth.Execute({...f.body,binding:f.auth.Binding('OTHER','HASH')});f.Fresh();});
test('unauthenticated challenge cannot invalidate existing decision',()=>{const f=Fixture();f.Observe();assert.throws(()=>f.auth.Execute({...f.body,sessionToken:'WRONG'}),/SESSION_INVALID/);f.Fresh();});
test('older pending challenge cannot overwrite newly admitted generation',()=>{const f=Fixture(),a=f.auth.Execute(f.body),signed=f.Signed(a),b=f.auth.Execute(f.body);assert.throws(()=>f.auth.Execute(signed),/OBSERVATION_REPLAY/);f.auth.Execute(f.Signed(b));f.Fresh();});
for(const [name,patch]of [
 ['missing bundle',v=>delete v.ownMeasurement],['false stable',v=>v.ownMeasurement.imageStable=false],['file skipped',v=>v.ownMeasurement.fileStatus='NOT_MEASURED'],['coverage partial',v=>v.ownMeasurement.coverage='PARTIAL'],['reverse time',v=>v.ownMeasurement.finishedTick=1],['unsafe time',v=>v.ownMeasurement.startedTick=2**53],['long measurement',v=>v.ownMeasurement.finishedTick=60011],['extra field',v=>v.ownMeasurement.normal=true],['null metadata',v=>v.ownMeasurement=null]
])test(name+' is rejected by the production authority path, old result not reused',()=>{const f=Fixture();f.Observe();const v=f.Value();patch(v);assert.throws(()=>f.Observe(v),/SECURITY_INPUT_INVALID|OWN_MEASUREMENT_REQUIRED/);assert.throws(()=>f.Fresh(),/FRESH_OBSERVATION_REQUIRED/);});
test('legacy approved capability permits omitted metadata, never malformed supplied metadata',()=>{const f=Fixture();f.artifact.ownMeasurementVersion=0;const v=f.Value();delete v.ownMeasurement;assert.equal(f.Observe(v).response.proceed,true);const bad=f.Value();bad.ownMeasurement.coverage='PARTIAL';assert.throws(()=>f.Observe(bad),/SECURITY_INPUT_INVALID/);});
test('failed CRC role cannot produce a complete observation even in observe mode',()=>{const f=Fixture('observe'),v=f.Value();f.artifact.ownMeasurementVersion=0;delete v.ownMeasurement;const old=v.crcLayers.nvme;v.crcLayers.nvme={algorithm:old.algorithm,role:old.role,status:'failed',reason:'READ_ERROR'};assert.equal(f.Observe(v).response.proceed,false);assert.throws(()=>f.Fresh(),/MEASUREMENT_INCOMPLETE/);});
test('observe retains explicit completed-mismatch semantics, not absent measurements',()=>{const f=Fixture('observe'),v=f.Value();v.fileSha512='f'.repeat(128);const out=f.Observe(v).response;assert.equal(out.status,'MISMATCH');assert.equal(out.proceed,true);f.Fresh();});
test('enforce never authorizes digest mismatch',()=>{const f=Fixture(),v=f.Value();v.fileSha512='f'.repeat(128);assert.equal(f.Observe(v).response.proceed,false);assert.throws(()=>f.Fresh(),/OBSERVATION_MISMATCH/);});
test('client normal/proceed fields are rejected instead of granting authority',()=>{const f=Fixture(),v=f.Value();v.normal=true;v.proceed=true;assert.throws(()=>f.Observe(v),/SECURITY_INPUT_INVALID/);assert.throws(()=>f.Fresh(),/FRESH_OBSERVATION_REQUIRED/);});
test('expiry and policy/operations revision changes prevent fresh use',()=>{for(const mutate of [f=>f.auth.__probe.decisions.values().next().value.deadline=0,f=>f.db.securityAuthorityPolicy.revision++,f=>f.setOps()]){const f=Fixture();f.Observe();mutate(f);assert.throws(()=>f.Fresh(),/FRESH_OBSERVATION_REQUIRED/);}});
test('expired challenge, invalid signature and failure invalidation never renew a decision',()=>{const f=Fixture();f.Observe();let c=f.auth.Execute(f.body),signed=f.Signed(c);signed.signature=Buffer.alloc(256).toString('base64');assert.throws(()=>f.auth.Execute(signed),/SIGNATURE_INVALID/);assert.throws(()=>f.Fresh(),/FRESH_OBSERVATION_REQUIRED/);f.auth.__probe.pending.get(c.challengeId).deadline=0;assert.throws(()=>f.auth.Execute(f.Signed(c)),/CHALLENGE_INVALID/);f.Observe();f.auth.Invalidate(f.row,'B','TEST_FAILURE');assert.throws(()=>f.Fresh(),/FRESH_OBSERVATION_REQUIRED/);});
test('service disabled and unknown action fail closed',()=>{const f=Fixture();f.disable();assert.throws(()=>f.auth.Execute(f.body),/SERVICE_DISABLED/);assert.throws(()=>Fixture().auth.Execute({...f.body,action:'permit'}),/SECURITY_INPUT_INVALID/);});

function GraphValue(f){const v=f.Value();f.artifact.ownMeasurementVersion=2;v.ownMeasurement={...v.ownMeasurement,contract:contract.OWN_GRAPH_CONTRACT,version:2,pointerGraph:require('../../services/integrity/peace.pointer-graph-contract').Expected(10)};return v;}
test('new approved pointer graph passes signed authority and fresh guard',()=>{const f=Fixture(),v=GraphValue(f);assert.equal(f.Observe(v).response.proceed,true);f.Fresh();assert.equal(f.revoked(),0);});
for(const edit of [v=>delete v.ownMeasurement,v=>{v.ownMeasurement={...v.ownMeasurement,contract:contract.OWN_CONTRACT,version:1};delete v.ownMeasurement.pointerGraph;},v=>v.ownMeasurement.pointerGraph.sha512='0'.repeat(128),v=>v.ownMeasurement.pointerGraph=require('../../services/integrity/peace.pointer-graph-contract').Expected(9)])test('signed pointer omission/downgrade/tamper retires related context',()=>{const f=Fixture(),v=GraphValue(f);f.Observe(v);edit(v);assert.throws(()=>f.Observe(v),/SECURITY_POINTER_GRAPH/);assert.equal(f.revoked(),1);assert.throws(()=>f.Fresh(),/FRESH_OBSERVATION_REQUIRED/);});
test('unsigned pointer mismatch cannot revoke a session',()=>{const f=Fixture(),v=GraphValue(f);v.ownMeasurement.pointerGraph.sha512='0'.repeat(128);const c=f.auth.Execute(f.body),signed=f.Signed(c,v);signed.signature=Buffer.alloc(256).toString('base64');assert.throws(()=>f.auth.Execute(signed),/SIGNATURE_INVALID/);assert.equal(f.revoked(),0);});

for(const mode of ['enforce','observe'])test(mode+': failed/omitted graph in incomplete measurement cannot renew or imply tamper',()=>{
 const f=Fixture(mode),v=GraphValue(f);f.Observe(v);v.measurement='READ_ERROR';for(const k of ['fileSha512','fileCrc64','codeSha512','codeCrc64','codeXxh3_128','codeBlake3'])v[k]='';delete v.crcLayers;
 Object.assign(v.ownMeasurement,{coverage:'PARTIAL',fileStatus:'READ_ERROR',codeStatus:'NOT_MEASURED',crcStatus:'NOT_MEASURED',imageStable:false,pointerGraph:{version:1,scope:'SEALED_API_ARENA',status:'FAILED',slots:0,nodes:0,edges:0,depth:0,sha512:'',crc64:''}});
 assert.equal(f.Observe(v).response.proceed,false);assert.throws(()=>f.Fresh(),/MEASUREMENT_INCOMPLETE/);assert.equal(f.revoked(),0);
 delete v.ownMeasurement;assert.equal(f.Observe(v).response.proceed,false);assert.throws(()=>f.Fresh(),/MEASUREMENT_INCOMPLETE/);assert.equal(f.revoked(),0);
});
