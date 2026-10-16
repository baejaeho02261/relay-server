'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'remaining-own-'));process.env.DATA_DIR=temp;process.env.HA_ENABLED='0';
const {Isolated}=require('./completion-6-10-fixture'),contract=require('../services/measurementPlanContract'),crc=require('../services/desktopCrcPolicy');
const baseline=require('../services/desktopIntegrity').CodeImage(require('./crc-test-fixture').crcTestFixture()),keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const artifact={id:'OWN_ARTIFACT',ownMeasurementVersion:1,codeSha512:baseline.sha512,codeCrc64:baseline.crc64,codeXxh3_128:baseline.xxh3_128,codeBlake3:baseline.blake3,fileXxh3_128:'e'.repeat(32),fileBlake3:'f'.repeat(64),crcLayers:baseline.crcLayers};
const row={id:'OWN_FLOW',sessionId:'OWN_SESSION',reportContextId:'OWN_SESSION',releaseId:artifact.id,stage:'B',machineId:'A'.repeat(64),publicKey:require('../services/connectTransportKey').PublicBlob(keys.publicKey).toString('base64'),integrityArtifact:artifact};
const reports=Isolated('services/desktopIntegrityReports.js',[],{'./desktopBootstrap':{AuthenticateIntegrityReport:()=>row,AuthenticateIntegrityReceipt:()=>row,Revoke:()=>{}},'./desktopSecurityAuthority':{Policy:()=>({revision:1,requireCompleteCrcLayers:true}),UsesAuthority:()=>false},'../storage/audit':{LogEvent:()=>{}}});
const common={stage:'B',sessionId:row.sessionId,sessionToken:'TEST_TOKEN',machineId:row.machineId};
function submit(p){const c=reports.Execute({...common,action:'challenge'}),payload=JSON.stringify(p);return reports.Execute({...common,action:'submit',reportId:c.reportId,payload,signature:crypto.sign('sha256',Buffer.from(reports.Canonical(row.reportContextId,c,payload)),keys.privateKey).toString('base64')});}
function payload(){return {version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha512:baseline.sha512,codeCrc64:baseline.crc64,codeXxh3_128:baseline.xxh3_128,codeBlake3:baseline.blake3,fileXxh3_128:artifact.fileXxh3_128,fileBlake3:artifact.fileBlake3},crcLayers:structuredClone(baseline.crcLayers),ownMeasurement:{contract:contract.OWN_CONTRACT,version:1,startedTick:100,finishedTick:200,coverage:'FULL',fileStatus:'MEASURED',codeStatus:'MEASURED',crcStatus:'MEASURED',imageStable:true}};}
function authorityRegression(){
 // Synthetic authenticated contexts isolate storage, device enrollment and
 // optional release/profile controls. Payload, Evaluate, challenge/receipt,
 // freshness and RSA proof verification are the actual authority services.
 const file=require('../services/desktopIntegrity').Digests(require('./crc-test-fixture').crcTestFixture());
 const db={artifacts:{},launchers:{}},contexts={},events=[];
 for(const stage of ['A','B','O']){
  const a={id:'AUTH_'+stage,component:stage,version:'1.0.0',authorityVersion:1,ownMeasurementVersion:1,hashVersion:3,
   sha512:file.sha512,crc64:file.crc64,codeSha512:baseline.sha512,codeCrc64:baseline.crc64,
   codeXxh3_128:baseline.xxh3_128,codeBlake3:baseline.blake3,crcLayers:structuredClone(baseline.crcLayers)};
  db.artifacts[a.id]=a;db.launchers['LA_'+stage]={artifactId:a.id};
  contexts[stage]={id:'FLOW_'+stage,sessionId:'SESSION_'+stage,launcherId:'LA_'+stage,releaseId:a.id,
   stage,machineId:row.machineId,publicKey:row.publicKey,integrityArtifact:a};
 }
 const authority=Isolated('services/desktopSecurityAuthority.js',[],{
  './desktopBootstrapStore':{Load:()=>db},
  './desktopBootstrap':{EnsureSecurityAvailable(){},AuthenticateIntegrityReport(body){
   const current=contexts[body.stage];assert(current,'fixture stage');
   assert.equal(body.sessionId,body.stage==='A'?current.id:current.sessionId);
   assert.equal(body.sessionToken,'AUTH_TEST_TOKEN');assert.equal(body.machineId,current.machineId);return current;
  }},
  './desktopDeviceIdentity':{AssertSession(){}},
  './desktopSecurityOperations':{EffectivePolicy:p=>p,ArtifactReason:()=>'',EvaluateContract:()=>null,Revision:()=>7},
  './desktopMitigationProfiles':{Select:()=>null,RequireCurrent(){},Check:()=>''},
  '../storage/audit':{LogEvent:(type,detail)=>events.push({type,...JSON.parse(detail)})}
 });
 let ordinal=0;
 function evidence(){return {version:1,hashVersion:3,measurement:'MEASURED',fileSha512:file.sha512,fileCrc64:file.crc64,
  codeSha512:baseline.sha512,codeCrc64:baseline.crc64,codeXxh3_128:baseline.xxh3_128,codeBlake3:baseline.blake3,
  crcLayers:structuredClone(baseline.crcLayers),ownMeasurement:payload().ownMeasurement,
  apiSealed:true,apiSlots:60,dynamicCode:'ALLOWED',cfg:'DISABLED'};}
 function request(stage='A',intent='finish'){
  const current=contexts[stage],context={stage,sessionId:stage==='A'?current.id:current.sessionId,
   sessionToken:'AUTH_TEST_TOKEN',machineId:current.machineId,intent,binding:authority.Binding('own-bundle-'+(++ordinal),file.sha512)};
  const challenge=authority.Execute({...context,action:'challenge'});
  return {context,challenge,fresh:()=>authority.RequireFresh(current,stage,intent,context.binding)};
 }
 function signed(r,value){const text=JSON.stringify(value);return {...r.context,action:'submit',challengeId:r.challenge.challengeId,
  payload:text,signature:crypto.sign('sha256',Buffer.from(authority.Canonical(r.context,r.challenge,text)),keys.privateKey).toString('base64')};}
 for(const [stage,intent] of [['A','finish'],['B','redeem'],['B','verify'],['O','verify']]){
  const r=request(stage,intent),p=evidence();
  assert.equal(contract.ValidateOwnMetadata(p.ownMeasurement,p.measurement,p.crcLayers),true);
  assert.equal(authority.Evaluate(authority.Payload(JSON.stringify(p)),contexts[stage].integrityArtifact,authority.Policy(),contexts[stage].integrityArtifact).status,'PASS');
  assert.throws(r.fresh,/SECURITY_FRESH_OBSERVATION_REQUIRED/);
  const body=signed(r,p),result=authority.Execute(body);
  assert.equal(result.status,'PASS',stage+'/'+intent+' signed FULL bundle');assert.equal(result.proceed,true);assert.equal(result.attested,false);
  r.fresh();assert.deepEqual(authority.Execute(body),result,'exact signed receipt remains recoverable');
  assert(events.some(e=>e.kind==='OBSERVATION'&&e.stage===stage&&e.intent===intent&&e.reason==='BASELINE_MATCH'));
 }
 const badSignature=request();
 assert.throws(()=>authority.Execute({...signed(badSignature,evidence()),signature:Buffer.alloc(256).toString('base64')}),/SECURITY_SIGNATURE_INVALID/);
 assert.throws(badSignature.fresh,/SECURITY_FRESH_OBSERVATION_REQUIRED/);
 function reject(edit,reason){const r=request(),p=evidence();edit(p);assert.throws(()=>authority.Execute(signed(r,p)),reason);assert.throws(r.fresh,/SECURITY_FRESH_OBSERVATION_REQUIRED/);}
 reject(p=>delete p.ownMeasurement,/INTEGRITY_OWN_MEASUREMENT_REQUIRED/);
 reject(p=>delete p.crcLayers,/SECURITY_INPUT_INVALID/);
 for(const edit of [m=>m.finishedTick=99,m=>m.finishedTick=60101,m=>m.startedTick=2**53,m=>m.imageStable=false,m=>m.fileStatus='NOT_MEASURED',m=>m.coverage='SAMPLED',m=>m.version=2]){
  reject(p=>edit(p.ownMeasurement),/SECURITY_INPUT_INVALID/);
 }
 // An optional supplied bundle still must be valid for a legacy artifact.
 contexts.A.integrityArtifact.ownMeasurementVersion=0;
 reject(p=>p.ownMeasurement.imageStable=false,/SECURITY_INPUT_INVALID/);
 contexts.A.integrityArtifact.ownMeasurementVersion=1;
 for(const role of Object.keys(baseline.crcLayers).filter(k=>k!=='version')){
  const r=request(),p=evidence(),before=p.crcLayers[role].digest;
  p.crcLayers[role].digest=(before[0]==='0'?'1':'0')+before.slice(1);
  const result=authority.Execute(signed(r,p));
  assert.equal(result.status,'MISMATCH',role+' tamper remains denied');assert.equal(result.reason,'CRC_ROLE_MISMATCH');assert.equal(result.proceed,false);
  assert.throws(r.fresh,/SECURITY_OBSERVATION_MISMATCH/);
 }
 console.log('PASS authority own bundle: real Payload/Evaluate and RSA Challenge/Submit/RequireFresh for A finish, B redeem/verify, O verify; invalid/missing metadata, missing CRC, invalid signature and all nine CRC tamper denials; synthetic contexts, no Windows execution');
}
try{
 assert(crc.Compare(baseline.crcLayers,baseline.crcLayers).complete);
 const valid=payload();assert.equal(submit(valid).status,'VERIFIED');
 const absent=payload();delete absent.ownMeasurement;assert.throws(()=>submit(absent),/INTEGRITY_OWN_MEASUREMENT_REQUIRED/);
 for(const edit of [m=>m.finishedTick=99,m=>m.finishedTick=60101,m=>m.startedTick=2**53,m=>m.imageStable=false,m=>m.fileStatus='NOT_MEASURED',m=>m.coverage='SAMPLED',m=>m.version=2]){const p=payload();edit(p.ownMeasurement);assert.throws(()=>submit(p),/INTEGRITY_REPORT_INVALID/);}
 for(const role of Object.keys(baseline.crcLayers).filter(k=>k!=='version')){
  const p=payload(),before=p.crcLayers[role];p.crcLayers[role]={algorithm:before.algorithm,role:before.role,status:'failed',reason:'DEADLINE_EXCEEDED'};
  const cmp=crc.Compare(p.crcLayers,baseline.crcLayers);assert.equal(cmp.matched,false);assert.equal(cmp.complete,false);assert.equal(cmp.signals.find(x=>x.role===role).reason,'DEADLINE_EXCEEDED');assert.equal(cmp.signals.filter(x=>x.status==='MATCH').length,8);
  assert.throws(()=>submit(p),/INTEGRITY_REPORT_INVALID/,'failed role cannot claim FULL');
  p.own={status:'COVERAGE_INSUFFICIENT'};Object.assign(p.ownMeasurement,{coverage:'PARTIAL',crcStatus:'COVERAGE_INSUFFICIENT'});
  const result=submit(p);assert.equal(result.terminate,true);const record=reports.List({sessionId:row.sessionId}).items.find(x=>x.id===result.reportId);assert.equal(record.ownMeasurement.coverage,'PARTIAL');assert.equal(record.crcComparison.signals.find(x=>x.role===role).status,'FAILED');
  p.crcLayers[role].digest=before.digest;assert.throws(()=>submit(p),/INTEGRITY_REPORT_INVALID/,'failed role cannot retain stale digest');
 }
 const old=payload();delete old.ownMeasurement;artifact.ownMeasurementVersion=0;assert.equal(submit(old).status,'VERIFIED','explicit approvedlegacy capability retained');
 const fixture=require('./desktop-bootstrap-fixture').PE('A','plain');assert.equal(contract.ArtifactOwnVersion(Buffer.concat([fixture,Buffer.from(contract.OWN_CONTRACT)])),0);Buffer.from(contract.OWN_CONTRACT).copy(fixture,600);assert.equal(contract.ArtifactOwnVersion(fixture),1);
 authorityRegression();
 console.log('PASS own bundle: actual RSA signed FULL/omitted/stale/unsafe metadata, nine independent failed roles preserve eight valid results, stale digest rejection, artifact capability and explicit legacy contract');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
