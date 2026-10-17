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
 console.log('PASS own bundle: actual RSA signed FULL/omitted/stale/unsafe metadata, nine independent failed roles preserve eight valid results, stale digest rejection, artifact capability and explicit legacy contract');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
