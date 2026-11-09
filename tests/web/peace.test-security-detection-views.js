'use strict';
// Real durable store + member attribution. Sensor observations are synthetic;
// this does not claim a native sensor, Windows process exit or hardware quote.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-detection-view-'));
Object.assign(process.env,{DATA_DIR:dir,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-DETECTION-VIEW'});
require('../../core/peace.utilities').EnsureDirs();
const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
const members=require('../../services/members/peace.desktop-members'),detections=require('../../services/security/peace.security-detections'),views=require('../../services/members/peace.desktop-security-detection-views'),catalog=require('../../services/security/peace.security-detection-catalog');
const bootstrap=require('../../services/bootstrap/peace.desktop-bootstrap');
const body=x=>({expectedRevision:members.State().revision,requestId:crypto.randomUUID(),...x});
const h=n=>BigInt(n).toString(16).padStart(16,'0');
const sample=(id,count=1,correlation=false)=>({id,source:'Cozy.NHW.Engine',firstTick:h(1),lastTick:h(50),count,families:correlation?24:1,confidence:correlation?80:0,correlation,attestationSequence:correlation?h(9):h(0),localOnly:!correlation});
let checks=0;
function check(label,fn){fn();checks++;console.log('PASS '+label);}
try{
 const deviceA=fixture.Device(),deviceB=fixture.Device();deviceB.machineId=deviceA.machineId;
 const sa=fixture.Session(deviceA),sb=fixture.Session(deviceB);
 const a=Object.values(store.Load().flows).find(f=>f.sessionId===sa.sessionId),b=Object.values(store.Load().flows).find(f=>f.sessionId===sb.sessionId);
 const alice=members.Create(body({displayName:'Alice',note:''}),'TEST').member,bob=members.Create(body({displayName:'Bob',note:''}),'TEST').member;
 members.Assign(body({kind:'FLOW',targetId:a.id,memberId:alice.id,expectedMemberId:''}),'TEST');
 members.Assign(body({kind:'FLOW',targetId:b.id,memberId:bob.id,expectedMemberId:''}),'TEST');
 const kinds=catalog.NHW.slice(0,23).map(x=>x.id);
 const payload={sequence:h(1),tick:h(100),detections:kinds.map(id=>sample(id))};
 detections.ParseRecords(payload.detections,payload.tick);detections.RecordPath(a,'B','integrity',payload,false);
 detections.RecordPath(a,'A','trust',{sequence:h(1),tick:h(100),detections:[sample('dkProcess',2)]},false);
 detections.RecordPath(b,'B','driver',{sequence:h(1),tick:h(100),detections:[sample('dkVulnerableDriver',3)]},false);
 check('Per-member pagination happens after exact flow/session binding, even for a shared PC',()=>{
  const ar=members.Detail(alice.id,{category:'detections',page:'2',pageSize:'20'}),br=members.Detail(bob.id,{category:'detections'});
  assert.equal(ar.counts.detections,24);assert.equal(ar.categories.detections.totalCount,24);assert.equal(ar.categories.detections.items.length,4);
  assert.ok(ar.categories.detections.items.every(r=>r.flowId===a.id&&r.memberId===alice.id));
  assert.equal(br.categories.detections.items.length,1);assert.equal(br.categories.detections.items[0].flowId,b.id);assert.equal(br.categories.detections.items[0].detectionId,'dkVulnerableDriver');
  assert.equal(members.Detail('unassigned',{category:'detections'}).categories.detections.totalCount,0);
 });
 check('Flow views retain exact cause, path, epoch, source and bounded detail',()=>{
  const record=members.Detail(bob.id,{category:'detections'}).categories.detections.items[0];
  assert.equal(record.epoch,String(b.createdAt));assert.equal(record.sensor,'Cozy.NHW.Engine');assert.equal(record.responsePath,'driver');assert.equal(record.count,3);assert.equal(record.confirmationCount,0);assert.equal(record.invalidated,false);assert.equal(record.evidenceLevel,'CLIENT_LOCAL_OBSERVATION');assert.deepEqual(record.evidenceFamilies,['HANDLE_SNAPSHOT']);
  const flow=members.Detail(alice.id,{category:'flows'}).categories.flows.items[0];assert.equal(flow.securityDetections.totalCount,24);assert.equal(flow.securityDetections.items.length,20);assert.equal(flow.securityDetections.truncated,true);assert.ok(flow.securityDetections.items.every(r=>r.rootFlowId===a.id));
  assert.equal(views.ForFlows([b.id]).items.length,1);assert.equal(views.ForFlows(['F'.repeat(24)]).items.length,0);
 });
 check('Repeated cumulative producer count does not invent new confirmations',()=>{
  detections.RecordPath(b,'B','driver',{sequence:h(2),tick:h(101),detections:[sample('dkVulnerableDriver',3)]},false);
  const record=views.ForFlows([b.id]).items[0];assert.equal(record.count,3);assert.equal(record.confirmationCount,0);
 });
 check('A later session revoke is distinct from a detection causing invalidation',()=>{
  bootstrap.Revoke(b.sessionId,{reason:'TEST_ADMIN_REVOKE'},'TEST');
  const record=views.ForFlows([b.id]).items[0];assert.equal(record.invalidated,false);assert.equal(record.sessionInvalidated,true);assert.equal(record.handoff.B,'REVOKED');
 });
 check('Reading view adds no state and excludes raw process data even from an unexpected provider field',()=>{
  const before=JSON.stringify(store.Load()),original=detections.MemberIndex,raw=original();
  detections.MemberIndex=()=>raw.map(r=>({...r,rawPath:'PRIVATE_PATH',pid:12345,machineId:'PRIVATE_MACHINE',attestation:{...r.attestation,rawQuote:'PRIVATE_QUOTE'},handoff:{...r.handoff,rawParent:'PRIVATE_PARENT'}}));
  try{const encoded=JSON.stringify(members.Detail(alice.id,{category:'detections'}));assert.doesNotMatch(encoded,/PRIVATE_|"pid"|rawPath|machineId|rawQuote|rawParent/);}
  finally{detections.MemberIndex=original;}
  assert.equal(JSON.stringify(store.Load()),before);
 });
 check('Mixed, missing and ambiguous flow/session identity never leaks into another member',()=>{
  const original=detections.MemberIndex,raw=original(),base=raw.find(r=>r.flowId===a.id);
  const hostile=[{...base,id:'a'.repeat(64),sessionId:b.sessionId},{...base,id:'b'.repeat(64),sessionId:'F'.repeat(24)},{...base,id:'c'.repeat(64),flowId:'F'.repeat(24)},{...base,id:'d'.repeat(64),epoch:'0'},{...base,id:'e'.repeat(64),role:'O'}];
  detections.MemberIndex=()=>[...raw,...hostile];
  try{
   assert.equal(members.Detail(alice.id,{category:'detections'}).categories.detections.totalCount,24);
   assert.equal(members.Detail(bob.id,{category:'detections'}).categories.detections.totalCount,1);
   const unassigned=members.Detail('unassigned',{category:'detections'}).categories.detections;
   assert.equal(unassigned.totalCount,5);assert.ok(unassigned.items.every(r=>r.rootFlowId===''&&r.memberId===''&&r.assignmentTargetId===''));
   assert.equal(views.ForFlows([a.id,b.id]).totalCount,25);
  }finally{detections.MemberIndex=original;}
 });
 console.log('SECURITY_DETECTION_VIEWS_PASS '+checks+' groups');
}finally{bootstrap.Stop();require('../../services/observability/peace.desktop-performance-metrics').Close();require('../../storage/sqlite/peace.sqlite-database').Close();fs.rmSync(dir,{recursive:true,force:true});}
