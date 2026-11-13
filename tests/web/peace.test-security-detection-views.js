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
  const record=views.ForFlows([b.id]).items[0];assert.equal(record.invalidated,false);assert.equal(record.sessionInvalidated,true);assert.equal(record.cohortRevoked,true);assert.equal(record.handoff.B,'REVOKED');
 });
 check('Reading view adds no state and excludes raw process data even from an unexpected provider field',()=>{
  const before=JSON.stringify(store.Load()),original=detections.MemberIndex,raw=original();
  detections.MemberIndex=()=>raw.map(r=>({...r,rawPath:'PRIVATE_PATH',pid:12345,machineId:'PRIVATE_MACHINE',attestation:{...r.attestation,rawQuote:'PRIVATE_QUOTE'},handoff:{...r.handoff,rawParent:'PRIVATE_PARENT'}}));
  try{const encoded=JSON.stringify(members.Detail(alice.id,{category:'detections'}));assert.doesNotMatch(encoded,/PRIVATE_|"pid"|rawPath|machineId|rawQuote|rawParent/);}
  finally{detections.MemberIndex=original;}
  assert.equal(JSON.stringify(store.Load()),before);
 });
 check('Member projection preserves bounded server context and rejects raw identity material',()=>{
  const original=detections.MemberIndex,base=original().find(row=>row.flowId===a.id);
  const context={actorClass:'TRUSTED_A',actorRole:'A',actorIdentity:'a'.repeat(64),targetRole:'B',targetIdentity:'b'.repeat(64),phase:'A_HANDOFF_TO_B',capability:'PROCESS_QUERY_LIMITED_INFORMATION',accessMask:0x00101000,tokenDelta:0,coverage:'HEALTHY',capabilityDecision:'EXPECTED',firstPartyAttested:true,sameSession:true,bindingScope:'SERVER_BOUND_CLIENT_OBSERVATION',peerId:'c'.repeat(48),grantId:'d'.repeat(48),baseline:false,contextMixed:false,rawPath:'PRIVATE_PATH',pid:54321,tokenId:'PRIVATE_TOKEN',rawQuote:'PRIVATE_QUOTE'};
  detections.MemberIndex=()=>[{...base,disposition:'EXPECTED_FIRST_PARTY',coverageState:'HEALTHY',context}];
  try{
   const item=members.Detail(alice.id,{category:'detections'}).categories.detections.items[0];
   assert.equal(item.disposition,'EXPECTED_FIRST_PARTY');assert.equal(item.coverageState,'HEALTHY');assert.equal(item.context.actorIdentity,'a'.repeat(64));assert.equal(item.context.grantId,'d'.repeat(48));assert.equal(item.context.firstPartyAttested,true);assert.equal(item.context.contextMixed,false);assert.equal(item.context.accessMask,0x00101000);assert.equal(item.context.tokenDelta,0);
   assert.doesNotMatch(JSON.stringify(item),/PRIVATE_|54321|rawPath|tokenId|rawQuote|"pid"/);
   detections.MemberIndex=()=>[{...base,context:{...context,actorIdentity:'PRIVATE_PATH',targetIdentity:'PRIVATE_PID',peerId:'PRIVATE_PEER',grantId:'PRIVATE_GRANT'}}];
   const invalid=views.ForFlows([a.id]).items[0];assert.equal(invalid.context.actorIdentity,undefined);assert.equal(invalid.context.grantId,undefined);assert.doesNotMatch(JSON.stringify(invalid),/PRIVATE_/);
  }finally{detections.MemberIndex=original;}
 });
 check('Mixed, missing and ambiguous flow/session identity never leaks into another member',()=>{
  const original=detections.MemberIndex,raw=original(),base=raw.find(r=>r.flowId===a.id);
  const hostile=[{...base,id:'a'.repeat(64),sessionId:b.sessionId},{...base,id:'b'.repeat(64),sessionId:'F'.repeat(24)},{...base,id:'c'.repeat(64),flowId:'F'.repeat(24)},{...base,id:'d'.repeat(64),epoch:'0'},{...base,id:'e'.repeat(64),role:'O'}];
  detections.MemberIndex=()=>[...raw,...hostile];
  try{
   assert.equal(members.Detail(alice.id,{category:'detections'}).categories.detections.totalCount,24);
   assert.equal(members.Detail(bob.id,{category:'detections'}).categories.detections.totalCount,1);
   const unassigned=members.Detail('unassigned',{category:'detections'}).categories.detections;
   assert.equal(unassigned.totalCount,5);assert.ok(unassigned.items.every(r=>r.rootFlowId===''&&r.memberId===''&&r.assignmentTargetId===''&&r.cohortRevoked===undefined));
   assert.equal(views.ForFlows([a.id,b.id]).totalCount,25);
  }finally{detections.MemberIndex=original;}
 });
 check('Durable detection metadata reaches the actual member renderer with original names and actual CRC variants',()=>{
  const dc=fixture.Device(),sc=fixture.Session(dc),c=Object.values(store.Load().flows).find(f=>f.sessionId===sc.sessionId);
  members.Assign(body({kind:'FLOW',targetId:c.id,memberId:alice.id,expectedMemberId:''}),'TEST');
  detections.RecordPath(c,'B','integrity',{sequence:h(1),tick:h(100),detections:[sample('dkProcess'),sample('dkSensorPressure')]},false);
  detections.RecordServer({row:c,stage:'B',id:'CRC_ROLE_MISMATCH',source:'peace.desktop-security-authority',crcComparison:{signals:[{role:'crc32c',status:'MISMATCH'},{role:'ecma182',status:'MATCH'}]}});
  const detail=members.Detail(alice.id,{category:'detections',pageSize:'100'}),rows=detail.categories.detections.items.filter(r=>r.flowId===c.id);
  assert.equal(rows.length,3);
  const process=rows.find(r=>r.detectionId==='dkProcess'),warning=rows.find(r=>r.detectionId==='dkSensorPressure'),crc=rows.find(r=>r.detectionId==='CRC_ROLE_MISMATCH');
  assert.equal(process.displayName,'Process Detect');assert.equal(process.origin,'NHW');
  assert.equal(warning.displayName,'Waring Detect');assert.match(warning.conditionLabel,/Sensor Pressure/);assert.equal(warning.signalClass,'UNKNOWN');
  assert.equal(crc.origin,'COZY');assert.deepEqual(crc.algorithms,['CRC-32/ISCSI']);assert.equal(crc.displayName,'CRC-32/ISCSI Detect');
  const {JSDOM}=require('jsdom'),dom=new JSDOM('<div id="content"></div>',{runScripts:'outside-only'}),window=dom.window;
  window.content=window.document.getElementById('content');window.desktopDate=v=>String(v);
  window.esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  require('node:vm').runInContext(fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-members.js'),'utf8'),dom.getInternalVMContext());
  try{
   window.content.innerHTML=window.desktopSecurityDetectionsMarkup(rows);
   const text=window.content.textContent;
   for(const name of ['Process Detect','Waring Detect','Sensor Pressure','CRC-32/ISCSI Detect','dkProcess','dkSensorPressure','CRC_ROLE_MISMATCH'])assert.ok(text.includes(name),name);
   const headline=row=>window.content.querySelector('[data-desktop-key="security-detection-'+row.id+'"] summary').textContent;
   assert.match(headline(process),/Process/);assert.doesNotMatch(headline(process),/Process Detect/);
   assert.match(headline(warning),/Sensor Pressure/);assert.doesNotMatch(headline(warning),/Waring Detect/);
   assert.ok(!text.includes('CRC-64/ECMA-182'),'A matching CRC must not be presented as a detection');
   assert.ok(!text.includes('보안 사건 · 서버 기록'));
   assert.ok(window.content.querySelectorAll('.desktop-security-detections details').length===3);
  }finally{window.close();}
 });
 check('Signed context survives real enrollment, policy, durable storage, member projection and renderer',()=>{
  const authority=require('../../services/security/peace.desktop-security-authority'),paths=require('../../services/security/peace.nhw-response-paths'),peers=require('../../services/security/peace.nhw-peer-context'),policy=require('../../services/security/peace.security-context-policy');
  const device=fixture.Device(),start=fixture.Begin(device),flow=store.Load().flows[start.begin.flowId],db=store.Load();
  const peer={pid:12345,creationTime:h(100000),imageSha256:db.launchers[flow.launcherId].peerImageSha256,imageSha512:flow.launcherSha512,parentIdentity:'',phase:'A_BOOTSTRAP'};
  const identity=peers.StableIdentity(peer),unknown=policy.UnknownContext('A'),context={...Object.fromEntries(policy.CONTEXT_FIELDS.map(key=>[key,unknown[key]])),actorClass:'SELF',actorRole:'A',actorIdentity:identity,targetRole:'A',targetIdentity:identity,phase:'A_BOOTSTRAP',capability:'TOKEN_STATE',baseline:true,coverage:'COMPLETE'};
  const record={...sample('dkTokenObject'),context,signal:'OBSERVED'};
  const send=(records,sequence)=>{
   const payload=JSON.stringify({version:5,sequence:h(sequence),tick:h(100+sequence),digest:crypto.createHash('sha512').update(JSON.stringify(records)).digest('hex').slice(0,16),confirmed:false,trust:0,detections:records,peer});
   const request={stage:'A',sessionId:flow.id,sessionToken:start.begin.downloadTicket,machineId:device.machineId,binding:crypto.createHash('sha512').update(payload).digest('hex'),action:'nhwIntegrityChallenge'},challenge=authority.Execute(request),submit={...request,action:'nhwIntegritySubmit',challengeId:challenge.challengeId,payload};
   submit.signature=fixture.Sign(device,paths.Canonical(submit,challenge,'integrity'));return authority.Execute(submit);
  };
  assert.equal(send([record],1).stopped,false);
  members.Assign(body({kind:'FLOW',targetId:flow.id,memberId:alice.id,expectedMemberId:''}),'TEST');
  const before=views.ForFlows([flow.id]).items[0];assert.equal(before.disposition,'EXPECTED_FIRST_PARTY');assert.equal(before.context.actorIdentity,identity);assert.equal(before.context.accessMask,0);assert.equal(before.context.tokenDelta,0);assert.equal(before.context.sameSession,true);assert.equal(before.context.firstPartyAttested,true);assert.equal(before.invalidated,false);assert.equal(before.cohortRevoked,false);assert.equal(before.signal,'OBSERVED');
  assert.equal(send([{...sample('dkPECodeIntegrity'),context:{...context,capability:'MODULE_STATE',baseline:false},signal:'DETECTED'}],2).stopped,true);
  const rows=members.Detail(alice.id,{category:'detections',pageSize:'100'}).categories.detections.items.filter(row=>row.flowId===flow.id),expected=rows.find(row=>row.detectionId==='dkTokenObject'),cause=rows.find(row=>row.detectionId==='dkPECodeIntegrity');
  assert.equal(expected.invalidated,false);assert.equal(expected.sessionInvalidated,true);assert.equal(expected.cohortRevoked,true);assert.equal(cause.invalidated,true);assert.equal(cause.disposition,'DETECTION');assert.equal(cause.signal,'DETECTED');
  const {JSDOM}=require('jsdom'),dom=new JSDOM('<main id="content"></main>',{runScripts:'outside-only'}),window=dom.window;
  window.desktopDate=String;window.esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  require('node:vm').runInContext(fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-members.js'),'utf8'),dom.getInternalVMContext());
  try{
   window.document.getElementById('content').innerHTML=window.desktopSecurityDetectionsMarkup(rows);
   const shown=window.document.querySelector('[data-desktop-key="security-detection-'+expected.id+'"]');assert.match(shown.textContent,/정상 역할 동작/);assert.match(shown.textContent,/동일 세션 바인딩 확인/);assert.match(shown.textContent,/무효화 기록 없음/);assert.match(shown.textContent,/센서 관측/);assert.doesNotMatch(shown.querySelector('summary').textContent,/Token Detect/);assert.doesNotMatch(shown.textContent,/서버 세션 무효화|PID 12345/);
   const shownCause=window.document.querySelector('[data-desktop-key="security-detection-'+cause.id+'"]');assert.match(shownCause.querySelector('summary').textContent,/확정 감지.*서버 세션 무효화/);assert.match(shownCause.textContent,/센서 감지/);assert.match(shownCause.textContent,/동일 실행의 서버 권한세션 폐기됨/);
  }finally{window.close();}
 });
 check('Every NHW state and Cozy detection remains renderable with all disposition classes',()=>{
  const {JSDOM}=require('jsdom'),dom=new JSDOM('<main id="content"></main>',{runScripts:'outside-only'}),window=dom.window;
  window.desktopDate=String;window.esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  require('node:vm').runInContext(fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-members.js'),'utf8'),dom.getInternalVMContext());
  try{
   const kinds=[...catalog.NHW,...catalog.COZY],statuses=['INTERNAL_EVIDENCE','EXPECTED_FIRST_PARTY','COVERAGE_WARNING','COVERAGE_DEGRADED','CORROBORATED_ANOMALY','DETECTION','OBSERVATION_UNRESOLVED'];
   assert.equal(catalog.NHW.length,204);assert.equal(catalog.COZY.length,122);
   const rows=kinds.map((kind,index)=>({id:'all-'+index,detectionId:kind.id,displayName:kind.displayName||kind.label||kind.id,disposition:statuses[index%statuses.length],invalidated:false,context:{actorClass:'UNKNOWN',bindingScope:'UNVERIFIED_CLIENT_OBSERVATION'}}));
   window.document.getElementById('content').innerHTML=window.desktopSecurityDetectionsMarkup(rows);
   const text=window.document.body.textContent;assert.equal(window.document.querySelectorAll('.desktop-security-detections>details').length,326);
   for(const row of rows)assert.ok(text.includes(row.detectionId),row.detectionId);
   for(const status of statuses)assert.ok(text.includes(status),status);
   assert.ok(!text.includes('동일 세션 바인딩 확인'));assert.ok(!text.includes('서버 세션 무효화'));
  }finally{window.close();}
 });
 console.log('SECURITY_DETECTION_VIEWS_PASS '+checks+' groups');
}finally{bootstrap.Stop();require('../../services/observability/peace.desktop-performance-metrics').Close();require('../../storage/sqlite/peace.sqlite-database').Close();fs.rmSync(dir,{recursive:true,force:true});}
