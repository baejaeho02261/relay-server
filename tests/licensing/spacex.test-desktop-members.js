'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-members-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-MEMBER-TEST'});
require('../../core/spacex.utilities').EnsureDirs();
const members=require('../../services/members/spacex.desktop-members'),store=require('../../services/bootstrap/spacex.desktop-bootstrap-store');
const licenses=require('../../services/licensing/spacex.desktop-licenses'),fixture=require('../fixtures/bootstrap/spacex.desktop-bootstrap-fixture');
const bootstrap=require('../../services/bootstrap/spacex.desktop-bootstrap'),reports=require('../../services/integrity/spacex.desktop-integrity-reports');
const auth=require('../../web/authentication/spacex.web-auth'),route=require('../../web/routes/licensing/spacex.desktop-member-routes');
const actor='ADMIN:member-fixture',requestId=()=>crypto.randomUUID();
const body=fields=>({expectedRevision:members.State().revision,requestId:requestId(),...fields});
const assign=(kind,targetId,memberId,expectedMemberId='')=>members.Assign(body({kind,targetId,memberId,expectedMemberId}),actor);
const reject=(code,fn)=>assert.throws(fn,e=>e.message===code,code);
let checks=0;
function check(name,fn){fn();checks++;console.log('PASS '+name);}
async function run(){
 let alice,bob,a,b,flowA,flowB,licenseA,licenseB,bindingId,aliceReportCount,bobReportCount;
 check('Old data remains unassigned without inventing a registry or changing authority',()=>{
  a=fixture.Device();b=fixture.Device();b.machineId=a.machineId;
  const sa=fixture.Session(a),sb=fixture.Session(b);
  flowA=Object.values(store.Load().flows).find(r=>r.sessionId===sa.sessionId);
  flowB=Object.values(store.Load().flows).find(r=>r.sessionId===sb.sessionId);
  licenseA=licenses.Create({productId:'cleaner.pubg',label:'Existing A',requestId:requestId()},actor);
  licenseB=licenses.Create({productId:'cleaner.pubg',label:'Existing B',requestId:requestId()},actor);
  const before=JSON.stringify(store.Load());
  const view=members.List();assert.equal(view.items.length,0);assert.equal(view.unassigned.counts.flows,2);assert.equal(view.unassigned.counts.licenses,2);
  assert.equal(store.Load().members,undefined);assert.equal(JSON.stringify(store.Load()),before);
 });
 check('Create is durable, versioned, exact-retry idempotent and body-bound',()=>{
  const request=body({displayName:'사용자 <Alice>',note:'운영자 메모\n연락 식별자 없음'});
  const created=members.Create(request,actor);alice=created.member;
  assert.match(alice.id,/^[A-F0-9]{24}$/);assert.equal(alice.displayName,'사용자 <Alice>');
  assert.deepEqual(members.Create(request,actor),created);assert.equal(members.State().revision,1);
  reject('MEMBER_REQUEST_REUSED',()=>members.Create({...request,note:'changed'},actor));
  reject('MEMBER_REVISION_CONFLICT',()=>members.Create({...request,requestId:requestId()},actor));
  bob=members.Create(body({displayName:'Bob',note:''}),actor).member;
  assert.notEqual(alice.id,bob.id);
 });
 check('Bounds, unknown fields and invalid member IDs are rejected before publication',()=>{
  const revision=members.State().revision;
  for(const input of [{displayName:'',note:''},{displayName:'a'.repeat(81),note:''},{displayName:'ok',note:'x'.repeat(1001)},{displayName:'a\u0000b',note:''},{displayName:'ok',note:'',role:'admin'}])reject('MEMBER_INPUT_INVALID',()=>members.Create(body(input),actor));
  reject('MEMBER_NOT_FOUND',()=>members.Update('a'.repeat(24),body({displayName:'x',note:''}),actor));
  assert.equal(members.State().revision,revision);
 });
 check('A shared PC is not a human association and cannot merge customer histories',()=>{
  bindingId=require('../../services/devices/spacex.desktop-device-registry').BindingId(a.machineId);
  assign('DEVICE',bindingId,alice.id);
  assert.equal(members.Detail(alice.id).counts.devices,1);assert.equal(members.Detail(alice.id).counts.flows,0);
  assert.equal(members.Detail('unassigned').counts.flows,2);
  assign('LAUNCHER',flowA.launcherId,alice.id);
  assign('FLOW',flowB.id,bob.id);
  const av=members.Detail(alice.id),bv=members.Detail(bob.id);
  assert.deepEqual(av.categories.flows.items.map(r=>r.id),[flowA.id]);
  assert.deepEqual(bv.categories.flows.items.map(r=>r.id),[flowB.id]);
  assert.equal(av.categories.flows.items[0].assignmentOrigin,'LINKED');
  assert.equal(av.categories.flows.items[0].assignedMemberId,'');
  assert.equal(bv.categories.flows.items[0].assignmentOrigin,'DIRECT');
 });
 check('Assignment guards reject stale owner, unknown targets and contradictory links',()=>{
  const revision=members.State().revision;
  reject('MEMBER_ASSIGNMENT_CONFLICT',()=>assign('FLOW',flowB.id,alice.id,''));
  reject('MEMBER_ASSOCIATION_CONFLICT',()=>assign('FLOW',flowA.id,bob.id));
  reject('MEMBER_ASSIGNMENT_NOT_DIRECT',()=>assign('FLOW',flowA.id,''));
  reject('MEMBER_TARGET_NOT_FOUND',()=>assign('LICENSE','F'.repeat(24),alice.id));
  reject('MEMBER_TARGET_NOT_FOUND',()=>assign('DEVICE',a.machineId,alice.id));
  assert.equal(members.State().revision,revision);
  assign('LICENSE',licenseA.license.id,alice.id);assign('LICENSE',licenseB.license.id,bob.id);
  assert.equal(members.Detail(alice.id).categories.licenses.items[0].id,licenseA.license.id);
 });
 check('License-linked issued launchers inherit only the explicitly assigned license owner',()=>{
  const issued=bootstrap.IssueLauncher({requestId:requestId(),licenseId:licenseA.license.id,label:'Bound Alice'},actor);
  const r=members.Detail(alice.id).categories.launchers.items.find(r=>r.id===issued.launcherId);
  assert.ok(r);assert.equal(r.assignmentOrigin,'LINKED');
  reject('MEMBER_ASSOCIATION_CONFLICT',()=>assign('LAUNCHER',issued.launcherId,bob.id));
 });
 check('All retained reports are partitioned before per-customer pagination',()=>{
  aliceReportCount=members.Detail(alice.id).counts.integrity+1;bobReportCount=members.Detail(bob.id).counts.integrity+105;
  reports.Record({stage:'B',check:'OWN_CODE',status:'REJECTED',reason:'CODE_HASH_MISMATCH',flowId:flowA.id,sessionId:flowA.sessionId,machineId:a.machineId,trusted:true});
  for(let i=0;i<105;i++)reports.Record({stage:'B',check:'MODULE_INVENTORY',status:'CLIENT_DIAGNOSTIC',reason:'CLIENT_REPORT',flowId:flowB.id,sessionId:flowB.sessionId,machineId:b.machineId});
  assert.equal(reports.List().items.length,100);
  const av=members.Detail(alice.id,{category:'integrity'}),bv=members.Detail(bob.id,{category:'integrity',page:'2',pageSize:'20'});
  assert.equal(av.categories.integrity.totalCount,aliceReportCount);assert.equal(av.categories.integrity.items[0].reason,'CODE_HASH_MISMATCH');
  assert.equal(av.categories.integrity.items[0].rootFlowId,flowA.id);assert.equal(av.categories.integrity.items[0].assignmentTargetId,flowA.id);
  assert.equal(bv.categories.integrity.totalCount,bobReportCount);assert.equal(bv.categories.integrity.items.length,20);
  assert.equal(members.Detail(alice.id,{category:'incidents'}).categories.incidents.items[0].kind,'INTEGRITY');
  assert.equal(members.Detail(alice.id,{category:'incidents'}).categories.incidents.items[0].source,'SERVER_COMPARISON');
  assert.equal(members.Detail(alice.id,{category:'incidents'}).categories.incidents.items[0].attested,false);
  assert.equal(members.Detail(bob.id,{category:'incidents'}).categories.incidents.items.length,0);
 });
 check('Mixed flow/session reports remain unassigned with original evidence classification',()=>{
  const mismatch=reports.Record({stage:'B',check:'OWN_CODE',status:'REJECTED',reason:'CODE_HASH_MISMATCH',flowId:flowA.id,sessionId:flowB.sessionId,machineId:a.machineId});
  const unassigned=members.Detail('unassigned',{category:'integrity'}).categories.integrity.items;
  const row=unassigned.find(r=>r.id===mismatch.id);assert.ok(row);assert.equal(row.rootFlowId,'');assert.equal(row.assignmentTargetId,'');assert.equal(row.source,'SIGNED_CLIENT_REPORT');
  assert.equal(members.Detail(alice.id).counts.integrity,aliceReportCount);
  assert.equal(members.Detail(bob.id).counts.integrity,bobReportCount);
 });
 check('Archive/restore and assignment removal do not modify execution authority',()=>{
  const before={licenses:JSON.stringify(licenses.DB()),flows:JSON.stringify(store.Load().flows),overlays:JSON.stringify(store.Load().overlays)};
  const archived=members.Archive(alice.id,body({archived:true}),actor);assert.equal(archived.authorizationChanged,false);
  assert.equal(members.List().items.some(r=>r.id===alice.id),false);assert.equal(members.List({status:'ARCHIVED'}).items[0].id,alice.id);
  assert.equal(members.Detail(alice.id).categories.integrity.totalCount,aliceReportCount);
  reject('MEMBER_ARCHIVED',()=>assign('FLOW',flowA.id,alice.id));
  members.Archive(alice.id,body({archived:false}),actor);
  assign('LICENSE',licenseB.license.id,'',bob.id);
  assert.ok(members.Detail('unassigned').categories.licenses.items.some(r=>r.id===licenseB.license.id));
  assert.equal(JSON.stringify(licenses.DB()),before.licenses);assert.equal(JSON.stringify(store.Load().flows),before.flows);assert.equal(JSON.stringify(store.Load().overlays),before.overlays);
 });
 check('Pagination/filter input is strict and metadata is escaped at the rendering boundary',()=>{
  assert.equal(members.List({q:'Alice',pageSize:'1'}).items[0].id,alice.id);
  assert.equal(members.List({q:'운영자 메모'}).items[0].id,alice.id);
  const p1=members.List({status:'ALL',page:'1',pageSize:'1'}),p2=members.List({status:'ALL',page:'2',pageSize:'1'});
  assert.equal(p1.totalCount,2);assert.notEqual(p1.items[0].id,p2.items[0].id);
  for(const q of [{page:'0'},{page:'01'},{pageSize:'101'},{page:'1e1'},{pageSize:20},{status:'ACTIVE\n'},{extra:'x'}])reject('MEMBER_QUERY_INVALID',()=>members.List(q));
  reject('MEMBER_QUERY_INVALID',()=>members.Detail(alice.id,{category:'everything'}));
  assert.equal(members.Detail(alice.id).member.displayName,'사용자 <Alice>','The API supplies text; HTML escaping belongs to the client renderer.');
 });
 check('Public projections contain no bearer key, private key or approval transcript',()=>{
  const encoded=JSON.stringify([members.List({status:'ALL'}),members.Detail(alice.id),members.Detail(bob.id),members.Detail('unassigned')]);
  assert.ok(!encoded.includes(licenseA.licenseKey));assert.ok(!encoded.includes(licenseB.licenseKey));
  assert.doesNotMatch(encoded,/"(?:launcherTicket|sessionToken|downloadNonce|handoffNonce|publicKey|privateKey|signature|tokenHash|keyHash|issuanceNonce)"/);
 });
 check('Retired products have no member listing, count or assignment target',()=>{
  const id='F'.repeat(24),stored=licenses.DB().licenses;
  stored[id]={id,label:'Historical product',productId:'spoofer.ace',issuedAt:1};
  try{
   const view=members.Detail('unassigned',{category:'licenses'});
   assert.equal(view.categories.licenses.totalCount,1);
   assert.deepEqual(view.categories.licenses.items.map(row=>row.id),[licenseB.license.id]);
   reject('MEMBER_TARGET_NOT_FOUND',()=>assign('LICENSE',id,alice.id));
   assert.equal(stored[id].productId,'spoofer.ace');
  }finally{delete stored[id];}
 });
 check('An aborted durable mutation leaves no changed member or consumed request',()=>{
  const original=store.Atomic,request=body({displayName:'Write failed',note:''}),before=JSON.stringify(members.State());
  store.Atomic=()=>{throw Error('SYNTHETIC_WRITE_FAILURE');};try{assert.throws(()=>members.Create(request,actor),/SYNTHETIC_WRITE_FAILURE/);}finally{store.Atomic=original;}
  assert.equal(JSON.stringify(members.State()),before);assert.equal(members.Create(request,actor).member.displayName,'Write failed');
 });
 check('Fresh process reads persisted members, exact receipts and existing unassigned records',()=>{
  const request=body({displayName:'Restart receipt',note:''}),result=members.Create(request,actor);
  const code=`const assert=require('node:assert/strict');const m=require(${JSON.stringify(require.resolve('../../services/members/spacex.desktop-members'))});assert.deepEqual(m.Create(${JSON.stringify(request)},${JSON.stringify(actor)}),${JSON.stringify(result)});const a=m.Detail(${JSON.stringify(alice.id)});assert.equal(a.categories.integrity.totalCount,${aliceReportCount});assert.ok(m.Detail('unassigned').categories.licenses.items.some(r=>r.id===${JSON.stringify(licenseB.license.id)}));console.log('MEMBERS_RESTART_PASS');`;
  const child=cp.spawnSync(process.execPath,['-e',code],{cwd:path.resolve(__dirname,'../..'),env:process.env,encoding:'utf8',timeout:15000});
  assert.equal(child.status,0,child.stderr);assert.match(child.stdout,/MEMBERS_RESTART_PASS/);
 });
 check('Storage validator rejects unsupported schema, malformed assignments and dangling member IDs',()=>{
  members.Validate(members.State());
  for(const change of [s=>s.version=2,s=>s.extra=true,s=>s.items[alice.id].status='ADMIN',s=>s.assignments['FLOW:'+flowA.id]={kind:'FLOW',targetId:flowA.id,memberId:'F'.repeat(24),updatedAt:Date.now()},s=>s.receipts.bad={}]){const copy=structuredClone(members.State());change(copy);assert.throws(()=>members.Validate(copy),/MEMBER_STORAGE_INVALID/);}
 });
 check('License detail reflects a reassignment after member-list loading without altering authority',()=>{
  const workspace=require('../../services/operations/spacex.desktop-workspace'),issued=licenses.Create({productId:'cleaner.pubg',label:'Reassignment detail fixture',requestId:requestId()},actor),id=issued.license.id;
  assign('LICENSE',id,alice.id);const cached=members.Detail(alice.id,{category:'licenses'}),first=workspace.Detail(id);
  assert.ok(cached.categories.licenses.items.some(row=>row.id===id));assert.equal(first.membership.memberId,alice.id);
  const before={license:JSON.stringify(licenses.DB().licenses[id]),flows:JSON.stringify(store.Load().flows)};
  assign('LICENSE',id,bob.id,alice.id);const current=workspace.Detail(id);
  assert.equal(current.membership.memberId,bob.id);assert.equal(current.membership.assignedMemberId,bob.id);assert.equal(current.membership.source,'EXPLICIT_LICENSE_ASSIGNMENT');assert.equal(current.membership.revision,members.State().revision);assert.equal(first.membership.memberId,alice.id,'previous response stays a historical snapshot');
  assert.equal(JSON.stringify(licenses.DB().licenses[id]),before.license);assert.equal(JSON.stringify(store.Load().flows),before.flows);
  assign('LICENSE',id,'',bob.id);assert.equal(workspace.Detail(id).membership.memberId,'');assert.equal(workspace.Detail(id).membership.assignedMemberId,'');
 });
 let pc,otherPc,matchedLicense,pendingFlow;
 check('A verified PC receives one stable identity across separate keys and contact assignments',()=>{
  const before=JSON.stringify(store.Load()),matching=members.List({scope:'MATCH',status:'ALL'});
  assert.equal(Object.hasOwn(matching,'unassigned'),false);
  assert.equal(matching.totalCount,1);
  assert.equal(matching.items.length,1);
  const verified=matching.items.filter(row=>row.identitySource==='VERIFIED_PC_BINDING');
  assert.equal(verified.length,1);
  pc=verified[0];
  assert.equal(pc.bindingId,bindingId);
  assert.match(pc.memberCode,/^[A-F0-9]{24}$/);
  assert.equal(pc.memberCode,pc.id);
  assert.equal(pc.nickname,'PC-'+pc.id);
  assert.equal(pc.contactId,alice.id);
  assert.equal(pc.canEdit,false);
  assert.equal(members.List({scope:'MATCH',q:pc.nickname}).items[0].id,pc.id);
  const detail=members.Detail(pc.id,{scope:'MATCH'});
  assert.equal(detail.member.id,pc.id);
  assert.equal(detail.readOnly,true);
  assert.deepEqual(detail.categories.flows.items.map(row=>row.id).sort(),[flowA.id,flowB.id].sort());
  assert.ok(detail.categories.flows.items.some(row=>row.id===flowB.id&&row.assignedMemberId===bob.id));
  assert.equal(members.Detail(alice.id,{scope:'MATCH'}).member.identitySource,'OPERATOR_CONTACT');
  assert.ok(members.List({status:'ALL'}).items.some(row=>row.id===alice.id));
  assert.equal(members.List({scope:'MATCH',q:'Bob'}).totalCount,0);
  assert.ok(!JSON.stringify(detail).includes(a.machineId));
  assert.equal(JSON.stringify(store.Load()),before);
  reject('MEMBER_NOT_FOUND',()=>members.Detail('unassigned',{scope:'MATCH'}));
  reject('MEMBER_QUERY_INVALID',()=>members.List({scope:'UNKNOWN'}));
 });
 check('A launch without verified proof appears only in its record and distinct certified PCs stay distinct',()=>{
  const device=fixture.Device(),started=fixture.Begin(device);
  pendingFlow=started.begin.flowId;
  assert.equal(members.MatchRecord('FLOW',pendingFlow).state,'AWAITING_PC');
  assert.equal(members.List({scope:'MATCH'}).items.filter(row=>row.identitySource==='VERIFIED_PC_BINDING').length,1);
  fixture.Download(started.begin);
  fixture.Finish(device,started.begin);
  const resolved=members.MatchRecord('FLOW',pendingFlow);
  otherPc=resolved.memberId;
  assert.equal(resolved.state,'MATCHED');
  assert.notEqual(otherPc,pc.id);
  assert.notEqual(resolved.nickname,pc.nickname);
  assert.equal(members.MatchRecord('LAUNCHER',started.issue.launcherId).memberId,otherPc);
  assert.equal(members.MatchRecord('DEVICE',resolved.bindingId).memberId,otherPc);
  assert.ok(!JSON.stringify(resolved).includes(device.machineId));
 });
 check('Matching license drill-down fails closed for a different PC and projects no PC name in matching detail',()=>{
  matchedLicense=licenses.Create({productId:'cleaner.pubg',label:'Bound PC verification',requestId:requestId()},actor);
  const id=matchedLicense.license.id,request=requestId();
  assert.equal(members.MatchRecord('LICENSE',id).state,'AWAITING_PC');
  const payload=fixture.LicensePayload(a,{licenseKey:matchedLicense.licenseKey,deviceName:'Private-PC-label'},request);
  const payloadJSON=JSON.stringify(payload),payloadHash=fixture.sha512(payloadJSON);
  const initial={action:'redeem',requestId:request,deviceId:a.deviceId,publicKey:a.publicKey,payloadHash};
  const challenge=licenses.Challenge(initial);
  fixture.ObserveLicense(a,'redeem',request,payloadHash,payload);
  licenses.Execute({...initial,challengeId:challenge.challengeId,payloadJSON,signature:fixture.Sign(a,challenge.canonical)});
  const linked=members.MatchRecord('LICENSE',id);
  assert.equal(linked.memberId,pc.id);
  const matching=members.Detail(pc.id,{scope:'MATCH',category:'licenses'}).categories.licenses.items.find(row=>row.id===id);
  assert.ok(matching);
  assert.equal(Object.hasOwn(matching,'machineId'),false);
  assert.equal(Object.hasOwn(matching,'deviceName'),false);
  const workspace=require('../../services/operations/spacex.desktop-workspace');
  assert.equal(workspace.Detail(id,pc.id).membership.source,'VERIFIED_PC_BINDING');
  reject('MEMBER_ASSIGNMENT_CONFLICT',()=>workspace.Detail(id,otherPc));
 });
 check('Conflicting PC evidence stays in its original audit record without contaminating a match',()=>{
  const different=fixture.Device();
  const conflicting=reports.Record({stage:'B',check:'OWN_CODE',status:'REJECTED',reason:'CODE_HASH_MISMATCH',flowId:flowA.id,sessionId:flowA.sessionId,machineId:different.machineId});
  assert.ok(!members.Detail(pc.id,{scope:'MATCH',category:'integrity'}).categories.integrity.items.some(row=>row.id===conflicting.id));
  assert.ok(reports.MemberRecords([conflicting.id]).some(row=>row.id===conflicting.id));
 });
 const req={headers:{},socket:{remoteAddress:'127.0.0.1',encrypted:true}},admin=auth.CreateSession(req,'admin');
 async function request(suffix='',method='GET',payload={},session=admin,csrf=true){const url=new URL('https://localhost/api/desktop/members'+suffix);let status,value;const res={writeHead(c){status=c;},end(v){value=JSON.parse(v);}};const headers=csrf?{'x-csrf-token':session?.csrf||''}:{};assert.equal(await route.Handle({method,pathname:url.pathname,url,req:{...req,headers},res,session,body:payload}),true);return {status,value};}
 assert.equal((await request('', 'GET',{},null)).status,403);
 assert.equal((await request('', 'GET',{}, {id:'viewer',role:'viewer'})).status,403);
 assert.equal((await request()).status,200);
 const auditFirst=await request('?q=read-audit-check'),auditRepeat=await request('?q=read-audit-check');
 assert.equal(auditFirst.value.readAudit.repeated,false);assert.equal(auditRepeat.value.readAudit.repeated,true);
 assert.equal((await request('?q=read-audit-other')).value.readAudit.repeated,false);
 const secondAdmin=auth.CreateSession(req,'admin');assert.equal((await request('?q=read-audit-check','GET',{},secondAdmin)).value.readAudit.repeated,false);
 // Isolate the read-audit cache's capacity/clock behavior from durable I/O.
 // The earlier requests exercised the real store and real audit writer.
 const audit=require('../../services/storage/spacex.desktop-operation-audit'),savedList=members.List,savedAudit=audit.RecordAccess;
 let emitted=0;members.List=()=>({version:1,items:[],revision:members.State().revision});audit.RecordAccess=()=>{emitted++;};
 try{
  for(let i=0;i<2050;i++)assert.equal((await request('?q=cache-cap-'+i)).value.readAudit.repeated,false);
  assert.equal((await request('?q=cache-cap-0')).value.readAudit.repeated,false,'Oldest audit window must be evicted at the bound.');
  const first=await request('?q=cache-expiry');assert.equal(first.value.readAudit.repeated,false);
  assert.equal((await request('?q=cache-expiry')).value.readAudit.repeated,true);
  const perf=require('node:perf_hooks').performance,descriptor=Object.getOwnPropertyDescriptor(perf,'now'),tick=perf.now();
  Object.defineProperty(perf,'now',{configurable:true,value:()=>tick+60001});
  try{assert.equal((await request('?q=cache-expiry')).value.readAudit.repeated,false,'A monotonic 60s expiry requires another durable read event.');}
  finally{if(descriptor)Object.defineProperty(perf,'now',descriptor);else delete perf.now;}
  assert.equal(emitted,2053);
 }finally{members.List=savedList;audit.RecordAccess=savedAudit;}
 checks++;console.log('PASS Repeated-read auditing is actor/query bound, monotonic, capped at 2048 and expires after 60 seconds');
 for(const suffix of ['?page=1&page=1','?__proto__=x','?q=a&q=b','/'+alice.id+'?category=flows&category=devices'])assert.equal((await request(suffix)).status,400);
 assert.equal((await request('','POST',body({displayName:'No CSRF',note:''}),admin,false)).status,403);
 const created=await request('','POST',body({displayName:'Protected route',note:''}));assert.equal(created.status,200);
 const nhwPath='/api/desktop/members/nhw-policy';
 const {Readable}=require('node:stream');
 const {HandleApiRequest}=require('../../web/http/spacex.web-api');
 const approval=require('../../services/authentication/spacex.desktop-action-approval');
 const guard=require('../../services/authentication/spacex.desktop-admin-guard');
 const coordinator=require('../../services/network/spacex.ha-coordinator');
 async function policyRequest(payload,headers={},session=admin){
  const incoming=Object.assign(Readable.from(payload===undefined?[]:[Buffer.from(JSON.stringify(payload))]),{
   url:nhwPath,method:payload===undefined?'GET':'POST',socket:req.socket,
   headers:{'x-csrf-token':session?.csrf||'',...headers}
  });
  let status,value;
  await HandleApiRequest(incoming,{writeHead(c){status=c;},end(v){value=JSON.parse(v);}},session);
  return {status,value};
 }
 const matchList=await request('?scope=MATCH');
 assert.equal(matchList.status,200);
 assert.equal(Object.hasOwn(matchList.value,'unassigned'),false);
 assert.equal((await request('/unassigned?scope=MATCH')).status,404);
 assert.equal((await request('/'+pc.id+'?scope=MATCH&category=devices')).value.member.nickname,pc.nickname);
 const recordPath='/record/FLOW/'+pendingFlow;
 assert.equal((await request(recordPath)).value.match.memberId,otherPc);
 assert.equal((await request(recordPath+'?scope=MATCH')).status,400);
 assert.equal((await request(recordPath,'GET',{},null)).status,403);
 async function scopedLicense(query){
  const incoming=Object.assign(Readable.from([]),{url:'/api/desktop/workspace/licenses/'+matchedLicense.license.id+query,method:'GET',socket:req.socket,headers:{}});
  let status,value;
  await HandleApiRequest(incoming,{writeHead(c){status=c;},end(v){value=JSON.parse(v);}},admin);
  return {status,value};
 }
 assert.equal((await scopedLicense('?scope=MATCH&memberId='+pc.id)).value.membership.memberId,pc.id);
 assert.equal((await scopedLicense('?scope=MATCH&memberId='+otherPc)).status,409);
 assert.equal((await scopedLicense('?scope=MATCH&scope=MATCH')).status,400);
 checks++;console.log('PASS Matching GETs enforce admin access, exact parameters and current PC ownership');
 async function approveNhw(payload){
  const response=await policyRequest(payload);
  assert.equal(response.status,428);assert.equal(response.value.error,'ADMIN_ACTION_REQUIRED');
  const action=response.value.action;
  assert.equal(action.path,nhwPath);assert.deepEqual(action.summary.observationOnlyDetectionIds,payload.disabledIds);
  assert.equal(auth.Reauthenticate(req,admin,process.env.ADMIN_SECRET).ok,true);
  approval.Approve(admin,action.id);
  return {'x-admin-action':action.id};
 }
 assert.equal(guard.CriticalMutation(nhwPath),true);
 assert.equal(guard.ReauthenticationRequired(nhwPath,'GET'),false);
 assert.equal((await policyRequest(undefined,{},null)).status,403);
 const viewer={id:'viewer',role:'viewer',csrf:'synthetic-viewer'};
 assert.equal((await policyRequest(undefined,{},viewer)).status,403);
 const change={expectedRevision:0,disabledIds:[0,7]};
 assert.equal((await policyRequest(change,{},viewer)).status,403);
 assert.equal((await policyRequest(change,{'x-csrf-token':''})).value.error,'CSRF_FAILED');
 assert.equal((await request('/nhw-policy?extra=1')).status,400);
 const initial=await policyRequest();
 assert.equal(initial.status,200);assert.equal(initial.value.canManageNhwPolicy,true);
 assert.deepEqual(initial.value.nhwPolicy,{version:1,revision:0,disabledIds:[87,159,166,180,181]});
 assert.equal((await request('/nhw-policy','POST',change)).value.error,'ADMIN_ACTION_REQUIRED');
 const changedBodyHeaders=await approveNhw(change);
 assert.equal((await policyRequest({...change,disabledIds:[7]},changedBodyHeaders)).value.error,'ADMIN_ACTION_CHANGED');
 assert.deepEqual((await policyRequest()).value.nhwPolicy,initial.value.nhwPolicy);
 const successHeaders=await approveNhw(change);
 const updated=await policyRequest(change,successHeaders);
 assert.equal(updated.status,200);assert.deepEqual(updated.value.nhwPolicy,{version:1,revision:1,disabledIds:[0,7,87,159,166,180,181]});
 assert.equal((await policyRequest(change,successHeaders)).value.error,'ADMIN_ACTION_INVALID');
 const stale={expectedRevision:0,disabledIds:[]};
 const staleResult=await policyRequest(stale,await approveNhw(stale));
 assert.equal(staleResult.status,409);assert.equal(staleResult.value.error,'NHW_POLICY_CONFLICT');
 const detailPolicy=await request('/unassigned?category=nhw');
 assert.deepEqual(detailPolicy.value.nhwPolicy,updated.value.nhwPolicy);
 assert.equal(detailPolicy.value.canManageNhwPolicy,true);
 const active=coordinator.CanAcceptTraffic;
 coordinator.CanAcceptTraffic=()=>false;
 try{
  assert.equal((await policyRequest()).value.canManageNhwPolicy,false);
  assert.equal((await request('/unassigned?category=nhw')).value.canManageNhwPolicy,false);
  assert.equal((await policyRequest({expectedRevision:1,disabledIds:[]})).value.error,'RELAY_STANDBY_READ_ONLY');
 }finally{coordinator.CanAcceptTraffic=active;}
 checks++;console.log('PASS NHW policy uses admin-only exact-request approval, CSRF, revision, and primary role protections');
 const originalNow=Date.now,now=Date.now();try{Date.now=()=>now+auth.REAUTH_MS+1;assert.equal((await request('','POST',body({displayName:'Stale auth',note:''}))).status,428);assert.equal((await request()).status,200);}finally{Date.now=originalNow;}
 auth.RevokeAllSessions();assert.equal((await request()).status,401);
 checks++;console.log('PASS Protected real routes enforce admin, exact query, CSRF, recent authentication and revoked-session checks');
 console.log('DESKTOP_MEMBERS_PASS '+checks+' checks; server metadata only, no client authorization granted');
}
run().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>{bootstrap.Stop();require('../../services/observability/spacex.desktop-performance-metrics').Close();require('../../storage/sqlite/spacex.sqlite-database').Close();fs.rmSync(temp,{recursive:true,force:true});});
