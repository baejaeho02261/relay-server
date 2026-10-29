'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-members-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-MEMBER-TEST'});
require('../../core/peace.utilities').EnsureDirs();
const members=require('../../services/members/peace.desktop-members'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
const licenses=require('../../services/licensing/peace.desktop-licenses'),fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');
const bootstrap=require('../../services/bootstrap/peace.desktop-bootstrap'),reports=require('../../services/integrity/peace.desktop-integrity-reports');
const auth=require('../../web/authentication/peace.web-auth'),route=require('../../web/routes/licensing/peace.desktop-member-routes');
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
  licenseA=licenses.Create({label:'Existing A',requestId:requestId()},actor);
  licenseB=licenses.Create({label:'Existing B',requestId:requestId()},actor);
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
  bindingId=require('../../services/devices/peace.desktop-device-registry').BindingId(a.machineId);
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
 check('An aborted durable mutation leaves no changed member or consumed request',()=>{
  const original=store.Atomic,request=body({displayName:'Write failed',note:''}),before=JSON.stringify(members.State());
  store.Atomic=()=>{throw Error('SYNTHETIC_WRITE_FAILURE');};try{assert.throws(()=>members.Create(request,actor),/SYNTHETIC_WRITE_FAILURE/);}finally{store.Atomic=original;}
  assert.equal(JSON.stringify(members.State()),before);assert.equal(members.Create(request,actor).member.displayName,'Write failed');
 });
 check('Fresh process reads persisted members, exact receipts and existing unassigned records',()=>{
  const request=body({displayName:'Restart receipt',note:''}),result=members.Create(request,actor);
  const code=`const assert=require('node:assert/strict');const m=require(${JSON.stringify(require.resolve('../../services/members/peace.desktop-members'))});assert.deepEqual(m.Create(${JSON.stringify(request)},${JSON.stringify(actor)}),${JSON.stringify(result)});const a=m.Detail(${JSON.stringify(alice.id)});assert.equal(a.categories.integrity.totalCount,${aliceReportCount});assert.ok(m.Detail('unassigned').categories.licenses.items.some(r=>r.id===${JSON.stringify(licenseB.license.id)}));console.log('MEMBERS_RESTART_PASS');`;
  const child=cp.spawnSync(process.execPath,['-e',code],{cwd:path.resolve(__dirname,'../..'),env:process.env,encoding:'utf8',timeout:15000});
  assert.equal(child.status,0,child.stderr);assert.match(child.stdout,/MEMBERS_RESTART_PASS/);
 });
 check('Storage validator rejects unsupported schema, malformed assignments and dangling member IDs',()=>{
  members.Validate(members.State());
  for(const change of [s=>s.version=2,s=>s.extra=true,s=>s.items[alice.id].status='ADMIN',s=>s.assignments['FLOW:'+flowA.id]={kind:'FLOW',targetId:flowA.id,memberId:'F'.repeat(24),updatedAt:Date.now()},s=>s.receipts.bad={}]){const copy=structuredClone(members.State());change(copy);assert.throws(()=>members.Validate(copy),/MEMBER_STORAGE_INVALID/);}
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
 const audit=require('../../services/storage/peace.desktop-operation-audit'),savedList=members.List,savedAudit=audit.RecordAccess;
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
 const originalNow=Date.now,now=Date.now();try{Date.now=()=>now+auth.REAUTH_MS+1;assert.equal((await request('','POST',body({displayName:'Stale auth',note:''}))).status,428);assert.equal((await request()).status,200);}finally{Date.now=originalNow;}
 auth.RevokeAllSessions();assert.equal((await request()).status,401);
 checks++;console.log('PASS Protected real routes enforce admin, exact query, CSRF, recent authentication and revoked-session checks');
 console.log('DESKTOP_MEMBERS_PASS '+checks+' checks; server metadata only, no client authorization granted');
}
run().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>{bootstrap.Stop();require('../../services/observability/peace.desktop-performance-metrics').Close();require('../../storage/sqlite/peace.sqlite-database').Close();fs.rmSync(temp,{recursive:true,force:true});});
