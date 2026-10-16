'use strict';
// Diagnostic authority is deliberately separate from runtime authority. A
// short-lived, one-use server nonce permits a signed shutdown observation after
// the runtime session has retired; it can never renew, claim, download or redeem.
const crypto=require('node:crypto'),store=require('./desktopBootstrapStore');
const TTL=180000,MAX_PERMITS=2048,MAX_FLOWS=512,MAX_EVENTS=96;
const TERMINAL=new Set(['CLOSED','REVOKED','EXPIRED']);
const PAIRS={SHUTDOWN_BEGIN:['REQUESTED'],CLOSE_RESPONSE:['ACKNOWLEDGED','FAILED'],PROCESS_EXIT:['OBSERVED','TIMEOUT','UNKNOWN'],FILE_CLEANUP:['REMOVED','FAILED','NOT_ATTEMPTED','SCHEDULED','TIMEOUT','UNKNOWN'],UI_HIDDEN:['OBSERVED'],LEASE_EXPIRED:['OBSERVED']};
const Plain=x=>!!x&&Object.getPrototypeOf(x)===Object.prototype;
const Id=x=>typeof x==='string'&&/^(?:(?:BF|DS|DL|LA)-)?[A-F0-9]{24}$/.test(x);
const KindId=(x,kind)=>typeof x==='string'&&new RegExp('^(?:'+kind+'-)?[A-F0-9]{24}$').test(x);
const SERVER_PAIRS={FLOW_STARTED:['STARTED'],HANDOFF_COMPLETED:['AUTHORITY_ENDED'],SESSION_CLAIMED:['ACTIVE'],LEASE_EXPIRED:['EXPIRED'],AUTHORITY_ENDED:['CLOSED','REVOKED','EXPIRED'],TRANSFER_COMMITTED:['AUTHORITY_ENDED'],CLOSE_RESPONSE_PREPARED:['CLOSED','TRANSFER_COMMITTED'],CLOSE_REQUEST_ACCEPTED:['CLOSED','ABORTED']};
const Hex=(x,n)=>typeof x==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(x);
const sha=x=>crypto.createHash('sha512').update(x).digest('hex');
function Fail(code,status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Fields(x,names){if(!Plain(x)||Object.keys(x).length!==names.length||names.some(k=>!Object.hasOwn(x,k)))Fail('LIFECYCLE_INPUT_INVALID');}
function RequestId(x){if(typeof x!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(x))Fail('LIFECYCLE_INPUT_INVALID');return x;}
function State(db){return db.lifecycleTrace||(db.lifecycleTrace={version:1,flows:{},permits:{}});}
function Expired(p){return require('./desktopDeadline').persistent.expired('lifecycle:'+p.id,p.createdAt,p.expiresAt);}
function PruneState(s){for(const [id,p]of Object.entries(s.permits))if(Expired(p)){delete s.permits[id];store.AfterCommit(()=>require('./desktopDeadline').persistent.forget('lifecycle:'+id));}}
// Expired diagnostic nonces must not wait for an unrelated authority mutation.
// A quiet server persists their removal too; a failed durable write throws and
// leaves the prior permit state intact rather than reporting cleanup success.
function Maintain(){
 const state=store.Load().lifecycleTrace;if(!state||!Object.values(state.permits).some(Expired))return {removed:0};
 return store.Atomic(next=>{const live=next.lifecycleTrace,before=Object.keys(live.permits).length;PruneState(live);return {removed:before-Object.keys(live.permits).length};});
}
function RootFlow(db,row,stage){return stage==='O'?db.flows[row.parentFlowId]:db.flows[row.id];}
function Binding(body){
 if(!['A','B','O'].includes(body.stage)||!['A','B','O'].includes(body.targetRole))Fail('LIFECYCLE_ROLE_INVALID',403);
 if(body.targetRole!==body.stage&&({B:'A',O:'B'})[body.stage]!==body.targetRole)Fail('LIFECYCLE_ROLE_INVALID',403);
 const identity=require('./desktopBootstrap').AuthenticateIntegrityReport(body),db=store.Load(),flow=RootFlow(db,identity,body.stage);
 if(!flow)Fail('LIFECYCLE_CONTEXT_INVALID',403);
 const targetSessionId=body.targetRole==='A'?flow.id:body.targetRole==='B'?flow.sessionId:identity.sessionId;
 return {flowId:flow.id,reporterRole:body.stage,reporterSessionId:body.sessionId,targetRole:body.targetRole,targetSessionId,publicKey:identity.publicKey,serverEpoch:require('./desktopRecovery').Epoch(db)};
}
function Response(p){return {version:1,permitId:p.id,nonce:p.nonce,expiresAt:p.expiresAt,flowId:p.flowId,reporterRole:p.reporterRole,targetRole:p.targetRole,targetSessionId:p.targetSessionId,serverTime:p.createdAt};}
function Challenge(body){
 Fields(body,['action','stage','sessionId','sessionToken','targetRole','requestId']);RequestId(body.requestId);
 const binding=Binding(body),db=store.Load(),key=sha(JSON.stringify([binding.reporterRole,binding.reporterSessionId,body.requestId])),s=db.lifecycleTrace;
 const prior=s&&Object.values(s.permits).find(p=>p.challengeKey===key);
 if(prior){if(prior.targetRole!==binding.targetRole||prior.publicKey!==binding.publicKey||prior.serverEpoch!==binding.serverEpoch)Fail('LIFECYCLE_REQUEST_REUSED',409);if(Expired(prior))Fail('LIFECYCLE_PERMIT_EXPIRED',410);return Response(prior);}
 const at=Date.now(),p={...binding,id:crypto.randomBytes(16).toString('hex'),nonce:crypto.randomBytes(24).toString('hex'),createdAt:at,expiresAt:at+TTL,challengeKey:key,requestId:body.requestId};
 store.Atomic(next=>{const current=State(next);PruneState(current);if(Object.keys(current.permits).length>=MAX_PERMITS||Object.values(current.permits).filter(x=>x.reporterRole===binding.reporterRole&&x.reporterSessionId===binding.reporterSessionId&&x.targetRole===binding.targetRole&&!x.receipt).length>=4)Fail('LIFECYCLE_CAPACITY',429);current.permits[p.id]=p;});
 return Response(p);
}
function Permit(id){if(!Hex(id,32))Fail('LIFECYCLE_INPUT_INVALID');const p=store.Load().lifecycleTrace?.permits[id];if(!p)Fail('LIFECYCLE_PERMIT_INVALID',403);if(Expired(p))Fail('LIFECYCLE_PERMIT_EXPIRED',410);if(p.serverEpoch!==require('./desktopRecovery').Epoch(store.Load()))Fail('LIFECYCLE_CONTEXT_RETIRED',403);return p;}
function Events(text,p){
 if(typeof text!=='string'||Buffer.byteLength(text)>8192)Fail('LIFECYCLE_INPUT_INVALID');let events;try{events=require('./strictJson').Parse(text,{maxBytes:8192,maxNodes:128});}catch(_){Fail('LIFECYCLE_INPUT_INVALID');}
 if(!Array.isArray(events)||!events.length||events.length>8)Fail('LIFECYCLE_INPUT_INVALID');
 for(const e of events){if(!Plain(e)||Object.keys(e).some(k=>!['event','status','pid','exitCode','win32Error','elapsedMs'].includes(k))||typeof e.event!=='string'||!Object.hasOwn(PAIRS,e.event)||!PAIRS[e.event].includes(e.status))Fail('LIFECYCLE_INPUT_INVALID');
  for(const k of ['pid','exitCode','win32Error','elapsedMs'])if(Object.hasOwn(e,k)&&(!Number.isSafeInteger(e[k])||e[k]<0||e[k]>(k==='elapsedMs'?600000:0xffffffff)))Fail('LIFECYCLE_INPUT_INVALID');
  if(p.reporterRole!==p.targetRole&&!['PROCESS_EXIT','FILE_CLEANUP'].includes(e.event)||p.reporterRole===p.targetRole&&e.event==='PROCESS_EXIT'&&e.status==='OBSERVED')Fail('LIFECYCLE_ROLE_INVALID',403);
 }
 return events;
}
function Canonical(p,requestId,eventsJson){return ['GAME-LIFECYCLE-REPORT-V1',p.id,p.nonce,requestId,sha(eventsJson)].join('\n');}
function Prepared(body){Fields(body,['action','permitId','requestId','eventsJson','signature']);RequestId(body.requestId);const p=Permit(body.permitId);if(body.requestId!==p.requestId)Fail('LIFECYCLE_REQUEST_REUSED',409);return {p,events:Events(body.eventsJson,p),canonical:Canonical(p,body.requestId,body.eventsJson)};}
function ProofTasks(body){if(body.action!=='lifecycleReport')return [];const {p,canonical}=Prepared(body);return [require('./desktopProofWork').Job(p.publicKey,canonical,body.signature)];}
function Append(db,flowId,event){
 const s=State(db),at=Date.now();let record=s.flows[flowId];
 if(!record){if(Object.keys(s.flows).length>=MAX_FLOWS){const oldest=Object.values(s.flows).sort((a,b)=>a.updatedAt-b.updatedAt)[0];delete s.flows[oldest.flowId];}record=s.flows[flowId]={flowId,updatedAt:at,events:[]};}
 record.events.push({...event,id:crypto.randomBytes(12).toString('hex'),at});if(record.events.length>MAX_EVENTS)record.events.splice(0,record.events.length-MAX_EVENTS);record.updatedAt=at;
}
function ServerEvent(db,flowId,role,event,status,targetSessionId){if(!KindId(flowId,'BF')||!db.flows[flowId]||!['A','B','O'].includes(role)||!Object.hasOwn(SERVER_PAIRS,event)||!SERVER_PAIRS[event].includes(status))return;const session=targetSessionId||(role==='A'?flowId:role==='B'?db.flows[flowId].sessionId:'');if(!Id(session)||role==='A'&&session!==flowId||role==='B'&&session!==db.flows[flowId].sessionId||role==='O'&&!Object.values(db.overlays||{}).some(o=>o.parentFlowId===flowId&&o.sessionId===session))return;Append(db,flowId,{role,event,status,targetSessionId:session,source:'SERVER_CONFIRMED'});}
function Report(body){
 const {p,events,canonical}=Prepared(body);require('./desktopBootstrap').Verify(p,canonical,body.signature);
 const fingerprint=sha(canonical+'\n'+body.signature);
 if(p.receipt){if(p.fingerprint!==fingerprint)Fail('LIFECYCLE_REQUEST_REUSED',409);return {...p.receipt};}
 const receipt={version:1,permitId:p.id,status:'RECORDED',recordedAt:Date.now(),eventCount:events.length};
 store.Atomic(next=>{const permit=next.lifecycleTrace?.permits[p.id];if(!permit||Expired(permit)||permit.serverEpoch!==require('./desktopRecovery').Epoch(next))Fail('LIFECYCLE_PERMIT_EXPIRED',410);if(permit.receipt)Fail('LIFECYCLE_REQUEST_REUSED',409);
  for(const event of events)Append(next,p.flowId,{...event,role:p.targetRole,targetSessionId:p.targetSessionId,source:'CLIENT_REPORTED',reporterRole:p.reporterRole,reporterSessionId:p.reporterSessionId});permit.receipt=receipt;permit.fingerprint=fingerprint;
  // Only a newly committed receipt contributes. An exact retry must not count
  // twice, and diagnostics persistence must never undo the authority commit.
  // Durations are authenticated client observations, not server OS attestation.
  store.AfterCommit(()=>{try{const metrics=require('./desktopPerformanceMetrics');for(const event of events)metrics.RecordLifecycle(p.targetRole,event.event,event.status,event.elapsedMs);}catch(_){}});
 });return receipt;
}
function Execute(body){if(body.action==='lifecycleChallenge')return Challenge(body);if(body.action==='lifecycleReport')return Report(body);Fail('LIFECYCLE_INPUT_INVALID');}
// Called in the existing authority transaction. Thus an authority-ended event
// and the retirement have the same durable commit. No independent telemetry
// I/O can fail between closing a session and recording the server decision.
function ObserveTransitions(before,next){
 // Recovery/reset may discard the entire diagnostic store. Its old monotonic
 // entries must not consume the shared capability-bound capacity forever.
 for(const id of Object.keys(before.lifecycleTrace?.permits||{}))if(!next.lifecycleTrace?.permits?.[id])store.AfterCommit(()=>require('./desktopDeadline').persistent.forget('lifecycle:'+id));
 for(const [id,row]of Object.entries(next.flows||{})){
  const old=before.flows?.[id];
  // Restored/imported historical rows are not live start or claim events.
  if(!old){if(row.status==='STARTED')ServerEvent(next,id,'A','FLOW_STARTED','STARTED');continue;}
  if(row.claimedAt&&!old.claimedAt){ServerEvent(next,id,'A','HANDOFF_COMPLETED','AUTHORITY_ENDED');ServerEvent(next,id,'B','SESSION_CLAIMED','ACTIVE');}
  if(row.status!==old?.status&&TERMINAL.has(row.status))ServerEvent(next,id,row.claimedAt?'B':'A',row.status==='EXPIRED'?'LEASE_EXPIRED':'AUTHORITY_ENDED',row.status);
  if(row.closedByOverlay&&!old?.closedByOverlay){ServerEvent(next,id,'B','TRANSFER_COMMITTED','AUTHORITY_ENDED');ServerEvent(next,id,'B','CLOSE_RESPONSE_PREPARED','TRANSFER_COMMITTED');}
 }
 for(const [id,row]of Object.entries(next.overlays||{})){
  const old=before.overlays?.[id];if(!old)continue;if(row.claimedAt&&!old.claimedAt)ServerEvent(next,row.parentFlowId,'O','SESSION_CLAIMED','ACTIVE',row.sessionId);
  if(row.status!==old?.status&&TERMINAL.has(row.status))ServerEvent(next,row.parentFlowId,'O',row.status==='EXPIRED'?'LEASE_EXPIRED':'AUTHORITY_ENDED',row.status,row.sessionId);
 }
 if(next.lifecycleTrace)PruneState(next.lifecycleTrace);
}
function Role(role,sessionId,status,events){
 const list=events.filter(e=>e.role===role&&e.targetSessionId===sessionId),childRole=({A:'B',B:'O'})[role];
 const last=(event,predicate=()=>true)=>list.filter(e=>e.event===event&&e.source==='CLIENT_REPORTED'&&predicate(e)).at(-1);
 // A delayed self-report may arrive after its child has already observed the
 // held parent process handle and removed that parent's file. Arrival order
 // must not turn the older self-cleanup failure into a residual-process claim.
 // Retain every receipt in the timeline; prefer the bound direct child's
 // observation for this exact parent session when one is available.
 const observation=event=>childRole&&last(event,e=>e.reporterRole===childRole)||last(event);
 return {role,sessionId,status,authorityEnded:TERMINAL.has(status)||status==='HANDED_OFF',processExit:observation('PROCESS_EXIT')?.status==='OBSERVED'?'CLIENT_REPORTED':'NOT_REPORTED',fileCleanup:observation('FILE_CLEANUP')?.status||'NOT_REPORTED',lastAt:list.at(-1)?.at||0};
}
function Flow(flowId){
 if(!KindId(flowId,'BF'))Fail('LIFECYCLE_INPUT_INVALID');const db=store.Load(),row=db.flows[flowId];if(!row)Fail('LIFECYCLE_NOT_FOUND',404);
 const overlay=Object.values(db.overlays||{}).filter(o=>o.parentFlowId===row.id).sort((a,b)=>b.createdAt-a.createdAt)[0],events=structuredClone(db.lifecycleTrace?.flows[flowId]?.events||[]);
 const roles={A:Role('A',row.id,row.claimedAt?'HANDED_OFF':row.status,events),B:Role('B',row.sessionId,row.claimedAt?row.status:'NOT_STARTED',events),O:Role('O',overlay?.sessionId||'',overlay?.status||'NOT_STARTED',events)};
 let code='B_NOT_STARTED',summary='B 실행이 서버에 등록되지 않았습니다.';
 if(row.claimedAt){if(!roles.B.authorityEnded){code='B_AUTHORITY_ACTIVE';summary='B의 서버 권한이 아직 종료되지 않았습니다.';}else if(roles.B.processExit==='NOT_REPORTED'){code='B_EXIT_NOT_REPORTED';summary='B의 서버 권한은 종료됐지만 자식의 프로세스 종료 관측 보고가 없습니다.';}else if(roles.B.fileCleanup==='FAILED'){code='B_FILE_CLEANUP_FAILED';summary='자식이 B 종료를 관측했으나 파일 정리 실패를 보고했습니다. 오류 코드를 확인하세요.';}else if(roles.B.fileCleanup!=='REMOVED'){code='B_FILE_CLEANUP_PENDING';summary='자식의 B 종료 관측은 있으나 파일 제거 완료 보고가 없습니다.';}else{code='B_CLEANUP_CLIENT_REPORTED';summary='인증된 자식이 B 프로세스 종료와 파일 제거를 보고했습니다. 서버의 OS 직접 관측은 아닙니다.';}}
 return {flowId:row.id,licenseId:row.licenseId||'',launcherId:row.launcherId,sessionId:row.sessionId,createdAt:row.createdAt,roles,events,bResidual:{code,summary,confirmed:false},processTruth:'AUTHENTICATED_CLIENT_OBSERVATION_ONLY',eventRetention:MAX_EVENTS};
}
function Overview(query={}){const {flowId,licenseId,limit=50}=query;if(Object.keys(query).some(k=>!['flowId','licenseId','limit'].includes(k))||flowId!==undefined&&!KindId(flowId,'BF')||licenseId!==undefined&&!KindId(licenseId,'DL')||!Number.isSafeInteger(Number(limit))||Number(limit)<1||Number(limit)>100)Fail('LIFECYCLE_INPUT_INVALID');const rows=Object.values(store.Load().flows).filter(r=>(!flowId||r.id===flowId)&&(!licenseId||r.licenseId===licenseId)).sort((a,b)=>b.createdAt-a.createdAt).slice(0,Number(limit));return {version:1,asOf:Date.now(),scope:'SERVER_DECISIONS_AND_AUTHENTICATED_CLIENT_OBSERVATIONS',items:rows.map(r=>Flow(r.id)),retention:{flows:MAX_FLOWS,eventsPerFlow:MAX_EVENTS,permitLifetimeMs:TTL}};}
function Validate(s,db){
 const invalid=()=>{throw Error('LIFECYCLE_STORAGE_INVALID');};
 const keys=(x,required,optional=[])=>Plain(x)&&required.every(k=>Object.hasOwn(x,k))&&Object.keys(x).every(k=>required.includes(k)||optional.includes(k));
 const rolePair=(reporter,target)=>reporter===target||({B:'A',O:'B'})[reporter]===target;
 const time=x=>Number.isSafeInteger(x)&&x>0;
 const bound=(flow,role,session)=>role==='A'?session===flow.id:role==='B'?session===flow.sessionId:Object.values(db.overlays||{}).some(o=>o.parentFlowId===flow.id&&o.sessionId===session);
 if(!keys(s,['version','flows','permits'])||s.version!==1||!Plain(s.flows)||!Plain(s.permits)||Object.keys(s.flows).length>MAX_FLOWS||Object.keys(s.permits).length>MAX_PERMITS)invalid();
 for(const [id,f]of Object.entries(s.flows)){
  const flow=db?.flows?.[id];if(!KindId(id,'BF')||!keys(f,['flowId','updatedAt','events'])||f.flowId!==id||!time(f.updatedAt)||!Array.isArray(f.events)||f.events.length>MAX_EVENTS||db&&!flow)invalid();
  const seen=new Set();
  for(const e of f.events){
   const client=e?.source==='CLIENT_REPORTED',required=['id','at','role','event','status','targetSessionId','source',...(client?['reporterRole','reporterSessionId']:[])];
   if(!keys(e,required,client?['pid','exitCode','win32Error','elapsedMs']:[])||!Hex(e.id,24)||seen.has(e.id)||!time(e.at)||!['A','B','O'].includes(e.role)||!Id(e.targetSessionId)||!['SERVER_CONFIRMED','CLIENT_REPORTED'].includes(e.source)||typeof e.event!=='string'||typeof e.status!=='string')invalid();seen.add(e.id);
   if(db&&!bound(flow,e.role,e.targetSessionId))invalid();
   if(client){
    if(!['A','B','O'].includes(e.reporterRole)||!Id(e.reporterSessionId)||!rolePair(e.reporterRole,e.role)||db&&!bound(flow,e.reporterRole,e.reporterSessionId))invalid();
    const clean={};for(const key of ['event','status','pid','exitCode','win32Error','elapsedMs'])if(Object.hasOwn(e,key))clean[key]=e[key];
    try{Events(JSON.stringify([clean]),{reporterRole:e.reporterRole,targetRole:e.role});}catch(_){invalid();}
   }else if(!Object.hasOwn(SERVER_PAIRS,e.event)||!SERVER_PAIRS[e.event].includes(e.status))invalid();
  }
  if(f.events.length&&f.events.at(-1).at!==f.updatedAt)invalid();
 }
 for(const [id,p]of Object.entries(s.permits)){
  const required=['flowId','reporterRole','reporterSessionId','targetRole','targetSessionId','publicKey','serverEpoch','id','nonce','createdAt','expiresAt','challengeKey','requestId'];
  if(!keys(p,required,['receipt','fingerprint'])||id!==p.id||!Hex(id,32)||!Hex(p.nonce,48)||!KindId(p.flowId,'BF')||!Id(p.reporterSessionId)||!Id(p.targetSessionId)||!['A','B','O'].includes(p.reporterRole)||!['A','B','O'].includes(p.targetRole)||!rolePair(p.reporterRole,p.targetRole)||!time(p.createdAt)||p.expiresAt!==p.createdAt+TTL||!Number.isSafeInteger(p.expiresAt)||!Number.isSafeInteger(p.serverEpoch)||p.serverEpoch<0||typeof p.publicKey!=='string'||p.publicKey.length<100||p.publicKey.length>500||!Hex(p.challengeKey,128)||typeof p.requestId!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(p.requestId)||p.challengeKey!==sha(JSON.stringify([p.reporterRole,p.reporterSessionId,p.requestId]))||(Object.hasOwn(p,'receipt')!==Object.hasOwn(p,'fingerprint')))invalid();
  if(db){const flow=db.flows[p.flowId];if(!flow||!bound(flow,p.reporterRole,p.reporterSessionId)||!bound(flow,p.targetRole,p.targetSessionId)||p.serverEpoch>(db.serverRecovery?.epoch||0))invalid();const identity=p.reporterRole==='A'?require('./desktopHandoffDelegation').Parent(flow):p.reporterRole==='B'?flow:Object.values(db.overlays||{}).find(o=>o.sessionId===p.reporterSessionId);if(identity.publicKey!==p.publicKey)invalid();}
  if(p.receipt){const r=p.receipt;if(!keys(r,['version','permitId','status','recordedAt','eventCount'])||r.version!==1||r.permitId!==id||r.status!=='RECORDED'||!time(r.recordedAt)||r.recordedAt<p.createdAt||r.recordedAt>=p.expiresAt||!Number.isInteger(r.eventCount)||r.eventCount<1||r.eventCount>8||!Hex(p.fingerprint,128))invalid();}
 }
 return s;
}
module.exports={Maintain,Execute,ProofTasks,Canonical,Validate,ObserveTransitions,ServerEvent,Flow,Overview,TTL};
