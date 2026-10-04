'use strict';
// Work is scheduled in the server process; closing the administrator tab does
// not cancel it. Mutations remain single-writer and retain durable receipts.
const crypto=require('node:crypto');
const state=require('../core/state');
const db=require('./desktopWorkspaceStore');
const licenses=require('./desktopLicenses');
const bootstrap=require('./desktopBootstrap');
const bootStore=require('./desktopBootstrapStore');
const space=require('./desktopStorageSpace');
const plans=new Map();
let runner=false,timer,summary={asOf:0,pending:true};
function Fail(code,status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Plain(x){return !!x&&Object.getPrototypeOf(x)===Object.prototype;}
function Fields(x,allowed,required=allowed){if(!Plain(x)||Object.keys(x).some(k=>!allowed.includes(k))||required.some(k=>!Object.hasOwn(x,k)))Fail('INPUT_INVALID');}
function Text(x,max){if(typeof x!=='string'||x.length>max||/[\x00-\x08\x0b-\x1f\x7f]/.test(x))Fail('INPUT_INVALID');return x.trim();}
function MetadataInput(x){Fields(x,['note','tags']);const note=Text(x.note,500);if(!Array.isArray(x.tags)||x.tags.length>10)Fail('INPUT_INVALID');return{note,tags:[...new Set(x.tags.map(t=>Text(t,30)).filter(Boolean))]};}
function Meta(id){return db.Load().metadata[id]||{revision:0,note:'',tags:[]};}
function Actor(session){return 'ADMIN:'+String(session.id);}
function Audit(kind,actor){require('./desktopSecurityOperations').AuditIntent('WORKSPACE_'+kind,actor);}
function Query(query={}){
 const page=Number(query.page||0),pageSize=Number(query.pageSize||25),q=String(query.q||'').trim().toLowerCase();
 if(!Number.isSafeInteger(page)||page<0||page>100000||!Number.isSafeInteger(pageSize)||pageSize<1||pageSize>100||q.length>120)Fail('INPUT_INVALID');
 const result=licenses.List({status:query.status||''}),metadata=db.Load().metadata;
 const linked=new Set(),match=values=>values.some(x=>String(x||'').toLowerCase().includes(q));
 if(q){const b=bootStore.Load();for(const a of Object.values(b.launchers))if(a.assignedLicenseId&&match([a.id,a.label,b.artifacts[a.artifactId]?.version,b.artifacts[a.artifactId]?.sha256]))linked.add(a.assignedLicenseId);
  for(const f of Object.values(b.flows)){const a=b.launchers[f.launcherId];if(match([f.id,f.sessionId,f.launcherId,b.artifacts[f.releaseId]?.version,b.artifacts[f.releaseId]?.sha256,a?.label,b.artifacts[a?.artifactId]?.version,b.artifacts[a?.artifactId]?.sha256])){const id=f.licenseId||a?.assignedLicenseId;if(id)linked.add(id);}}}
 const all=result.items.filter(r=>!q||linked.has(r.id)||match([r.id,r.label,r.deviceId,r.deviceName,r.machineId,r.binarySha256,r.bootstrapSessionId,r.appVersion,metadata[r.id]?.note,...(metadata[r.id]?.tags||[])]));
 const actual=Math.min(page,Math.max(0,Math.ceil(all.length/pageSize)-1));
 return{...result,items:all.slice(actual*pageSize,(actual+1)*pageSize).map(r=>({...r,metadata:Meta(r.id)})),filteredCount:all.length,page:actual,pageSize,pages:Math.max(1,Math.ceil(all.length/pageSize))};
}
function Detail(id){
 const license=licenses.Detail(id).license,boot=bootStore.Load();
 const redeemedLaunchers=new Set(Object.values(boot.flows).filter(x=>x.licenseId===id).map(x=>x.launcherId));
 const launchers=Object.values(boot.launchers).filter(x=>x.assignedLicenseId===id||redeemedLaunchers.has(x.id));
 const flows=Object.values(boot.flows).filter(x=>x.licenseId===id||!x.licenseId&&launchers.some(l=>l.id===x.launcherId));
 const timeline=[{at:license.issuedAt,type:'LICENSE_ISSUED',label:'라이선스 발급'}];
 for(const l of launchers)timeline.push({at:l.issuedAt,type:'LAUNCHER_ISSUED',label:'A 발급',launcherId:l.id});
 const stages=[['createdAt','FLOW_STARTED','A 실행'],['downloadedAt','DOWNLOADED','B 다운로드 완료'],['claimedAt','B_CLAIMED','B 연결'],['lastVerifiedAt','VERIFIED','최근 인증'],['closedAt','CLOSED','종료'],['revokedAt','REVOKED','관리자 종료']];
 for(const f of flows)for(const [key,type,label]of stages)if(f[key])timeline.push({at:f[key],type,label,flowId:f.id,sessionId:f.sessionId});
 const ids=new Set([id,...launchers.map(x=>x.id),...flows.flatMap(x=>[x.id,x.sessionId])].filter(Boolean));
 for(const e of state.events.slice(-1000)){
  if(!String(e.type).startsWith('DESKTOP_'))continue;
  let d;try{d=JSON.parse(e.detail);}catch(_){continue;}
  if(!Plain(d)||!['id','licenseId','sessionId','flowId','launcherId'].some(k=>ids.has(d[k])))continue;
  // BASELINE_MATCH is the authority evaluator's PASS reason, not an error.
  // Restrict this rendering exception to its real observation event; unknown
  // event kinds and actual failures retain the existing error guidance.
  const baselineMatched=e.type==='DESKTOP_SECURITY_AUTHORITY'&&d.kind==='OBSERVATION'&&d.reason==='BASELINE_MATCH'&&(!Object.hasOwn(d,'status')||d.status==='PASS');
  timeline.push({at:e.time||e.at||0,type:String(e.type).slice(0,80),label:baselineMatched?'서버 보안 검사 정상':e.type==='DESKTOP_RUNTIME_REQUEST_FAILED'?'서버에서 요청 거절':String(e.type).slice(0,80),reason:typeof d.reason==='string'?d.reason.slice(0,80):'',problem:!baselineMatched&&typeof d.reason==='string'?require('./desktopOperationsErrors').Explain(d.reason):null});
 }
 const histories=flows.map(f=>({flowId:f.id,sessionId:f.sessionId,launcherId:f.launcherId,status:bootstrap.SessionView(f).status,createdAt:f.createdAt,version:boot.artifacts[f.releaseId]?.version||'',binarySha256:boot.artifacts[f.releaseId]?.sha256||'',machineId:f.machineId||'',lastVerifiedAt:f.lastVerifiedAt||0}));
 return{license,metadata:Meta(id),timeline:timeline.sort((a,b)=>b.at-a.at).slice(0,150),flows:histories,timelineScope:'PERSISTED_FLOW_TIMES_AND_LAST_1000_SERVER_EVENTS',support:'APK_SUPPORT_RETIRED_NO_NEW_COLLECTION'};
}
function SaveMetadata(id,body,actor){
 Fields(body,['expectedRevision','note','tags']);licenses.Detail(id);const value=MetadataInput({note:body.note,tags:body.tags});
 if(body.expectedRevision!==Meta(id).revision)Fail('WORKSPACE_CONFLICT',409);
 Audit('METADATA',actor);db.Atomic(next=>{const old=next.metadata[id]?.revision||0;if(old!==body.expectedRevision)Fail('WORKSPACE_CONFLICT',409);next.metadata[id]={...value,revision:old+1,updatedAt:Date.now(),updatedBy:actor};});return Meta(id);
}
function SaveReleaseNote(body,actor){
 Fields(body,['aId','bId','note']);const b=bootStore.Load();if(b.artifacts[body.aId]?.component!=='A'||b.artifacts[body.bId]?.component!=='B')Fail('INPUT_INVALID');
 const note=Text(body.note,1000);Audit('RELEASE_NOTE',actor);db.Atomic(next=>{next.releaseNotes||={};next.releaseNotes[body.aId+':'+body.bId]={note,updatedAt:Date.now(),updatedBy:actor};});return{saved:true};
}
function RefreshSummary(){
 const b=bootStore.Load(),all=Object.values(b.flows),since=Date.now()-7*86400000,flows=all.filter(f=>f.createdAt>=since),issued=Object.values(b.launchers).filter(l=>l.issuedAt>=since);
 const byVersion={};let downloaded=0,claimed=0,authorized=0;const durations=[],downloadDurations=[],claimDurations=[];
 for(const f of flows){const version=b.artifacts[f.releaseId]?.version||'unknown';const group=byVersion[version]||(byVersion[version]={version,started:0,downloaded:0,claimed:0,authorized:0,closed:0,revoked:0,expired:0});group.started++;
  if(f.handoffHash||f.downloadedAt){downloaded++;group.downloaded++;if(f.downloadedAt>=f.createdAt)downloadDurations.push(f.downloadedAt-f.createdAt);}if(f.claimedAt){claimed++;group.claimed++;const d=f.claimedAt-f.createdAt;if(d>=0)durations.push(d);if(f.claimedAt>=f.downloadedAt)claimDurations.push(f.claimedAt-f.downloadedAt);}if(f.licenseId){authorized++;group.authorized++;}
  const s=bootstrap.SessionView?bootstrap.SessionView(f).status:f.status;if(s==='CLOSED')group.closed++;if(s==='REVOKED')group.revoked++;if(s==='EXPIRED')group.expired++;
 }
 durations.sort((a,b)=>a-b);const quantile=p=>durations.length?durations[Math.min(durations.length-1,Math.floor((durations.length-1)*p))]:null;
 const timings=values=>{values.sort((a,b)=>a-b);return{count:values.length,medianMs:values.length?values[Math.floor((values.length-1)*.5)]:null,p95Ms:values.length?values[Math.floor((values.length-1)*.95)]:null};};
 const failures={};for(const e of state.events.slice(-1000)){if(e.type!=='DESKTOP_RUNTIME_REQUEST_FAILED'||e.time<since)continue;let info;try{info=JSON.parse(e.detail);}catch(_){continue;}if(!Plain(info))continue;const version=b.artifacts[info.releaseId]?.version||'unknown',key=version+':'+info.reason;const f=failures[key]||(failures[key]={version,reason:info.reason,count:0,lastAt:0,problem:require('./desktopOperationsErrors').Explain(info.reason)});f.count++;f.lastAt=Math.max(f.lastAt,e.time);}
 summary={asOf:Date.now(),since,pending:false,scope:'FLOW_CREATED_WITHIN_7_DAYS',issued:issued.length,started:flows.length,downloaded,claimed,authorized,medianStartToClaimMs:quantile(.5),p95StartToClaimMs:quantile(.95),versions:Object.values(byVersion),incompleteIsFailure:false,flowCountLifetime:all.length,downloadTiming:timings(downloadDurations),claimTiming:timings(claimDurations),recentRequestFailures:Object.values(failures),failureScope:'LAST_1000_EVENTS_10_SECOND_DEDUP_NOT_ALL_FAILED_USERS',releaseNote:db.Load().releaseNotes?.[b.active.A+':'+b.active.B]?.note||''};return summary;
}
function Summary(){if(!summary.asOf)RefreshSummary();return structuredClone(summary);}
function ProjectJob(j){return{id:j.id,kind:j.kind,status:j.status,createdAt:j.createdAt,updatedAt:j.updatedAt||j.createdAt,total:j.items.length,done:j.items.filter(x=>x.status==='DONE').length,failed:j.items.filter(x=>x.status==='FAILED').length,items:j.items.map((x,index)=>({index,status:x.status,reference:x.input.id||x.input.label||'',result:x.result||null,error:x.error||''})),createdBy:j.createdBy};}
function Jobs(){return{items:Object.values(db.Load().jobs).sort((a,b)=>b.createdAt-a.createdAt).slice(0,100).map(ProjectJob),serverTime:Date.now(),storage:'SERVER_ONLY'};}
function Ids(input){if(!Array.isArray(input)||!input.length||input.length>100||new Set(input).size!==input.length)Fail('INPUT_INVALID');for(const id of input)licenses.Detail(id);return input;}
async function Preview(body,session){
 Fields(body,['kind','count','prefix','ids','note','tags'],['kind']);let items=[];
 if(body.kind==='CREATE'){
  if(!Number.isSafeInteger(body.count)||body.count<1||body.count>100)Fail('INPUT_INVALID');const prefix=Text(body.prefix||'사용자',100);
  items=Array.from({length:body.count},(_,n)=>({label:prefix+' '+String(n+1).padStart(3,'0')}));
 }else if(body.kind==='METADATA'){
  const m=MetadataInput({note:body.note,tags:body.tags});items=Ids(body.ids).map(id=>({id,...m,expectedRevision:Meta(id).revision}));
 }else if(body.kind==='EXPORT')items=Ids(body.ids).map(id=>({id}));
 else if(body.kind==='CLEANUP'){
  if(!Array.isArray(body.ids)||!body.ids.length||body.ids.length>100||new Set(body.ids).size!==body.ids.length)Fail('INPUT_INVALID');
  await space.Scan();items=body.ids.map(id=>{const a=bootStore.Load().artifacts[id];if(!a)Fail('WORKSPACE_CONFLICT',409);space.Check(id,a.sha256);return{id,sha256:a.sha256};});
 }else Fail('INPUT_INVALID');
 for(const [key,p] of plans)if(p.expiresAt<=Date.now())plans.delete(key);if(plans.size>=256)Fail('WORKSPACE_JOB_CAPACITY',429);
 const planId=crypto.randomBytes(24).toString('hex'),expiresAt=Date.now()+300000;
 plans.set(planId,{owner:session.id,kind:body.kind,items,expiresAt});
 return{planId,kind:body.kind,expiresAt,count:items.length,items,requiresExplicitCommit:true};
}
function Submit(body,session){
 Fields(body,['planId','requestId']);if(!/^[a-f0-9]{48}$/.test(body.planId||'')||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId||''))Fail('INPUT_INVALID');
 const stateNow=db.Load(),receiptKey=crypto.createHash('sha256').update(session.id+'|'+body.requestId).digest('hex'),prior=stateNow.receipts[receiptKey];
 if(prior){if(prior.planId!==body.planId)Fail('WORKSPACE_CONFLICT',409);return ProjectJob(stateNow.jobs[prior.jobId]);}
 const plan=plans.get(body.planId);if(!plan||plan.owner!==session.id||plan.expiresAt<=Date.now())Fail('WORKSPACE_PLAN_EXPIRED',409);
 if(Object.keys(stateNow.jobs).length>=1000||Object.values(stateNow.jobs).filter(j=>['QUEUED','RUNNING'].includes(j.status)).length>=100)Fail('WORKSPACE_JOB_CAPACITY',429);
 if(plan.kind==='CLEANUP')for(const i of plan.items)space.Check(i.id,i.sha256);
 if(plan.kind==='METADATA')for(const i of plan.items)if(Meta(i.id).revision!==i.expectedRevision)Fail('WORKSPACE_CONFLICT',409);
 const actor=Actor(session);Audit(plan.kind,actor);const id=crypto.randomBytes(16).toString('hex');
 const job={id,kind:plan.kind,status:'QUEUED',createdAt:Date.now(),createdBy:actor,items:plan.items.map(input=>({status:'PENDING',input}))};
 db.Atomic(next=>{next.jobs[id]=job;next.receipts[receiptKey]={planId:body.planId,jobId:id};});plans.delete(body.planId);Schedule();return ProjectJob(job);
}
function DoItem(job,index){
 const item=job.items[index],input=item.input,actor='WORKSPACE_JOB:'+job.id;
 if(job.kind==='CREATE')return licenses.CreateReference({label:input.label,requestId:job.id+'-'+index},actor);
 if(job.kind==='METADATA'){
  const previous=Meta(input.id);if(previous.lastJob===job.id+':'+index)return {id:input.id,metadata:previous};
  if(previous.revision!==input.expectedRevision)Fail('WORKSPACE_CONFLICT',409);licenses.Detail(input.id);
  db.Atomic(next=>{next.metadata[input.id]={note:input.note,tags:input.tags,revision:previous.revision+1,updatedAt:Date.now(),updatedBy:job.createdBy,lastJob:job.id+':'+index};});return{id:input.id,metadata:Meta(input.id)};
 }
 if(job.kind==='EXPORT'){const l=licenses.Detail(input.id).license;return{id:l.id,label:l.label,status:l.status,issuedAt:l.issuedAt,lastVerifiedAt:l.lastVerifiedAt||0,appVersion:l.appVersion||'',metadata:Meta(l.id)};}
 if(job.kind==='CLEANUP')return space.DeleteCandidate(input.id,input.sha256);
 Fail('INPUT_INVALID');
}
function Pump(){
 if(runner||!require('./haCoordinator').CanAcceptTraffic())return;runner=true;
 try{
  const job=Object.values(db.Load().jobs).find(j=>['QUEUED','RUNNING'].includes(j.status));if(!job)return;
  const index=job.items.findIndex(x=>['PENDING','RUNNING'].includes(x.status));
  if(index<0){db.Atomic(next=>{const j=next.jobs[job.id];j.status=j.items.some(x=>x.status==='FAILED')?'PARTIAL':'DONE';j.updatedAt=Date.now();});return;}
  db.Atomic(next=>{next.jobs[job.id].status='RUNNING';next.jobs[job.id].items[index].status='RUNNING';});
  let result,error='';try{result=DoItem(job,index);}catch(e){error=e.desktopError?e.message:'WORKSPACE_ITEM_FAILED';}
  // Saving failure leaves RUNNING for idempotent retry after server restart.
  db.Atomic(next=>{const j=next.jobs[job.id],i=j.items[index];i.status=error?'FAILED':'DONE';if(result)i.result=result;if(error)i.error=error;j.updatedAt=Date.now();if(!j.items.some(x=>['PENDING','RUNNING'].includes(x.status)))j.status=j.items.some(x=>x.status==='FAILED')?'PARTIAL':'DONE';});
 }catch(e){console.error('WORKSPACE_WORKER_FAILED',e.desktopError?e.message:'INTERNAL');}
 finally{runner=false;}
}
function Schedule(){setImmediate(Pump);}
function Retry(id,actor){const j=db.Load().jobs[id];if(!j)Fail('NOT_FOUND',404);if(!['DONE','PARTIAL'].includes(j.status))Fail('WORKSPACE_CONFLICT',409);if(j.status==='DONE')return ProjectJob(j);Audit('RETRY',actor);db.Atomic(next=>{const row=next.jobs[id];for(const i of row.items)if(i.status==='FAILED'){i.status='PENDING';delete i.error;}row.status='QUEUED';});Schedule();return ProjectJob(db.Load().jobs[id]);}
function Cancel(id,actor){const j=db.Load().jobs[id];if(!j)Fail('NOT_FOUND',404);Audit('CANCEL',actor);db.Atomic(next=>{if(['QUEUED','RUNNING'].includes(next.jobs[id].status))next.jobs[id].status='CANCELLED';});return ProjectJob(db.Load().jobs[id]);}
function Export(id){const j=db.Load().jobs[id];if(!j||j.kind!=='EXPORT')Fail('NOT_FOUND',404);if(!['DONE','PARTIAL'].includes(j.status))Fail('WORKSPACE_CONFLICT',409);return{jobId:j.id,generatedAt:j.updatedAt,items:j.items.filter(i=>i.status==='DONE').map(i=>i.result),failed:j.items.filter(i=>i.status==='FAILED').map(i=>({id:i.input.id,error:i.error}))};}
function Start(){if(timer)return;db.Load();timer=setInterval(()=>{Pump();if(Date.now()-summary.asOf>10000)try{RefreshSummary();}catch(e){summary={...summary,error:'WORKSPACE_SUMMARY_UNAVAILABLE'};}},250);timer.unref();Schedule();space.Scan().catch(()=>{});}
function Stop(){if(timer)clearInterval(timer);timer=undefined;}
module.exports={Query,Detail,SaveMetadata,SaveReleaseNote,Summary,RefreshSummary,Preview,Submit,Jobs,Retry,Cancel,Export,Start,Stop,Pump,Meta,Fail};
