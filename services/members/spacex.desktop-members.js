'use strict';
// Operator contact assignments and an independent, read-only PC projection.
// Neither supplies execution authority or determines the identity of a person.
const crypto=require('node:crypto');
const store=require('../bootstrap/spacex.desktop-bootstrap-store');
const registry=require('../devices/spacex.desktop-device-registry');
const CATEGORIES=['licenses','launchers','flows','devices','integrity','incidents','nhw'];
const KINDS=['LICENSE','LAUNCHER','FLOW','DEVICE'];
const ID=/^[A-F0-9]{24}$/,HASH=/^[a-f0-9]{64}$/;
const LIMITS={members:10000,assignments:100000,receipts:4096,pageSize:100};
const plain=v=>!!v&&Object.getPrototypeOf(v)===Object.prototype;
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
function Fail(code,status=400){throw Object.assign(Error(code),{desktopError:true,status});}
function Fields(v,required,optional=[]){if(!plain(v)||required.some(k=>!Object.hasOwn(v,k))||Object.keys(v).some(k=>!required.includes(k)&&!optional.includes(k)))Fail('MEMBER_INPUT_INVALID');}
function Text(v,max,required=false,multiline=false){if(typeof v!=='string'||v.length>max||new RegExp(multiline?'[\\x00-\\x08\\x0b-\\x1f\\x7f]':'[\\x00-\\x1f\\x7f]').test(v)||required&&!v.trim())Fail('MEMBER_INPUT_INVALID');return v.trim();}
function Empty(){return {version:1,revision:0,items:{},assignments:{},receipts:{}};}
function State(db=store.Load()){return db.members||Empty();}
function TargetId(kind,id){return typeof id==='string'&&(kind==='DEVICE'?HASH.test(id):new RegExp('^(?:'+({LICENSE:'DL',LAUNCHER:'LA',FLOW:'BF'})[kind]+'-)?[A-F0-9]{24}$').test(id));}
function AssignmentKey(kind,id){return kind+':'+id;}
function Validate(s){
 const bad=()=>{throw Error('MEMBER_STORAGE_INVALID');};
 const keys=(v,r)=>plain(v)&&Object.keys(v).sort().join(',')===r.slice().sort().join(',');
 const time=v=>Number.isSafeInteger(v)&&v>0;
 if(!keys(s,['version','revision','items','assignments','receipts'])||s.version!==1||!Number.isSafeInteger(s.revision)||s.revision<0||!plain(s.items)||!plain(s.assignments)||!plain(s.receipts)||Object.keys(s.items).length>LIMITS.members||Object.keys(s.assignments).length>LIMITS.assignments||Object.keys(s.receipts).length>LIMITS.receipts)bad();
 for(const [id,r]of Object.entries(s.items)){
  if(!ID.test(id)||!keys(r,['id','displayName','note','status','createdAt','updatedAt'])||r.id!==id||!['ACTIVE','ARCHIVED'].includes(r.status)||!time(r.createdAt)||!time(r.updatedAt)||r.updatedAt<r.createdAt)bad();
  try{if(Text(r.displayName,80,true)!==r.displayName||Text(r.note,1000,false,true)!==r.note)bad();}catch(_){bad();}
 }
 for(const [key,a]of Object.entries(s.assignments))if(!keys(a,['kind','targetId','memberId','updatedAt'])||!KINDS.includes(a.kind)||!TargetId(a.kind,a.targetId)||key!==AssignmentKey(a.kind,a.targetId)||!s.items[a.memberId]||!time(a.updatedAt))bad();
 for(const [key,r]of Object.entries(s.receipts))if(!HASH.test(key)||!keys(r,['fingerprint','revision','response'])||!HASH.test(r.fingerprint)||!Number.isSafeInteger(r.revision)||r.revision<1||r.revision>s.revision||!plain(r.response)||r.response.revision!==r.revision||Buffer.byteLength(JSON.stringify(r.response))>4096)bad();
 return s;
}
function Direct(s,kind,id){return s.assignments[AssignmentKey(kind,id)]?.memberId||'';}
function Owners(s,db,row){
 const launcher=db.launchers[row.launcherId],ids=[Direct(s,'FLOW',row.id),Direct(s,'LAUNCHER',row.launcherId)];
 if(row.licenseId)ids.push(Direct(s,'LICENSE',row.licenseId));
 if(launcher?.assignedLicenseId)ids.push(Direct(s,'LICENSE',launcher.assignedLicenseId));
 return [...new Set(ids.filter(Boolean))];
}
function FlowOwner(s,db,row){const ids=Owners(s,db,row);return ids.length===1?ids[0]:'';}
function PcMatches(db,s,licenses){
 const bindings=db.deviceRegistry?.bindings||{},keys=new Map(),items=new Map(),flows=new Map(),licenseCandidates=new Map(),launchers=new Map();
 const bindingFor=machine=>typeof machine==='string'&&/^[A-F0-9]{64}$/.test(machine)?registry.BindingId(machine,db):'';
 function memberFor(binding){
  if(keys.has(binding.id))return keys.get(binding.id);
  const id=crypto.createHmac('sha256',Buffer.from(db.secret,'hex')).update('SPACEX-PC-MEMBER-V1\n'+binding.id).digest('hex').slice(0,24).toUpperCase();
  if(s.items[id]||items.has(id))Fail('MEMBER_ID_COLLISION',503);
  const nickname='PC-'+id,contact=s.items[Direct(s,'DEVICE',binding.id)];
  items.set(id,{id,memberCode:id,nickname,displayName:nickname,bindingId:binding.id,
   identitySource:'VERIFIED_PC_BINDING',status:binding.status==='REGISTERED'?'ACTIVE':'ARCHIVED',note:'',
   createdAt:binding.firstSeenAt,updatedAt:binding.lastSeenAt,canEdit:false,
   ...(contact?{contactId:contact.id,contactDisplayName:contact.displayName}:{})});
  keys.set(binding.id,id);
  return id;
 }
 for(const binding of Object.values(bindings))if(binding.proofs?.length)memberFor(binding);
 // These checkpoints are stored in the same transaction as ObserveVerified.
 // STARTED alone only means that a launcher ticket was presented.
 for(const flow of Object.values(db.flows)){
  if(!(flow.downloadedAt>0||flow.claimedAt>0))continue;
  const binding=bindings[bindingFor(flow.machineId)];
  if(!binding)continue;
  const owner=memberFor(binding);
  flows.set(flow.id,owner);
  if(db.launchers[flow.launcherId]?.flowId===flow.id)launchers.set(flow.launcherId,owner);
  const license=flow.licenseId||db.launchers[flow.launcherId]?.assignedLicenseId;
  if(!license)continue;
  const candidates=licenseCandidates.get(license)||new Set();
  candidates.add(owner);
  licenseCandidates.set(license,candidates);
 }
 const licenseOwners=new Map();
 for(const row of Object.values(licenses)){
  if(row.consumed&&row.machineId){
   // Redemption authenticated this license to the stored PC. Historic ticket
   // reservations for another machine cannot override the activation.
   const owner=keys.get(bindingFor(row.machineId));
   if(owner)licenseOwners.set(row.id,owner);
   continue;
  }
  const candidates=licenseCandidates.get(row.id);
  if(candidates?.size===1)licenseOwners.set(row.id,candidates.values().next().value);
 }
 return {items,flows,launchers,licenseOwners,keys,bindingFor};
}
function Contact(row){return {...row,memberCode:'',nickname:'',identitySource:'OPERATOR_CONTACT',canEdit:true};}
function RecordOwner(db,s,matched,kind,id){
 if(kind==='FLOW')return matched?.flows.get(id)||FlowOwner(s,db,db.flows[id]);
 if(kind==='LAUNCHER'){
  const launcher=db.launchers[id],licenseId=launcher.assignedLicenseId;
  return matched?.launchers.get(id)||Direct(s,kind,id)||Direct(s,'LICENSE',licenseId||'');
 }
 if(kind==='DEVICE')return matched?.keys.get(id)||Direct(s,kind,id);
 return matched?.licenseOwners.get(id)||Direct(s,kind,id);
}
function MatchRecord(kind,id,db=store.Load()){
 if(!TargetExists(db,kind,id))Fail('MEMBER_TARGET_NOT_FOUND',404);
 const s=State(db),matched=PcMatches(db,s,require('../licensing/spacex.desktop-licenses').DB().licenses);
 const memberId=RecordOwner(db,s,matched,kind,id),member=matched.items.get(memberId)||s.items[memberId]||{};
 const assignedMemberId=Direct(s,kind,id),contact=s.items[assignedMemberId];
 return {state:member.bindingId?'MATCHED':memberId?'CONTACT':'AWAITING_PC',memberId,
  memberCode:member.memberCode||'',nickname:member.nickname||'',bindingId:member.bindingId||'',
  identitySource:member.identitySource||(memberId?'OPERATOR_CONTACT':'AWAITING_PC_PROOF'),
  assignmentKind:kind,assignmentTargetId:id,assignedMemberId,memberDisplayName:member.displayName||'',
  assignedContactName:contact?.displayName||''};
}
function AssertNoConflicts(s,db){
 for(const row of Object.values(db.flows))if(Owners(s,db,row).length>1)Fail('MEMBER_ASSOCIATION_CONFLICT',409);
 for(const row of Object.values(db.launchers))if(row.assignedLicenseId){const a=Direct(s,'LAUNCHER',row.id),b=Direct(s,'LICENSE',row.assignedLicenseId);if(a&&b&&a!==b)Fail('MEMBER_ASSOCIATION_CONFLICT',409);}
}
function Mutation(action,id,body,actor,fields,apply){
 Fields(body,['expectedRevision','requestId',...fields]);
 if(!Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0||typeof body.requestId!=='string'||!/^[-A-Za-z0-9_]{16,80}$/.test(body.requestId))Fail('MEMBER_INPUT_INVALID');
 const actorText=typeof actor==='string'&&actor?actor:'ADMIN';
 const key=sha('COZY-MEMBER-REQUEST-V1\n'+actorText+'\n'+body.requestId);
 const fingerprint=sha(JSON.stringify([action,id,Object.keys(body).sort().map(k=>[k,body[k]])]));
 const previous=State().receipts[key];
 if(previous){if(previous.fingerprint!==fingerprint)Fail('MEMBER_REQUEST_REUSED',409);return structuredClone(previous.response);}
 if(State().revision!==body.expectedRevision)Fail('MEMBER_REVISION_CONFLICT',409);
 return require('../storage/spacex.desktop-operation-audit').Run('MEMBER_'+action,actorText,{subject:sha(id||'NEW_MEMBER'),fingerprint,revision:body.expectedRevision},db=>{
  const s=db.members||(db.members=Empty());
  if(s.revision!==body.expectedRevision)Fail('MEMBER_REVISION_CONFLICT',409);
  const result=apply(s,db),response={version:1,revision:++s.revision,...result};
  s.receipts[key]={fingerprint,revision:s.revision,response:structuredClone(response)};
  // Old requests retain their old expected revision, so removing a bounded
  // receipt cannot replay the old mutation. It fails MEMBER_REVISION_CONFLICT.
  const receipts=Object.entries(s.receipts).sort((a,b)=>a[1].revision-b[1].revision);
  for(const [old]of receipts.slice(0,Math.max(0,receipts.length-LIMITS.receipts)))delete s.receipts[old];
  Validate(s);return response;
 });
}
function Create(body,actor){return Mutation('CREATE','',body,actor,['displayName','note'],s=>{
 if(Object.keys(s.items).length>=LIMITS.members)Fail('MEMBER_CAPACITY',409);
 const displayName=Text(body.displayName,80,true),note=Text(body.note,1000,false,true),id=crypto.randomBytes(12).toString('hex').toUpperCase(),at=Date.now();
 if(s.items[id])Fail('MEMBER_ID_COLLISION',503);
 const member={id,displayName,note,status:'ACTIVE',createdAt:at,updatedAt:at};s.items[id]=member;return {member:{...member}};
});}
function Member(s,id){if(!ID.test(id)||!s.items[id])Fail('MEMBER_NOT_FOUND',404);return s.items[id];}
function Update(id,body,actor){return Mutation('UPDATE',id,body,actor,['displayName','note'],s=>{const row=Member(s,id);row.displayName=Text(body.displayName,80,true);row.note=Text(body.note,1000,false,true);row.updatedAt=Math.max(row.createdAt,Date.now());return {member:{...row}};});}
function Archive(id,body,actor){return Mutation('ARCHIVE',id,body,actor,['archived'],(s,db)=>{if(typeof body.archived!=='boolean')Fail('MEMBER_INPUT_INVALID');const row=Member(s,id);row.status=body.archived?'ARCHIVED':'ACTIVE';row.updatedAt=Math.max(row.createdAt,Date.now());return {member:{...row},authorizationChanged:false};});}
function TargetExists(db,kind,id){if(!KINDS.includes(kind)||!TargetId(kind,id))return false;if(kind==='LICENSE'){const licenses=require('../licensing/spacex.desktop-licenses');return licenses.IsOperational(licenses.DB().licenses[id]);}if(kind==='DEVICE')return !!db.deviceRegistry?.bindings[id];return !!db[kind==='LAUNCHER'?'launchers':'flows'][id];}
function Assign(body,actor){return Mutation('ASSIGN',String(body?.kind||'')+':'+String(body?.targetId||''),body,actor,['kind','targetId','memberId','expectedMemberId'],(s,db)=>{
 if(!TargetExists(db,body.kind,body.targetId))Fail('MEMBER_TARGET_NOT_FOUND',404);
 if(typeof body.memberId!=='string'||body.memberId&&!ID.test(body.memberId)||typeof body.expectedMemberId!=='string'||body.expectedMemberId&&!ID.test(body.expectedMemberId))Fail('MEMBER_INPUT_INVALID');
 const key=AssignmentKey(body.kind,body.targetId),current=Direct(s,body.kind,body.targetId);
 if(current!==body.expectedMemberId)Fail('MEMBER_ASSIGNMENT_CONFLICT',409);
 if(!body.memberId&&!current)Fail('MEMBER_ASSIGNMENT_NOT_DIRECT',409);
 if(body.memberId){if(Member(s,body.memberId).status!=='ACTIVE')Fail('MEMBER_ARCHIVED',409);if(!s.assignments[key]&&Object.keys(s.assignments).length>=LIMITS.assignments)Fail('MEMBER_CAPACITY',409);s.assignments[key]={kind:body.kind,targetId:body.targetId,memberId:body.memberId,updatedAt:Date.now()};}
 else delete s.assignments[key];
 AssertNoConflicts(s,db);
 return {assignment:{kind:body.kind,targetId:body.targetId,memberId:body.memberId,previousMemberId:current},authorizationChanged:false};
});}
function Page(query,allowed){
 if(!plain(query)||Object.keys(query).some(k=>!allowed.includes(k)))Fail('MEMBER_QUERY_INVALID');
 const integer=(name,fallback,max)=>{const v=query[name];if(v===undefined)return fallback;if(typeof v!=='string'||!new RegExp('^[1-9][0-9]{0,5}$').test(v)||Number(v)>max)Fail('MEMBER_QUERY_INVALID');return Number(v);};
 return {page:integer('page',1,100000),pageSize:integer('pageSize',20,LIMITS.pageSize)};
}
function Decorate(row,kind,targetId,owner,s,matched){
 const direct=kind&&targetId?Direct(s,kind,targetId):'',pc=matched?.items.get(owner),contact=s.items[direct];
 return {...row,assignmentKind:kind||'',assignmentTargetId:targetId||'',assignedMemberId:direct,
  memberId:owner,memberDisplayName:pc?.nickname||s.items[owner]?.displayName||'',
  assignmentOrigin:pc?'VERIFIED_PC_BINDING':direct?'DIRECT':owner?'LINKED':'UNASSIGNED',
  ...(matched?{assignedContactName:contact?.displayName||''}:{})};
}
function LicenseMembership(id,db=store.Load()){const s=State(db),owner=Direct(s,'LICENSE',id);return {memberId:owner,memberDisplayName:s.items[owner]?.displayName||'',assignedMemberId:owner};}
// Reuse the same explicit flow/launcher/license ownership rules for support links.
function FlowMembership(id,db=store.Load()){const s=State(db),row=db.flows?.[id],owner=row?FlowOwner(s,db,row):'';return {memberId:owner};}
function Snapshot(scope){
 const db=store.Load(),s=State(db),licenses=require('../licensing/spacex.desktop-licenses'),licenseRows=licenses.DB().licenses;
 const matched=scope==='MATCH'?PcMatches(db,s,licenseRows):null;
 const data=Object.fromEntries(CATEGORIES.map(k=>[k,[]])),flowOwners=new Map(),sessionFlow=new Map();
 for(const r of Object.values(db.flows)){flowOwners.set(r.id,RecordOwner(db,s,matched,'FLOW',r.id));sessionFlow.set(r.id,r.id);sessionFlow.set(r.sessionId,r.id);}
 for(const r of Object.values(db.overlays||{}))sessionFlow.set(r.sessionId,r.parentFlowId);
 for(const r of Object.values(licenseRows))if(licenses.IsOperational(r))data.licenses.push(Decorate({id:r.id,label:r.label,issuedAt:r.issuedAt},'LICENSE',r.id,RecordOwner(db,s,matched,'LICENSE',r.id),s,matched));
 for(const r of Object.values(db.launchers)){
  const owner=RecordOwner(db,s,matched,'LAUNCHER',r.id);
  data.launchers.push(Decorate({id:r.id,label:r.label,status:r.status==='AVAILABLE'&&r.expiresAt<=Date.now()?'EXPIRED':r.status,issuedAt:r.issuedAt,expiresAt:r.expiresAt,flowId:r.flowId||''},'LAUNCHER',r.id,owner,s,matched));
 }
 for(const r of Object.values(db.flows))data.flows.push(Decorate({id:r.id,flowId:r.id,sessionId:r.sessionId,launcherId:r.launcherId,licenseId:r.licenseId||'',status:r.status,createdAt:r.createdAt,lastVerifiedAt:r.lastVerifiedAt},'FLOW',r.id,flowOwners.get(r.id)||'',s,matched));
 for(const r of Object.values(db.deviceRegistry?.bindings||{})){
  data.devices.push(Decorate({id:r.id,status:r.status,firstSeenAt:r.firstSeenAt,lastSeenAt:r.lastSeenAt,assurance:r.proofs?.some(p=>Date.now()>=p.at&&Date.now()-p.at<30*86400000)?'APP_KEY_POSSESSION':'IDENTIFIED_ONLY'},'DEVICE',r.id,RecordOwner(db,s,matched,'DEVICE',r.id),s,matched));
 }
 const reportIndex=require('../integrity/spacex.desktop-integrity-reports').MemberIndex(matched?.bindingFor);
 for(const r of reportIndex){
  const byFlow=db.flows[r.flowId]?r.flowId:db.overlays?.[r.flowId]?.parentFlowId||'',bySession=sessionFlow.get(r.sessionId)||'';
  const knownPc=matched?.items.get(matched.flows.get(byFlow||bySession));
  const conflict=!!(r.flowId&&!byFlow||r.sessionId&&!bySession||byFlow&&bySession&&byFlow!==bySession||knownPc&&r.machineBindingId&&knownPc.bindingId!==r.machineBindingId);
  const flowId=conflict?'':byFlow||bySession,owner=flowOwners.get(flowId)||'';
  const row=Decorate({...r,rootFlowId:flowId},flowId?'FLOW':'',flowId,owner,s,matched);data.integrity.push(row);
  if(r.status==='REJECTED'||r.hasMismatch)data.incidents.push(Decorate({id:'integrity:'+r.id,at:r.at,kind:'INTEGRITY',source:r.source,attested:false,flowId,stage:r.stage,status:r.status,reason:r.reason,reportId:r.id},flowId?'FLOW':'',flowId,owner,s,matched));
 }
 for(const [flowId,trace]of Object.entries(db.lifecycleTrace?.flows||{}))for(const e of trace.events){
  if(!['FAILED','TIMEOUT','UNKNOWN','EXPIRED','REVOKED'].includes(e.status))continue;
  const owner=flowOwners.get(flowId)||'';
  data.incidents.push(Decorate({id:'lifecycle:'+e.id,at:e.at,kind:'LIFECYCLE',source:e.source,flowId,stage:e.role,status:e.status,reason:e.event},db.flows[flowId]?'FLOW':'',db.flows[flowId]?flowId:'',owner,s,matched));
 }
 for(const row of require('../observability/spacex.monitor-reports').MemberIndex(db)){
  const owner=flowOwners.get(row.flowId)||'';
  data.nhw.push({...row,memberId:owner});
 }
 const counts=new Map();
 for(const category of CATEGORIES)for(const row of data[category]){if(!counts.has(row.memberId))counts.set(row.memberId,Object.fromEntries(CATEGORIES.map(k=>[k,0])));counts.get(row.memberId)[category]++;}
 return {db,s,data,counts,matched};
}
function Counts(counts,id){return {...(counts.get(id)||Object.fromEntries(CATEGORIES.map(k=>[k,0])))};}
function List(query={}){
 const paging=Page(query,['q','status','page','pageSize','scope']),q=query.q===undefined?'':Text(query.q,80).toLocaleLowerCase('ko'),status=query.status===undefined?'ACTIVE':query.status;
 if(!['ACTIVE','ARCHIVED','ALL'].includes(status)||query.scope!==undefined&&query.scope!=='MATCH')Fail('MEMBER_QUERY_INVALID');
 const {s,counts,matched}=Snapshot(query.scope);
 const rows=matched?[...matched.items.values()]:Object.values(s.items);
 const items=rows.filter(r=>(status==='ALL'||r.status===status)&&(!q||r.id.toLowerCase().includes(q)||r.displayName.toLocaleLowerCase('ko').includes(q)||r.note.toLocaleLowerCase('ko').includes(q)||r.contactDisplayName?.toLocaleLowerCase('ko').includes(q))).sort((a,b)=>b.updatedAt-a.updatedAt||a.id.localeCompare(b.id));
 const start=(paging.page-1)*paging.pageSize;
 return {version:1,revision:s.revision,items:items.slice(start,start+paging.pageSize).map(r=>({...r,counts:Counts(counts,r.id)})),totalCount:items.length,...paging,
  ...(matched?{identitySource:'VERIFIED_PC_BINDING'}:{unassigned:{counts:Counts(counts,'')},identitySource:'OPERATOR_ASSIGNED_NOT_HARDWARE_INFERRED'}),serverTime:Date.now()};
}
function Detail(id,query={}){
 const paging=Page(query,['category','page','pageSize','scope']),category=query.category===undefined?'all':query.category;
 if(!['all',...CATEGORIES].includes(category)||query.scope!==undefined&&query.scope!=='MATCH')Fail('MEMBER_QUERY_INVALID');
 const {db,s,data,counts,matched}=Snapshot(query.scope),owner=id==='unassigned'&&!matched?'':id,categories={};
 const member=matched?.items.get(id)||(owner?(matched?Contact(Member(s,owner)):{...Member(s,owner)}):null);
 for(const name of category==='all'?CATEGORIES:[category]){
  const rows=data[name].filter(r=>r.memberId===owner).sort((a,b)=>(b.at||b.createdAt||b.issuedAt||b.lastSeenAt||0)-(a.at||a.createdAt||a.issuedAt||a.lastSeenAt||0)||a.id.localeCompare(b.id)),start=(paging.page-1)*paging.pageSize;
  let items=rows.slice(start,start+paging.pageSize);
  if(name==='integrity'){
   const full=new Map(require('../integrity/spacex.desktop-integrity-reports').MemberRecords(items.map(r=>r.id)).map(r=>[r.id,r]));
   items=items.map(r=>{
    const result={...full.get(r.id),...r};
    if(matched)delete result.machineId;
    return result;
   });
  }
  if(name==='licenses')items=items.map(r=>{
   const licenses=require('../licensing/spacex.desktop-licenses'),result={...licenses.Public(licenses.DB().licenses[r.id]),...r};
   if(matched){delete result.machineId;delete result.deviceName;delete result.machinePolicy;}
   return result;
  });
  if(name==='devices'){
   const wanted=new Set(items.map(r=>r.id)),machineByBinding=new Map(),binding=require('../devices/spacex.desktop-device-registry');
   for(const row of Object.values(db.flows))if(row.machineId){const key=binding.BindingId(row.machineId,db);if(wanted.has(key))machineByBinding.set(key,row.machineId);}
   items=items.map(r=>{const policy=machineByBinding.has(r.id)?require('../devices/spacex.desktop-machine-policy').Public(machineByBinding.get(r.id)):null;return {...r,blocked:policy?policy.blocked:null,blockSource:policy?.source||'UNKNOWN',blockGeneration:policy?.generation??null};});
  }
  if(name==='flows')items=items.map(r=>({...r,machineBindingId:db.flows[r.id].machineId?require('../devices/spacex.desktop-device-registry').BindingId(db.flows[r.id].machineId,db):'',lifecycle:require('../observability/spacex.desktop-lifecycle-trace').Flow(r.id)}));
  categories[name]={items,totalCount:rows.length,...paging};
 }
 const nhw=require('../observability/spacex.monitor-reports');
 return {version:1,revision:s.revision,member,categories,nhwCatalog:nhw.PublicCatalog(),...(categories.nhw?{nhwPolicy:nhw.Policy(db)}:{}),counts:Counts(counts,owner),readOnly:member?.canEdit===false,authorizationChanged:false,identitySource:member?.identitySource||'OPERATOR_ASSIGNED_NOT_HARDWARE_INFERRED',serverTime:Date.now()};
}
module.exports={Empty,State,Validate,Create,Update,Archive,Assign,List,Detail,LicenseMembership,FlowMembership,MatchRecord,LIMITS};
