'use strict';
// Display data and a separately published, capability-bound native renderer.
// Neither surface carries a second copy of the B authorization.
// Its authority shares B's durable transaction so completion cannot leave a
// valid B session and a newly issued overlay capability active together.
const crypto=require('node:crypto');
const store=require('./desktopBootstrapStore');
const LEASE_MS=30000,POLL_MS=10000,COMPLETION_MS=60000,MAX_SESSIONS=10000;
const FORMAT='GAME-OVERLAY-DATA-1';
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
const now=()=>Date.now();
const messages={OVERLAY_INPUT_INVALID:'오버레이 표시 데이터를 확인해 주세요.',OVERLAY_DISABLED:'오버레이가 중지되었습니다.',OVERLAY_NOT_AUTHORIZED:'라이선스 인증을 먼저 완료해 주세요.',OVERLAY_SESSION_INVALID:'오버레이 인증을 확인할 수 없습니다.',OVERLAY_SESSION_CLOSED:'종료된 오버레이입니다. 새로 인증해 주세요.',OVERLAY_EXPIRED:'오버레이 연결이 만료되었습니다.',OVERLAY_COMPLETION_EXPIRED:'인증 완료 응답의 재시도 시간이 지났습니다.',OVERLAY_REQUEST_REUSED:'다른 인증 완료 요청에 사용한 요청 번호입니다.',OVERLAY_TEMPLATE_CONFLICT:'오버레이 설정이 변경되었습니다. 새로 고침해 주세요.',OVERLAY_CAPACITY:'동시에 표시할 수 있는 오버레이 수를 초과했습니다.',OVERLAY_STORAGE_INVALID:'오버레이 저장 정보를 확인할 수 없습니다.'};
function Fail(code,status=400){const error=Error(code);error.desktopError=true;error.status=status;throw error;}
function Plain(value){return !!value&&Object.getPrototypeOf(value)===Object.prototype;}
function Fields(value,names){if(!Plain(value)||Object.keys(value).some(key=>!names.includes(key))||names.some(key=>!Object.hasOwn(value,key)))Fail('OVERLAY_INPUT_INVALID');}
function Text(value,limit,required=false){if(typeof value!=='string'||value.length>limit||/[\u0000-\u001f\u007f]/.test(value)||!value.isWellFormed()||required&&!value.trim())Fail('OVERLAY_INPUT_INVALID');return value;}
function Document(value){
 Fields(value,['schema','format','title','lines','theme']);
 if(value.schema!==1||value.format!==FORMAT||!['dark','light'].includes(value.theme)||!Array.isArray(value.lines)||value.lines.length>8)Fail('OVERLAY_INPUT_INVALID');
 return {schema:1,format:FORMAT,title:Text(value.title,120,true),lines:value.lines.map(line=>Text(line,240)),theme:value.theme};
}
function Empty(){return {schema:1,version:1,enabled:true,document:Document({schema:1,format:FORMAT,title:'GameConnect',lines:['라이선스 인증이 완료되었습니다.'],theme:'dark'}),sessions:{}};}
function State(db=store.Load()){return db.overlayState||Empty();}
function Atomic(fn){try{return store.Atomic(fn);}catch(error){if(error.desktopError)throw error;Fail(error.message==='BOOTSTRAP_STORAGE_RESTART_REQUIRED'?error.message:'STORAGE_SAVE_FAILED',503);}}
function Digest(value){return typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);}
function Id(value){return typeof value==='string'&&/^[A-F0-9]{24}$/.test(value);}
function Identity(value){return typeof value==='string'&&/^[A-F0-9]{64}$/.test(value);}
function Time(value){return Number.isSafeInteger(value)&&value>0;}
function ValidateState(value,db){
 try{
  Fields(value,['schema','version','enabled','document','sessions']);
  if(value.schema!==1||!Number.isSafeInteger(value.version)||value.version<1||typeof value.enabled!=='boolean'||!Plain(value.sessions)||Object.keys(value.sessions).length>MAX_SESSIONS)throw Error();
  Document(value.document);
  for(const [id,row]of Object.entries(value.sessions)){
   require('./desktopOverlayPlugin').ValidateSession(row,db);
   if(!Id(id)||!Plain(row)||row.id!==id||!['ACTIVE','CLOSED','EXPIRED','REVOKED'].includes(row.status)||!Identity(row.deviceId)||!Identity(row.machineId)||!Number.isSafeInteger(row.machinePolicyGeneration)||row.machinePolicyGeneration<0||!Digest(row.tokenHash)||!Digest(row.completionHash)||!Time(row.createdAt)||!Time(row.lastSeenAt)||!Time(row.leaseExpiresAt)||!Time(row.completionExpiresAt)||row.completionExpiresAt>row.createdAt+COMPLETION_MS||!Number.isSafeInteger(row.documentVersion)||row.documentVersion<1||row.documentVersion>value.version||!Number.isSafeInteger(row.policyRevision)||row.policyRevision<0||!Number.isSafeInteger(row.operationsRevision)||row.operationsRevision<0||!Number.isSafeInteger(row.integrityRevision)||row.integrityRevision<0)throw Error();
   if(row.lastSeenAt<row.createdAt||row.leaseExpiresAt<=row.lastSeenAt||row.leaseExpiresAt>row.lastSeenAt+LEASE_MS||row.completionExpiresAt!==row.createdAt+COMPLETION_MS||row.closedAt!==undefined&&(!Time(row.closedAt)||row.closedAt<row.createdAt))throw Error();
   if(row.status==='ACTIVE'){if(typeof row.nonce!=='string'||!/^[a-f0-9]{48}$/.test(row.nonce)||hash(Token(db,row))!==row.tokenHash)throw Error();}
   else if(row.nonce!==undefined)throw Error();
   if(typeof row.documentText!=='string'||row.documentText.length>10000||!Digest(row.documentSha256)||hash(row.documentText)!==row.documentSha256||JSON.stringify(Document(JSON.parse(row.documentText)))!==row.documentText)throw Error();
   const flow=db.flows[row.flowId];
   if(!flow||flow.sessionId!==row.bootstrapSessionId||flow.licenseId!==row.licenseId||flow.deviceId!==row.deviceId||flow.machineId!==row.machineId||flow.machinePolicyGeneration!==row.machinePolicyGeneration||flow.overlaySessionId!==id||flow.closedByLicenseCompletion!==true||!['CLOSED','REVOKED','EXPIRED'].includes(flow.status))throw Error();
  }
 }catch(_){throw Error('OVERLAY_STORAGE_INVALID');}
}
function Token(db,row){return crypto.createHmac('sha256',Buffer.from(db.secret,'hex')).update(['GAME-OVERLAY-CAPABILITY-1',row.id,row.deviceId,row.nonce].join('|')).digest('base64url');}
function EqualToken(value,digest){if(typeof value!=='string'||value.length>200||!Digest(digest))return false;return crypto.timingSafeEqual(Buffer.from(hash(value),'hex'),Buffer.from(digest,'hex'));}
function Revisions(){return {policyRevision:require('./desktopSecurityAuthority').Policy().revision,operationsRevision:require('./desktopSecurityOperations').Revision(),integrityRevision:require('./desktopIntegrityReports').Policy().revision};}
function Available(){require('./desktopBootstrap').EnsureSecurityAvailable();if(!State().enabled)Fail('OVERLAY_DISABLED',403);}
function License(flow,deviceId,activationToken){
 const row=require('./desktopLicenses').DB().licenses[flow.licenseId];
 if(!row||!row.consumed||row.deviceId!==deviceId||row.bootstrapSessionId!==flow.sessionId||row.machineId!==flow.machineId||row.machinePolicyGeneration!==flow.machinePolicyGeneration)Fail('OVERLAY_NOT_AUTHORIZED',403);
 if(activationToken!==undefined&&!EqualToken(activationToken,row.tokenHash))Fail('DESKTOP_ACTIVATION_INVALID',401);
 if(row.status==='REVOKED')Fail('DESKTOP_REVOKED',403);
 if(row.status==='RELEASED'||row.releasedAt)Fail('DESKTOP_RELEASED',403);
 if(row.expiresAt&&row.expiresAt<=now())Fail('DESKTOP_EXPIRED',403);
 require('./desktopMachinePolicy').AssertAllowed(row.machineId,row.machinePolicyGeneration,flow.sessionId);
 return row;
}
function Runtime(flow){
 const db=store.Load(),a=db.artifacts[db.launchers[flow.launcherId]?.artifactId],b=db.artifacts[flow.releaseId];
 require('./desktopSecurityAuthority').RequireArtifact(a);require('./desktopSecurityAuthority').RequireArtifact(b);
 require('./desktopSecurityOperations').RequireRuntimePair(a,b);
}
function Active(row){
 if(!row)Fail('OVERLAY_SESSION_INVALID',401);
 if(row.status!=='ACTIVE')Fail('OVERLAY_SESSION_CLOSED',403);
 if(now()<row.lastSeenAt||require('./desktopOverlayPlugin').LiveDeadline(row)<=now())Fail('OVERLAY_EXPIRED',403);
 require('./desktopOverlayPlugin').CheckRuntime(row);
 const flow=store.Load().flows[row.flowId];
 if(!flow||flow.status!=='CLOSED'||flow.closedByLicenseCompletion!==true||flow.overlaySessionId!==row.id)Fail('OVERLAY_SESSION_CLOSED',403);
 const license=License(flow,row.deviceId);Runtime(flow);
 const revisions=Revisions();
 if(row.policyRevision!==revisions.policyRevision||row.operationsRevision!==revisions.operationsRevision||row.integrityRevision!==revisions.integrityRevision)Fail('SECURITY_FRESH_OBSERVATION_REQUIRED',403);
 return license;
}
function Result(row){const at=now();return {sessionId:row.id,sessionToken:Token(store.Load(),row),leaseExpiresAt:row.leaseExpiresAt,serverTime:at,pollAfterMs:Math.max(1,Math.min(POLL_MS,Math.floor((row.leaseExpiresAt-at)/3))),documentText:row.documentText,documentSha256:row.documentSha256,documentVersion:row.documentVersion};}
function CompletionFingerprint(body){return hash(JSON.stringify({requestId:body.requestId,sessionId:body.sessionId,deviceId:body.deviceId,activationHash:hash(body.activationToken)}));}
function Complete(flow,body,retireFlow){
 Available();
 if(!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId||'')||!Identity(body.deviceId)||typeof body.activationToken!=='string'||body.activationToken.length>200)Fail('OVERLAY_INPUT_INVALID');
 if(flow.deviceId!==body.deviceId)Fail('OVERLAY_NOT_AUTHORIZED',403);
 const license=License(flow,body.deviceId,body.activationToken),fingerprint=CompletionFingerprint(body);
 if(flow.closedByLicenseCompletion){
  const previous=State().sessions[flow.overlaySessionId];
  if(!previous||previous.completionHash!==fingerprint)Fail('OVERLAY_REQUEST_REUSED',409);
  if(previous.completionExpiresAt<=now())Fail('OVERLAY_COMPLETION_EXPIRED',409);
  Active(previous);return Result(previous);
 }
 if(flow.status!=='CLAIMED'||!flow.lastVerifiedAt||flow.lastVerifiedAt>now()||now()-flow.lastVerifiedAt>LEASE_MS||!flow.licenseLeaseExpiresAt||flow.licenseLeaseExpiresAt<=now())Fail('OVERLAY_NOT_AUTHORIZED',403);
 Runtime(flow);
 require('./desktopIntegrityReports').RequireSnapshot(flow,'B');
 require('./desktopSecurityAuthority').RequireFresh(flow,'B',flow.lastSecurityIntent||'redeem',flow.lastSecurityBinding||'');
 const at=now(),s=State(),id=crypto.randomBytes(12).toString('hex').toUpperCase(),documentText=JSON.stringify(Document(s.document)),leaseExpiresAt=Math.min(at+LEASE_MS,license.expiresAt||Number.MAX_SAFE_INTEGER);
 if(at<flow.createdAt||at<flow.lastVerifiedAt||flow.licenseLeaseExpiresAt<=at)Fail('OVERLAY_NOT_AUTHORIZED',403);
 if(leaseExpiresAt<=at)Fail('DESKTOP_EXPIRED',403);
 const row={id,flowId:flow.id,bootstrapSessionId:flow.sessionId,licenseId:license.id,deviceId:flow.deviceId,machineId:flow.machineId,machinePolicyGeneration:flow.machinePolicyGeneration,status:'ACTIVE',nonce:crypto.randomBytes(24).toString('hex'),createdAt:at,lastSeenAt:at,leaseExpiresAt,completionExpiresAt:at+COMPLETION_MS,completionHash:fingerprint,documentVersion:s.version,documentText,documentSha256:hash(documentText),...Revisions()};
 const pluginId=require('./desktopOverlayPlugin').Pin();if(pluginId)Object.assign(row,{pluginId,pluginPhase:'PENDING'});
 row.tokenHash=hash(Token(store.Load(),row));
 Atomic(db=>{
  const target=db.flows[flow.id];if(target.status!=='CLAIMED'||target.closedByLicenseCompletion)Fail('OVERLAY_REQUEST_REUSED',409);
  db.overlayState||=Empty();PruneState(db.overlayState,at);
  if(Object.keys(db.overlayState.sessions).length>=MAX_SESSIONS)Fail('OVERLAY_CAPACITY',503);
  db.overlayState.sessions[id]=row;
  Object.assign(target,{status:'CLOSED',closedAt:at,closedByLicenseCompletion:true,overlaySessionId:id,licenseLeaseExpiresAt:0});
  retireFlow(target);
 });
 require('./desktopLicenses').RetireAuthorization(flow.deviceId,license.id);
 require('./desktopIntegrityReports').RetireSession(flow);
 require('./desktopSecurityAuthority').Invalidate(flow,'A','LICENSE_COMPLETED');
 require('./desktopSecurityAuthority').Invalidate(flow,'B','LICENSE_COMPLETED');
 Audit('ISSUED',{sessionId:id,bootstrapSessionId:flow.sessionId,licenseId:license.id,documentVersion:row.documentVersion});
 return Result(State().sessions[id]);
}
function Retire(row,status,reason=''){require('./desktopOverlayPlugin').Retire(row.id);row.status=status;row.closedAt=Math.max(now(),row.createdAt,row.lastSeenAt);row.reason=reason;delete row.nonce;}
function PruneState(state,at){
 for(const row of Object.values(state.sessions))if(row.status==='ACTIVE'&&require('./desktopOverlayPlugin').LiveDeadline(row)<=at)Retire(row,'EXPIRED');
 // Tombstones and token hashes support close retries for one day. Original
 // B flow tombstones still forbid reissuance after an overlay row is removed.
 for(const [id,row]of Object.entries(state.sessions))if(row.status!=='ACTIVE'&&Math.max(row.completionExpiresAt,row.closedAt||row.leaseExpiresAt)+86400000<=at)delete state.sessions[id];
}
function Execute(body){
 const pluginAction=['plugin-manifest','plugin-chunk','plugin-report'].includes(body?.action);
 Fields(body,['action','sessionId','sessionToken','deviceId',...(body?.action==='plugin-chunk'?['pluginId','offset']:body?.action==='plugin-report'?['pluginId','reportId','payload']:[])]);
 if(!['poll','close','plugin-manifest','plugin-chunk','plugin-report'].includes(body.action)||!Id(body.sessionId)||!Identity(body.deviceId))Fail('OVERLAY_INPUT_INVALID');
 const row=State().sessions[body.sessionId];
 if(!row||row.deviceId!==body.deviceId||!EqualToken(body.sessionToken,row.tokenHash))Fail('OVERLAY_SESSION_INVALID',401);
 if(body.action==='close'){
  if(row.status==='ACTIVE')Atomic(db=>Retire(db.overlayState.sessions[row.id],'CLOSED'));
  return {sessionId:row.id,status:'CLOSED',serverTime:now()};
 }
 let license,at,leaseExpiresAt;
 try{Available();license=Active(row);
  const plugin=require('./desktopOverlayPlugin');
  if(pluginAction){if(body.action==='plugin-manifest')return plugin.Manifest(row,license);if(body.action==='plugin-chunk')return plugin.Chunk(row,body);return plugin.Report(row,body,license);}
  plugin.RequireReady(row);at=now();if(at<row.lastSeenAt)Fail('OVERLAY_EXPIRED',403);leaseExpiresAt=Math.min(at+LEASE_MS,license.expiresAt||Number.MAX_SAFE_INTEGER);if(leaseExpiresAt<=at)Fail('DESKTOP_EXPIRED',403);}catch(error){
  // Policy, license, maintenance and disconnect failures never leave a grant
  // that can become usable again when the rejecting condition is removed.
  if(row.status==='ACTIVE'&&error.desktopError&&(!pluginAction||error.status===403||error.status===503)&&error.message!=='OVERLAY_PLUGIN_NOT_READY')Atomic(db=>Retire(db.overlayState.sessions[row.id],error.message==='OVERLAY_EXPIRED'?'EXPIRED':'REVOKED',error.message));
  throw error;
 }
 Atomic(db=>{const state=db.overlayState,item=state.sessions[row.id];item.lastSeenAt=at;item.leaseExpiresAt=leaseExpiresAt;item.documentText=JSON.stringify(state.document);item.documentSha256=hash(item.documentText);item.documentVersion=state.version;});
 return Result(State().sessions[row.id]);
}
function Audit(kind,value){try{require('../storage/audit').LogEvent('DESKTOP_OVERLAY_'+kind,JSON.stringify(value));}catch(_){} }
function View(row){let status=row.status;if(status==='ACTIVE'&&require('./desktopOverlayPlugin').LiveDeadline(row)<=now())status='EXPIRED';return {id:row.id,licenseId:row.licenseId,bootstrapSessionId:row.bootstrapSessionId,deviceId:row.deviceId,machineId:row.machineId,status,createdAt:row.createdAt,lastSeenAt:row.lastSeenAt,leaseExpiresAt:row.leaseExpiresAt,documentVersion:row.documentVersion,...(row.pluginId?{pluginId:row.pluginId,pluginPhase:row.pluginPhase,pluginVerifiedAt:row.pluginVerifiedAt||0}:{} )};}
function Overview(){const state=State();return {enabled:state.enabled,version:state.version,document:structuredClone(state.document),documentSha256:hash(JSON.stringify(state.document)),fileName:'overlay.dat',sessions:Object.values(state.sessions).map(View).sort((a,b)=>b.createdAt-a.createdAt).slice(0,500),limits:{leaseMs:LEASE_MS,pollAfterMs:POLL_MS},serverTime:now()};}
function Update(body,actor){
 Fields(body,['expectedVersion','enabled','document']);
 if(!Number.isSafeInteger(body.expectedVersion)||typeof body.enabled!=='boolean')Fail('OVERLAY_INPUT_INVALID');
 const document=Document(body.document);
 Atomic(db=>{const current=State(db);if(body.expectedVersion!==current.version)Fail('OVERLAY_TEMPLATE_CONFLICT',409);db.overlayState={...current,enabled:body.enabled,version:current.version+1,document};if(!body.enabled)for(const row of Object.values(db.overlayState.sessions))if(row.status==='ACTIVE')Retire(row,'REVOKED','OVERLAY_DISABLED');PruneState(db.overlayState,now());});
 Audit('TEMPLATE_UPDATED',{actor:String(actor).slice(0,160),version:State().version,enabled:body.enabled});return Overview();
}
function Revoke(id,body,actor){
 Fields(body,['reason']);const reason=Text(body.reason,300,true).trim();if(reason.length<3)Fail('OVERLAY_INPUT_INVALID');
 if(!Id(id)||!State().sessions[id])Fail('OVERLAY_SESSION_INVALID',404);
 Atomic(db=>Retire(db.overlayState.sessions[id],'REVOKED',reason));Audit('REVOKED',{sessionId:id,actor:String(actor).slice(0,160)});return View(State().sessions[id]);
}
function ModuleBytes(){return Buffer.from(JSON.stringify(State().document),'utf8');}
module.exports={FORMAT,LEASE_MS,POLL_MS,COMPLETION_MS,messages,ValidateState,Complete,Execute,Overview,Update,Revoke,ModuleBytes};
