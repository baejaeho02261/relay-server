'use strict';
// Authenticated desktop rendering handoff. This service authorizes only approved
// own-process O artifacts; it never accesses another process or injects code.
const delegation=require("../bootstrap/peace.desktop-handoff-delegation"),crypto=require('node:crypto'),fs=require('node:fs'),store=require("../bootstrap/peace.desktop-bootstrap-store");
const config=require("../../config/peace.runtime-configuration"),products=require("../licensing/peace.licensed-products");
// One immutable B->O startup capability: the native parent allows at most
// 300s to download/verify O and 110s for authenticated child startup. This is
// not a lease: every use still requires the parent's CURRENT live authority.
const HANDOFF_MS=410000,SESSION_MS=120000,TRANSFER_RECOVERY_MS=30000,CHUNK_SIZE=262144;
const TERMINAL=['CLOSED','REVOKED','EXPIRED'];
const sha512=value=>crypto.createHash('sha512').update(value).digest('hex');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const plain=value=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;
const id=()=>crypto.randomBytes(12).toString('hex').toUpperCase();
const nonce=()=>crypto.randomBytes(24).toString('hex');
const now=()=>Date.now();
function Atomic(kind,actor,fn){try{return require("../storage/peace.desktop-operation-audit").Run(kind,actor,{component:'O'},fn);}catch(error){require('../security/peace.nhw-peer-context').RecordGrantRejection(error);throw error;}}
function Boot(){return require("../bootstrap/peace.desktop-bootstrap");}
function Fail(code,status=403){Boot().Fail(code,status);}
function Fields(body,names){if(!plain(body)||Object.keys(body).some(k=>!['action',...names].includes(k)))Fail('BOOTSTRAP_INPUT_INVALID',400);}
function Rows(){return store.Load().overlays||{};}
function Ticket(row){return Token('OVERLAY-HANDOFF',row.id,row.ticketNonce);}
function SessionToken(row){return Token('OVERLAY-SESSION',row.sessionId,row.sessionNonce);}
function Token(domain,key,value){if(!value)Fail('BOOTSTRAP_SESSION_CLOSED');return crypto.createHmac('sha256',Buffer.from(store.Load().secret,'hex')).update(['GAME-OVERLAY-V1',domain,key,value].join('|')).digest('base64url');}
function Canonical(row,kind){const artifact=store.Load().artifacts[row.releaseId];return ['GAME-OVERLAY-'+kind+'-V2','3',row.id,row.parentSessionId,delegation.Parent(row).deviceId,row.machineId,artifact.id,artifact.sha512,artifact.crc64,artifact.xxh3_128,artifact.blake3,artifact.codeSha512,artifact.codeCrc64,artifact.codeXxh3_128,artifact.codeBlake3,String(artifact.size),row.ticketBinding,String(row.expiresAt)].join('\n');}
function RecordFinding(row,id,invalidated=false,confirmed=false) {
 const db=store.Load(),persisted=db.overlays?.[row?.id],owner=persisted||db.flows[row?.parentFlowId];
 if(!owner)return;
 try{require('../security/peace.security-detections').RecordServer({row:owner,stage:persisted?'O':'B',id,
  source:'peace.desktop-overlay',confidence:confirmed?100:0,correlation:confirmed,invalidated});}
 catch(_){console.error('SECURITY_DETECTION_RECORD_FAILED');}
}
function License(row){const license=require("../licensing/peace.desktop-licenses").DB().licenses[row.licenseId];if(!license||!license.consumed||license.status!=='USED'||license.releasedAt||license.expiresAt&&license.expiresAt<=now()||license.deviceId!==delegation.Parent(row).deviceId||license.bootstrapSessionId!==row.parentSessionId){RecordFinding(row,'DESKTOP_ACTIVATION_INVALID');Fail('DESKTOP_ACTIVATION_INVALID');}require("../devices/peace.desktop-machine-policy").AssertAllowed(row.machineId,row.machinePolicyGeneration,row.parentSessionId);return license;}
function Transferred(row,parent){return row.transferVersion===1&&Number.isSafeInteger(row.transferredAt)&&parent?.closedByOverlay===true&&parent.overlayTransferVersion===1&&parent.transferredOverlayId===row.id&&parent.transferredAt===row.transferredAt&&parent.status==='CLOSED';}
function RequireArtifact(row){const db=store.Load(),parent=db.flows[row.parentFlowId],context=db.overlays?.[row.id]?{row,stage:'O'}:{row:parent,stage:'B'};if(!parent||parent.overlayReleaseId!==row.releaseId||(!Transferred(row,parent)&&(parent.status!=='CLAIMED'||parent.sessionExpiresAt<=now()))||parent.sessionId!==row.parentSessionId||parent.licenseId!==row.licenseId)Fail('BOOTSTRAP_FLOW_INVALID');require('../bootstrap/peace.issued-a-keyring').AssertLauncher(db.launchers[parent.launcherId],db);require("../security/peace.desktop-security-authority").RequireArtifact(db.artifacts[db.launchers[parent.launcherId]?.artifactId],context);require("../security/peace.desktop-security-authority").RequireArtifact(db.artifacts[parent.releaseId],context);require("../security/peace.desktop-security-authority").RequireArtifact(db.artifacts[row.releaseId],context);require("../security/peace.desktop-security-operations").RequireRuntimePair(db.artifacts[db.launchers[parent.launcherId]?.artifactId],db.artifacts[parent.releaseId],db.artifacts[row.releaseId]);if(!Transferred(row,parent))Boot().AssertFlowLifetime(parent);return db.artifacts[row.releaseId];}
function Expired(row){return require("../runtime/peace.desktop-deadline").persistent.expired('O.'+(row.status==='CLAIMED'?'session:':'handoff:')+row.id,row.status==='CLAIMED'?Math.max(row.claimedAt||0,row.lastVerifiedAt||0,row.transferredAt||0):row.createdAt,row.status==='CLAIMED'?row.sessionExpiresAt:row.expiresAt);}
function AssertLifetime(row){if(!row||Expired(row))Fail('BOOTSTRAP_EXPIRED');}
function Live(row){if(row){require("../recovery/peace.desktop-recovery").Assert(row,store.Load());require("../devices/peace.desktop-device-registry").AssertMachineAllowed(row.machineId,store.Load());}if(!row)Fail('BOOTSTRAP_SESSION_INVALID',401);if(TERMINAL.includes(row.status))Fail(row.status==='EXPIRED'?'BOOTSTRAP_EXPIRED':row.status==='REVOKED'?'BOOTSTRAP_REVOKED':'BOOTSTRAP_SESSION_CLOSED');AssertLifetime(row);License(row);return RequireArtifact(row);}
function Retire(row){store.AfterCommit(()=>{for(const kind of ['O.session:','O.handoff:','O.claim-recovery:','O.verify-recovery:','O.start-recovery:'])require("../runtime/peace.desktop-deadline").persistent.forget(kind+row.id);});row.retiredAt||=now();delete row.verifyReceipt;delete row.ticketNonce;delete row.sessionNonce;delete row.claimRecoveryUntil;delete row.claimFingerprint;row.chunkOffsets=[];require("../devices/peace.desktop-device-identity").RetireContext(row,'O');require("../security/peace.desktop-security-authority").RetireContext(row,'O');require("../integrity/peace.desktop-integrity-reports").RetireContext(row);}
function Prepare(parent,license,requestId,fingerprint){
 Prune();if(parent.overlayPrepareCancellation)Fail('BOOTSTRAP_SESSION_CLOSED');const db=store.Load(),artifact=db.artifacts[parent.overlayReleaseId];if(!artifact||artifact.component!=='O')Fail('BOOTSTRAP_OVERLAY_NOT_READY',409);
 if(delegation.Version(parent)!==delegation.Version(artifact))Fail('BOOTSTRAP_HANDOFF_VERSION_MISMATCH',409);
 if(parent.status!=='CLAIMED'||parent.licenseId!==license.id)Fail('BOOTSTRAP_LICENSE_MISMATCH');
 const prior=Object.values(Rows()).find(r=>r.parentFlowId===parent.id);
 if(prior){if(prior.requestId!==requestId||prior.fingerprint!==fingerprint)Fail('BOOTSTRAP_REQUEST_REUSED',409);Live(prior);if(prior.status!=='PREPARED')Fail('BOOTSTRAP_LAUNCHER_USED',409);return PrepareResult(prior);}
 // Freezing a renewable parent lease here made a slow, otherwise valid
 // download expire even after B had renewed. Keep the signed startup budget
 // fixed instead; RequireArtifact/AssertFlowLifetime gate the live parent.
 const createdAt=now();
 const row={serverEpoch:require("../recovery/peace.desktop-recovery").Epoch(db),id:id(),sessionId:id(),parentFlowId:parent.id,parentSessionId:parent.sessionId,launcherId:parent.launcherId,releaseId:artifact.id,licenseId:license.id,deviceId:parent.deviceId,publicKey:parent.publicKey,handoffVersion:delegation.Version(parent),...(delegation.Version(parent)===3?{parentDeviceId:parent.deviceId,parentPublicKey:parent.publicKey}:{}),machineId:parent.machineId,machinePolicyGeneration:parent.machinePolicyGeneration,requestId,fingerprint,status:'PREPARED',createdAt,expiresAt:Math.min(createdAt+HANDOFF_MS,license.expiresAt||Number.MAX_SAFE_INTEGER),ticketNonce:nonce(),chunkOffsets:[],lastVerifiedAt:0};
 row.ticketHash=sha(Ticket(row));row.ticketBinding=sha512(Ticket(row));AssertLifetime(row);License(row);RequireArtifact(row);Boot().ReadArtifactBytes(artifact);AssertLifetime(row);Boot().AssertFlowLifetime(parent);
 Atomic('OVERLAY_PREPARE','SERVER',next=>{next.overlays||={};if(Object.values(next.overlays).some(r=>r.parentFlowId===parent.id))Fail('BOOTSTRAP_REQUEST_REUSED',409);next.overlays[row.id]=row;});
 Audit('PREPARED',row);return PrepareResult(row);
}
function PrepareResult(row){return require('../protocol/peace.packet-schema').ValidateDocument('overlayPrepare',{overlayId:row.id,parentSessionId:row.parentSessionId,overlayTicket:Ticket(row),release:Boot().Release(store.Load().artifacts[row.releaseId]),chunkSize:CHUNK_SIZE,expiresAt:row.expiresAt,finishCanonical:Canonical(row,'FINISH'),claimCanonical:Canonical(row,'CLAIM')});}
function TicketRow(body){const row=Rows()[body.overlayId];if(!row||!Boot().EqualHash(body.overlayTicket,row.ticketHash))Fail('BOOTSTRAP_FLOW_INVALID',401);Live(row);return row;}
function Chunk(body){Fields(body,['overlayId','overlayTicket','offset']);const row=TicketRow(body);if(row.status!=='PREPARED')Fail('BOOTSTRAP_LAUNCHER_USED',409);const parent=store.Load().flows[row.parentFlowId];if(parent.status!=='CLAIMED'||parent.sessionExpiresAt<=now())Fail('BOOTSTRAP_SESSION_CLOSED');const artifact=RequireArtifact(row);
 if(!Number.isSafeInteger(body.offset)||body.offset<0||body.offset>=artifact.size||body.offset%CHUNK_SIZE)Fail('BOOTSTRAP_INPUT_INVALID',400);
 const size=Math.min(CHUNK_SIZE,artifact.size-body.offset),bytes=Buffer.alloc(size);let fd;
 try{
  try{fd=fs.openSync(store.ArtifactPath(artifact.id),fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const st=fs.fstatSync(fd);if(!st.isFile()||st.size!==artifact.size)throw Error();let at=0;while(at<size){const n=fs.readSync(fd,bytes,at,size-at,body.offset+at);if(!n)throw Error();at+=n;}}
  catch(_){Fail('BOOTSTRAP_ARTIFACT_INVALID',503);}finally{if(fd!==undefined)fs.closeSync(fd);}
  const current=TicketRow(body);if(current.status!=='PREPARED'||current.releaseId!==artifact.id)Fail('BOOTSTRAP_FLOW_INVALID');
  if(!current.chunkOffsets.includes(body.offset))Atomic('OVERLAY_CHUNK','SERVER',next=>{
   TicketRow(body);Live(next.overlays[row.id]);
   if(!next.overlays[row.id].chunkOffsets.includes(body.offset))next.overlays[row.id].chunkOffsets.push(body.offset);
  });
  const data=bytes.toString('base64');Boot().EnsureSecurityAvailable();TicketRow(body);
  return {offset:body.offset,data,size};
 }finally{bytes.fill(0);}
}
function Finish(body){Fields(body,['overlayId','overlayTicket','signature']);const row=TicketRow(body);if(!['PREPARED','READY'].includes(row.status))Fail('BOOTSTRAP_LAUNCHER_USED',409);Boot().Verify(delegation.Parent(row),Canonical(row,'FINISH'),body.signature);Live(row);const artifact=RequireArtifact(row);
 if(row.status==='PREPARED'){
  const parent=store.Load().flows[row.parentFlowId];if(parent.status!=='CLAIMED'||parent.sessionExpiresAt<=now())Fail('BOOTSTRAP_SESSION_CLOSED');
  if(row.chunkOffsets.length!==Math.ceil(artifact.size/CHUNK_SIZE))Fail('BOOTSTRAP_DOWNLOAD_INCOMPLETE',409);Boot().ReadArtifactBytes(artifact);Live(row);Boot().AssertFlowLifetime(parent);
  Atomic('OVERLAY_FINISH','SERVER',next=>{const item=next.overlays[row.id],flow=next.flows[row.parentFlowId];if(item.status!=='PREPARED'||flow.status!=='CLAIMED')Fail('BOOTSTRAP_SESSION_CLOSED');AssertLifetime(item);Boot().AssertFlowLifetime(flow);item.status='READY';item.readyAt=now();require('../security/peace.nhw-peer-context').MakeGrant(next,item,'O');});
  Audit('READY',row);
 }
 return {overlayId:row.id,overlayTicket:body.overlayTicket,claimCanonical:Canonical(row,'CLAIM'),expiresAt:row.expiresAt};
}
function Claim(body){Fields(body,['overlayId','overlayTicket','signature','binarySha512','crc64','oCodeSha512','oCodeCrc64','productScopeVersion',...delegation.FIELDS]);if(Object.hasOwn(body,'productScopeVersion')&&body.productScopeVersion!==1)Fail('BOOTSTRAP_INPUT_INVALID',400);const row=TicketRow(body),child=delegation.Check(row,body,'O',Canonical(row,'CLAIM')),delegatedFingerprint=child?delegation.Fingerprint(body):'',fingerprint=sha(JSON.stringify([body.overlayId,body.overlayTicket,body.signature,body.binarySha512,body.crc64,body.oCodeSha512,body.oCodeCrc64,...(body.productScopeVersion===1?[1]:[])]));Live(row);if(row.status==='CLAIMED'){if(require("../runtime/peace.desktop-deadline").persistent.expired('O.claim-recovery:'+row.id,row.claimedAt,row.claimRecoveryUntil)||!row.claimRecoveryUntil||row.claimFingerprint!==fingerprint||child&&row.delegatedClaimFingerprint!==delegatedFingerprint)Fail('BOOTSTRAP_LAUNCHER_USED',409);return ClaimResult(row,body.productScopeVersion);}if(row.status!=='READY')Fail('BOOTSTRAP_LAUNCHER_USED',409);const artifact=RequireArtifact(row),parent=store.Load().flows[row.parentFlowId];if(parent.status!=='CLAIMED'||parent.sessionExpiresAt<=now())Fail('BOOTSTRAP_FLOW_INVALID');CheckMeasurement(row,artifact,{binarySha512:body.binarySha512,binaryCrc64:body.crc64,codeSha512:body.oCodeSha512,codeCrc64:body.oCodeCrc64});Boot().ReadArtifactBytes(artifact);Live(row);const license=License(row);Boot().AssertFlowLifetime(parent);
 Atomic('OVERLAY_CLAIM','SERVER',next=>{const item=next.overlays[row.id];if(item.status!=='READY')Fail('BOOTSTRAP_LAUNCHER_USED',409);AssertLifetime(item);Boot().AssertFlowLifetime(next.flows[item.parentFlowId]);item.status='CLAIMED';item.claimedAt=now();require('../security/peace.nhw-peer-context').ConsumeGrant(next,item,'O',child,delegatedFingerprint);if(body.productScopeVersion===1)item.productScopeVersion=1;if(child){item.publicKey=child.publicKey;item.deviceId=child.deviceId;item.childNonce=child.nonce;item.delegatedClaimFingerprint=delegatedFingerprint;item.delegatedClaimRecoveryUntil=Math.min(item.expiresAt,item.claimedAt+30000);}item.claimRecoveryUntil=Math.min(row.expiresAt,item.claimedAt+30000);item.claimFingerprint=fingerprint;item.lastVerifiedAt=now();item.sessionExpiresAt=Math.min(now()+SESSION_MS,store.Load().flows[row.parentFlowId].sessionExpiresAt,license.expiresAt||Number.MAX_SAFE_INTEGER);item.sessionNonce=nonce();item.sessionHash=sha(SessionToken(item));delete item.ticketNonce;item.chunkOffsets=[];require("../devices/peace.desktop-device-registry").ObserveVerified(next,item,'O');});
 const claimed=Rows()[row.id];AssertLifetime(claimed);Audit('CLAIMED',claimed);return ClaimResult(claimed,body.productScopeVersion);
}
function ClaimResult(row,productScopeVersion){return {sessionId:row.sessionId,sessionToken:SessionToken(row),expiresAt:row.sessionExpiresAt,release:Boot().Release(RequireArtifact(row)),...(productScopeVersion===1?{productScopeVersion:1,productId:products.Id(License(row))}:{})};}
function Session(id,token){const row=Object.values(Rows()).find(r=>r.sessionId===id);if(!row||!row.sessionHash||!Boot().EqualHash(token,row.sessionHash))Fail('BOOTSTRAP_SESSION_INVALID',401);return row;}
function CheckMeasurement(row,artifact,body){if(!/^[a-f0-9]{128}$/.test(body.binarySha512||'')||!/^[A-F0-9]{16}$/.test(body.binaryCrc64||'')||!/^[a-f0-9]{128}$/.test(body.codeSha512||'')||!/^[A-F0-9]{16}$/.test(body.codeCrc64||''))Fail('BOOTSTRAP_INPUT_INVALID',400);Boot().CheckFile(artifact,body.binarySha512,body.binaryCrc64,{stage:'O',row});if(artifact.codeSha512!==body.codeSha512||artifact.codeCrc64!==body.codeCrc64){Revoke(row.sessionId,{reason:'CODE_DIGEST_MISMATCH'},'INTEGRITY_REPORT');RecordFinding(row,'CODE_DIGEST_MISMATCH',true,true);Fail('BOOTSTRAP_CODE_MISMATCH');}}
function AuthenticateIntegrityReceipt(body){
 const row=Session(body.sessionId,body.sessionToken);if(body.stage!=='O'||body.machineId!==undefined&&body.machineId!==row.machineId)Fail('BOOTSTRAP_SESSION_INVALID');
 return {...row,stage:'O',reportContextId:row.sessionId};
}
function AuthenticateIntegrityReport(body){const row=Session(body.sessionId,body.sessionToken),artifact=Live(row);if(row.status!=='CLAIMED'||body.machineId!==undefined&&body.machineId!==row.machineId)Fail('BOOTSTRAP_SESSION_INVALID');return {...row,stage:'O',reportContextId:row.sessionId,integrityArtifact:{id:artifact.id,component:artifact.component,pointerGraphSlots:artifact.ownMeasurementVersion>=2?require('../security/peace.desktop-security-operations').PointerGraphSlots(artifact):0,measurementPlanVersion:artifact.measurementPlanVersion||0,ownMeasurementVersion:artifact.ownMeasurementVersion||0,hashVersion:3,crcLayers:artifact.crcLayers,sha512:artifact.sha512,crc64:artifact.crc64,fileXxh3_128:artifact.xxh3_128,fileBlake3:artifact.blake3,codeSha512:artifact.codeSha512,codeCrc64:artifact.codeCrc64,codeXxh3_128:artifact.codeXxh3_128,codeBlake3:artifact.codeBlake3}};}
function Progress(body){
 const tracker=require('./peace.desktop-overlay-startup');tracker.Parse(body);
 const row=Session(body.sessionId,body.sessionToken);Live(row);
 if(row.status!=='CLAIMED')Fail('BOOTSTRAP_SESSION_CLOSED');
 Boot().Verify(row,tracker.Canonical(body),body.signature);
 return tracker.Record(row,body);
}
function ParseStart(body){
 Fields(body,['sessionId','sessionToken','productId','requestId','sequence','signature']);
 if(!products.Find(body.productId)||typeof body.requestId!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId)||!Number.isSafeInteger(body.sequence)||body.sequence<1||body.sequence>2147483647)Fail('BOOTSTRAP_INPUT_INVALID',400);
}
function StartCanonical(body){return ['COZY-OVERLAY-START-V1',body.sessionId,body.productId,body.requestId,String(body.sequence)].join('\n');}
function StartResult(row,value){return {version:1,sessionId:row.sessionId,productId:value.productId,requestId:value.requestId,sequence:value.sequence,status:'AUTHORIZED',durationMs:5000,serverTime:value.at,expiresAt:value.until};}
function StartAuthority(row,productId){
 const artifact=Live(row),parent=store.Load().flows[row.parentFlowId],license=License(row);
 if(row.status!=='CLAIMED'||!Transferred(row,parent))Fail('BOOTSTRAP_OVERLAY_NOT_READY',409);
 if(row.productScopeVersion!==1)Fail('DESKTOP_PRODUCT_UNASSIGNED');
 const assigned=products.Id(license);if(!assigned)Fail('DESKTOP_PRODUCT_UNASSIGNED');
 if(assigned!==productId)Fail('DESKTOP_PRODUCT_NOT_LICENSED');
 require('../devices/peace.desktop-device-identity').AssertSession(row,'O');
 const authority=require('../security/peace.desktop-security-authority');
 const observation=authority.RenewalIdentity(row,'O','verify',authority.Binding(row.sessionId,artifact.sha512));
 const snapshot=require('../integrity/peace.desktop-integrity-reports').RequireSnapshot(row,'O');
 return Math.min(row.sessionExpiresAt,observation.expiresAt,snapshot?.expiresAt??Number.MAX_SAFE_INTEGER,license.expiresAt||Number.MAX_SAFE_INTEGER);
}
// One signed presentation request for the exact licensed product. This is not
// a game/driver operation and never extends the execution or observation lease.
// A monotonic sequence and one durable receipt prevent older-request replay
// without an unbounded list; duplicate responses retain their original deadline.
function Start(body){
 ParseStart(body);const row=Session(body.sessionId,body.sessionToken);
 Live(row);Boot().Verify(row,StartCanonical(body),body.signature);
 const authorityUntil=StartAuthority(row,body.productId),prior=row.startReceipt;
 const fingerprint=require('../protocol/peace.desktop-request-protocol').Fingerprint('overlay.start',body);
 if(prior&&body.sequence<=prior.sequence){
  if(body.sequence!==prior.sequence||prior.fingerprint!==fingerprint)Fail('BOOTSTRAP_REQUEST_REUSED',409);
  if(require('../runtime/peace.desktop-deadline').persistent.expired('O.start-recovery:'+row.id,prior.at,prior.until)||authorityUntil<prior.until)Fail('BOOTSTRAP_EXPIRED');
  return StartResult(row,prior);
 }
 const at=now(),until=Math.min(at+TRANSFER_RECOVERY_MS,authorityUntil);
 if(until<at+5000)Fail('SECURITY_FRESH_OBSERVATION_REQUIRED');
 const receipt={requestId:body.requestId,sequence:body.sequence,productId:body.productId,fingerprint,at,until};
 Atomic('OVERLAY_PRODUCT_START','SERVER',next=>{
  Boot().AssertSecurityAvailable();const item=next.overlays[row.id];
  if(StartAuthority(item,body.productId)<until)Fail('SECURITY_FRESH_OBSERVATION_REQUIRED');
  if(item.startReceipt&&body.sequence<=item.startReceipt.sequence)Fail('BOOTSTRAP_REQUEST_REUSED',409);
  item.startReceipt=receipt;
 });
 try{require('../../storage/audit/peace.audit.js').LogEvent('DESKTOP_OVERLAY_PRODUCT_STARTED',JSON.stringify({sessionId:row.sessionId,licenseId:row.licenseId,productId:body.productId,sequence:body.sequence}));}catch(_){console.error('OVERLAY_START_AUDIT_FAILED');}
 return StartResult(Rows()[row.id],receipt);
}
function ValidateStartReceipt(row){
 const value=row.startReceipt;if(value===undefined)return;
 if(!plain(value)||Object.keys(value).sort().join(',')!=='at,fingerprint,productId,requestId,sequence,until'||!products.Find(value.productId)||typeof value.requestId!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(value.requestId)||!Number.isSafeInteger(value.sequence)||value.sequence<1||value.sequence>2147483647||!/^[a-f0-9]{128}$/.test(value.fingerprint)||!Number.isSafeInteger(value.at)||value.at<row.claimedAt||!Number.isSafeInteger(value.until)||value.until<value.at+5000||value.until>value.at+TRANSFER_RECOVERY_MS||row.transferVersion!==1||row.productScopeVersion!==1)throw Error('OVERLAY_STORE_INVALID');
}
function Verify(body){
 Fields(body,['sessionId','sessionToken','machineId','binarySha512','binaryCrc64','codeSha512','codeCrc64','capturePrivacyVersion','renewalBudgetVersion','productScopeVersion']);
 if(Object.hasOwn(body,'capturePrivacyVersion')&&body.capturePrivacyVersion!==1)Fail('BOOTSTRAP_INPUT_INVALID',400);
 if(Object.hasOwn(body,'renewalBudgetVersion')&&body.renewalBudgetVersion!==1)Fail('BOOTSTRAP_INPUT_INVALID',400);
 if(Object.hasOwn(body,'productScopeVersion')&&body.productScopeVersion!==1)Fail('BOOTSTRAP_INPUT_INVALID',400);
 const row=Session(body.sessionId,body.sessionToken),artifact=Live(row);
 if(body.productScopeVersion!==row.productScopeVersion)Fail('BOOTSTRAP_INPUT_INVALID',400);
 if(row.status!=='CLAIMED'||body.machineId!==row.machineId)Fail('BOOTSTRAP_SESSION_INVALID');
 require("../devices/peace.desktop-device-identity").AssertSession(row,'O');CheckMeasurement(row,artifact,body);const snapshot=require("../integrity/peace.desktop-integrity-reports").RequireSnapshot(row,'O');
 const authority=require("../security/peace.desktop-security-authority"),observation=authority.RenewalIdentity(row,'O','verify',authority.Binding(row.sessionId,artifact.sha512));
 const fingerprint=require("../protocol/peace.desktop-request-protocol").Fingerprint('overlay.verify',body),prior=row.verifyReceipt;
 Live(row);
 if(prior&&prior.observation===observation.id){
  if(prior.fingerprint!==fingerprint)Fail('BOOTSTRAP_REQUEST_REUSED',409);
  if(require("../runtime/peace.desktop-deadline").persistent.expired('O.verify-recovery:'+row.id,prior.at,prior.until))Fail('BOOTSTRAP_EXPIRED');
  return structuredClone(prior.response);
 }
 const license=License(row),parent=store.Load().flows[row.parentFlowId],transferConfirmed=Transferred(row,parent),at=now(),expiresAt=Math.min(at+SESSION_MS,observation.expiresAt,snapshot?.expiresAt??Number.MAX_SAFE_INTEGER,transferConfirmed?Number.MAX_SAFE_INTEGER:parent.sessionExpiresAt,license.expiresAt||Number.MAX_SAFE_INTEGER);
 const response={status:'ACTIVE',leaseExpiresAt:expiresAt,serverTime:at,expiresAt,handoffVersion:1,transferConfirmed,parentSessionId:row.parentSessionId};
 if(body.productScopeVersion===1){response.productScopeVersion=1;response.productId=products.Id(license);}
 // Negotiate the optional field; older O binaries require exactly seven fields.
 if(body.capturePrivacyVersion===1)response.capturePrivacy=config.OVERLAY_CAPTURE_PRIVACY===true;
 // Scheduling information, never a separate capability or an expiry extension.
 if(body.renewalBudgetVersion===1)response.renewalBudget={version:1,snapshotExpiresAt:snapshot?.expiresAt??0,observationExpiresAt:observation.expiresAt};
 const receipt={observation:observation.id,fingerprint,at,until:Math.min(at+TRANSFER_RECOVERY_MS,observation.expiresAt,expiresAt),response};
 if(receipt.until<=at)Fail('SECURITY_FRESH_OBSERVATION_REQUIRED');
 Atomic('OVERLAY_VERIFY','SERVER',next=>{Boot().AssertSecurityAvailable();const item=next.overlays[row.id];Live(item);if(item.status!=='CLAIMED')Fail('BOOTSTRAP_SESSION_CLOSED');const committedObservation=authority.RenewalIdentity(item,'O','verify',authority.Binding(item.sessionId,artifact.sha512)),committedSnapshot=require("../integrity/peace.desktop-integrity-reports").RequireSnapshot(item,'O');if(committedObservation.id!==observation.id||expiresAt>committedObservation.expiresAt||committedSnapshot&&expiresAt>committedSnapshot.expiresAt)Fail('SECURITY_FRESH_OBSERVATION_REQUIRED');item.sessionExpiresAt=expiresAt;item.lastVerifiedAt=at;item.authorizedAt=at;item.verifyReceipt=receipt;delete item.claimRecoveryUntil;delete item.claimFingerprint;});
 Live(Rows()[row.id]);
 // Record the actual bound, so repeated successful own-image checks cannot be
 // mistaken for a newly completed module snapshot. No tokens/keys/file paths.
 try{require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_OVERLAY_LEASE_BOUND',JSON.stringify({sessionId:row.sessionId,overlayId:row.id,serverTime:at,expiresAt,snapshotExpiresAt:snapshot?.expiresAt??0,observationExpiresAt:observation.expiresAt,transferConfirmed,bound:snapshot&&expiresAt===snapshot.expiresAt?'MODULE_SNAPSHOT':expiresAt===observation.expiresAt?'OWN_OBSERVATION':license.expiresAt&&expiresAt===license.expiresAt?'LICENSE':!transferConfirmed&&expiresAt===parent.sessionExpiresAt?'PARENT':'SESSION_CAP'}));}catch(_){console.error('OVERLAY_LEASE_AUDIT_FAILED');}
 return response;
}
function TransferCanonical(parentId,overlayId){return ['GAME-OVERLAY-TRANSFER-V1',parentId,overlayId].join('\n');}
function EqualStrong(value,expected){return typeof value==='string'&&typeof expected==='string'&&/^[a-f0-9]{128}$/.test(expected)&&crypto.timingSafeEqual(Buffer.from(sha512(value),'hex'),Buffer.from(expected,'hex'));}
// A receipt verifier is never a bootstrap session credential. B's ordinary
// session hash/nonces are retired atomically, and only exact commit recovery or
// best-effort close can use this short-lived, non-reconstructible digest.
function AuthenticateRetiredParent(parent,token){if(!parent?.closedByOverlay||parent.status!=='CLOSED'||!Number.isSafeInteger(parent.transferRecoveryUntil)||parent.transferRecoveryUntil<=now()||require("../runtime/peace.desktop-deadline").persistent.expired('O.transfer-recovery:'+parent.id,parent.transferredAt,parent.transferRecoveryUntil)||!EqualStrong(token,parent.transferReceiptHash))Fail('BOOTSTRAP_SESSION_INVALID',401);return parent;}
function CommitResult(row){return {handoffVersion:1,status:'TRANSFERRED',parentSessionId:row.parentSessionId,overlayId:row.id,overlaySessionId:row.sessionId};}
function Commit(body){
 Fields(body,['handoffVersion','sessionId','sessionToken','overlayId','signature']);if(body.handoffVersion!==1||!/^[A-F0-9]{24}$/.test(body.overlayId||'')||!/^[A-F0-9]{24}$/.test(body.sessionId||'')||typeof body.sessionToken!=='string'||body.sessionToken.length>200||typeof body.signature!=='string'||body.signature.length>1000)Fail('BOOTSTRAP_INPUT_INVALID',400);
 const row=Rows()[body.overlayId],parent=row&&store.Load().flows[row.parentFlowId];if(!row||!parent||body.sessionId!==row.parentSessionId)Fail('BOOTSTRAP_SESSION_INVALID',401);
 const fingerprint=sha512(JSON.stringify([1,body.sessionId,body.sessionToken,body.overlayId,body.signature]));
 if(Transferred(row,parent)){AuthenticateRetiredParent(parent,body.sessionToken);if(parent.transferFingerprint!==fingerprint)Fail('BOOTSTRAP_REQUEST_REUSED',409);Boot().Verify(parent,TransferCanonical(parent.sessionId,row.id),body.signature);Live(row);return CommitResult(row);}
 const authenticated=Boot().SessionAuthenticated(body.sessionId,body.sessionToken);if(authenticated.id!==parent.id||parent.status!=='CLAIMED'||parent.sessionExpiresAt<=now())Fail('BOOTSTRAP_SESSION_CLOSED');
 Live(row);if(row.status!=='CLAIMED'||!Number.isSafeInteger(row.authorizedAt)||row.authorizedAt<row.claimedAt||row.authorizedAt+TRANSFER_RECOVERY_MS<=now())Fail('BOOTSTRAP_OVERLAY_NOT_READY',409);
 Boot().Verify(parent,TransferCanonical(parent.sessionId,row.id),body.signature);require("../devices/peace.desktop-device-identity").AssertSession(parent,'B');require("../devices/peace.desktop-device-identity").AssertSession(row,'O');require("../integrity/peace.desktop-integrity-reports").RequireSnapshot(row,'O');
 const authority=require("../security/peace.desktop-security-authority"),binding=authority.Binding(row.sessionId,store.Load().artifacts[row.releaseId].sha512);
 authority.RequireFresh(row,'O','verify',binding);
 Live(row);Boot().AssertFlowLifetime(parent);const license=License(row),at=now();
 Atomic('OVERLAY_COMMIT','SERVER',next=>{const item=next.overlays[row.id],flow=next.flows[parent.id];if(item.status!=='CLAIMED'||flow.status!=='CLAIMED'||item.transferVersion!==undefined)Fail('BOOTSTRAP_SESSION_CLOSED');AssertLifetime(item);Boot().AssertFlowLifetime(flow);authority.RequireFresh(item,'O','verify',binding);if(now()<item.authorizedAt||now()>=item.authorizedAt+TRANSFER_RECOVERY_MS)Fail('BOOTSTRAP_OVERLAY_NOT_READY',409);item.transferVersion=1;item.transferredAt=at;item.sessionExpiresAt=Math.min(item.sessionExpiresAt,authority.RenewalIdentity(item,'O','verify',binding).expiresAt,require("../integrity/peace.desktop-integrity-reports").RequireSnapshot(item,'O')?.expiresAt??Number.MAX_SAFE_INTEGER,at+SESSION_MS,license.expiresAt||Number.MAX_SAFE_INTEGER);flow.status='CLOSED';flow.closedAt=at;flow.closedByOverlay=true;flow.overlayTransferVersion=1;flow.transferredOverlayId=item.id;flow.transferredAt=at;flow.transferRecoveryUntil=at+TRANSFER_RECOVERY_MS;flow.transferReceiptHash=sha512(body.sessionToken);flow.transferFingerprint=fingerprint;flow.licenseLeaseExpiresAt=0;Boot().RetireFlow(flow,next);delete flow.sessionHash;});
 const committed=Rows()[row.id];Audit('TRANSFERRED',committed);try{require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_BOOTSTRAP_CLOSED',JSON.stringify({sessionId:parent.sessionId,licenseId:parent.licenseId,reason:'OVERLAY_TRANSFERRED',overlayId:row.id}));}catch(_){console.error('OVERLAY_AUDIT_FAILED');}return CommitResult(committed);
}
function Close(body){Fields(body,['sessionId','sessionToken','shutdown']);if(body.shutdown!==undefined){try{require("../runtime/peace.desktop-work-queue").ValidateShutdown(body.shutdown);}catch(_){Fail('BOOTSTRAP_INPUT_INVALID',400);}}const row=Session(body.sessionId,body.sessionToken);Boot().RequireCleanupReceipt(row);if(!TERMINAL.includes(row.status)){Atomic('OVERLAY_CLOSE','SERVER',next=>{require("../observability/peace.desktop-lifecycle-trace").ServerEvent(next,row.parentFlowId,'O','CLOSE_REQUEST_ACCEPTED','CLOSED',row.sessionId);require("../observability/peace.desktop-lifecycle-trace").ServerEvent(next,row.parentFlowId,'O','CLOSE_RESPONSE_PREPARED','CLOSED',row.sessionId);const item=next.overlays[row.id];item.status='CLOSED';item.closedAt=now();Retire(item);});Audit('CLOSED',row);if(body.shutdown!==undefined)require("../runtime/peace.desktop-work-queue").RecordShutdown(body.shutdown,'O');}else if(row.shutdownIntent&&body.shutdown!==undefined){
 // A prior shutdown intent ends authority before the client's final cleanup.
 // Preserve the existing final shutdown diagnostics once, without converting
 // an authenticated client report into server-observed OS cleanup evidence.
 if(require('../runtime/peace.desktop-deadline').persistent.expired('O.shutdown-recovery:'+row.id,row.shutdownIntent.at,row.shutdownIntent.until))Fail('BOOTSTRAP_SESSION_CLOSED');
 const fingerprint=sha512(require('../protocol/peace.desktop-request-protocol').Stable(body.shutdown)),prior=row.shutdownIntent.cleanupReceipt;
 if(prior){if(prior.fingerprint!==fingerprint)Fail('BOOTSTRAP_REQUEST_REUSED',409);}
 else Atomic('OVERLAY_SHUTDOWN_CLEANUP_RECEIPT','SERVER',next=>{const item=next.overlays[row.id];Boot().RequireCleanupReceipt(item);if(!item.shutdownIntent||item.shutdownIntent.cleanupReceipt)Fail('BOOTSTRAP_REQUEST_REUSED',409);const at=now();if(at<item.shutdownIntent.at||at>=item.shutdownIntent.until)Fail('BOOTSTRAP_SESSION_CLOSED');item.shutdownIntent.cleanupReceipt={fingerprint,at};store.AfterCommit(()=>require('../runtime/peace.desktop-work-queue').RecordShutdown(body.shutdown,'O'));});
 }return {sessionId:row.sessionId,status:Rows()[row.id].status};}
function ShutdownResult(row){return {version:1,sessionId:row.sessionId,parentSessionId:row.parentSessionId,status:'CLOSED',scope:'OWNED_A_B_O',cleanup:'PENDING'};}
// End the already transferred, exact caller-owned cohort before local teardown.
// This acknowledgement never claims that any client process/file was removed.
// Existing one-use lifecycle permits remain independent cleanup-only authority.
function Shutdown(body){
 Fields(body,['sessionId','sessionToken','requestId']);
 if(typeof body.requestId!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId))Fail('BOOTSTRAP_INPUT_INVALID',400);
 const row=Session(body.sessionId,body.sessionToken),protocol=require('../protocol/peace.desktop-request-protocol');
 const fingerprint=protocol.Fingerprint('overlay.shutdown',body),prior=row.shutdownIntent;
 if(prior){
  if(prior.requestId!==body.requestId||prior.fingerprint!==fingerprint)Fail('BOOTSTRAP_REQUEST_REUSED',409);
  if(require('../runtime/peace.desktop-deadline').persistent.expired('O.shutdown-recovery:'+row.id,prior.at,prior.until))Fail('BOOTSTRAP_SESSION_CLOSED');
  return ShutdownResult(row);
 }
 Boot().EnsureSecurityAvailable();Live(row);
 const parent=store.Load().flows[row.parentFlowId],launcher=parent&&store.Load().launchers[parent.launcherId];
 if(row.status!=='CLAIMED'||!Transferred(row,parent)||!launcher||launcher.flowId!==parent.id||launcher.status!=='CONSUMED')Fail('BOOTSTRAP_OVERLAY_NOT_READY',409);
 require('../devices/peace.desktop-device-identity').AssertSession(row,'O');
 const at=now();
 Atomic('OVERLAY_OWNED_COHORT_SHUTDOWN','SERVER',next=>{
  Boot().AssertSecurityAvailable();const item=next.overlays[row.id],flow=next.flows[row.parentFlowId];
  Live(item);if(item.status!=='CLAIMED'||item.shutdownIntent||!Transferred(item,flow))Fail('BOOTSTRAP_SESSION_CLOSED');
  require('../devices/peace.desktop-device-identity').AssertSession(item,'O');
  // B and A already ended their authority during the one-way transfer. Clear
  // any volatile lease caches again; no other flow, license or machine is used.
  Boot().RetireFlow(flow,next);Boot().RetireLauncher(next.launchers[flow.launcherId]);
  item.status='CLOSED';item.closedAt=at;item.reason='OWNED_COHORT_SHUTDOWN';Retire(item);
  item.shutdownIntent={requestId:body.requestId,fingerprint,at:item.retiredAt,until:item.retiredAt+TRANSFER_RECOVERY_MS};
  require('../observability/peace.desktop-lifecycle-trace').ServerEvent(next,flow.id,'O','CLOSE_REQUEST_ACCEPTED','CLOSED',item.sessionId);
  require('../observability/peace.desktop-lifecycle-trace').ServerEvent(next,flow.id,'O','CLOSE_RESPONSE_PREPARED','CLOSED',item.sessionId);
 });
 const committed=Rows()[row.id];Audit('OWNED_COHORT_SHUTDOWN',committed);return ShutdownResult(committed);
}
function ValidateShutdownIntent(row){
 const value=row.shutdownIntent;if(value===undefined)return;
 if(!plain(value)||!['at,fingerprint,requestId,until','at,cleanupReceipt,fingerprint,requestId,until'].includes(Object.keys(value).sort().join(','))||typeof value.requestId!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(value.requestId)||!/^[a-f0-9]{128}$/.test(value.fingerprint)||!Number.isSafeInteger(value.at)||value.at<row.claimedAt||value.until!==value.at+TRANSFER_RECOVERY_MS||!TERMINAL.includes(row.status)||row.transferVersion!==1||!Number.isSafeInteger(row.retiredAt)||row.retiredAt>value.at)throw Error('OVERLAY_STORE_INVALID');
 if(value.cleanupReceipt!==undefined&&(!plain(value.cleanupReceipt)||Object.keys(value.cleanupReceipt).sort().join(',')!=='at,fingerprint'||!Number.isSafeInteger(value.cleanupReceipt.at)||value.cleanupReceipt.at<value.at||value.cleanupReceipt.at>=value.until||!/^[a-f0-9]{128}$/.test(value.cleanupReceipt.fingerprint)))throw Error('OVERLAY_STORE_INVALID');
}
function RetireForParent(db,parent){
 for(const item of Object.values(db.overlays||{})){
  if(item.parentFlowId!==parent.id||TERMINAL.includes(item.status))continue;
  if(Transferred(item,parent))continue; // normal completed B->O transfer survives
  item.status=parent.status==='REVOKED'?'REVOKED':parent.status==='EXPIRED'?'EXPIRED':'CLOSED';
  if(item.status==='REVOKED')item.revokedAt=now();else item.closedAt=now();
  item.reason='PARENT_'+item.status;Retire(item);
 }
}
// A failed child lease/revocation invalidates the still-running parent in the
// same durable transaction. Normal optional-overlay close/abort does not. A
// completed B->O transfer already retired B and remains a one-way transition.
// This is server lease retirement, not client suspension/debugger detection.
function RetireParentForFailure(db,row,status){
 const parent=db.flows[row.parentFlowId];
 if(!parent||parent.sessionId!==row.parentSessionId||parent.status!=='CLAIMED')return;
 parent.status=status;parent.reason='OVERLAY_'+status;
 if(status==='REVOKED')parent.revokedAt=now();else parent.closedAt=now();
 Boot().RetireFlow(parent,db);
}
function AbortCanonical(parentId,scope,identifier){return ['GAME-OVERLAY-ABORT-V3',parentId,scope,identifier].join('\n');}
function AbortResult(parent,row){return {handoffVersion:3,parentSessionId:parent.sessionId,overlayId:row?.id||'',status:row?.status||'NOT_PREPARED'};}
function Abort(body){
 Fields(body,['handoffVersion','parentSessionId','parentSessionToken','overlayId','prepareRequestId','signature','securityStop']);
 const byOverlay=Object.hasOwn(body,'overlayId'),byRequest=Object.hasOwn(body,'prepareRequestId'),securityStop=body.securityStop===true;
 if(body.handoffVersion!==3||byOverlay===byRequest||!/^[A-F0-9]{24}$/.test(body.parentSessionId||'')||byOverlay&&!/^[A-F0-9]{24}$/.test(body.overlayId||'')||byRequest&&!/^[-A-Za-z0-9_]{8,80}$/.test(body.prepareRequestId||''))Fail('BOOTSTRAP_INPUT_INVALID',400);
 if(Object.hasOwn(body,'securityStop')&&(!securityStop||!byOverlay))Fail('BOOTSTRAP_INPUT_INVALID',400);
 const parent=Object.values(store.Load().flows).find(r=>r.sessionId===body.parentSessionId);
 if(!parent||delegation.Version(parent)!==3)Fail('BOOTSTRAP_SESSION_INVALID',401);
 const row=byOverlay?Rows()[body.overlayId]:Object.values(Rows()).find(r=>r.parentFlowId===parent.id),scope=securityStop?'COHORT':byOverlay?'OVERLAY':'PREPARE',identifier=byOverlay?body.overlayId:body.prepareRequestId;
 if(byOverlay&&!row||row&&(row.parentFlowId!==parent.id||byRequest&&row.requestId!==body.prepareRequestId||delegation.Version(row)!==3))Fail('BOOTSTRAP_FLOW_INVALID',401);
 if(parent.closedByOverlay)AuthenticateRetiredParent(parent,body.parentSessionToken);else Boot().SessionAuthenticated(body.parentSessionId,body.parentSessionToken);
 Boot().Verify(parent,AbortCanonical(parent.sessionId,scope,identifier),body.signature);
 if(securityStop){
  // Exact signed termination can race a durable transfer. The retired B
  // receipt authorizes only this original cohort and expires after 30s.
  Boot().RequireCleanupReceipt(parent);
  if(parent.status==='CLAIMED')Boot().Revoke(parent.sessionId,{reason:'SECURITY_SESSION_STOP'},'SECURITY_AUTHORITY');
  else if(!TERMINAL.includes(row.status))Revoke(row.sessionId,{reason:'SECURITY_SESSION_STOP'},'SECURITY_AUTHORITY');
  return AbortResult(parent,Rows()[row.id]);
 }
 if(row&&Transferred(row,parent)){Live(row);return {...AbortResult(parent,row),status:'TRANSFERRED'};}
 Boot().RequireCleanupReceipt(parent);
 const fingerprint=require("../protocol/peace.desktop-request-protocol").Fingerprint('overlay.abort',{version:3,parentSessionId:parent.sessionId,scope,identifier,signature:body.signature}),prior=parent.overlayPrepareCancellation;
 if(prior){if(prior.fingerprint!==fingerprint)Fail('BOOTSTRAP_REQUEST_REUSED',409);if(now()<prior.at||prior.until<=now())Fail('BOOTSTRAP_EXPIRED');return AbortResult(parent,row);}
 const at=now();Atomic('OVERLAY_ABORT','SERVER',next=>{const flow=next.flows[parent.id];flow.overlayPrepareCancellation={requestId:row?.requestId||body.prepareRequestId,overlayId:row?.id||'',fingerprint,at,until:at+TRANSFER_RECOVERY_MS};
  if(row){const item=next.overlays[row.id];if(!TERMINAL.includes(item.status)){item.status='CLOSED';item.closedAt=at;item.reason='PARENT_ABORT';Retire(item);}}
 });
 const current=store.Load().flows[parent.id],child=row&&Rows()[row.id];
 if(child)Audit('ABORTED_BY_PARENT',child);else try{require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_OVERLAY_PREPARATION_CANCELLED',JSON.stringify({parentSessionId:parent.sessionId,requestId:body.prepareRequestId}));}catch(_){console.error('OVERLAY_AUDIT_FAILED');}
 return AbortResult(current,child);
}
function ValidateParentCancellation(db,parent){
 const value=parent.overlayPrepareCancellation;if(value===undefined)return;
 if(delegation.Version(parent)!==3||!plain(value)||Object.keys(value).length!==5||!/^[-A-Za-z0-9_]{8,80}$/.test(value.requestId||'')||typeof value.overlayId!=='string'||value.overlayId&&!/^[A-F0-9]{24}$/.test(value.overlayId)||!/^[a-f0-9]{128}$/.test(value.fingerprint||'')||!Number.isSafeInteger(value.at)||value.at<parent.createdAt||value.until!==value.at+TRANSFER_RECOVERY_MS)throw Error('OVERLAY_STORE_INVALID');
 if(value.overlayId){const row=db.overlays?.[value.overlayId];if(!row||row.parentFlowId!==parent.id||row.requestId!==value.requestId||!TERMINAL.includes(row.status)||row.transferVersion!==undefined)throw Error('OVERLAY_STORE_INVALID');}
 else if(Object.values(db.overlays||{}).some(row=>row.parentFlowId===parent.id))throw Error('OVERLAY_STORE_INVALID');
}
function Revoke(sessionId,body,actor,signedStop){const row=Object.values(Rows()).find(r=>r.sessionId===sessionId);if(!row)Fail('BOOTSTRAP_SESSION_INVALID',404);Atomic('OVERLAY_REVOKE',actor,next=>{const item=next.overlays[row.id];item.status='REVOKED';item.revokedAt=now();item.reason=String(body.reason||'REVOKED').slice(0,300);Retire(item);RetireParentForFailure(next,item,'REVOKED');
 if(signedStop)require('../security/peace.security-detections').RecordSignedStop(next,item,signedStop,item.reason);
 });Audit('REVOKED',row);return View(Rows()[row.id]);}
function Prune(){const expired=Object.values(Rows()).filter(r=>!TERMINAL.includes(r.status)&&Expired(r)),receipts=Object.values(store.Load().flows).filter(r=>r.transferRecoveryUntil!==undefined&&require("../runtime/peace.desktop-deadline").persistent.expired('O.transfer-recovery:'+r.id,r.transferredAt,r.transferRecoveryUntil));if(expired.length||receipts.length)Atomic('OVERLAY_PRUNE','SERVER',next=>{for(const row of expired){const item=next.overlays[row.id];item.status='EXPIRED';item.reason='LEASE_EXPIRED';Retire(item);RetireParentForFailure(next,item,'EXPIRED');}for(const row of receipts){const item=next.flows[row.id];delete item.transferReceiptHash;delete item.transferFingerprint;delete item.transferRecoveryUntil;store.AfterCommit(()=>require("../runtime/peace.desktop-deadline").persistent.forget('O.transfer-recovery:'+row.id));}});}
function View(row){return {id:row.sessionId,flowId:row.id,parentSessionId:row.parentSessionId,component:'O',status:row.status,online:row.status==='CLAIMED'&&row.sessionExpiresAt>now(),deviceId:row.deviceId,machineId:row.machineId,releaseId:row.releaseId,licenseId:row.licenseId,createdAt:row.createdAt,claimedAt:row.claimedAt||0,expiresAt:row.sessionExpiresAt||row.expiresAt,lastVerifiedAt:row.lastVerifiedAt,reason:row.reason||'',startup:require('./peace.desktop-overlay-startup').View(row.sessionId)};}
function List(){Prune();return Object.values(Rows()).map(View);}
function Audit(kind,row){try{require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_OVERLAY_'+kind,JSON.stringify({overlayId:row.id,sessionId:row.sessionId,parentSessionId:row.parentSessionId,licenseId:row.licenseId,releaseId:row.releaseId}));}catch(_){console.error('OVERLAY_AUDIT_FAILED');}}
function ValidateStore(db){if(!plain(db.overlays))throw Error('OVERLAY_STORE_INVALID');const sessions=new Set(Object.values(db.flows).map(r=>r.sessionId));for(const [key,row]of Object.entries(db.overlays)){if(!plain(row)||key!==row.id||!/^[A-F0-9]{24}$/.test(key)||!/^[A-F0-9]{24}$/.test(row.sessionId)||sessions.has(row.sessionId)||!['PREPARED','READY','CLAIMED',...TERMINAL].includes(row.status)||db.artifacts[row.releaseId]?.component!=='O'||db.flows[row.parentFlowId]?.sessionId!==row.parentSessionId||db.flows[row.parentFlowId]?.overlayReleaseId!==row.releaseId||delegation.Parent(row).deviceId!==db.flows[row.parentFlowId]?.deviceId||delegation.Parent(row).publicKey!==db.flows[row.parentFlowId]?.publicKey||delegation.Version(row)!==delegation.Version(db.flows[row.parentFlowId])||row.machineId!==db.flows[row.parentFlowId]?.machineId||row.machinePolicyGeneration!==db.flows[row.parentFlowId]?.machinePolicyGeneration||row.licenseId!==db.flows[row.parentFlowId]?.licenseId||!Number.isSafeInteger(row.createdAt)||!Number.isSafeInteger(row.expiresAt)||row.expiresAt<=row.createdAt||!/^[a-f0-9]{128}$/.test(row.ticketBinding)||!/^[a-f0-9]{64}$/.test(row.ticketHash)||!/^[a-f0-9]{64}$/.test(row.fingerprint)||typeof row.requestId!=='string')throw Error('OVERLAY_STORE_INVALID');delegation.ValidateIdentity(row);sessions.add(row.sessionId);if((row.claimRecoveryUntil===undefined)!==(row.claimFingerprint===undefined)||row.claimRecoveryUntil!==undefined&&(row.status!=='CLAIMED'||!Number.isSafeInteger(row.claimRecoveryUntil)||row.claimRecoveryUntil<row.claimedAt||row.claimRecoveryUntil>Math.min(row.expiresAt,row.claimedAt+30000)||!/^([a-f0-9]{64})$/.test(row.claimFingerprint)))throw Error('OVERLAY_STORE_INVALID');if(!Array.isArray(row.chunkOffsets)||row.chunkOffsets.length>256||new Set(row.chunkOffsets).size!==row.chunkOffsets.length||row.chunkOffsets.some(o=>!Number.isSafeInteger(o)||o<0||o>=db.artifacts[row.releaseId].size||o%CHUNK_SIZE))throw Error('OVERLAY_STORE_INVALID');if(['PREPARED','READY'].includes(row.status)){if(!/^[a-f0-9]{48}$/.test(row.ticketNonce)||row.ticketHash!==TokenHash(db.secret,'OVERLAY-HANDOFF',row.id,row.ticketNonce)||row.ticketBinding!==TokenBinding(db.secret,'OVERLAY-HANDOFF',row.id,row.ticketNonce))throw Error('OVERLAY_STORE_INVALID');}else if(row.ticketNonce!==undefined)throw Error('OVERLAY_STORE_INVALID');if(row.status==='CLAIMED'){if(!/^[a-f0-9]{48}$/.test(row.sessionNonce)||row.sessionHash!==TokenHash(db.secret,'OVERLAY-SESSION',row.sessionId,row.sessionNonce)||!Number.isSafeInteger(row.sessionExpiresAt)||!Number.isSafeInteger(row.claimedAt))throw Error('OVERLAY_STORE_INVALID');}else if(row.sessionNonce!==undefined)throw Error('OVERLAY_STORE_INVALID');if(TERMINAL.includes(row.status)&&!Number.isSafeInteger(row.retiredAt))throw Error('OVERLAY_STORE_INVALID');}return db.overlays;}
function TokenBinding(secret,domain,key,value){return sha512(crypto.createHmac('sha256',Buffer.from(secret,'hex')).update(['GAME-OVERLAY-V1',domain,key,value].join('|')).digest('base64url'));}
function TokenHash(secret,domain,key,value){return sha(crypto.createHmac('sha256',Buffer.from(secret,'hex')).update(['GAME-OVERLAY-V1',domain,key,value].join('|')).digest('base64url'));}
function ValidateParentTransfer(db,parent){
 const fields=['closedByOverlay','overlayTransferVersion','transferredOverlayId','transferredAt'],receipt=['transferRecoveryUntil','transferReceiptHash','transferFingerprint'];
 if(fields.every(k=>parent[k]===undefined)){if(receipt.some(k=>parent[k]!==undefined))throw Error('OVERLAY_STORE_INVALID');return;}
 const row=db.overlays?.[parent.transferredOverlayId];
 if(parent.closedByOverlay!==true||parent.overlayTransferVersion!==1||!['CLOSED','REVOKED','EXPIRED'].includes(parent.status)||!Number.isSafeInteger(parent.transferredAt)||parent.transferredAt!==parent.closedAt||parent.retiredAt===undefined||parent.sessionHash!==undefined||parent.sessionNonce!==undefined||!row||row.parentFlowId!==parent.id||row.transferVersion!==1||row.transferredAt!==parent.transferredAt)throw Error('OVERLAY_STORE_INVALID');
 if(receipt.some(k=>parent[k]!==undefined)&&(!Number.isSafeInteger(parent.transferRecoveryUntil)||parent.transferRecoveryUntil!==parent.transferredAt+TRANSFER_RECOVERY_MS||!/^[a-f0-9]{128}$/.test(parent.transferReceiptHash)||!/^[a-f0-9]{128}$/.test(parent.transferFingerprint)))throw Error('OVERLAY_STORE_INVALID');
}
function ValidateVerifyReceipt(row){
 const v=row.verifyReceipt;if(v===undefined)return;
 if(!plain(v)||Object.keys(v).sort().join(',')!=='at,fingerprint,observation,response,until'||!/^[a-f0-9]{48}:[1-9][0-9]*$/.test(v.observation)||!/^[a-f0-9]{128}$/.test(v.fingerprint)||!Number.isSafeInteger(v.at)||v.at<row.claimedAt||!Number.isSafeInteger(v.until)||v.until<=v.at||v.until>v.at+TRANSFER_RECOVERY_MS||!plain(v.response))throw Error('OVERLAY_STORE_INVALID');
 const q=v.response,fields=Object.keys(q).filter(k=>!['renewalBudget','productScopeVersion','productId'].includes(k)).sort().join(',');if(!['expiresAt,handoffVersion,leaseExpiresAt,parentSessionId,serverTime,status,transferConfirmed','capturePrivacy,expiresAt,handoffVersion,leaseExpiresAt,parentSessionId,serverTime,status,transferConfirmed'].includes(fields)||(Object.hasOwn(q,'capturePrivacy')&&typeof q.capturePrivacy!=='boolean')||q.status!=='ACTIVE'||q.serverTime!==v.at||q.handoffVersion!==1||q.parentSessionId!==row.parentSessionId||typeof q.transferConfirmed!=='boolean'||!Number.isSafeInteger(q.expiresAt)||q.expiresAt<=v.at||q.expiresAt>v.at+SESSION_MS||q.leaseExpiresAt!==q.expiresAt||v.until>q.expiresAt)throw Error('OVERLAY_STORE_INVALID');
 if(Object.hasOwn(q,'productScopeVersion')!==Object.hasOwn(q,'productId')||Object.hasOwn(q,'productId')&&(q.productScopeVersion!==1||row.productScopeVersion!==1||typeof q.productId!=='string'||q.productId!==''&&!products.Find(q.productId)))throw Error('OVERLAY_STORE_INVALID');
 if(Object.hasOwn(q,'renewalBudget')){const b=q.renewalBudget;if(!plain(b)||Object.keys(b).sort().join(',')!=='observationExpiresAt,snapshotExpiresAt,version'||b.version!==1||!Number.isSafeInteger(b.snapshotExpiresAt)||b.snapshotExpiresAt<0||b.snapshotExpiresAt>q.serverTime+120000||(b.snapshotExpiresAt!==0&&b.snapshotExpiresAt<q.expiresAt)||!Number.isSafeInteger(b.observationExpiresAt)||b.observationExpiresAt<q.expiresAt)throw Error('OVERLAY_STORE_INVALID');}
}
function ValidateTransferRows(db){for(const row of Object.values(db.overlays||{})){if(row.productScopeVersion!==undefined&&(row.productScopeVersion!==1||!Number.isSafeInteger(row.claimedAt)||['PREPARED','READY'].includes(row.status)))throw Error('OVERLAY_STORE_INVALID');ValidateVerifyReceipt(row);ValidateShutdownIntent(row);ValidateStartReceipt(row);if(row.authorizedAt!==undefined&&(!Number.isSafeInteger(row.authorizedAt)||row.authorizedAt<row.claimedAt||row.authorizedAt!==row.lastVerifiedAt))throw Error('OVERLAY_STORE_INVALID');if(row.transferVersion===undefined){if(row.transferredAt!==undefined)throw Error('OVERLAY_STORE_INVALID');continue;}const parent=db.flows[row.parentFlowId];if(row.transferVersion!==1||!Number.isSafeInteger(row.transferredAt)||row.transferredAt<row.claimedAt||row.authorizedAt===undefined||parent?.transferredOverlayId!==row.id||parent?.transferredAt!==row.transferredAt||parent?.overlayTransferVersion!==1||parent?.closedByOverlay!==true||!['CLOSED','REVOKED','EXPIRED'].includes(parent.status))throw Error('OVERLAY_STORE_INVALID');}}
function Execute(body){if(!plain(body))Fail('BOOTSTRAP_INPUT_INVALID',400);const purpose=require("../protocol/peace.desktop-request-protocol").Resolve('bootstrap',body.action);if(!purpose.name.startsWith('overlay.'))Fail('BOOTSTRAP_INPUT_INVALID',400);if(!['overlayClose','overlayAbort','overlayShutdown'].includes(body.action))Boot().EnsureSecurityAvailable();Prune();let response;switch(body.action){case 'overlayChunk':response=Chunk(body);break;case 'overlayFinish':response=Finish(body);break;case 'overlayClaim':response=Claim(body);break;case 'overlayProgress':return Progress(body);case 'overlayVerify':response=Verify(body);break;case 'overlayStart':response=Start(body);break;case 'overlayCommit':response=Commit(body);break;case 'overlayClose':response=Close(body);break;case 'overlayShutdown':response=Shutdown(body);break;case 'overlayAbort':response=Abort(body);break;default:Fail('BOOTSTRAP_INPUT_INVALID',400);}return require('../protocol/peace.packet-schema').ValidateDocument(body.action,response);}
function ProofTasks(body){
 const db=store.Load(),row=db.overlays?.[body.overlayId],work=require("../integrity/peace.desktop-proof-work");
 if(body.action==='overlayFinish'&&row)return [work.Job(delegation.Parent(row).publicKey,Canonical(row,'FINISH'),body.signature)];
 if(body.action==='overlayStart'){ParseStart(body);const r=Session(body.sessionId,body.sessionToken);Live(r);return [work.Job(r.publicKey,StartCanonical(body),body.signature)];}
 if(body.action==='overlayProgress'){const r=Session(body.sessionId,body.sessionToken);Live(r);return [work.Job(r.publicKey,require('./peace.desktop-overlay-startup').Canonical(body),body.signature)];}
 if(body.action==='overlayClaim'&&row)return delegation.ProofTasks(row,body,'O',Canonical(row,'CLAIM'));
 if(body.action==='overlayCommit'&&row){const parent=db.flows[row.parentFlowId];if(parent)return [work.Job(parent.publicKey,TransferCanonical(parent.sessionId,row.id),body.signature)];}
 if(body.action==='overlayAbort'){
  const parent=Object.values(db.flows).find(r=>r.sessionId===body.parentSessionId);
  if(parent){const byOverlay=Object.hasOwn(body,'overlayId'),scope=body.securityStop===true?'COHORT':byOverlay?'OVERLAY':'PREPARE';return [work.Job(parent.publicKey,AbortCanonical(parent.sessionId,scope,byOverlay?body.overlayId:body.prepareRequestId),body.signature)];}
 }
 return [];
}
module.exports={RetireForDevice:Retire,ProofTasks,AuthenticateIntegrityReceipt,RetireForParent,ValidateParentCancellation,Prepare,Execute,AuthenticateIntegrityReport,AuthenticateRetiredParent,Revoke,Prune,List,ValidateStore,ValidateParentTransfer,ValidateTransferRows};
