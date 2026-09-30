'use strict';
// FIX80 A -> B authorization. All tickets are domain-separated, unguessable
// HMAC capabilities; only their hashes and derivation nonces are persisted.
// Claim additionally proves possession of A's ephemeral RSA key. Neither this
// service nor its administrator projections expose a desktop activation token.
const crypto=require('node:crypto'),fs=require('node:fs');
const store=require('./desktopBootstrapStore'),config=require('../config/config'),state=require('../core/state');
const MAX_ARTIFACT_BYTES=64*1024*1024,CHUNK_SIZE=262144,LAUNCHER_MS=86400000,FLOW_MS=900000,HANDOFF_MS=120000,SESSION_MS=300000;
const FOOTER=Buffer.from('GAMEA80CONFIG!','ascii');
let activityRevision=-1,activityIndex=new Map(),retirementTimer;
const messages={BOOTSTRAP_REQUIRED:'관리자가 발급한 실행 파일 A로 다시 시작해 주세요.',BOOTSTRAP_INPUT_INVALID:'실행 요청을 확인해 주세요.',BOOTSTRAP_PE_INVALID:'올바른 Windows 64비트 실행 파일을 선택해 주세요.',BOOTSTRAP_ARTIFACT_TOO_LARGE:'실행 파일은 64MiB 이하여야 합니다.',BOOTSTRAP_TEMPLATE_PERSONALIZED:'개인화하지 않은 A 템플릿을 업로드해 주세요.',BOOTSTRAP_NOT_READY:'관리자가 A와 B 실행 파일을 먼저 등록해야 합니다.',BOOTSTRAP_LAUNCHER_INVALID:'실행 파일 A를 확인해 주세요.',BOOTSTRAP_LAUNCHER_USED:'이미 사용한 실행 파일입니다. 새 실행 파일을 발급받아 주세요.',BOOTSTRAP_EXPIRED:'실행 인증이 만료되었습니다. 새 실행 파일로 시작해 주세요.',BOOTSTRAP_REQUEST_REUSED:'요청 번호가 다른 실행에 사용되었습니다.',BOOTSTRAP_PROOF_INVALID:'실행 파일의 기기 서명을 확인하지 못했습니다.',BOOTSTRAP_FLOW_INVALID:'실행 요청을 확인할 수 없습니다.',BOOTSTRAP_HASH_MISMATCH:'실행 파일 검증에 실패했습니다.',BOOTSTRAP_DOWNLOAD_INCOMPLETE:'실행 파일 다운로드를 완료해 주세요.',BOOTSTRAP_SESSION_INVALID:'실행 세션을 확인할 수 없습니다.',BOOTSTRAP_SESSION_CLOSED:'종료된 실행 세션입니다. 새 실행 파일로 시작해 주세요.',BOOTSTRAP_REVOKED:'관리자가 이 실행 세션을 종료했습니다.',BOOTSTRAP_LICENSE_MISMATCH:'다른 라이선스가 연결된 실행 세션입니다.',BOOTSTRAP_SINGLE_WRITER_REQUIRED:'이 서비스는 단일 인스턴스와 영구 저장소가 필요합니다.',BOOTSTRAP_STORAGE_INVALID:'실행 인증 저장소를 확인할 수 없습니다.',BOOTSTRAP_STORAGE_RESTART_REQUIRED:'저장 결과를 확인하려면 서버를 다시 시작해야 합니다.',BOOTSTRAP_ARTIFACT_INVALID:'등록된 실행 파일을 읽거나 검증하지 못했습니다.'};
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
const now=()=>Date.now();
function Fail(code,status=400){const error=Error(code);error.desktopError=true;error.bootstrapError=true;error.status=status;throw error;}
function Plain(x){return !!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function Fields(value,names){if(!Plain(value)||Object.keys(value).some(key=>!['action',...names].includes(key)))Fail('BOOTSTRAP_INPUT_INVALID');}
function Id(){return crypto.randomBytes(12).toString('hex').toUpperCase();}
function Nonce(){return crypto.randomBytes(24).toString('hex');}
function DB(){try{return store.Load();}catch(error){Fail(messages[error.message]?error.message:'BOOTSTRAP_STORAGE_INVALID',503);}}
function Atomic(fn){try{return store.Atomic(fn);}catch(error){if(error.desktopError)throw error;Fail(messages[error.message]?error.message:'STORAGE_SAVE_FAILED',503);}}
function Available(){if(config.HA_ENABLED)Fail('BOOTSTRAP_SINGLE_WRITER_REQUIRED',503);if(!state.serviceEnabled||state.maintenanceMode||!require('./haCoordinator').CanAcceptTraffic())Fail('SERVICE_DISABLED',503);DB();Prune();}
function Token(domain,id,nonce){return crypto.createHmac('sha256',Buffer.from(DB().secret,'hex')).update(['GAME-A80',domain,id,nonce].join('|')).digest('base64url');}
function EqualHash(value,digest){if(typeof value!=='string'||value.length>200||typeof digest!=='string')return false;const a=Buffer.from(hash(value)),b=Buffer.from(digest);return a.length===b.length&&crypto.timingSafeEqual(a,b);}
function Sha(value){if(typeof value!=='string'||!/^[a-f0-9]{64}$/i.test(value))Fail('BOOTSTRAP_INPUT_INVALID');return value.toLowerCase();}
function RequestId(value){if(typeof value!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(value))Fail('BOOTSTRAP_INPUT_INVALID');return value;}
function Audit(type,value){try{require('../storage/audit').LogEvent(type,JSON.stringify(value));}catch(error){console.error('BOOTSTRAP_AUDIT_FAILED:',type);}}
function Artifact(row){return row?{id:row.id,component:row.component,version:row.version,sha256:row.sha256,size:row.size,createdAt:row.createdAt}:null;}
function Release(row){if(!row)Fail('BOOTSTRAP_ARTIFACT_INVALID',503);return {id:row.id,version:row.version,sha256:row.sha256,size:row.size};}
function Pe(bytes,component){
 if(!Buffer.isBuffer(bytes)||bytes.length>MAX_ARTIFACT_BYTES)Fail('BOOTSTRAP_ARTIFACT_TOO_LARGE',413);
 if(bytes.length<512||bytes.readUInt16LE(0)!==0x5a4d)Fail('BOOTSTRAP_PE_INVALID');
 const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe>bytes.length-24||bytes.readUInt32LE(pe)!==0x00004550)Fail('BOOTSTRAP_PE_INVALID');
 const sections=bytes.readUInt16LE(pe+6),optionalSize=bytes.readUInt16LE(pe+20),characteristics=bytes.readUInt16LE(pe+22),optional=pe+24;
 if(bytes.readUInt16LE(pe+4)!==0x8664||sections<1||sections>96||optionalSize<112||optional+optionalSize+sections*40>bytes.length||!(characteristics&2)||(characteristics&0x2000)||bytes.readUInt16LE(optional)!==0x20b||bytes.readUInt16LE(optional+68)!==2)Fail('BOOTSTRAP_PE_INVALID');
 const entry=bytes.readUInt32LE(optional+16),imageSize=bytes.readUInt32LE(optional+56),headerSize=bytes.readUInt32LE(optional+60),table=optional+optionalSize;
 if(!entry||entry>=imageSize||headerSize<table+sections*40||headerSize>bytes.length)Fail('BOOTSTRAP_PE_INVALID');
 let entryExecutable=false;const ranges=[];
 for(let i=0;i<sections;i++){
  const p=table+i*40,virtualSize=bytes.readUInt32LE(p+8),virtualAddress=bytes.readUInt32LE(p+12),rawSize=bytes.readUInt32LE(p+16),rawOffset=bytes.readUInt32LE(p+20),flags=bytes.readUInt32LE(p+36);
  if(virtualAddress+Math.max(virtualSize,rawSize)>imageSize||rawSize&&(rawOffset<headerSize||rawOffset+rawSize>bytes.length))Fail('BOOTSTRAP_PE_INVALID');
  if(rawSize){if(ranges.some(([from,to])=>rawOffset<to&&rawOffset+rawSize>from))Fail('BOOTSTRAP_PE_INVALID');ranges.push([rawOffset,rawOffset+rawSize]);}
  if(entry>=virtualAddress&&entry<virtualAddress+rawSize&&(flags&0x20000000))entryExecutable=true;
 }
 if(!entryExecutable)Fail('BOOTSTRAP_PE_INVALID');
 // The parser's marker literal may occur inside a valid template. Only a
 // terminal marker means the file already carries an individualized overlay.
 if(component==='A'&&bytes.subarray(-FOOTER.length).equals(FOOTER))Fail('BOOTSTRAP_TEMPLATE_PERSONALIZED');
 // Explicit historical wire bytes: old native builds cannot understand the new
 // overlay/profile. Reject them instead of silently distributing a broken pair.
 for(const encoded of ['4d4f41504c41592d434f4e4e4543542d31','4d4f41504c4159413830434f4e46494721']){
  const marker=Buffer.from(encoded,'hex');if(bytes.includes(marker)||bytes.includes(Buffer.from(marker.toString('ascii'),'utf16le')))Fail('BOOTSTRAP_PE_INVALID');
 }
}
function Publish(component,version,bytes){
 if(config.HA_ENABLED)Fail('BOOTSTRAP_SINGLE_WRITER_REQUIRED',503);
 if(!['A','B'].includes(component)||typeof version!=='string'||!/^\d+(?:\.\d+){0,3}$/.test(version)||version.length>40)Fail('BOOTSTRAP_INPUT_INVALID');
 DB();Pe(bytes,component);const row={id:Id(),component,protocol:'GAME-CONNECT-1',version,sha256:hash(bytes),size:bytes.length,createdAt:now()};
 try{store.PublishBytes(row.id,bytes);}catch(_){Fail('STORAGE_SAVE_FAILED',503);}
 Atomic(db=>{db.artifacts[row.id]=row;db.active[component]=row.id;});
 Audit('DESKTOP_BOOTSTRAP_PUBLISHED',Artifact(row));return Artifact(row);
}
function Bytes(artifact){
 try{const file=store.ArtifactPath(artifact.id),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size!==artifact.size)throw Error();const bytes=fs.readFileSync(file);if(hash(bytes)!==artifact.sha256)throw Error();return bytes;}
 catch(_){Fail('BOOTSTRAP_ARTIFACT_INVALID',503);}
}
function LauncherTicket(row){return Token('LAUNCHER',row.id,row.ticketNonce);}
function DownloadTicket(row){return Token('DOWNLOAD',row.id,row.downloadNonce);}
function HandoffToken(row){return Token('HANDOFF',row.id,row.handoffNonce);}
function SessionToken(row){return Token('SESSION',row.sessionId,row.sessionNonce);}
function MakeLauncher(row){
 const template=DB().artifacts[row.artifactId];if(!template||template.component!=='A')Fail('BOOTSTRAP_ARTIFACT_INVALID',503);
 const overlay=Buffer.from(JSON.stringify({schema:1,profile:row.profile,launcherId:row.id,launcherTicket:LauncherTicket(row),expiresAt:row.expiresAt}),'utf8');
 if(overlay.length>8192)Fail('BOOTSTRAP_INPUT_INVALID');const length=Buffer.alloc(4);length.writeUInt32LE(overlay.length);
 return Buffer.concat([Bytes(template),overlay,length,FOOTER]);
}
function LauncherName(row){return row.downloadName||crypto.createHmac('sha256',Buffer.from(DB().secret,'hex')).update('GAME-LAUNCHER-NAME-V1|'+row.id).digest('hex').slice(0,32)+'.exe';}
function LauncherResult(row){return {launcherId:row.id,downloadName:LauncherName(row),expiresAt:row.expiresAt,downloadUrl:'/api/desktop/bootstrap/launchers/'+row.id+'/download'};}
function IssueLauncher(body={},actor='ADMIN'){
 Prune();Fields(body,['requestId','label']);RequestId(body.requestId);if(body.label!==undefined&&(typeof body.label!=='string'||body.label.length>120||/[\x00-\x1f\x7f]/.test(body.label)))Fail('BOOTSTRAP_INPUT_INVALID');
 const db=DB(),receiptKey=hash(String(actor))+'|'+body.requestId,fingerprint=hash(JSON.stringify({label:body.label||''})),old=db.issueReceipts[receiptKey];
 if(old){if(old.fingerprint!==fingerprint)Fail('BOOTSTRAP_REQUEST_REUSED',409);const row=db.launchers[old.launcherId];if(!row)Fail('BOOTSTRAP_STORAGE_INVALID',503);if(row.status==='EXPIRED')Fail('BOOTSTRAP_EXPIRED',410);if(row.status!=='AVAILABLE')Fail('BOOTSTRAP_LAUNCHER_USED',409);return LauncherResult(row);}
 if(!db.artifacts[db.active.A]||!db.artifacts[db.active.B]||db.artifacts[db.active.A].protocol!=='GAME-CONNECT-1'||db.artifacts[db.active.B].protocol!=='GAME-CONNECT-1')Fail('BOOTSTRAP_NOT_READY',409);
 Pe(Bytes(db.artifacts[db.active.A]),'A');Pe(Bytes(db.artifacts[db.active.B]),'B');
 const raw=require('./connectTransportKey').Profile(),profile={version:raw.version,protocol:raw.protocol,host:raw.host,port:raw.port,serverKeyId:raw.serverKeyId,serverPublicKey:raw.serverPublicKey};
 const row={id:Id(),downloadName:crypto.randomBytes(16).toString('hex')+'.exe',label:(body.label||'').trim(),artifactId:db.active.A,profile,ticketNonce:Nonce(),status:'AVAILABLE',issuedAt:now(),expiresAt:now()+LAUNCHER_MS,issuedBy:String(actor).slice(0,160),flowId:''};
 row.ticketHash=hash(LauncherTicket(row));row.sha256=hash(MakeLauncher(row));
 Atomic(next=>{next.launchers[row.id]=row;next.issueReceipts[receiptKey]={fingerprint,launcherId:row.id};});
 Audit('DESKTOP_BOOTSTRAP_ISSUED',{launcherId:row.id,label:row.label,expiresAt:row.expiresAt});return LauncherResult(row);
}
function LauncherBytes(id){Prune();const row=DB().launchers[id];if(!row)Fail('BOOTSTRAP_LAUNCHER_INVALID',404);if(row.status==='EXPIRED'||row.expiresAt<=now())Fail('BOOTSTRAP_EXPIRED',410);if(row.status!=='AVAILABLE')Fail('BOOTSTRAP_LAUNCHER_USED',409);const bytes=MakeLauncher(row);if(hash(bytes)!==row.sha256)Fail('BOOTSTRAP_ARTIFACT_INVALID',503);return bytes;}
function FinishCanonical(row){const release=DB().artifacts[row.releaseId];return ['GAME-A80-FINISH-V1',row.id,row.launcherId,row.launcherSha256,row.deviceId,release.id,release.sha256,String(release.size),row.downloadHash,row.finishNonce,String(row.expiresAt)].join('\n');}
function ClaimCanonical(row){const release=DB().artifacts[row.releaseId];return ['GAME-B80-CLAIM-V1',row.id,row.launcherId,row.launcherSha256,row.deviceId,release.id,release.sha256,String(release.size),row.handoffHash,row.claimNonce,String(row.handoffExpiresAt)].join('\n');}
function Verify(row,canonical,signature){
 if(typeof signature!=='string'||signature.length!==344||!/^[A-Za-z0-9+/]{342}==$/.test(signature))Fail('BOOTSTRAP_PROOF_INVALID',401);
 const bytes=Buffer.from(signature,'base64');if(bytes.length!==256||bytes.toString('base64')!==signature)Fail('BOOTSTRAP_PROOF_INVALID',401);
 const key=require('./desktopLicenses').ParseKey(row.publicKey).key;
 if(!crypto.verify('sha256',Buffer.from(canonical,'utf8'),{key,padding:crypto.constants.RSA_PKCS1_PADDING},bytes))Fail('BOOTSTRAP_PROOF_INVALID',401);
}
function FlowLive(row,allowClaimed=false){if(row?.status==='EXPIRED')Fail('BOOTSTRAP_EXPIRED',403);if(!row)Fail('BOOTSTRAP_FLOW_INVALID',401);if(row.status==='REVOKED')Fail('BOOTSTRAP_REVOKED',403);if(row.status==='CLOSED')Fail('BOOTSTRAP_SESSION_CLOSED',403);if(row.status==='CLAIMED'){if(!allowClaimed)Fail('BOOTSTRAP_LAUNCHER_USED',409);if(row.sessionExpiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);}else if(row.expiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);}
function DownloadFlow(body,allowClaimed=false){const row=DB().flows[body.flowId];FlowLive(row,allowClaimed);if(!EqualHash(body.downloadTicket,row.downloadHash))Fail('BOOTSTRAP_FLOW_INVALID',401);return row;}
function Begin(body){
 Fields(body,['requestId','launcherId','launcherTicket','launcherSha256','publicKey','deviceId']);RequestId(body.requestId);const digest=Sha(body.launcherSha256);
 const parsed=require('./desktopLicenses').ParseKey(body.publicKey);if(body.deviceId!==parsed.deviceId)Fail('BOOTSTRAP_PROOF_INVALID',401);
 const db=DB(),launcher=db.launchers[body.launcherId];if(!launcher||!EqualHash(body.launcherTicket,launcher.ticketHash))Fail('BOOTSTRAP_LAUNCHER_INVALID',401);
 if(digest!==launcher.sha256)Fail('BOOTSTRAP_HASH_MISMATCH',403);
 const fingerprint=hash(JSON.stringify({requestId:body.requestId,launcherId:body.launcherId,sha256:digest,deviceId:parsed.deviceId,publicKey:parsed.publicKey}));
 if(launcher.status==='CONSUMED'){
  const prior=db.flows[launcher.flowId];if(!prior||prior.beginFingerprint!==fingerprint)Fail('BOOTSTRAP_LAUNCHER_USED',409);FlowLive(prior,true);return BeginResult(prior);
 }
 if(launcher.status==='REVOKED')Fail('BOOTSTRAP_REVOKED',403);if(launcher.status==='EXPIRED')Fail('BOOTSTRAP_EXPIRED',403);if(launcher.expiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);
 const release=db.artifacts[db.active.B];if(!release)Fail('BOOTSTRAP_NOT_READY',409);Pe(Bytes(release),'B');
 const row={id:Id(),sessionId:Id(),launcherId:launcher.id,launcherSha256:digest,releaseId:release.id,deviceId:parsed.deviceId,publicKey:parsed.publicKey,beginFingerprint:fingerprint,status:'STARTED',createdAt:now(),expiresAt:now()+FLOW_MS,downloadNonce:Nonce(),finishNonce:Nonce(),chunkOffsets:[],licenseId:'',lastVerifiedAt:0};row.downloadHash=hash(DownloadTicket(row));
 Atomic(next=>{if(next.launchers[launcher.id].status!=='AVAILABLE')Fail('BOOTSTRAP_LAUNCHER_USED',409);next.launchers[launcher.id].status='CONSUMED';next.launchers[launcher.id].flowId=row.id;RetireLauncher(next.launchers[launcher.id]);next.flows[row.id]=row;});
 Audit('DESKTOP_BOOTSTRAP_BEGAN',{flowId:row.id,launcherId:row.launcherId,deviceId:row.deviceId,releaseId:row.releaseId});return BeginResult(row);
}
function BeginResult(row){return {flowId:row.id,downloadTicket:DownloadTicket(row),release:Release(DB().artifacts[row.releaseId]),chunkSize:CHUNK_SIZE,expiresAt:row.expiresAt,finishCanonical:FinishCanonical(row)};}
function Chunk(body){
 Fields(body,['flowId','downloadTicket','offset']);const row=DownloadFlow(body),artifact=DB().artifacts[row.releaseId];
 if(!Number.isSafeInteger(body.offset)||body.offset<0||body.offset>=artifact.size||body.offset%CHUNK_SIZE!==0)Fail('BOOTSTRAP_INPUT_INVALID');
 const size=Math.min(CHUNK_SIZE,artifact.size-body.offset),bytes=Buffer.alloc(size);let fd;
 try{const file=store.ArtifactPath(artifact.id),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size!==artifact.size)throw Error();fd=fs.openSync(file,'r');let read=0;while(read<size){const count=fs.readSync(fd,bytes,read,size-read,body.offset+read);if(!count)throw Error();read+=count;}}
 catch(_){Fail('BOOTSTRAP_ARTIFACT_INVALID',503);}finally{if(fd!==undefined)fs.closeSync(fd);}
 // Receipt is committed before acknowledging a chunk; retries of a lost reply
 // read the same frozen artifact and never skip verification/download coverage.
 if(!row.chunkOffsets.includes(body.offset))Atomic(db=>{db.flows[row.id].chunkOffsets.push(body.offset);});
 return {offset:body.offset,data:bytes.toString('base64'),size};
}
function Finish(body){
 Fields(body,['flowId','downloadTicket','sha256','signature']);const row=DownloadFlow(body,true),artifact=DB().artifacts[row.releaseId];if(Sha(body.sha256)!==artifact.sha256)Fail('BOOTSTRAP_HASH_MISMATCH',403);Verify(row,FinishCanonical(row),body.signature);
 if(row.status==='CLAIMED'||row.status==='DOWNLOADED'){if(row.handoffExpiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);return FinishResult(row);}
 if(row.chunkOffsets.length!==Math.ceil(artifact.size/CHUNK_SIZE))Fail('BOOTSTRAP_DOWNLOAD_INCOMPLETE',409);
 Atomic(db=>{const item=db.flows[row.id];item.status='DOWNLOADED';item.downloadedAt=now();item.handoffNonce=Nonce();item.claimNonce=Nonce();item.handoffExpiresAt=Math.min(item.expiresAt,now()+HANDOFF_MS);item.handoffHash=hash(HandoffToken(item));});
 return FinishResult(DB().flows[row.id]);
}
function FinishResult(row){return {handoffToken:HandoffToken(row),claimCanonical:ClaimCanonical(row),expiresAt:row.handoffExpiresAt};}
function Claim(body){
 Fields(body,['flowId','handoffToken','signature','binarySha256']);const row=DB().flows[body.flowId];FlowLive(row,true);
 if(!['DOWNLOADED','CLAIMED'].includes(row.status)||!EqualHash(body.handoffToken,row.handoffHash))Fail('BOOTSTRAP_FLOW_INVALID',401);
 const artifact=DB().artifacts[row.releaseId];if(Sha(body.binarySha256)!==artifact.sha256)Fail('BOOTSTRAP_HASH_MISMATCH',403);Verify(row,ClaimCanonical(row),body.signature);
 if(row.status==='CLAIMED')return ClaimResult(row);
 if(row.handoffExpiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);
 Atomic(db=>{const item=db.flows[row.id];item.status='CLAIMED';item.claimedAt=now();item.sessionNonce=Nonce();item.sessionHash=hash(SessionToken(item));item.sessionExpiresAt=now()+SESSION_MS;});
 const claimed=DB().flows[row.id];Audit('DESKTOP_BOOTSTRAP_CLAIMED',{flowId:claimed.id,sessionId:claimed.sessionId,deviceId:claimed.deviceId,releaseId:claimed.releaseId});return ClaimResult(claimed);
}
function ClaimResult(row){return {sessionId:row.sessionId,sessionToken:SessionToken(row),expiresAt:row.sessionExpiresAt,release:Release(DB().artifacts[row.releaseId])};}
function FindSession(id){return Object.values(DB().flows).find(row=>row.sessionId===id);}
function SessionAuthenticated(id,token){const row=FindSession(id);if(!row||!row.sessionHash||!EqualHash(token,row.sessionHash))Fail('BOOTSTRAP_SESSION_INVALID',401);return row;}
function Gate(id,token,deviceId,options={}){
 Available();if(!id||!token)Fail('BOOTSTRAP_REQUIRED',403);const row=SessionAuthenticated(id,token);
 const released=options.allowReleased&&row.status==='CLOSED'&&row.closedByLicenseRelease;
 if(!released)FlowLive(row,true);
 if((row.status!=='CLAIMED'&&!released)||row.deviceId!==deviceId)Fail('BOOTSTRAP_SESSION_INVALID',403);return row;
}
function LicenseState(row){
 if(!row.licenseId)return {licenseStatus:'',licenseLastVerifiedAt:0};
 const license=require('./desktopLicenses').DB().licenses[row.licenseId];if(!license)return {licenseStatus:'UNKNOWN',licenseLastVerifiedAt:0};
 const view=require('./desktopLicenses').Public(license);return {licenseStatus:view.status,licenseLastVerifiedAt:Math.max(view.lastVerifiedAt,row.lastVerifiedAt||0)};
}
function EffectiveExpiry(row){return row.sessionExpiresAt|| (row.handoffExpiresAt?Math.min(row.expiresAt,row.handoffExpiresAt):row.expiresAt);}
function ProjectStatus(row){if(['CLOSED','REVOKED','EXPIRED'].includes(row.status))return row.status;if(EffectiveExpiry(row)<=now())return 'EXPIRED';return row.status;}
function SessionView(row){const status=ProjectStatus(row);return {id:row.sessionId,flowId:row.id,launcherId:row.launcherId,status,online:status==='CLAIMED',deviceId:row.deviceId,releaseId:row.releaseId,version:DB().artifacts[row.releaseId]?.version||'',createdAt:row.createdAt,claimedAt:row.claimedAt||0,expiresAt:EffectiveExpiry(row),lastVerifiedAt:row.lastVerifiedAt||0,licenseId:row.licenseId||'',...LicenseState(row),revokedAt:row.revokedAt||0,reason:row.reason||''};}
function Status(body){Fields(body,['sessionId','sessionToken']);const row=SessionAuthenticated(body.sessionId,body.sessionToken);return {sessionId:row.sessionId,status:ProjectStatus(row),expiresAt:row.sessionExpiresAt,licenseId:row.licenseId||'',licenseStatus:LicenseState(row).licenseStatus,lastVerifiedAt:row.lastVerifiedAt||0,release:Release(DB().artifacts[row.releaseId])};}
function Close(body){
 Fields(body,['sessionId','sessionToken']);const row=SessionAuthenticated(body.sessionId,body.sessionToken);
 if(!['CLOSED','REVOKED','EXPIRED'].includes(row.status)){Atomic(db=>{db.flows[row.id].status='CLOSED';db.flows[row.id].closedAt=now();RetireFlow(db.flows[row.id]);});Audit('DESKTOP_BOOTSTRAP_CLOSED',{sessionId:row.sessionId,licenseId:row.licenseId||''});}
 return Status(body);
}
function Abort(body){
 Fields(body,['flowId','downloadTicket']);const row=DB().flows[body.flowId];
 if(!row||!EqualHash(body.downloadTicket,row.downloadHash))Fail('BOOTSTRAP_FLOW_INVALID',401);
 if(!['CLOSED','REVOKED','EXPIRED'].includes(row.status)){
  Atomic(db=>{const item=db.flows[row.id];item.status='CLOSED';item.closedAt=now();RetireFlow(item);});
  Audit('DESKTOP_BOOTSTRAP_ABORTED',{flowId:row.id,sessionId:row.sessionId,licenseId:row.licenseId||''});
 }
 return {flowId:row.id,status:DB().flows[row.id].status};
}
function Revoke(id,body={},actor='ADMIN'){
 Fields(body,['reason']);if(typeof body.reason!=='string'||body.reason.trim().length<3||body.reason.length>300||/[\x00-\x1f\x7f]/.test(body.reason))Fail('BOOTSTRAP_INPUT_INVALID');
 const row=FindSession(id);if(!row)Fail('BOOTSTRAP_SESSION_INVALID',404);
 if(row.status!=='REVOKED')Atomic(db=>{const item=db.flows[row.id];item.status='REVOKED';item.revokedAt=now();item.reason=body.reason.trim();item.revokedBy=String(actor).slice(0,160);db.launchers[item.launcherId].status='REVOKED';RetireLauncher(db.launchers[item.launcherId]);RetireFlow(item);});
 Audit('DESKTOP_BOOTSTRAP_REVOKED',{sessionId:id,licenseId:row.licenseId||'',actor:String(actor).slice(0,160)});return SessionView(DB().flows[row.id]);
}
function TouchLicense(id,token,deviceId,license,action,verification={}){
 // desktopLicenses calls Gate before its synchronous journal transaction.
 // Do not re-check the wall clock after that durable commit: a slow fsync on
 // the expiry boundary must not consume a key without renewing its session.
 const row=SessionAuthenticated(id,token),released=action==='release'&&row.status==='CLOSED'&&row.closedByLicenseRelease;
 if((row.status!=='CLAIMED'&&!released)||row.deviceId!==deviceId)Fail('BOOTSTRAP_SESSION_INVALID',403);
 if(row.licenseId&&row.licenseId!==license.id)Fail('BOOTSTRAP_LICENSE_MISMATCH',409);
 Atomic(db=>{const item=db.flows[row.id];item.licenseId=license.id;item.lastVerifiedAt=now();item.licenseLeaseExpiresAt=Number(verification.leaseExpiresAt)||0;item.appVersion=typeof verification.appVersion==='string'?verification.appVersion.slice(0,40):'';item.sessionExpiresAt=Math.min(now()+SESSION_MS,license.expiresAt||Number.MAX_SAFE_INTEGER);if(action==='release'){item.status='CLOSED';item.closedAt=now();item.closedByLicenseRelease=true;RetireFlow(item);}});
}
function LicenseActivity(id){
 // This direct projection intentionally never calls desktopLicenses.Public or
 // Overview: Public consumes it, including after a server restart.
 const db=DB();if(activityRevision!==db.revision){const index=new Map();for(const row of Object.values(db.flows)){if(!row.licenseId)continue;const old=index.get(row.licenseId);if(!old||row.lastVerifiedAt>=old.lastVerifiedAt)index.set(row.licenseId,{lastVerifiedAt:row.lastVerifiedAt||0,leaseExpiresAt:row.licenseLeaseExpiresAt||0,appVersion:row.appVersion||'',sessionId:row.sessionId});}activityIndex=index;activityRevision=db.revision;}
 return activityIndex.get(id)||null;
}
function RetireLauncher(row){delete row.ticketNonce;delete row.profile;row.retiredAt||=now();}
function RetireFlow(row){for(const key of ['downloadNonce','finishNonce','handoffNonce','claimNonce','sessionNonce'])delete row[key];row.retiredAt||=now();}
function Prune(){
 const db=DB(),at=now(),launchers=Object.values(db.launchers).filter(row=>row.status==='AVAILABLE'&&row.expiresAt<=at||row.status!=='AVAILABLE'&&!row.retiredAt),flows=Object.values(db.flows).filter(row=>!['CLOSED','REVOKED','EXPIRED'].includes(row.status)&&EffectiveExpiry(row)<=at||['CLOSED','REVOKED','EXPIRED'].includes(row.status)&&!row.retiredAt);
 if(!launchers.length&&!flows.length)return;
 Atomic(next=>{
  for(const row of launchers){const item=next.launchers[row.id];if(item.status==='AVAILABLE')item.status='EXPIRED';RetireLauncher(item);}
  for(const row of flows){const item=next.flows[row.id];if(!['CLOSED','REVOKED','EXPIRED'].includes(item.status))item.status='EXPIRED';RetireFlow(item);}
 });
}
function Initialize(){DB();Prune();if(!retirementTimer){retirementTimer=setInterval(()=>{try{Prune();}catch(_){console.error('BOOTSTRAP_RETIREMENT_FAILED');}},1000);retirementTimer.unref();}return DB();}
function Overview(){
 Prune();const db=DB();return {artifacts:{A:Artifact(db.artifacts[db.active.A]),B:Artifact(db.artifacts[db.active.B])},launchers:Object.values(db.launchers).map(row=>({id:row.id,downloadName:LauncherName(row),label:row.label,issuedAt:row.issuedAt,expiresAt:row.expiresAt,status:row.status==='AVAILABLE'&&row.expiresAt<=now()?'EXPIRED':row.status,flowId:row.flowId||'',sha256:row.sha256})).sort((a,b)=>b.issuedAt-a.issuedAt),sessions:Object.values(db.flows).map(SessionView).sort((a,b)=>b.createdAt-a.createdAt),limits:{maxArtifactBytes:MAX_ARTIFACT_BYTES,chunkSize:CHUNK_SIZE,launcherLifetimeMs:LAUNCHER_MS,flowLifetimeMs:FLOW_MS,sessionLifetimeMs:SESSION_MS},serverTime:now()};
}
function Execute(body){if(!Plain(body))Fail('BOOTSTRAP_INPUT_INVALID');if(['close','abort'].includes(body.action)){DB();Prune();}else Available();switch(body.action){case 'begin':return Begin(body);case 'chunk':return Chunk(body);case 'finish':return Finish(body);case 'claim':return Claim(body);case 'status':return Status(body);case 'close':return Close(body);case 'abort':return Abort(body);default:Fail('BOOTSTRAP_INPUT_INVALID');}}
module.exports={MAX_ARTIFACT_BYTES,CHUNK_SIZE,LAUNCHER_MS,FLOW_MS,HANDOFF_MS,SESSION_MS,FOOTER,messages,Fail,Initialize,Publish,IssueLauncher,LauncherBytes,LauncherName,Execute,Gate,TouchLicense,LicenseActivity,Overview,Revoke};
