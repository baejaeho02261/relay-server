'use strict';
// A -> B authorization with pinned TLS, SHA-512, XXH3-128, BLAKE3 and role-separated CRC evidence. All tickets are domain-separated, unguessable
// HMAC capabilities; only their hashes and derivation nonces are persisted.
// Claim additionally proves possession of A's ephemeral RSA key. Neither this
// service nor its administrator projections expose a desktop activation token.
const crypto=require('node:crypto'),fs=require('node:fs');
const integrity=require('./desktopIntegrity'),store=require('./desktopBootstrapStore'),config=require('../config/config'),state=require('../core/state');
const MAX_ARTIFACT_BYTES=64*1024*1024,CHUNK_SIZE=262144,LAUNCHER_MS=86400000,FLOW_MS=900000,HANDOFF_MS=120000,SESSION_MS=300000;
const FOOTER=Buffer.from('GAMEA80CONFIG!','ascii');
let activityRevision=-1,activityIndex=new Map(),retirementTimer;
const integritySuccessTimes=new Map();
const messages={BOOTSTRAP_OVERLAY_NOT_READY:'관리자가 O(GameOverlay) 실행 파일을 승인하여 A/B와 함께 게시해야 합니다.',BOOTSTRAP_REQUIRED:'관리자가 발급한 실행 파일 A로 다시 시작해 주세요.',BOOTSTRAP_INPUT_INVALID:'실행 요청을 확인해 주세요.',BOOTSTRAP_PE_INVALID:'올바른 Windows 64비트 실행 파일을 선택해 주세요.',BOOTSTRAP_ARTIFACT_TOO_LARGE:'실행 파일은 64MiB 이하여야 합니다.',BOOTSTRAP_TEMPLATE_PERSONALIZED:'개인화하지 않은 A 템플릿을 업로드해 주세요.',BOOTSTRAP_NOT_READY:'관리자가 A와 B 실행 파일을 먼저 등록해야 합니다.',BOOTSTRAP_LAUNCHER_INVALID:'실행 파일 A를 확인해 주세요.',BOOTSTRAP_LAUNCHER_USED:'이미 사용한 실행 파일입니다. 새 실행 파일을 발급받아 주세요.',BOOTSTRAP_EXPIRED:'실행 인증이 만료되었습니다. 새 실행 파일로 시작해 주세요.',BOOTSTRAP_REQUEST_REUSED:'요청 번호가 다른 실행에 사용되었습니다.',BOOTSTRAP_PROOF_INVALID:'실행 파일의 기기 서명을 확인하지 못했습니다.',BOOTSTRAP_FLOW_INVALID:'실행 요청을 확인할 수 없습니다.',BOOTSTRAP_CODE_MISMATCH:'실행 코드 무결성 검증에 실패했습니다.',BOOTSTRAP_HASH_MISMATCH:'실행 파일 검증에 실패했습니다.',BOOTSTRAP_DOWNLOAD_INCOMPLETE:'실행 파일 다운로드를 완료해 주세요.',BOOTSTRAP_SESSION_INVALID:'실행 세션을 확인할 수 없습니다.',BOOTSTRAP_SESSION_CLOSED:'종료된 실행 세션입니다. 새 실행 파일로 시작해 주세요.',BOOTSTRAP_REVOKED:'관리자가 이 실행 세션을 종료했습니다.',BOOTSTRAP_LICENSE_MISMATCH:'다른 라이선스가 연결된 실행 세션입니다.',BOOTSTRAP_SINGLE_WRITER_REQUIRED:'이 서비스는 단일 인스턴스와 영구 저장소가 필요합니다.',BOOTSTRAP_STORAGE_INVALID:'실행 인증 저장소를 확인할 수 없습니다.',BOOTSTRAP_STORAGE_RESTART_REQUIRED:'저장 결과를 확인하려면 서버를 다시 시작해야 합니다.',BOOTSTRAP_ARTIFACT_INVALID:'등록된 실행 파일을 읽거나 검증하지 못했습니다.'};
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
function Sha(value){if(typeof value!=='string'||!/^[a-f0-9]{128}$/i.test(value))Fail('BOOTSTRAP_INPUT_INVALID');return value.toLowerCase();}
function Crc(value){if(typeof value!=='string'||!/^[A-F0-9]{16}$/.test(value))Fail('BOOTSTRAP_INPUT_INVALID');return value;}
function MachinePolicy(){return require('./desktopMachinePolicy');}
function RequestId(value){if(typeof value!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(value))Fail('BOOTSTRAP_INPUT_INVALID');return value;}
function Audit(type,value){try{require('../storage/audit').LogEvent(type,JSON.stringify(value));}catch(error){console.error('BOOTSTRAP_AUDIT_FAILED:',type);}}
function Artifact(row){return row?{id:row.id,component:row.component,version:row.version,hashVersion:row.hashVersion,sha512:row.sha512,crc64:row.crc64,xxh3_128:row.xxh3_128,blake3:row.blake3,codeSha512:row.codeSha512,codeCrc64:row.codeCrc64,codeXxh3_128:row.codeXxh3_128,codeBlake3:row.codeBlake3,codeAlgorithm:row.codeAlgorithm,size:row.size,createdAt:row.createdAt,backgroundVersion:row.backgroundVersion||0,crcCoverage:require('./desktopCrcPolicy').Compare(row.crcLayers,row.crcLayers)}:null;}
// GAME-CONNECT-4 clients validate the versioned 13-field release at Begin
// and Claim. All four file/code measurements and hashVersion are explicit;
// the v4 envelope and new signed domains reject mixed old/new clients.
function Release(row){if(!row||row.hashVersion!==3)Fail('BOOTSTRAP_ARTIFACT_INVALID',503);return {id:row.id,version:row.version,hashVersion:3,sha512:row.sha512,crc64:row.crc64,xxh3_128:row.xxh3_128,blake3:row.blake3,codeSha512:row.codeSha512,codeCrc64:row.codeCrc64,codeXxh3_128:row.codeXxh3_128,codeBlake3:row.codeBlake3,codeAlgorithm:row.codeAlgorithm,size:row.size};}
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
 if(!bytes.includes(Buffer.from('GAME-CONNECT-4'))&&!bytes.includes(Buffer.from('GAME-CONNECT-4','utf16le')))Fail('BOOTSTRAP_PROTOCOL_UPGRADE_REQUIRED');
 for(const encoded of ['47414d452d434f4e4e4543542d33','47414d452d434f4e4e4543542d32','47414d452d434f4e4e4543542d31','4d4f41504c41592d434f4e4e4543542d31','4d4f41504c4159413830434f4e46494721']){
  const marker=Buffer.from(encoded,'hex');if(bytes.includes(marker)||bytes.includes(Buffer.from(marker.toString('ascii'),'utf16le')))Fail('BOOTSTRAP_PE_INVALID');
 }
}
function Publish(component,version,bytes,releaseApproval,options={}){
 if(config.HA_ENABLED)Fail('BOOTSTRAP_SINGLE_WRITER_REQUIRED',503);
 if(!['A','B','O'].includes(component)||typeof version!=='string'||!/^\d+(?:\.\d+){0,3}$/.test(version)||version.length>40)Fail('BOOTSTRAP_INPUT_INVALID');
 DB();Pe(bytes,component);if(!bytes.includes(Buffer.from('GAME-AUTHORITY-V2'))&&!bytes.includes(Buffer.from('GAME-AUTHORITY-V2','utf16le')))Fail('SECURITY_CLIENT_UPGRADE_REQUIRED');const securityMetadata=require('./desktopSecurityAuthority').PublishMetadata(component,version,bytes,releaseApproval);let code;try{code=integrity.CodeImage(bytes);}catch(_){Fail('BOOTSTRAP_PE_INVALID');}const row={id:Id(),component,protocol:'GAME-CONNECT-4',version,...securityMetadata,backgroundVersion:bytes.includes(Buffer.from('SERVER_ASSIGNED_V1'))||bytes.includes(Buffer.from('SERVER_ASSIGNED_V1','utf16le'))?1:0,...integrity.Digests(bytes),codeSha512:code.sha512,codeCrc64:code.crc64,codeXxh3_128:code.xxh3_128,codeBlake3:code.blake3,codeAlgorithm:code.algorithm,crcLayers:code.crcLayers,size:bytes.length,createdAt:now()};
 if(options.deduplicate===true){
  const same=Object.values(DB().artifacts).find(x=>x.component===component&&x.version===version&&x.sha512===row.sha512&&JSON.stringify(x.releaseApproval||null)===JSON.stringify(row.releaseApproval||null));
  if(same){Bytes(same);Audit('DESKTOP_BOOTSTRAP_STAGE_REUSED',{id:same.id,component,version,sha512:same.sha512});return Artifact(same);}
 }
 try{store.PublishBytes(row.id,bytes);}catch(_){Fail('STORAGE_SAVE_FAILED',503);}
 Atomic(db=>{db.artifacts[row.id]=row;if(options.activate!==false)db.active[component]=row.id;});
 Audit(options.activate===false?'DESKTOP_BOOTSTRAP_STAGED':'DESKTOP_BOOTSTRAP_PUBLISHED',Artifact(row));return Artifact(row);
}
function Bytes(artifact){
 require('./desktopSecurityAuthority').RequireArtifact(artifact);
 let fd;
 try{const file=store.ArtifactPath(artifact.id);fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size!==artifact.size)throw Error();const bytes=fs.readFileSync(fd),digests=integrity.Digests(bytes);if(artifact.hashVersion!==3||digests.sha512!==artifact.sha512||digests.crc64!==artifact.crc64||digests.xxh3_128!==artifact.xxh3_128||digests.blake3!==artifact.blake3)throw Error();return bytes;}
 catch(_){Fail('BOOTSTRAP_ARTIFACT_INVALID',503);}finally{if(fd!==undefined)fs.closeSync(fd);}
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
 Prune();Fields(body,['requestId','label','licenseId']);RequestId(body.requestId);if(body.label!==undefined&&(typeof body.label!=='string'||body.label.length>120||/[\x00-\x1f\x7f]/.test(body.label)))Fail('BOOTSTRAP_INPUT_INVALID');
 const db=DB(),receiptKey=hash(String(actor))+'|'+body.requestId,fingerprint=hash(JSON.stringify({label:body.label||'',...(body.licenseId?{licenseId:body.licenseId}:{})})),old=db.issueReceipts[receiptKey];
 if(old){if(old.fingerprint!==fingerprint)Fail('BOOTSTRAP_REQUEST_REUSED',409);const row=db.launchers[old.launcherId];if(!row)Fail('BOOTSTRAP_STORAGE_INVALID',503);if(row.status==='EXPIRED')Fail('BOOTSTRAP_EXPIRED',410);if(row.status!=='AVAILABLE')Fail('BOOTSTRAP_LAUNCHER_USED',409);return LauncherResult(row);}
 if(!db.artifacts[db.active.A]||!db.artifacts[db.active.B]||db.artifacts[db.active.A].protocol!=='GAME-CONNECT-4'||db.artifacts[db.active.B].protocol!=='GAME-CONNECT-4')Fail('BOOTSTRAP_NOT_READY',409);
 require('./desktopSecurityOperations').RequireRuntimePair(db.artifacts[db.active.A],db.artifacts[db.active.B],db.artifacts[db.active.O]);
 Pe(Bytes(db.artifacts[db.active.A]),'A');Pe(Bytes(db.artifacts[db.active.B]),'B');if(db.active.O)Pe(Bytes(db.artifacts[db.active.O]),'O');
 if(body.licenseId!==undefined){
  if(typeof body.licenseId!=='string'||!/^(?:DL-)?[A-F0-9]{24}$/.test(body.licenseId))Fail('BOOTSTRAP_INPUT_INVALID');
  const license=require('./desktopLicenses').Detail(body.licenseId).license;
  if(license.status!=='AVAILABLE'||license.consumed)Fail('DESKTOP_KEY_USED',409);
  if(Object.values(db.launchers).some(l=>l.assignedLicenseId===body.licenseId&&(l.status==='AVAILABLE'&&l.expiresAt>now()||l.status==='CONSUMED'&&db.flows[l.flowId]&&!['CLOSED','REVOKED','EXPIRED'].includes(ProjectStatus(db.flows[l.flowId])))))Fail('WORKSPACE_LICENSE_RESERVED',409);
 }else if(db.artifacts[db.active.B].backgroundVersion===1)Fail('WORKSPACE_LICENSE_REQUIRED',409);
 const raw=require('./connectTransportKey').Profile(),profile={version:raw.version,protocol:raw.protocol,host:raw.host,port:raw.port,serverKeyId:raw.serverKeyId,serverPublicKey:raw.serverPublicKey,tlsServerName:raw.tlsServerName,tlsCertificateSha256:raw.tlsCertificateSha256};
 const row={id:Id(),downloadName:crypto.randomBytes(16).toString('hex')+'.exe',label:(body.label||'').trim(),artifactId:db.active.A,profile,ticketNonce:Nonce(),status:'AVAILABLE',issuedAt:now(),expiresAt:now()+LAUNCHER_MS,issuedBy:String(actor).slice(0,160),flowId:''};
 if(body.licenseId)row.assignedLicenseId=body.licenseId;
 row.ticketHash=hash(LauncherTicket(row));Object.assign(row,integrity.Digests(MakeLauncher(row)));
 Atomic(next=>{next.launchers[row.id]=row;next.issueReceipts[receiptKey]={fingerprint,launcherId:row.id};});
 Audit('DESKTOP_BOOTSTRAP_ISSUED',{launcherId:row.id,label:row.label,expiresAt:row.expiresAt,licenseId:row.assignedLicenseId||''});return LauncherResult(row);
}
function LauncherBytes(id){Prune();const row=DB().launchers[id];if(!row)Fail('BOOTSTRAP_LAUNCHER_INVALID',404);if(row.status==='EXPIRED'||row.expiresAt<=now())Fail('BOOTSTRAP_EXPIRED',410);if(row.status!=='AVAILABLE')Fail('BOOTSTRAP_LAUNCHER_USED',409);const bytes=MakeLauncher(row),digests=integrity.Digests(bytes);if(row.hashVersion!==3||['sha512','crc64','xxh3_128','blake3'].some(k=>digests[k]!==row[k]))Fail('BOOTSTRAP_ARTIFACT_INVALID',503);return bytes;}
function FinishCanonical(row){const release=DB().artifacts[row.releaseId];return ['GAME-A85-FINISH-V2',row.id,row.launcherId,row.launcherSha512,row.launcherCrc64,row.aCodeSha512,row.aCodeCrc64,row.deviceId,row.machineId,release.id,release.sha512,release.crc64,release.codeSha512,release.codeCrc64,String(release.size),row.downloadHash,row.finishNonce,String(row.expiresAt)].join('\n');}
function ClaimCanonical(row){const release=DB().artifacts[row.releaseId];return ['GAME-B85-CLAIM-V2',row.id,row.launcherId,row.launcherSha512,row.launcherCrc64,row.aCodeSha512,row.aCodeCrc64,row.deviceId,row.machineId,release.id,release.sha512,release.crc64,release.codeSha512,release.codeCrc64,String(release.size),row.handoffHash,row.claimNonce,String(row.handoffExpiresAt)].join('\n');}
function Verify(row,canonical,signature){
 if(typeof signature!=='string'||signature.length!==344||!/^[A-Za-z0-9+/]{342}==$/.test(signature))Fail('BOOTSTRAP_PROOF_INVALID',401);
 const bytes=Buffer.from(signature,'base64');if(bytes.length!==256||bytes.toString('base64')!==signature)Fail('BOOTSTRAP_PROOF_INVALID',401);
 const key=require('./desktopLicenses').ParseKey(row.publicKey).key;
 if(!crypto.verify('sha256',Buffer.from(canonical,'utf8'),{key,padding:crypto.constants.RSA_PKCS1_PADDING},bytes))Fail('BOOTSTRAP_PROOF_INVALID',401);
}
function FlowLive(row,allowClaimed=false){if(row?.machineId)MachinePolicy().AssertAllowed(row.machineId,row.machinePolicyGeneration,row.sessionId);if(row?.status==='EXPIRED')Fail('BOOTSTRAP_EXPIRED',403);if(!row)Fail('BOOTSTRAP_FLOW_INVALID',401);if(row.status==='REVOKED')Fail('BOOTSTRAP_REVOKED',403);if(row.status==='CLOSED')Fail('BOOTSTRAP_SESSION_CLOSED',403);if(row.status==='CLAIMED'){if(!allowClaimed)Fail('BOOTSTRAP_LAUNCHER_USED',409);if(row.sessionExpiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);}else if(row.expiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);}
function RequireFlowPair(row){const db=DB();require('./desktopSecurityOperations').RequireRuntimePair(db.artifacts[db.launchers[row.launcherId]?.artifactId],db.artifacts[row.releaseId],db.artifacts[row.overlayReleaseId]);}
function DownloadFlow(body,allowClaimed=false){const row=DB().flows[body.flowId];FlowLive(row,allowClaimed);if(!EqualHash(body.downloadTicket,row.downloadHash))Fail('BOOTSTRAP_FLOW_INVALID',401);require('./desktopSecurityAuthority').RequireArtifact(DB().artifacts[row.releaseId]);require('./desktopSecurityAuthority').RequireArtifact(DB().artifacts[DB().launchers[row.launcherId].artifactId]);RequireFlowPair(row);return row;}
function Begin(body){
 Fields(body,['requestId','launcherId','launcherTicket','launcherSha512','launcherCrc64','aCodeSha512','aCodeCrc64','publicKey','deviceId','machineId']);RequestId(body.requestId);const digest=Sha(body.launcherSha512),crc64=Crc(body.launcherCrc64),machineId=MachinePolicy().Validate(body.machineId);MachinePolicy().AssertAllowed(machineId);
 const parsed=require('./desktopLicenses').ParseKey(body.publicKey);if(body.deviceId!==parsed.deviceId)Fail('BOOTSTRAP_PROOF_INVALID',401);
 const db=DB(),launcher=db.launchers[body.launcherId];if(!launcher||!EqualHash(body.launcherTicket,launcher.ticketHash))Fail('BOOTSTRAP_LAUNCHER_INVALID',401);
 require('./desktopSecurityAuthority').RequireArtifact(db.artifacts[launcher.artifactId]);
 CheckFile(launcher,digest,crc64,{stage:'A',machineId,artifactId:launcher.artifactId});
 const aCodeSha512=Sha(body.aCodeSha512),aCodeCrc64=Crc(body.aCodeCrc64),aArtifact=db.artifacts[launcher.artifactId];CheckCode(aArtifact,aCodeSha512,aCodeCrc64,{stage:'A',machineId,launcherId:launcher.id});
 const fingerprint=hash(JSON.stringify({requestId:body.requestId,launcherId:body.launcherId,sha512:digest,crc64,aCodeSha512,aCodeCrc64,machineId,deviceId:parsed.deviceId,publicKey:parsed.publicKey}));
 if(launcher.status==='CONSUMED'){
  const prior=db.flows[launcher.flowId];if(!prior||prior.beginFingerprint!==fingerprint)Fail('BOOTSTRAP_LAUNCHER_USED',409);FlowLive(prior,true);RequireFlowPair(prior);return BeginResult(prior);
 }
 if(launcher.status==='REVOKED')Fail('BOOTSTRAP_REVOKED',403);if(launcher.status==='EXPIRED')Fail('BOOTSTRAP_EXPIRED',403);if(launcher.expiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);
 const release=db.artifacts[db.active.B];if(!release)Fail('BOOTSTRAP_NOT_READY',409);require('./desktopSecurityOperations').RequireRuntimePair(aArtifact,release,db.artifacts[db.active.O]);Pe(Bytes(release),'B');if(db.active.O)Pe(Bytes(db.artifacts[db.active.O]),'O');
 const row={id:Id(),sessionId:Id(),launcherId:launcher.id,launcherSha512:digest,launcherCrc64:crc64,aCodeSha512,aCodeCrc64,codeIntegrityStatus:'VERIFIED',lastCodeVerifiedAt:now(),machineId,machinePolicyGeneration:MachinePolicy().Generation(machineId),releaseId:release.id,...(db.active.O?{overlayReleaseId:db.active.O}:{}),deviceId:parsed.deviceId,publicKey:parsed.publicKey,beginFingerprint:fingerprint,status:'STARTED',createdAt:now(),expiresAt:now()+FLOW_MS,downloadNonce:Nonce(),finishNonce:Nonce(),chunkOffsets:[],licenseId:'',lastVerifiedAt:0};row.downloadHash=hash(DownloadTicket(row));
 Atomic(next=>{if(next.launchers[launcher.id].status!=='AVAILABLE')Fail('BOOTSTRAP_LAUNCHER_USED',409);next.launchers[launcher.id].status='CONSUMED';next.launchers[launcher.id].flowId=row.id;RetireLauncher(next.launchers[launcher.id]);next.flows[row.id]=row;});
 Audit('DESKTOP_BOOTSTRAP_BEGAN',{flowId:row.id,launcherId:row.launcherId,deviceId:row.deviceId,releaseId:row.releaseId});return BeginResult(row);
}
function BeginResult(row){return {flowId:row.id,downloadTicket:DownloadTicket(row),release:Release(DB().artifacts[row.releaseId]),chunkSize:CHUNK_SIZE,expiresAt:row.expiresAt,finishCanonical:FinishCanonical(row)};}
function Chunk(body){
 Fields(body,['flowId','downloadTicket','offset']);const row=DownloadFlow(body),artifact=DB().artifacts[row.releaseId];
 if(!Number.isSafeInteger(body.offset)||body.offset<0||body.offset>=artifact.size||body.offset%CHUNK_SIZE!==0)Fail('BOOTSTRAP_INPUT_INVALID');
 const size=Math.min(CHUNK_SIZE,artifact.size-body.offset),bytes=Buffer.alloc(size);let fd;
 try{const file=store.ArtifactPath(artifact.id);fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size!==artifact.size)throw Error();let read=0;while(read<size){const count=fs.readSync(fd,bytes,read,size-read,body.offset+read);if(!count)throw Error();read+=count;}}
 catch(_){Fail('BOOTSTRAP_ARTIFACT_INVALID',503);}finally{if(fd!==undefined)fs.closeSync(fd);}
 // Receipt is committed before acknowledging a chunk; retries of a lost reply
 // read the same frozen artifact and never skip verification/download coverage.
 if(!row.chunkOffsets.includes(body.offset))Atomic(db=>{db.flows[row.id].chunkOffsets.push(body.offset);});
 return {offset:body.offset,data:bytes.toString('base64'),size};
}
function Finish(body){
 Fields(body,['flowId','downloadTicket','sha512','crc64','aCodeSha512','aCodeCrc64','signature']);const row=DownloadFlow(body,true),artifact=DB().artifacts[row.releaseId];CheckFile(artifact,Sha(body.sha512),Crc(body.crc64),{stage:'B',row});Verify(row,FinishCanonical(row),body.signature);CheckCode(DB().artifacts[DB().launchers[row.launcherId].artifactId],Sha(body.aCodeSha512),Crc(body.aCodeCrc64),{stage:'A',row});Bytes(artifact);
 require('./desktopIntegrityReports').RequireSnapshot(row,'A');
 require('./desktopSecurityAuthority').RequireFresh(row,'A','finish',require('./desktopSecurityAuthority').Binding(row.id,artifact.sha512));
 if(row.status==='CLAIMED'||row.status==='DOWNLOADED'){if(row.handoffExpiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);return FinishResult(row);}
 if(row.chunkOffsets.length!==Math.ceil(artifact.size/CHUNK_SIZE))Fail('BOOTSTRAP_DOWNLOAD_INCOMPLETE',409);
 Atomic(db=>{const item=db.flows[row.id];item.status='DOWNLOADED';item.downloadedAt=now();item.handoffNonce=Nonce();item.claimNonce=Nonce();item.handoffExpiresAt=Math.min(item.expiresAt,now()+HANDOFF_MS);item.handoffHash=hash(HandoffToken(item));});
 return FinishResult(DB().flows[row.id]);
}
function FinishResult(row){return {handoffToken:HandoffToken(row),claimCanonical:ClaimCanonical(row),expiresAt:row.handoffExpiresAt};}
function Claim(body){
 Fields(body,['flowId','handoffToken','signature','binarySha512','crc64','bCodeSha512','bCodeCrc64']);const row=DB().flows[body.flowId];FlowLive(row,true);
 if(!['DOWNLOADED','CLAIMED'].includes(row.status)||!EqualHash(body.handoffToken,row.handoffHash))Fail('BOOTSTRAP_FLOW_INVALID',401);
 RequireFlowPair(row);
 const artifact=DB().artifacts[row.releaseId];CheckFile(artifact,Sha(body.binarySha512),Crc(body.crc64),{stage:'B',row});Verify(row,ClaimCanonical(row),body.signature);CheckCode(artifact,Sha(body.bCodeSha512),Crc(body.bCodeCrc64),{stage:'B',row});Bytes(artifact);
 if(row.status==='CLAIMED')return ClaimResult(row);
 if(row.handoffExpiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);
 Atomic(db=>{const item=db.flows[row.id];item.bCodeSha512=artifact.codeSha512;item.bCodeCrc64=artifact.codeCrc64;item.codeIntegrityStatus='VERIFIED';item.lastCodeVerifiedAt=now();item.status='CLAIMED';item.claimedAt=now();item.sessionNonce=Nonce();item.sessionHash=hash(SessionToken(item));item.sessionExpiresAt=now()+SESSION_MS;});
 const claimed=DB().flows[row.id];Audit('DESKTOP_BOOTSTRAP_CLAIMED',{flowId:claimed.id,sessionId:claimed.sessionId,deviceId:claimed.deviceId,releaseId:claimed.releaseId});return ClaimResult(claimed);
}
function ClaimResult(row){return {sessionId:row.sessionId,sessionToken:SessionToken(row),expiresAt:row.sessionExpiresAt,release:Release(DB().artifacts[row.releaseId])};}
function FindSession(id){return Object.values(DB().flows).find(row=>row.sessionId===id);}
function SessionAuthenticated(id,token){const row=FindSession(id);if(!row||!row.sessionHash||!EqualHash(token,row.sessionHash))Fail('BOOTSTRAP_SESSION_INVALID',401);return row;}
function Gate(id,token,deviceId,options={}){
 Available();if(!id||!token)Fail('BOOTSTRAP_REQUIRED',403);const row=SessionAuthenticated(id,token);
 const released=options.allowReleased&&row.status==='CLOSED'&&row.closedByLicenseRelease;
 if(!released)FlowLive(row,true);
 const artifact=DB().artifacts[row.releaseId];if(MachinePolicy().Validate(options.machineId)!==row.machineId)Fail('BOOTSTRAP_HASH_MISMATCH',403);CheckFile(artifact,Sha(options.binarySha512),Crc(options.binaryCrc64),{stage:'B',row});MachinePolicy().AssertAllowed(row.machineId,row.machinePolicyGeneration,row.sessionId);
 if((row.status!=='CLAIMED'&&!released)||row.deviceId!==deviceId)Fail('BOOTSTRAP_SESSION_INVALID',403);CheckCode(artifact,Sha(options.codeSha512),Crc(options.codeCrc64),{stage:'B',row});if(!released)require('./desktopIntegrityReports').RequireSnapshot(row,'B');
 if(!released&&options.securityIntent!=='release'){RequireFlowPair(row);require('./desktopSecurityAuthority').RequireFresh(row,'B',options.securityIntent||'verify',options.securityBinding||'');}return row;
}
function RecordIntegritySuccess(info){
 const key=info.stage+':'+info.sessionId+':'+info.check,at=now();if(at-(integritySuccessTimes.get(key)||0)<10000)return;
 try{require('./desktopIntegrityReports').Record(info);integritySuccessTimes.delete(key);integritySuccessTimes.set(key,at);if(integritySuccessTimes.size>4096)integritySuccessTimes.delete(integritySuccessTimes.keys().next().value);}catch(_){Audit('DESKTOP_INTEGRITY_REPORT_FAILED',{stage:info.stage,sessionId:info.sessionId,check:info.check});}
}
function CheckFile(artifact,sha512,crc64,context){
 if(artifact&&sha512===artifact.sha512&&crc64===artifact.crc64)return;
 const row=context.row,info={stage:context.stage,machineId:row?.machineId||context.machineId||'',flowId:row?.id||'',sessionId:row?.sessionId||'',artifactId:context.artifactId||artifact?.id||'',check:'OWN_FILE',status:'REJECTED',reason:'FILE_DIGEST_MISMATCH',expectedSha512:artifact?.sha512||'',observedSha512:sha512,expectedCrc64:artifact?.crc64||'',observedCrc64:crc64,trusted:true};
 try{require('./desktopIntegrityReports').Record(info);}catch(_){Audit('DESKTOP_INTEGRITY_REJECTED',info);}
 Fail('BOOTSTRAP_HASH_MISMATCH',403);
}
// Compare only with a baseline computed from administrator-published bytes.
// This detects changes reported by an honest verifier, not privileged evasion.
function CheckCode(artifact,sha512,crc64,context){
 const row=context.row,info={stage:context.stage,machineId:row?.machineId||context.machineId||'',flowId:row?.id||'',sessionId:row?.sessionId||'',artifactId:artifact?.id||'',check:'OWN_CODE',expectedSha512:artifact?.codeSha512||'',observedSha512:sha512,expectedCrc64:artifact?.codeCrc64||'',observedCrc64:crc64,trusted:true};
 const valid=artifact&&sha512===artifact.codeSha512&&crc64===artifact.codeCrc64;
 if(valid){if(row)RecordIntegritySuccess({...info,status:'VERIFIED',reason:'BASELINE_MATCH'});return;}
 info.status='REJECTED';info.reason='CODE_DIGEST_MISMATCH';
 try{require('./desktopIntegrityReports').Record(info);}catch(_){Audit('DESKTOP_INTEGRITY_REJECTED',info);}
 if(row&&!['CLOSED','REVOKED','EXPIRED'].includes(row.status))Atomic(db=>{const item=db.flows[row.id];item.status='REVOKED';item.revokedAt=now();item.reason='CODE_DIGEST_MISMATCH';item.codeIntegrityStatus='REJECTED';item.lastCodeVerifiedAt=now();RetireFlow(item);});
 Fail('BOOTSTRAP_CODE_MISMATCH',403);
}
function AuthenticateIntegrityReport(body){
 const stage=body.stage===undefined?'B':body.stage;if(stage==='O')return require('./desktopOverlay').AuthenticateIntegrityReport(body);if(!['A','B'].includes(stage))Fail('BOOTSTRAP_INPUT_INVALID');
 let row,artifact;
 if(stage==='A'){
  row=DB().flows[body.sessionId];if(!row||!EqualHash(body.sessionToken,row.downloadHash))Fail('BOOTSTRAP_FLOW_INVALID',401);
  FlowLive(row);if(!['STARTED','DOWNLOADED'].includes(row.status))Fail('BOOTSTRAP_FLOW_INVALID',403);if(row.status==='DOWNLOADED'&&row.handoffExpiresAt<=now())Fail('BOOTSTRAP_EXPIRED',403);
  artifact=DB().artifacts[DB().launchers[row.launcherId].artifactId];
 }else{
  row=SessionAuthenticated(body.sessionId,body.sessionToken);FlowLive(row,true);if(row.status!=='CLAIMED')Fail('BOOTSTRAP_SESSION_INVALID',403);
  artifact=DB().artifacts[row.releaseId];
 }
 if(body.machineId!==undefined&&MachinePolicy().Validate(body.machineId)!==row.machineId)Fail('BOOTSTRAP_SESSION_INVALID',403);
 return {...row,stage,reportContextId:stage==='A'?row.id:row.sessionId,integrityArtifact:{id:artifact.id,hashVersion:3,sha512:stage==='A'?row.launcherSha512:artifact.sha512,crc64:stage==='A'?row.launcherCrc64:artifact.crc64,fileXxh3_128:stage==='A'?DB().launchers[row.launcherId].xxh3_128:artifact.xxh3_128,fileBlake3:stage==='A'?DB().launchers[row.launcherId].blake3:artifact.blake3,codeSha512:artifact.codeSha512,codeCrc64:artifact.codeCrc64,codeXxh3_128:artifact.codeXxh3_128,codeBlake3:artifact.codeBlake3,crcLayers:artifact.crcLayers}};
}
function LicenseState(row){
 if(!row.licenseId)return {licenseStatus:'',licenseLastVerifiedAt:0};
 const license=require('./desktopLicenses').DB().licenses[row.licenseId];if(!license)return {licenseStatus:'UNKNOWN',licenseLastVerifiedAt:0};
 const view=require('./desktopLicenses').Public(license);return {licenseStatus:view.status,licenseLastVerifiedAt:Math.max(view.lastVerifiedAt,row.lastVerifiedAt||0)};
}
function EffectiveExpiry(row){return row.sessionExpiresAt|| (row.handoffExpiresAt?Math.min(row.expiresAt,row.handoffExpiresAt):row.expiresAt);}
function ProjectStatus(row){if(['CLOSED','REVOKED','EXPIRED'].includes(row.status))return row.status;if(row.machineId){const policy=MachinePolicy().Public(row.machineId);if(policy.blocked&&policy.allowedSessionId!==row.sessionId||policy.generation!==row.machinePolicyGeneration)return 'REVOKED';}if(EffectiveExpiry(row)<=now())return 'EXPIRED';return row.status;}
function SessionView(row){const status=ProjectStatus(row);return {id:row.sessionId,flowId:row.id,launcherId:row.launcherId,status,online:status==='CLAIMED',deviceId:row.deviceId,machineId:row.machineId||'',binarySha512:DB().artifacts[row.releaseId]?.sha512||'',binaryCrc64:DB().artifacts[row.releaseId]?.crc64||'',codeSha512:DB().artifacts[row.releaseId]?.codeSha512||'',codeCrc64:DB().artifacts[row.releaseId]?.codeCrc64||'',codeIntegrityStatus:row.codeIntegrityStatus||'UNMEASURED',lastCodeVerifiedAt:row.lastCodeVerifiedAt||0,releaseId:row.releaseId,version:DB().artifacts[row.releaseId]?.version||'',createdAt:row.createdAt,claimedAt:row.claimedAt||0,expiresAt:EffectiveExpiry(row),lastVerifiedAt:row.lastVerifiedAt||0,licenseId:row.licenseId||'',...LicenseState(row),revokedAt:row.revokedAt||0,reason:row.reason||''};}
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
 const row=FindSession(id);if(!row)return require('./desktopOverlay').Revoke(id,body,actor);
 if(row.status!=='REVOKED')Atomic(db=>{const item=db.flows[row.id];item.status='REVOKED';item.revokedAt=now();item.reason=body.reason.trim();item.revokedBy=String(actor).slice(0,160);if(actor==='INTEGRITY_REPORT'){item.codeIntegrityStatus='REJECTED';item.lastCodeVerifiedAt=now();}db.launchers[item.launcherId].status='REVOKED';RetireLauncher(db.launchers[item.launcherId]);RetireFlow(item);});
 Audit('DESKTOP_BOOTSTRAP_REVOKED',{sessionId:id,licenseId:row.licenseId||'',actor:String(actor).slice(0,160)});return SessionView(DB().flows[row.id]);
}
function TouchLicense(id,token,deviceId,license,action,verification={}){
 // desktopLicenses calls Gate before its synchronous journal transaction.
 // Do not re-check the wall clock after that durable commit: a slow fsync on
 // the expiry boundary must not consume a key without renewing its session.
 const row=SessionAuthenticated(id,token),released=action==='release'&&row.status==='CLOSED'&&row.closedByLicenseRelease;
 if((row.status!=='CLAIMED'&&!released)||row.deviceId!==deviceId)Fail('BOOTSTRAP_SESSION_INVALID',403);
 if(row.licenseId&&row.licenseId!==license.id)Fail('BOOTSTRAP_LICENSE_MISMATCH',409);
 Atomic(db=>{const item=db.flows[row.id];item.licenseId=license.id;item.codeIntegrityStatus='VERIFIED';item.lastCodeVerifiedAt=now();item.lastVerifiedAt=now();item.licenseLeaseExpiresAt=Number(verification.leaseExpiresAt)||0;item.appVersion=typeof verification.appVersion==='string'?verification.appVersion.slice(0,40):'';item.sessionExpiresAt=Math.min(now()+SESSION_MS,license.expiresAt||Number.MAX_SAFE_INTEGER);if(action==='release'){item.status='CLOSED';item.closedAt=now();item.closedByLicenseRelease=true;RetireFlow(item);}});
}
function LicenseActivity(id){
 // This direct projection intentionally never calls desktopLicenses.Public or
 // Overview: Public consumes it, including after a server restart.
 const db=DB();if(activityRevision!==db.revision){const index=new Map();for(const row of Object.values(db.flows)){if(!row.licenseId)continue;const old=index.get(row.licenseId);if(!old||row.lastVerifiedAt>=old.lastVerifiedAt)index.set(row.licenseId,{lastVerifiedAt:row.lastVerifiedAt||0,leaseExpiresAt:row.licenseLeaseExpiresAt||0,appVersion:row.appVersion||'',sessionId:row.sessionId,sessionStatus:row.status});}for(const row of Object.values(db.overlays||{})){const old=index.get(row.licenseId);if(!old||row.lastVerifiedAt>=old.lastVerifiedAt)index.set(row.licenseId,{lastVerifiedAt:row.lastVerifiedAt||0,leaseExpiresAt:row.status==='CLAIMED'?row.sessionExpiresAt:0,appVersion:db.artifacts[row.releaseId]?.version||'',sessionId:row.parentSessionId,overlaySessionId:row.sessionId,sessionStatus:row.status});}activityIndex=index;activityRevision=db.revision;}
 return activityIndex.get(id)||null;
}
function RetireLauncher(row){delete row.ticketNonce;delete row.profile;row.retiredAt||=now();}
function RetireFlow(row){RetireRuntime(row);for(const key of ['downloadNonce','finishNonce','handoffNonce','claimNonce','sessionNonce'])delete row[key];row.retiredAt||=now();}
function RetireRuntime(row){require('./desktopSecurityAuthority').RetireContext(row,'A');require('./desktopSecurityAuthority').RetireContext(row,'B');require('./desktopIntegrityReports').RetireContext(row);require('./desktopLicenses').RetireRuntime(row);for(const key of integritySuccessTimes.keys())if(key.includes(':'+row.sessionId+':'))integritySuccessTimes.delete(key);}
function Prune(){
 const db=DB(),at=now(),launchers=Object.values(db.launchers).filter(row=>row.status==='AVAILABLE'&&row.expiresAt<=at||row.status!=='AVAILABLE'&&!row.retiredAt),flows=Object.values(db.flows).filter(row=>!['CLOSED','REVOKED','EXPIRED'].includes(row.status)&&EffectiveExpiry(row)<=at||['CLOSED','REVOKED','EXPIRED'].includes(row.status)&&!row.retiredAt);
 if(!launchers.length&&!flows.length)return;
 Atomic(next=>{
  for(const row of launchers){const item=next.launchers[row.id];if(item.status==='AVAILABLE')item.status='EXPIRED';RetireLauncher(item);}
  for(const row of flows){const item=next.flows[row.id];if(!['CLOSED','REVOKED','EXPIRED'].includes(item.status))item.status='EXPIRED';RetireFlow(item);}
 });
}
function Initialize(){DB();Prune();if(!retirementTimer){retirementTimer=setInterval(()=>{try{Prune();require('./desktopOverlay').Prune();}catch(_){console.error('BOOTSTRAP_RETIREMENT_FAILED');}},1000);retirementTimer.unref();}return DB();}
function Overview(){
 Prune();const db=DB();return {artifacts:{A:Artifact(db.artifacts[db.active.A]),B:Artifact(db.artifacts[db.active.B]),O:Artifact(db.artifacts[db.active.O])},launchers:Object.values(db.launchers).map(row=>({id:row.id,downloadName:LauncherName(row),label:row.label,issuedAt:row.issuedAt,expiresAt:row.expiresAt,status:row.status==='AVAILABLE'&&row.expiresAt<=now()?'EXPIRED':row.status,flowId:row.flowId||'',sha512:row.sha512,crc64:row.crc64})).sort((a,b)=>b.issuedAt-a.issuedAt),sessions:[...Object.values(db.flows).map(SessionView),...require('./desktopOverlay').List()].sort((a,b)=>b.createdAt-a.createdAt),limits:{maxArtifactBytes:MAX_ARTIFACT_BYTES,chunkSize:CHUNK_SIZE,launcherLifetimeMs:LAUNCHER_MS,flowLifetimeMs:FLOW_MS,sessionLifetimeMs:SESSION_MS},serverTime:now()};
}
function Execute(body){if(!Plain(body))Fail('BOOTSTRAP_INPUT_INVALID');if(typeof body.action==='string'&&body.action.startsWith('overlay')){if(body.action!=='overlayClose')Available();else DB();return require('./desktopOverlay').Execute(body);}if(['close','abort'].includes(body.action)){DB();Prune();}else Available();switch(body.action){case 'begin':return Begin(body);case 'chunk':return Chunk(body);case 'finish':return Finish(body);case 'claim':return Claim(body);case 'status':return Status(body);case 'close':return Close(body);case 'abort':return Abort(body);default:Fail('BOOTSTRAP_INPUT_INVALID');}}
module.exports={RetireFlow,RetireRuntime,Release,Verify,CheckFile,CheckCode,EqualHash,Artifact,SessionAuthenticated,RequireFlowPair,ReadArtifactBytes:Bytes,EnsureSecurityAvailable:Available,MAX_ARTIFACT_BYTES,CHUNK_SIZE,LAUNCHER_MS,FLOW_MS,HANDOFF_MS,SESSION_MS,FOOTER,messages,Fail,Initialize,Publish,IssueLauncher,LauncherBytes,LauncherName,Execute,Gate,AuthenticateIntegrityReport,TouchLicense,LicenseActivity,Overview,SessionView,Revoke};
