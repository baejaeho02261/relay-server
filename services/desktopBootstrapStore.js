'use strict';
// One writer, one durable DATA_DIR. This authority is deliberately outside the
// administrator's restorable database: restoring a snapshot must not revive a
// launcher ticket, handoff, or closed session. HA snapshot replication is not
// supported for this store; deploy this service with HA_ENABLED=0 and one replica.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const config=require('../config/config');
const DIR=path.join(config.DATA_DIR,'desktop-bootstrap'),FILE=path.join(DIR,'authority.json');
let current,poisoned=false;
// Read-only compatibility with schema 1 authority. Historical bytes are explicit
// migration constants, never the protocol or HMAC domain for new capabilities.
const LEGACY_PROTOCOL=Buffer.from('4d4f41504c41592d434f4e4e4543542d31','hex').toString('ascii');
const LEGACY_TOKEN_DOMAIN=Buffer.from('4d4f41504c41592d413830','hex').toString('ascii');
const PROTOCOL='GAME-CONNECT-3';
function Identifier(value,legacyPrefix){return typeof value==='string'&&(/^[A-F0-9]{24}$/.test(value)||new RegExp('^'+legacyPrefix+'-[A-F0-9]{24}$').test(value));}
function SyncDir(){if(process.platform==='win32')return;const fd=fs.openSync(DIR,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Plain(x){return !!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function Time(x){return Number.isSafeInteger(x)&&x>0;}
function Nonce(x){return typeof x==='string'&&/^[a-f0-9]{48}$/.test(x);}
function Digest(x){return typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);}
function Crc(x){return typeof x==='string'&&/^[A-F0-9]{16}$/.test(x);}
function ExtendedFields(row){return ['xxh64','codeXxh64'].every(key=>row[key]===undefined||typeof row[key]==='string'&&/^[a-f0-9]{16}$/.test(row[key]))&&['blake3','codeBlake3'].every(key=>row[key]===undefined||Digest(row[key]));}
function Machine(x){return typeof x==='string'&&/^[A-F0-9]{64}$/.test(x);}
function Invalid(){throw Error('BOOTSTRAP_STORAGE_INVALID');}
function TokenHash(secret,domain,id,nonce,legacy=false){return crypto.createHash('sha256').update(crypto.createHmac('sha256',Buffer.from(secret,'hex')).update([legacy?LEGACY_TOKEN_DOMAIN:'GAME-A80',domain,id,nonce].join('|')).digest('base64url')).digest('hex');}
function Load(){
 if(current)return current;
 if(config.HA_ENABLED)throw Error('BOOTSTRAP_SINGLE_WRITER_REQUIRED');
 fs.mkdirSync(DIR,{recursive:true,mode:0o700});
 if(fs.existsSync(FILE)){
  const stat=fs.lstatSync(FILE);if(!stat.isFile()||stat.isSymbolicLink())throw Error('BOOTSTRAP_STORAGE_INVALID');
  let value;try{value=JSON.parse(fs.readFileSync(FILE,'utf8'));}catch(_){throw Error('BOOTSTRAP_STORAGE_INVALID');}
  if(!Plain(value)||![1,2,3,4].includes(value.schema)||!Number.isSafeInteger(value.revision)||value.revision<0||!/^[a-f0-9]{64}$/.test(value.secret)||!['artifacts','active','launchers','flows','issueReceipts'].every(key=>Plain(value[key])))throw Error('BOOTSTRAP_STORAGE_INVALID');
  if(value.workspaceGarbage!==undefined){
   if(!Plain(value.workspaceGarbage))Invalid();
   for(const [id,g]of Object.entries(value.workspaceGarbage))if(!Identifier(id,'DA')||!Plain(g)||!Digest(g.sha256)||!Number.isSafeInteger(g.size)||g.size<1||!Time(g.createdAt)||(g.deletedAt!==undefined&&!Time(g.deletedAt))||value.artifacts[id])Invalid();
  }
  if(value.securityOperations!==undefined){try{require('./desktopSecurityOperations').ValidateState(value.securityOperations);}catch(_){Invalid();}}
  if(value.securityActivation!==undefined){try{require('./desktopSecurityActivation').ValidateRecord(value.securityActivation);}catch(_){Invalid();}}
  if(value.securityAuthorityPolicy!==undefined){try{require('./desktopSecurityAuthority').ValidatePolicy(value.securityAuthorityPolicy);}catch(_){Invalid();}}
  for(const artifact of Object.values(value.artifacts)){if(artifact.authorityVersion!==undefined&&![0,1].includes(artifact.authorityVersion)||artifact.compiledCfg!==undefined&&typeof artifact.compiledCfg!=='boolean')Invalid();}
  const legacy=value.schema===1,upgrade=value.schema<4,previousProtocol=value.schema<=2?'GAME-CONNECT-1':'GAME-CONNECT-2',previousVersion=value.schema<=2?1:2;
  for(const [id,row]of Object.entries(value.artifacts))if(!Identifier(id,'DA')||!Plain(row)||!ExtendedFields(row)||row.id!==id||!['A','B'].includes(row.component)||!Digest(row.sha256)||!Number.isSafeInteger(row.size)||row.size<1||row.size>64*1024*1024||!Time(row.createdAt)||(row.protocol===PROTOCOL&&(!Crc(row.crc64)||!Digest(row.codeSha256)||!Crc(row.codeCrc64)||row.codeAlgorithm!=='PE64-CODE-V1'))||typeof row.version!=='string'||!/^\d+(?:\.\d+){0,3}$/.test(row.version))Invalid();
  for(const [component,id]of Object.entries(value.active))if(!['A','B'].includes(component)||value.artifacts[id]?.component!==component||!legacy&&value.artifacts[id]?.protocol!==(upgrade?previousProtocol:PROTOCOL))Invalid();
  for(const [id,row]of Object.entries(value.launchers)){
   if(!Identifier(id,'LA')||!Plain(row)||row.id!==id||!['AVAILABLE','CONSUMED','REVOKED','EXPIRED'].includes(row.status)||!Digest(row.sha256)||!Digest(row.ticketHash)||!Time(row.issuedAt)||!Time(row.expiresAt)||row.expiresAt<=row.issuedAt||value.artifacts[row.artifactId]?.component!=='A'||typeof row.label!=='string'||row.label.length>120)Invalid();
   if(row.assignedLicenseId!==undefined&&!Identifier(row.assignedLicenseId,'DL'))Invalid();
   if(row.crc64!==undefined&&!Crc(row.crc64)||!ExtendedFields(row))Invalid();
   if(row.downloadName!==undefined&&!/^[a-f0-9]{32}\.exe$/.test(row.downloadName))Invalid();
   if(row.retiredAt!==undefined){if(!Time(row.retiredAt)||row.status==='AVAILABLE'||row.ticketNonce!==undefined||row.profile!==undefined)Invalid();}
   else if(!Nonce(row.ticketNonce)||!Plain(row.profile)||row.profile.protocol!==(legacy?LEGACY_PROTOCOL:upgrade?previousProtocol:PROTOCOL)||row.profile.version!==(upgrade?previousVersion:3)||(!upgrade&&(!Crc(row.crc64)||!Digest(row.profile.tlsCertificateSha256)||typeof row.profile.tlsServerName!=='string'||row.profile.tlsServerName.length<1||row.profile.tlsServerName.length>253))||row.ticketHash!==TokenHash(value.secret,'LAUNCHER',id,row.ticketNonce,legacy))Invalid();
   if(['CONSUMED','REVOKED'].includes(row.status)&&(!value.flows[row.flowId]||value.flows[row.flowId].launcherId!==id))Invalid();
  }
  const sessionIds=new Set();
  for(const [id,row]of Object.entries(value.flows)){
   if(!Identifier(id,'BF')||!Plain(row)||row.id!==id||!['STARTED','DOWNLOADED','CLAIMED','CLOSED','REVOKED','EXPIRED'].includes(row.status)||!Identifier(row.sessionId,'DS')||sessionIds.has(row.sessionId)||!/^[A-F0-9]{64}$/.test(row.deviceId)||typeof row.publicKey!=='string'||row.publicKey.length>500||crypto.createHash('sha256').update(Buffer.from(row.publicKey,'base64')).digest('hex').toUpperCase()!==row.deviceId||!Time(row.createdAt)||!Time(row.expiresAt)||row.expiresAt<=row.createdAt||!Digest(row.beginFingerprint)||!Digest(row.launcherSha256)||!Digest(row.downloadHash)||value.launchers[row.launcherId]?.flowId!==id||value.artifacts[row.releaseId]?.component!=='B')Invalid();
   sessionIds.add(row.sessionId);
   if(row.machineId!==undefined&&(!Machine(row.machineId)||!Number.isSafeInteger(row.machinePolicyGeneration)||row.machinePolicyGeneration<0||!Crc(row.launcherCrc64)))Invalid();
   if(!upgrade&&!['CLOSED','REVOKED','EXPIRED'].includes(row.status)&&(!Machine(row.machineId)||!Crc(row.launcherCrc64)||value.artifacts[row.releaseId]?.protocol!==PROTOCOL||!Digest(row.aCodeSha256)||!Crc(row.aCodeCrc64)))Invalid();
   if(!Array.isArray(row.chunkOffsets)||row.chunkOffsets.length>256||new Set(row.chunkOffsets).size!==row.chunkOffsets.length||row.chunkOffsets.some(offset=>!Number.isSafeInteger(offset)||offset<0||offset>=value.artifacts[row.releaseId].size||offset%262144))Invalid();
   if(row.retiredAt!==undefined){
    if(!Time(row.retiredAt)||!['CLOSED','REVOKED','EXPIRED'].includes(row.status)||['downloadNonce','finishNonce','handoffNonce','claimNonce','sessionNonce'].some(key=>row[key]!==undefined))Invalid();
    if(row.handoffHash!==undefined&&(!Digest(row.handoffHash)||!Time(row.handoffExpiresAt)))Invalid();
    if(row.sessionHash!==undefined&&(!Digest(row.sessionHash)||!Time(row.claimedAt)||!Time(row.sessionExpiresAt)))Invalid();
   }else{
    if(!Nonce(row.downloadNonce)||!Nonce(row.finishNonce)||row.downloadHash!==TokenHash(value.secret,'DOWNLOAD',id,row.downloadNonce,legacy))Invalid();
    if(row.handoffNonce!==undefined){if(!Nonce(row.handoffNonce)||!Nonce(row.claimNonce)||!Time(row.handoffExpiresAt)||row.handoffHash!==TokenHash(value.secret,'HANDOFF',id,row.handoffNonce,legacy))Invalid();}
    else if(['DOWNLOADED','CLAIMED'].includes(row.status))Invalid();
    if(row.sessionNonce!==undefined){if(!Nonce(row.sessionNonce)||!Time(row.claimedAt)||!Time(row.sessionExpiresAt)||row.sessionHash!==TokenHash(value.secret,'SESSION',row.sessionId,row.sessionNonce,legacy))Invalid();}
    else if(row.status==='CLAIMED')Invalid();
   }
   if(typeof row.licenseId!=='string'||row.licenseId&&!Identifier(row.licenseId,'DL')||!Number.isSafeInteger(row.lastVerifiedAt)||row.lastVerifiedAt<0)Invalid();
   if(row.lastSecurityIntent!==undefined&&!['redeem','verify','release'].includes(row.lastSecurityIntent)||row.lastSecurityBinding!==undefined&&row.lastSecurityBinding!==''&&!Digest(row.lastSecurityBinding))Invalid();
   if(row.closedByLicenseCompletion!==undefined&&(row.closedByLicenseCompletion!==true||!Identifier(row.overlaySessionId,'OS')||!['CLOSED','REVOKED','EXPIRED'].includes(row.status)))Invalid();
  }
  if(value.overlayState!==undefined){try{require('./desktopOverlay').ValidateState(value.overlayState,value);}catch(_){Invalid();}}
  for(const receipt of Object.values(value.issueReceipts))if(!Plain(receipt)||!Digest(receipt.fingerprint)||!value.launchers[receipt.launcherId])Invalid();
  if(upgrade){
   // Protocol upgrades cannot reuse native templates or old secret capabilities.
   // Preserve the authority secret, artifacts and all consumed/audit tombstones;
   // retire running/pending flows durably before serving any new requests.
   const at=Date.now();value.schema=4;value.revision++;value.protocolMigratedAt=at;value.active={};
   for(const row of Object.values(value.launchers)){
    if(row.status==='AVAILABLE')row.status='EXPIRED';
    delete row.ticketNonce;delete row.profile;row.retiredAt||=at;
   }
   for(const row of Object.values(value.flows)){
    if(!['CLOSED','REVOKED','EXPIRED'].includes(row.status)){row.status='REVOKED';row.revokedAt=at;row.reason='CODE_INTEGRITY_UPGRADE';}
    for(const key of ['downloadNonce','finishNonce','handoffNonce','claimNonce','sessionNonce'])delete row[key];row.retiredAt||=at;
   }
   Write(value);
  }
  current=value;
 }else{
  current={schema:4,revision:0,secret:crypto.randomBytes(32).toString('hex'),artifacts:{},active:{},launchers:{},flows:{},issueReceipts:{}};
  try{Write(current,true);}catch(error){current=undefined;throw error;}
 }
 return current;
}
function Write(value,initial=false){
 const temporary=FILE+'.'+crypto.randomBytes(12).toString('hex')+'.tmp';let fd,published=false;
 try{
  fd=fs.openSync(temporary,'wx',0o600);fs.writeFileSync(fd,JSON.stringify(value));fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
  if(initial){fs.linkSync(temporary,FILE);fs.unlinkSync(temporary);}else fs.renameSync(temporary,FILE);
  published=true;SyncDir();
 }catch(error){
  // Once rename succeeds, never allow a retry against rolled-back RAM. A
  // directory-fsync error has an uncertain durable outcome and needs restart.
  if(published)poisoned=true;
  throw error;
 }finally{if(fd!==undefined)try{fs.closeSync(fd);}catch(_){}try{fs.unlinkSync(temporary);}catch(_){} }
}
function Atomic(fn){
 if(poisoned)throw Error('BOOTSTRAP_STORAGE_RESTART_REQUIRED');
 const before=Load(),next=structuredClone(before),result=fn(next);
 next.revision=before.revision+1;
 try{Write(next);current=next;}catch(error){if(poisoned)current=next;throw error;}
 return result;
}
function ArtifactPath(id){if(!Identifier(id,'DA'))throw Error('BOOTSTRAP_ARTIFACT_INVALID');return path.join(DIR,id+'.exe');}
function PublishBytes(id,bytes){
 Load();const file=ArtifactPath(id),tmp=file+'.'+crypto.randomBytes(12).toString('hex')+'.tmp';let fd;
 try{fd=fs.openSync(tmp,'wx',0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;fs.linkSync(tmp,file);fs.unlinkSync(tmp);SyncDir();}
 finally{if(fd!==undefined)try{fs.closeSync(fd);}catch(_){}try{fs.unlinkSync(tmp);}catch(_){} }
}
module.exports={DIR,Load,Atomic,ArtifactPath,PublishBytes};
