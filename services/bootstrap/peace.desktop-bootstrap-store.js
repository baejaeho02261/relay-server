'use strict';
// One writer, one durable DATA_DIR. This authority is deliberately outside the
// administrator's restorable database: restoring a snapshot must not revive a
// launcher ticket, handoff, or closed session. HA snapshot replication is not
// supported for this store; deploy this service with HA_ENABLED=0 and one replica.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const config=require("../../config/peace.runtime-configuration");
const DIR=path.join(config.DATA_DIR,'desktop-bootstrap'),FILE=path.join(DIR,'authority.json');
let current,poisoned=false,commitCallbacks;
const HEAD=FILE+'.head';
function Anchor(value){return require("../licensing/peace.desktop-journal-head").Create(HEAD,Buffer.from(value.secret,'hex'),'DESKTOP_BOOTSTRAP');}
function Mark(value,raw){return {seq:value.revision,hash:crypto.createHash('sha256').update(raw).digest('hex')};}
// Read-only compatibility with schema 1 authority. Historical bytes are explicit
// migration constants, never the protocol or HMAC domain for new capabilities.
const LEGACY_PROTOCOL=Buffer.from('4d4f41504c41592d434f4e4e4543542d31','hex').toString('ascii');
const LEGACY_TOKEN_DOMAIN=Buffer.from('4d4f41504c41592d413830','hex').toString('ascii');
const PROTOCOL='GAME-CONNECT-4';
function Identifier(value,legacyPrefix){return typeof value==='string'&&(/^[A-F0-9]{24}$/.test(value)||new RegExp('^'+legacyPrefix+'-[A-F0-9]{24}$').test(value));}
function SyncDir(){if(process.platform==='win32')return;const fd=fs.openSync(DIR,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Plain(x){return !!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function Time(x){return Number.isSafeInteger(x)&&x>0;}
function Nonce(x){return typeof x==='string'&&/^[a-f0-9]{48}$/.test(x);}
function Digest(x){return typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);}
function StrongDigest(x){return typeof x==='string'&&/^[a-f0-9]{128}$/.test(x);}
function Crc(x){return typeof x==='string'&&/^[A-F0-9]{16}$/.test(x);}
function ExtendedFields(row){return ['xxh3_128','codeXxh3_128'].every(key=>row[key]===undefined||typeof row[key]==='string'&&/^[a-f0-9]{32}$/.test(row[key]))&&['blake3','codeBlake3'].every(key=>row[key]===undefined||Digest(row[key]));}
function Machine(x){return typeof x==='string'&&/^[A-F0-9]{64}$/.test(x);}
function Invalid(){throw Error('BOOTSTRAP_STORAGE_INVALID');}
function OwnProtection(v,role){try{require('../artifacts/peace.cozy-protection-engine').ValidateMetadata(v);if(['SEALED','BOUND'].includes(v.state)&&v.role!==role)Invalid();}catch(_){Invalid();}}

function TokenHash(secret,domain,id,nonce,legacy=false){return crypto.createHash('sha256').update(crypto.createHmac('sha256',Buffer.from(secret,'hex')).update([legacy?LEGACY_TOKEN_DOMAIN:'GAME-A80',domain,id,nonce].join('|')).digest('base64url')).digest('hex');}
function Load(){
 if(poisoned)throw Error('BOOTSTRAP_STORAGE_RESTART_REQUIRED');
 if(current)return current;
 if(config.HA_ENABLED)throw Error('BOOTSTRAP_SINGLE_WRITER_REQUIRED');
 fs.mkdirSync(DIR,{recursive:true,mode:0o700});
 if(fs.existsSync(FILE)){
  const stat=fs.lstatSync(FILE);if(!stat.isFile()||stat.isSymbolicLink())throw Error('BOOTSTRAP_STORAGE_INVALID');
  let value,raw;try{raw=require("../storage/peace.durable-file").ReadRegular(FILE);value=require("../protocol/peace.strict-json").Parse(raw,{maxBytes:64*1024*1024,maxNodes:4000000});}catch(_){throw Error('BOOTSTRAP_STORAGE_INVALID');}
  if(!Plain(value)||![1,2,3,4,5].includes(value.schema)||!Number.isSafeInteger(value.revision)||value.revision<0||!/^[a-f0-9]{64}$/.test(value.secret)||!['artifacts','active','launchers','flows','issueReceipts'].every(key=>Plain(value[key])))throw Error('BOOTSTRAP_STORAGE_INVALID');

  if(value.securityOperations?.releaseGovernance&&['requireCiEvidence','ciKeys','ciEvidence'].some(k=>Object.hasOwn(value.securityOperations.releaseGovernance,k))){
   require('../storage/peace.desktop-single-writer').Acquire(config.DATA_DIR,{haEnabled:config.HA_ENABLED});
   if(!raw.equals(require('../storage/peace.durable-file').ReadRegular(FILE)))throw Error('BOOTSTRAP_STORAGE_RESTART_REQUIRED');
  }
  Anchor(value).Open(Mark(value,raw),!fs.existsSync(HEAD));
  let retiredGovernanceRemoved=false;
  if(value.securityOperations?.releaseGovernance){const old=value.securityOperations.releaseGovernance,upgraded=require('../artifacts/peace.desktop-release-provenance').UpgradeStoredState(old);retiredGovernanceRemoved=upgraded.changed;if(upgraded.changed)require('../security/peace.desktop-mitigation-profiles').MigrateProfileTrust(value,old);value.securityOperations.releaseGovernance=upgraded.value;}
  if(value.transportKeyRotation!==undefined)require("../network/peace.desktop-transport-rotation").Validate(value.transportKeyRotation);
  if(value.mitigationProfiles!==undefined)require("../security/peace.desktop-mitigation-profiles").ValidateStore(value.mitigationProfiles);
  if(value.mitigationCompatibility!==undefined)require("../security/peace.desktop-mitigation-compatibility").Validate(value.mitigationCompatibility);
  if(value.tlsPinTransition!==undefined)require("../network/peace.desktop-tls-pin-transition").Validate(value.tlsPinTransition);
  if(value.serverRecovery!==undefined)require("../recovery/peace.desktop-recovery").Validate(value);
  if(value.registrationResetAuthorization!==undefined)require('../operations/peace.registration-reset-authorization').Validate(value.registrationResetAuthorization);
  if(value.serverAuditOutbox!==undefined)require("../storage/peace.desktop-operation-audit").Validate(value.serverAuditOutbox);
  if(value.deviceRegistry!==undefined)require("../devices/peace.desktop-device-registry").Validate(value.deviceRegistry);
  if(value.deviceIdentity!==undefined)require("../devices/peace.desktop-device-identity").Validate(value.deviceIdentity);
  if(value.members!==undefined)require("../members/peace.desktop-members").Validate(value.members);
  if(value.serverPolicies!==undefined)require('../security/peace.server-policy-registry').ValidateStore(value);
  if(value.orphanQuarantine!==undefined)require("../storage/peace.desktop-orphan-files").Validate(value.orphanQuarantine);
  if(value.manualVerifications!==undefined)require("../runtime/peace.desktop-manual-verification").Validate(value.manualVerifications);
  if(value.adminCredentialRevocations!==undefined)require("../authentication/peace.admin-credential-revocations").Validate(value.adminCredentialRevocations);
  if(value.releaseSafety!==undefined)require("../artifacts/peace.desktop-release-safety").ValidateState(value.releaseSafety);
  try{require("../artifacts/peace.desktop-packing-evidence").ValidateStore(value);}catch(_){Invalid();}
  if(value.lifecycleTrace!==undefined)require("../observability/peace.desktop-lifecycle-trace").Validate(value.lifecycleTrace,value);

  if(value.schema<5){
   // Old native binaries have a different signed transcript and digest schema.
   // Preserve the original authority as a private immutable audit archive, but
   // do not relabel SHA-256 bytes as SHA-512 or revive any old capability.
   for(const [id,row] of Object.entries(value.artifacts))if(!Identifier(id,'DA')||!Plain(row)||!Digest(row.sha256)||!['A','B','O'].includes(row.component))Invalid();
   const original=Buffer.from(JSON.stringify(value)),archiveHash=crypto.createHash('sha512').update(original).digest('hex'),archiveName='authority.schema'+value.schema+'.'+archiveHash.slice(0,24)+'.archive.json',archiveFile=path.join(DIR,archiveName);
   let fd;try{fd=fs.openSync(archiveFile,'wx',0o600);fs.writeFileSync(fd,original);fs.fsyncSync(fd);}catch(error){if(error.code!=='EEXIST')throw error;const st=fs.lstatSync(archiveFile);if(!st.isFile()||st.isSymbolicLink()||crypto.createHash('sha512').update(fs.readFileSync(archiveFile)).digest('hex')!==archiveHash)Invalid();}finally{if(fd!==undefined)fs.closeSync(fd);}
   SyncDir();
   const previous=value,at=Date.now();value={schema:5,revision:previous.revision+1,secret:previous.secret,artifacts:{},active:{},launchers:{},flows:{},overlays:{},issueReceipts:{},protocolMigratedAt:at,legacyArchive:{file:archiveName,sha512:archiveHash,schema:previous.schema,at}};
   // License issuance/consumption has a separate authenticated journal and is
   // deliberately untouched. Keep policy strictness and release-key revocations.
   if(previous.securityAuthorityPolicy){const p=previous.securityAuthorityPolicy;value.securityAuthorityPolicy={...p,minVersionO:p.minVersionO||'0',revokedSha512:[],revokedLegacySha256:p.revokedSha256||[]};delete value.securityAuthorityPolicy.revokedSha256;}
   if(previous.securityOperations){const p=previous.securityOperations;value.securityOperations={...require("../security/peace.desktop-security-operations").Defaults(),revision:p.revision+1,requireBuildContract:p.requireBuildContract===true,requireTestEvidence:p.requireTestEvidence===true,signerStates:p.signerStates||{},...(p.releaseGovernance?{releaseGovernance:p.releaseGovernance}:{})};}
   if(value.securityAuthorityPolicy)require("../security/peace.desktop-security-authority").ValidatePolicy(value.securityAuthorityPolicy);
   if(value.securityOperations)require("../security/peace.desktop-security-operations").ValidateState(value.securityOperations);
   Write(value);
  }
  if(value.workspaceGarbage!==undefined){
   if(!Plain(value.workspaceGarbage))Invalid();
   for(const [id,g]of Object.entries(value.workspaceGarbage))if(!Identifier(id,'DA')||!Plain(g)||!StrongDigest(g.sha512)||!Number.isSafeInteger(g.size)||g.size<1||!Time(g.createdAt)||(g.deletedAt!==undefined&&!Time(g.deletedAt))||value.artifacts[id])Invalid();
  }
  if(value.securityOperations!==undefined){try{require("../security/peace.desktop-security-operations").ValidateState(value.securityOperations);}catch(_){Invalid();}}
  if(value.securityActivation!==undefined){try{require("../security/peace.desktop-security-activation").ValidateRecord(value.securityActivation);}catch(_){Invalid();}}
  if(value.securityAuthorityPolicy!==undefined){try{require("../security/peace.desktop-security-authority").ValidatePolicy(value.securityAuthorityPolicy);}catch(_){Invalid();}}
  for(const artifact of Object.values(value.artifacts)){if(artifact.tlsPinVersion!==undefined&&![0,1].includes(artifact.tlsPinVersion))Invalid();if(artifact.ownMeasurementVersion!==undefined&&![0,1,2].includes(artifact.ownMeasurementVersion))Invalid();if(artifact.measurementPlanVersion!==undefined&&![0,1].includes(artifact.measurementPlanVersion))Invalid();if(artifact.authorityVersion!==undefined&&![0,1].includes(artifact.authorityVersion)||artifact.compiledCfg!==undefined&&typeof artifact.compiledCfg!=='boolean')Invalid();}
  const legacy=false,upgrade=false,previousProtocol='',previousVersion=0;
  for(const [id,row]of Object.entries(value.artifacts))if(!Identifier(id,'DA')||!Plain(row)||!ExtendedFields(row)||row.id!==id||!['A','B','O'].includes(row.component)||row.hashVersion!==3||![1,3].includes(require('./peace.desktop-handoff-delegation').Version(row))||row.protocol!==PROTOCOL||!['xxh3_128','codeXxh3_128','blake3','codeBlake3'].every(k=>typeof row[k]==='string')||!require("../runtime/peace.desktop-crc-policy").Validate(row.crcLayers)||!StrongDigest(row.sha512)||!Number.isSafeInteger(row.size)||row.size<1||row.size>64*1024*1024||!Time(row.createdAt)||(row.protocol===PROTOCOL&&(!Crc(row.crc64)||!StrongDigest(row.codeSha512)||!Crc(row.codeCrc64)||row.codeAlgorithm!=='PE64-CODE-V1'))||typeof row.version!=='string'||!/^\d+(?:\.\d+){0,3}$/.test(row.version))Invalid();
  for(const row of Object.values(value.artifacts))if(row.ownProtection!==undefined)OwnProtection(row.ownProtection,row.component);
  for(const row of Object.values(value.artifacts))if(row.deploymentManifestId!==undefined){
   if(!StrongDigest(row.deploymentManifestId))Invalid();const m=value.securityOperations?.releaseGovernance?.manifests?.[row.deploymentManifestId]?.manifest;
   if(!m||m.artifacts[row.component]!==row.sha512||m.protocol!==row.protocol||m.hashVersion!==row.hashVersion||m.handoffVersion!==require('./peace.desktop-handoff-delegation').Version(row))Invalid();
  }
  for(const [component,id]of Object.entries(value.active))if(!['A','B','O'].includes(component)||value.artifacts[id]?.component!==component||!legacy&&value.artifacts[id]?.protocol!==(upgrade?previousProtocol:PROTOCOL))Invalid();
  for(const [id,row]of Object.entries(value.launchers)){
   if(!Identifier(id,'LA')||!Plain(row)||row.id!==id||!['AVAILABLE','CONSUMED','REVOKED','EXPIRED'].includes(row.status)||!StrongDigest(row.sha512)||!Digest(row.ticketHash)||!Time(row.issuedAt)||!Time(row.expiresAt)||row.expiresAt<=row.issuedAt||value.artifacts[row.artifactId]?.component!=='A'||typeof row.label!=='string'||row.label.length>120)Invalid();
   if(row.assignedLicenseId!==undefined&&!Identifier(row.assignedLicenseId,'DL'))Invalid();
   if(row.keylessApprovalVersion!==undefined&&(row.keylessApprovalVersion!==1||row.configFormat!=='COZY_A_CONFIG_V3'||row.status==='AVAILABLE'||!value.flows[row.flowId]?.keylessApproval))Invalid();
   const own=value.artifacts[row.artifactId].ownProtection;
   if(row.configFormat==='COZY_A_CONFIG_V3'){if(own?.engine!=='COZY_SERVER_POLICY_V2'||own.state!=='BOUND'||own.role!=='A'||row.configNonce!==undefined)Invalid();}
   else if(row.configFormat!==undefined){if(row.configFormat!=='COZY_A_CONFIG_V2'||own?.state!=='SEALED'||own.role!=='A'||(row.retiredAt===undefined?typeof row.configNonce!=='string'||!/^[a-f0-9]{24}$/.test(row.configNonce):row.configNonce!==undefined))Invalid();}
   else if(row.configNonce!==undefined||['SEALED','BOUND'].includes(own?.state))Invalid();

   if(row.finalIssuedSignature!==undefined){if(row.configFormat!=='COZY_A_CONFIG_V3')Invalid();try{require('./peace.issued-a-signing').ValidateReceiptShape(row.finalIssuedSignature,row);}catch(_){Invalid();}}
   if(row.releaseSelection!==undefined){try{require("../artifacts/peace.desktop-release-safety").ValidateSelection(value,row.releaseSelection);if(row.releaseSelection.A.id!==row.artifactId)Invalid();}catch(_){Invalid();}}
   if(row.crc64!==undefined&&!Crc(row.crc64)||!ExtendedFields(row))Invalid();
   if(row.downloadName!==undefined&&!/^[a-f0-9]{32}\.exe$/.test(row.downloadName))Invalid();
   if(row.retiredAt!==undefined){if(!Time(row.retiredAt)||row.status==='AVAILABLE'||row.ticketNonce!==undefined||row.profile!==undefined)Invalid();}
   else if(!Nonce(row.ticketNonce)||!Plain(row.profile)||row.profile.protocol!==(legacy?LEGACY_PROTOCOL:upgrade?previousProtocol:PROTOCOL)||row.profile.version!==(upgrade?previousVersion:4)||(!upgrade&&(!Crc(row.crc64)||!Digest(row.profile.tlsCertificateSha256)||typeof row.profile.tlsServerName!=='string'||row.profile.tlsServerName.length<1||row.profile.tlsServerName.length>253))||row.ticketHash!==TokenHash(value.secret,'LAUNCHER',id,row.ticketNonce,legacy))Invalid();
   if(['CONSUMED','REVOKED'].includes(row.status)&&(!value.flows[row.flowId]||value.flows[row.flowId].launcherId!==id))Invalid();
  }
  const sessionIds=new Set();
  for(const [id,row]of Object.entries(value.flows)){
   const approvedLauncher=value.launchers[row.launcherId];
   if(row.keylessApproval!==undefined||approvedLauncher?.keylessApprovalVersion!==undefined){try{require('./peace.keyless-approval-receipt').Validate(row.keylessApproval,row,approvedLauncher);}catch(_){Invalid();}}
   if(value.launchers[row.launcherId]?.configFormat==='COZY_A_CONFIG_V3'){if(typeof row.keylessPersistentKeyId!=='string'||!/^[A-F0-9]{64}$/.test(row.keylessPersistentKeyId))Invalid();}else if(row.keylessPersistentKeyId!==undefined)Invalid();
   if(!Identifier(id,'BF')||!Plain(row)||row.id!==id||!['STARTED','DOWNLOADED','CLAIMED','CLOSED','REVOKED','EXPIRED'].includes(row.status)||!Identifier(row.sessionId,'DS')||sessionIds.has(row.sessionId)||!/^[A-F0-9]{64}$/.test(row.deviceId)||typeof row.publicKey!=='string'||row.publicKey.length>500||crypto.createHash('sha256').update(Buffer.from(row.publicKey,'base64')).digest('hex').toUpperCase()!==row.deviceId||!Time(row.createdAt)||!Time(row.expiresAt)||row.expiresAt<=row.createdAt||!Digest(row.beginFingerprint)||!StrongDigest(row.launcherSha512)||!Digest(row.downloadHash)||value.launchers[row.launcherId]?.flowId!==id||value.artifacts[row.releaseId]?.component!=='B')Invalid();
   try{require('./peace.desktop-handoff-delegation').ValidateIdentity(row);}catch(_){Invalid();}
   if(require('./peace.desktop-handoff-delegation').Version(row)!==require('./peace.desktop-handoff-delegation').Version(value.artifacts[row.releaseId])||require('./peace.desktop-handoff-delegation').Version(row)!==require('./peace.desktop-handoff-delegation').Version(value.artifacts[value.launchers[row.launcherId].artifactId])||row.overlayReleaseId&&require('./peace.desktop-handoff-delegation').Version(row)!==require('./peace.desktop-handoff-delegation').Version(value.artifacts[row.overlayReleaseId]))Invalid();
   sessionIds.add(row.sessionId);if(row.overlayReleaseId!==undefined&&value.artifacts[row.overlayReleaseId]?.component!=='O')Invalid();
   if(row.machineId!==undefined&&(!Machine(row.machineId)||!Number.isSafeInteger(row.machinePolicyGeneration)||row.machinePolicyGeneration<0||!Crc(row.launcherCrc64)))Invalid();
   if(!upgrade&&!['CLOSED','REVOKED','EXPIRED'].includes(row.status)&&(!Machine(row.machineId)||!Crc(row.launcherCrc64)||value.artifacts[row.releaseId]?.protocol!==PROTOCOL||!StrongDigest(row.aCodeSha512)||!Crc(row.aCodeCrc64)))Invalid();
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
   if((row.lastLicenseOperationId===undefined)!==(row.lastLicenseOperationRevision===undefined)||row.lastLicenseOperationId!==undefined&&(!Digest(row.lastLicenseOperationId)||!Number.isSafeInteger(row.lastLicenseOperationRevision)||row.lastLicenseOperationRevision<1||!row.licenseId))Invalid();
   if(typeof row.licenseId!=='string'||row.licenseId&&!Identifier(row.licenseId,'DL')||!Number.isSafeInteger(row.lastVerifiedAt)||row.lastVerifiedAt<0)Invalid();
   try{require("../overlay/peace.desktop-overlay").ValidateParentTransfer(value,row);require("../overlay/peace.desktop-overlay").ValidateParentCancellation(value,row);}catch(_){Invalid();}
  }
  if(value.overlays!==undefined){try{require("../overlay/peace.desktop-overlay").ValidateStore(value);require("../overlay/peace.desktop-overlay").ValidateTransferRows(value);}catch(_){Invalid();}}
  for(const receipt of Object.values(value.issueReceipts))if(!Plain(receipt)||!Digest(receipt.fingerprint)||!value.launchers[receipt.launcherId])Invalid();
  require("../security/peace.desktop-security-operations").ReserveKnownKeyPurposes(value);
  if(retiredGovernanceRemoved){require('../storage/peace.desktop-single-writer').Acquire(config.DATA_DIR,{haEnabled:config.HA_ENABLED});value.revision++;value.securityOperations.revision++;Write(value);}
  current=value;
 }else{
  current={schema:5,revision:0,secret:crypto.randomBytes(32).toString('hex'),artifacts:{},active:{},launchers:{},flows:{},issueReceipts:{}};
  try{Write(current,true);}catch(error){current=undefined;throw error;}
 }
 return current;
}
function Write(value,initial=false){
 const bytes=Buffer.from(JSON.stringify(value)),next=Mark(value,bytes);let previous,previousValue,published=false;
 try{
  if(bytes.length>64*1024*1024)throw Error('BOOTSTRAP_STORAGE_CAPACITY');
  if(!initial){const raw=require("../storage/peace.durable-file").ReadRegular(FILE);previousValue=require("../protocol/peace.strict-json").Parse(raw,{maxBytes:64*1024*1024,maxNodes:4000000});previous=Mark(previousValue,raw);if(previousValue.secret!==value.secret||next.seq!==previous.seq+1)throw Error('BOOTSTRAP_STORAGE_SEQUENCE_INVALID');Anchor(previousValue).Prepare(previous,next);}
  require("../storage/peace.durable-file").Atomic(FILE,bytes,{createOnly:initial});published=true;
  if(initial)Anchor(value).Open(next,true);else Anchor(value).Settle(next);
 }catch(error){
  if(published||error.published)poisoned=true;
  else if(previous)try{Anchor(previousValue).Open(previous);}catch(_){poisoned=true;}
  throw error;
 }finally{bytes.fill(0);}
}
// In-memory cleanup that would reset a live capability's monotonic bound must
// follow its durable terminal state. These callbacks are non-throwing cleanup;
// a failed mutation/write drops the queue without changing existing bounds.
function AfterCommit(callback){
 if(typeof callback!=='function')throw Error('BOOTSTRAP_COMMIT_CALLBACK_INVALID');
 if(commitCallbacks)commitCallbacks.push(callback);else callback();
}
function Atomic(fn){
 if(poisoned)throw Error('BOOTSTRAP_STORAGE_RESTART_REQUIRED');
 const before=Load(),next=structuredClone(before),previousCallbacks=commitCallbacks,callbacks=[];let result;
 commitCallbacks=callbacks;
 try{result=fn(next);require("../observability/peace.desktop-lifecycle-trace").ObserveTransitions(before,next);next.revision=before.revision+1;Write(next);current=next;}
 catch(error){if(poisoned){current=next;error.authorityMayBeCommitted=true;}throw error;}
 finally{commitCallbacks=previousCallbacks;}
 for(const callback of callbacks)callback();
 return result;
}
function ArtifactPath(id){if(!Identifier(id,'DA'))throw Error('BOOTSTRAP_ARTIFACT_INVALID');return path.join(DIR,id+'.exe');}
function PublishBytes(id,bytes){
 Load();const file=ArtifactPath(id),tmp=file+'.'+crypto.randomBytes(12).toString('hex')+'.tmp';let fd;
 try{fd=fs.openSync(tmp,'wx',0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;fs.linkSync(tmp,file);fs.unlinkSync(tmp);SyncDir();}
 finally{if(fd!==undefined)try{fs.closeSync(fd);}catch(_){}try{fs.unlinkSync(tmp);}catch(_){} }
}
module.exports={DIR,Load,Atomic,AfterCommit,ArtifactPath,PublishBytes};
