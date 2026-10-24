'use strict';
// Real handlers with isolated state/files, not production integration.
const crypto=require('node:crypto');
const {Isolated}=require("../protocol/peace.completion-6-10-fixture"),protocol=require("../../../services/protocol/peace.desktop-request-protocol");
const {DeviceRate}=require("../../../services/runtime/peace.desktop-request-rate");
const digest=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>{const e=Error(code);e.desktopError=true;e.status=403;throw e;};
function BootFixture(){
 const at=Date.now(),id=crypto.randomBytes(12).toString('hex'),bytes=Buffer.from('SYNTHETIC_ARTIFACT_DATA_ONLY');
 const make=role=>({id:role,component:role,sha512:'a'.repeat(128),crc64:'A'.repeat(16),codeSha512:'b'.repeat(128),codeCrc64:'B'.repeat(16),size:bytes.length});
 const row={id,sessionId:'SESSION',launcherId:'L',releaseId:'B',overlayReleaseId:'O',status:'STARTED',createdAt:at-1000,expiresAt:at+60000,sessionExpiresAt:at+60000,claimedAt:at-1000,deviceId:'DEVICE',machineId:'MACHINE',downloadHash:digest('DOWNLOAD_SECRET'),sessionHash:digest('SESSION_SECRET'),chunkOffsets:[]};
 const db={launchers:{L:{id:'L',artifactId:'A',status:'AVAILABLE',issuedAt:at-1000,expiresAt:at+60000}},artifacts:{A:make('A'),B:make('B'),O:make('O')},flows:{[id]:row}},state={serviceEnabled:true,maintenanceMode:false};
 const calls={artifacts:[],fresh:0,writes:0,read:0};const revoked=new Set();let afterRead=()=>{},afterWrite=()=>{},beforeWrite=()=>{},fresh=true;
 const api=Isolated("services/bootstrap/peace.desktop-bootstrap.js",['Chunk','RequireFlowPair','TouchLicense'],{
  './peace.desktop-bootstrap-store':{Load:()=>db,ArtifactPath:()=>'/synthetic',AfterCommit:fn=>fn(),Atomic(fn){beforeWrite();calls.writes++;const r=fn(db);afterWrite();return r;}},"../../config/peace.runtime-configuration":{HA_ENABLED:false},"../../core/peace.runtime-state":state,
  'node:fs':{constants:{O_RDONLY:0,O_NOFOLLOW:0},openSync:()=>1,closeSync(){},fstatSync:()=>({isFile:()=>true,size:bytes.length}),readSync(_fd,b,offset,count,pos){bytes.copy(b,offset,pos,pos+count);calls.read++;afterRead();return count;}},
  "../storage/peace.desktop-operation-audit":{Run(_kind,_actor,_meta,fn){beforeWrite();calls.writes++;fn(db);afterWrite();}},"../network/peace.ha-coordinator":{CanAcceptTraffic:()=>true},
  "../recovery/peace.desktop-recovery":{Assert(){}},"../devices/peace.desktop-device-registry":{AssertMachineAllowed(){}},"../devices/peace.desktop-machine-policy":{Validate:x=>x,AssertAllowed(){}},
  './peace.desktop-handoff-delegation':{RequirePair:()=>3,Version:()=>3,Parent:r=>r},
  "../security/peace.desktop-security-operations":{RequireRuntimePair(){}},"../security/peace.desktop-security-authority":{RequireArtifact(a){if(!a||revoked.has(a.id))fail('SECURITY_RELEASE_REVOKED');calls.artifacts.push(a.id);},RequireFresh(){calls.fresh++;if(!fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');}},
  "../licensing/peace.desktop-licenses":{DB:()=>({licenses:db.licenses||{}})},"../devices/peace.desktop-device-identity":{AssertSession(){}},"../integrity/peace.desktop-integrity-reports":{RequireSnapshot(){},Record(){}},"../../storage/audit/peace.audit.js":{LogEvent(){}}
 });
 const body={action:'chunk',flowId:id,downloadTicket:'DOWNLOAD_SECRET',offset:0};
 const options={machineId:row.machineId,binarySha512:db.artifacts.B.sha512,binaryCrc64:db.artifacts.B.crc64,codeSha512:db.artifacts.B.codeSha512,codeCrc64:db.artifacts.B.codeCrc64,securityIntent:'verify',securityBinding:'SERVER_BOUND'};
 return {api,row,db,body,bytes,state,calls,revoked,options,beforeWrite:fn=>beforeWrite=fn,onRead:fn=>afterRead=fn,onWrite:fn=>afterWrite=fn,denyFresh:()=>fresh=false};
}
function OverlayFixture(options={}){
 const at=Date.now(),bytes=Buffer.from('SYNTHETIC_OVERLAY'),keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
 const parent={id:'P',sessionId:'A'.repeat(24),launcherId:'L',releaseId:'B',overlayReleaseId:'O',licenseId:'LICENSE',deviceId:'PARENT_DEVICE',status:'CLAIMED',claimedAt:at-1000,sessionExpiresAt:at+60000};
 const row={id:crypto.randomBytes(12).toString('hex').toUpperCase(),sessionId:crypto.randomBytes(12).toString('hex').toUpperCase(),parentFlowId:parent.id,parentSessionId:parent.sessionId,releaseId:'O',licenseId:'LICENSE',parentDeviceId:parent.deviceId,deviceId:'CHILD_DEVICE',machineId:'MACHINE',status:'PREPARED',createdAt:at-1000,expiresAt:at+60000,claimedAt:at-1000,authorizedAt:at-10,sessionExpiresAt:at+60000,ticketHash:digest('TICKET'),sessionHash:digest('TOKEN'),chunkOffsets:[]};
 const artifact=id=>({id,component:id,sha512:'a'.repeat(128),crc64:'A'.repeat(16),codeSha512:'b'.repeat(128),codeCrc64:'B'.repeat(16),size:bytes.length});
 const license={id:'LICENSE',consumed:true,status:'USED',deviceId:parent.deviceId,bootstrapSessionId:parent.sessionId,expiresAt:at+120000};
 const db={flows:{P:parent},launchers:{L:{artifactId:'A'}},artifacts:{A:artifact('A'),B:artifact('B'),O:artifact('O')},overlays:{[row.id]:row}};
 let afterRead=()=>{},beforeWrite=()=>{},fresh=true;const calls={fresh:0,writes:0,artifacts:[],events:[]},revoked=new Set();
 const boot={Fail:fail,EnsureSecurityAvailable(){},AssertSecurityAvailable(){},EqualHash:(v,h)=>digest(v)===h,AssertFlowLifetime(p){if(p.sessionExpiresAt<=Date.now())fail('BOOTSTRAP_EXPIRED');},SessionAuthenticated(id,token){if(id!==parent.sessionId||token!=='PARENT_TOKEN')fail('BOOTSTRAP_SESSION_INVALID');return parent;},Verify(_row,canonical,signature){if(!crypto.verify('sha256',Buffer.from(canonical),keys.publicKey,Buffer.from(signature,'base64')))fail('BOOTSTRAP_PROOF_INVALID');},RetireFlow(){},CheckFile(a,h,c){if(a.sha512!==h||a.crc64!==c)fail('HASH_MISMATCH');}};
 const authority={RequireArtifact(a){if(!a||revoked.has(a.id))fail('SECURITY_RELEASE_REVOKED');calls.artifacts.push(a.id);},Binding:(id,h)=>id+'|'+h,RequireFresh(){calls.fresh++;if(!fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');},RenewalIdentity(){if(!fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');return {id:options.observationId||'CURRENT_OBSERVATION',expiresAt:options.observationExpiry||Date.now()+30000};}};
 const api=Isolated("services/overlay/peace.desktop-overlay.js",['Chunk','Commit','Verify','Progress','ValidateVerifyReceipt'],{
  "../bootstrap/peace.desktop-bootstrap":boot,"../bootstrap/peace.desktop-bootstrap-store":{Load:()=>db,ArtifactPath:()=>'/synthetic'},"../../config/peace.runtime-configuration":{},
  "../bootstrap/peace.desktop-handoff-delegation":{Parent:r=>({deviceId:r.parentDeviceId}),Version:()=>3},
  'node:fs':{constants:{O_RDONLY:0,O_NOFOLLOW:0},openSync:()=>1,closeSync(){},fstatSync:()=>({isFile:()=>true,size:bytes.length}),readSync(_fd,b,offset,count,pos){bytes.copy(b,offset,pos,pos+count);afterRead();return count;}},
  "../recovery/peace.desktop-recovery":{Assert(){}},"../devices/peace.desktop-device-registry":{AssertMachineAllowed(){}},"../devices/peace.desktop-machine-policy":{AssertAllowed(){}},"../licensing/peace.desktop-licenses":{DB:()=>({licenses:{LICENSE:license}})},
  "../security/peace.desktop-security-authority":authority,"../security/peace.desktop-security-operations":{RequireRuntimePair(){}},"../devices/peace.desktop-device-identity":{AssertSession(){}},"../integrity/peace.desktop-integrity-reports":{RequireSnapshot(){return options.snapshotExpiry?{expiresAt:options.snapshotExpiry}:undefined;}},
  "../storage/peace.desktop-operation-audit":{Run(_kind,_actor,_meta,fn){beforeWrite();calls.writes++;return fn(db);}},"../../storage/audit/peace.audit.js":{LogEvent(kind,payload){calls.events.push({kind,...JSON.parse(payload)});}}
 });
 const chunk={action:'overlayChunk',overlayId:row.id,overlayTicket:'TICKET',offset:0};
 const commit={action:'overlayCommit',handoffVersion:1,sessionId:parent.sessionId,sessionToken:'PARENT_TOKEN',overlayId:row.id,signature:crypto.sign('sha256',Buffer.from(['GAME-OVERLAY-TRANSFER-V1',parent.sessionId,row.id].join('\n')),keys.privateKey).toString('base64')};
 const verify={action:'overlayVerify',sessionId:row.sessionId,sessionToken:'TOKEN',machineId:row.machineId,binarySha512:db.artifacts.O.sha512,binaryCrc64:db.artifacts.O.crc64,codeSha512:db.artifacts.O.codeSha512,codeCrc64:db.artifacts.O.codeCrc64};
 return {api,row,parent,license,chunk,commit,verify,bytes,calls,revoked,keys,boot,options,onRead:fn=>afterRead=fn,beforeWrite:fn=>beforeWrite=fn,denyFresh:()=>fresh=false};
}
module.exports={BootFixture,OverlayFixture};
