'use strict';
// Real handlers with isolated state/files, not production integration.
const crypto=require('node:crypto');
const {Isolated}=require("../protocol/spacex.completion-6-10-fixture"),protocol=require("../../../services/protocol/spacex.desktop-request-protocol");
const {DeviceRate}=require("../../../services/runtime/spacex.desktop-request-rate");
const digest=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>{const e=Error(code);e.desktopError=true;e.status=403;throw e;};
function BootFixture(){
 const at=Date.now(),id=crypto.randomBytes(12).toString('hex'),bytes=Buffer.from('SYNTHETIC_ARTIFACT_DATA_ONLY');
 const make=role=>({id:role,component:role,sha512:'a'.repeat(128),crc64:'A'.repeat(16),codeSha512:'b'.repeat(128),codeCrc64:'B'.repeat(16),size:bytes.length});
 const row={id,sessionId:'SESSION',launcherId:'L',releaseId:'B',overlayReleaseId:'O',status:'STARTED',createdAt:at-1000,expiresAt:at+60000,sessionExpiresAt:at+60000,claimedAt:at-1000,deviceId:'DEVICE',machineId:'MACHINE',downloadHash:digest('DOWNLOAD_SECRET'),sessionHash:digest('SESSION_SECRET'),chunkOffsets:[]};
 const db={launchers:{L:{id:'L',artifactId:'A',status:'AVAILABLE',issuedAt:at-1000,expiresAt:at+60000}},artifacts:{A:make('A'),B:make('B'),O:make('O')},flows:{[id]:row}},state={serviceEnabled:true,maintenanceMode:false};
 const calls={artifacts:[],fresh:0,writes:0,read:0};const revoked=new Set();let afterRead=()=>{},afterWrite=()=>{},beforeWrite=()=>{},fresh=true;
 const api=Isolated("services/bootstrap/spacex.desktop-bootstrap.js",['Chunk','RequireFlowPair','TouchLicense'],{
  './spacex.desktop-bootstrap-store':{Load:()=>db,ArtifactPath:()=>'/synthetic',AfterCommit:fn=>fn(),Atomic(fn){beforeWrite();calls.writes++;const r=fn(db);afterWrite();return r;}},"../../config/spacex.runtime-configuration":{HA_ENABLED:false},"../../core/spacex.runtime-state":state,
  'node:fs':{constants:{O_RDONLY:0,O_NOFOLLOW:0},openSync:()=>1,closeSync(){},fstatSync:()=>({isFile:()=>true,size:bytes.length}),readSync(_fd,b,offset,count,pos){bytes.copy(b,offset,pos,pos+count);calls.read++;afterRead();return count;}},
  "../storage/spacex.desktop-operation-audit":{Run(_kind,_actor,_meta,fn){beforeWrite();calls.writes++;fn(db);afterWrite();}},"../network/spacex.ha-coordinator":{CanAcceptTraffic:()=>true},
  "../recovery/spacex.desktop-recovery":{Assert(){}},"../devices/spacex.desktop-device-registry":{AssertMachineAllowed(){}},"../devices/spacex.desktop-machine-policy":{Validate:x=>x,AssertAllowed(){}},
  './spacex.desktop-handoff-delegation':{RequirePair:()=>3,Version:()=>3,Parent:r=>r},
  "../security/spacex.desktop-security-operations":{RequireRuntimePair(){}},"../security/spacex.desktop-security-authority":{RequireArtifact(a){if(!a||revoked.has(a.id))fail('SECURITY_RELEASE_REVOKED');calls.artifacts.push(a.id);},RequireFresh(){calls.fresh++;if(!fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');}},
  "../licensing/spacex.desktop-licenses":{DB:()=>({licenses:db.licenses||{}})},"../devices/spacex.desktop-device-identity":{AssertSession(){}},"../integrity/spacex.desktop-integrity-reports":{RequireSnapshot(){},Record(){}},"../../storage/audit/spacex.audit.js":{LogEvent(){}}
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
 const db={secret:'1'.repeat(64),flows:{P:parent},launchers:{L:{artifactId:'A'}},artifacts:{A:artifact('A'),B:artifact('B'),O:artifact('O')},overlays:{[row.id]:row}};
 let afterRead=()=>{},beforeWrite=()=>{},fresh=true;const calls={fresh:0,writes:0,artifacts:[],events:[]},revoked=new Set();
 const boot={Fail:fail,EnsureSecurityAvailable(){},AssertSecurityAvailable(){},EqualHash:(v,h)=>digest(v)===h,AssertFlowLifetime(p){if(p.sessionExpiresAt<=Date.now())fail('BOOTSTRAP_EXPIRED');},SessionAuthenticated(id,token){if(id!==parent.sessionId||token!=='PARENT_TOKEN')fail('BOOTSTRAP_SESSION_INVALID');return parent;},Verify(_row,canonical,signature){if(!crypto.verify('sha256',Buffer.from(canonical),keys.publicKey,Buffer.from(signature,'base64')))fail('BOOTSTRAP_PROOF_INVALID');},RetireFlow(){},Release:a=>({...a}),ReadArtifactBytes:()=>bytes,CheckFile(a,h,c){if(a.sha512!==h||a.crc64!==c)fail('HASH_MISMATCH');}};
 const authority={RequireArtifact(a){if(!a||revoked.has(a.id))fail('SECURITY_RELEASE_REVOKED');calls.artifacts.push(a.id);},Binding:(id,h)=>id+'|'+h,RequireFresh(){calls.fresh++;if(!fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');},RenewalIdentity(){if(!fresh)fail('SECURITY_FRESH_OBSERVATION_REQUIRED');return {id:options.observationId||'CURRENT_OBSERVATION',expiresAt:options.observationExpiry||Date.now()+30000};}};
 const api=Isolated("services/overlay/spacex.desktop-overlay.js",['Chunk','Claim','ClaimResult','Canonical','Commit','Verify','Progress','Start','StartCanonical','ValidateStartReceipt','ValidateVerifyReceipt'],{
  "../bootstrap/spacex.desktop-bootstrap":boot,"../bootstrap/spacex.desktop-bootstrap-store":{Load:()=>db,ArtifactPath:()=>'/synthetic'},"../../config/spacex.runtime-configuration":{},
  "../bootstrap/spacex.desktop-handoff-delegation":{Parent:r=>({deviceId:r.parentDeviceId}),Version:()=>3,FIELDS:[],Check(r,b,_role,canonical){boot.Verify(r,canonical,b.signature);return null;}},
  'node:fs':{constants:{O_RDONLY:0,O_NOFOLLOW:0},openSync:()=>1,closeSync(){},fstatSync:()=>({isFile:()=>true,size:bytes.length}),readSync(_fd,b,offset,count,pos){bytes.copy(b,offset,pos,pos+count);afterRead();return count;}},
  "../recovery/spacex.desktop-recovery":{Assert(){}},"../devices/spacex.desktop-device-registry":{AssertMachineAllowed(){},ObserveVerified(){}},"../devices/spacex.desktop-machine-policy":{AssertAllowed(){}},"../licensing/spacex.desktop-licenses":{DB:()=>({licenses:{LICENSE:license}})},
  "../security/spacex.desktop-security-authority":authority,"../security/spacex.desktop-security-operations":{RequireRuntimePair(){}},"../devices/spacex.desktop-device-identity":{AssertSession(){}},"../integrity/spacex.desktop-integrity-reports":{RequireSnapshot(){return options.snapshotExpiry?{expiresAt:options.snapshotExpiry}:undefined;}},
  "../storage/spacex.desktop-operation-audit":{Run(_kind,_actor,_meta,fn){beforeWrite();calls.writes++;return fn(db);}},"../../storage/audit/spacex.audit.js":{LogEvent(kind,payload){calls.events.push({kind,...JSON.parse(payload)});}}
 });
 const chunk={action:'overlayChunk',overlayId:row.id,overlayTicket:'TICKET',offset:0};
 const commit={action:'overlayCommit',handoffVersion:1,sessionId:parent.sessionId,sessionToken:'PARENT_TOKEN',overlayId:row.id,signature:crypto.sign('sha256',Buffer.from(['GAME-OVERLAY-TRANSFER-V1',parent.sessionId,row.id].join('\n')),keys.privateKey).toString('base64')};
 const verify={action:'overlayVerify',sessionId:row.sessionId,sessionToken:'TOKEN',machineId:row.machineId,binarySha512:db.artifacts.O.sha512,binaryCrc64:db.artifacts.O.crc64,codeSha512:db.artifacts.O.codeSha512,codeCrc64:db.artifacts.O.codeCrc64};
 return {api,row,parent,license,db,chunk,commit,verify,bytes,calls,revoked,keys,boot,options,onRead:fn=>afterRead=fn,beforeWrite:fn=>beforeWrite=fn,denyFresh:()=>fresh=false};
}
module.exports={BootFixture,OverlayFixture};
