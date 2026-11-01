'use strict';
// Public A files contain no bearer invitation. Execution starts only after two
// fresh possession proofs and an explicit, recently authenticated administrator
// decision. Pending proof/approval state is bounded process memory: restart
// loses it and cannot resurrect an approval. No private key leaves its owner.
const crypto=require('node:crypto'),store=require('./peace.desktop-bootstrap-store');
const tpmRecovery=require('./peace.keyless-tpm');
const deadline=require('../runtime/peace.desktop-deadline'),identity=require('../devices/peace.desktop-device-identity');
const pending=new Map(),rates=new Map(),authorizations=new WeakMap();
const TTL=300000,PROOF_MS=30000,APPROVAL_MS=60000,RETRY_MS=30000,MAX_PENDING=256;
const FORMAT='COZY_A_CONFIG_V3',FOOTER=Buffer.from('COZYA3CONFIG!','ascii');
const BASE=['requestId','launcherId','launcherSha512','launcherCrc64','aCodeSha512','aCodeCrc64','publicKey','deviceId','machineId','handoffVersion'];
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function Fail(code,status=403){const e=Error(code);e.desktopError=true;e.bootstrapError=true;e.status=status;throw e;}
function Fields(body,names){if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).some(k=>!['action','version',...names].includes(k))||body.version!==1)Fail('KEYLESS_REQUEST_INVALID',400);}
function Boot(){return require('./peace.desktop-bootstrap');}
function MachineGeneration(id){return require('../devices/peace.desktop-machine-policy').Generation(id);}
function CurrentPolicy(p,db=store.Load()){
 const policy=identity.BootstrapPolicy(p.begin.machineId,db);
 if(policy.epoch!==p.epoch||policy.revision!==p.revision||policy.keyProvider!==p.keyProvider||MachineGeneration(p.begin.machineId)!==p.machinePolicyGeneration){Delete(p.id);Fail('KEYLESS_REQUEST_EXPIRED');}
 if(p.tpmCandidate&&!p.tpmConsumed)tpmRecovery.Assert(p,db);else identity.CheckBootstrapKey(p.persistentPublicKey,p.begin.machineId,p.keyProvider,db);
 return policy;
}
function Wipe(p){p?.tpmSecret?.fill(0);for(const secret of p?.preparingSecrets||[])secret.fill(0);p?.preparingSecrets?.clear();}
function Delete(id){Wipe(pending.get(id));pending.delete(id);}
function Prune(){const at=deadline.Now();for(const [id,p]of pending)if(deadline.Expired(p,at)||p.status==='PROOF_REQUIRED'&&deadline.Expired(p.proof,at)||p.status==='APPROVED'&&deadline.Expired(p.approval,at)||p.status==='CONSUMED'&&deadline.Expired(p.recovery,at))Delete(id);for(const [id,r]of rates)if(deadline.Expired(r,at))rates.delete(id);}
function Launcher(id,machineId,allowConsumed=false,db=store.Load()){
 Boot().AssertSecurityAvailable();
 const row=db.launchers[id];
 if(!row||row.configFormat!==FORMAT||db.artifacts[row.artifactId]?.ownProtection?.engine!=='COZY_SERVER_POLICY_V2'||db.artifacts[row.artifactId]?.ownProtection?.state!=='BOUND')Fail('KEYLESS_REQUEST_INVALID');
 require('../recovery/peace.desktop-recovery').Assert(row,db);
 if(row.status==='EXPIRED'||(row.status==='AVAILABLE'?Boot().LauncherExpired(row):row.expiresAt<=Date.now()))Fail('KEYLESS_REQUEST_EXPIRED');
 if(row.status!=='AVAILABLE'&&!(allowConsumed&&row.status==='CONSUMED'))Fail('BOOTSTRAP_LAUNCHER_USED',409);
 require('../devices/peace.desktop-device-registry').AssertMachineAllowed(machineId,db);
 require('../devices/peace.desktop-machine-policy').AssertAllowed(machineId,undefined,allowConsumed?db.flows[row.flowId]?.sessionId:undefined);
 if(row.status==='AVAILABLE')Boot().RequireLauncherSelection(row);
 return row;
}
function Policy(body){
 Fields(body,['launcherId','machineId']);Launcher(body.launcherId,body.machineId);
 const p=identity.BootstrapPolicy(body.machineId);
 return {version:1,keyNamespace:p.keyNamespace,keyProvider:p.keyProvider,epoch:p.epoch,revision:p.revision,mode:p.mode,trustConfigured:p.trustConfigured};
}
function Canonical(p){const b=p.begin;return ['COZY-KEYLESS-BOOTSTRAP-V1',p.id,p.nonce,b.requestId,b.launcherId,b.launcherSha512,b.launcherCrc64,b.aCodeSha512,b.aCodeCrc64,b.machineId,b.deviceId,p.persistentKeyId,p.keyProvider,String(p.epoch),String(p.revision),String(p.expiresAt)].join('\n');}
function ChallengeResult(p){return {version:1,status:'PROOF_REQUIRED',challengeId:p.id,nonce:p.nonce,epoch:p.epoch,revision:p.revision,expiresAt:p.expiresAt,canonical:Canonical(p),...(p.tpmCandidate?{tpmRequired:true}:{})};}
function Challenge(body){
 Fields(body,[...BASE,'persistentPublicKey','persistentKeyId','keyProvider','epoch','revision']);
 if(!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId||'')||!/^[A-F0-9]{24}$/.test(body.launcherId||'')||!/^[A-F0-9]{64}$/.test(body.machineId||'')||body.handoffVersion!==3||!['SOFTWARE','PLATFORM'].includes(body.keyProvider)||!Number.isSafeInteger(body.epoch)||!Number.isSafeInteger(body.revision))Fail('KEYLESS_REQUEST_INVALID',400);
 Prune();const row=Launcher(body.launcherId,body.machineId),db=store.Load(),artifact=db.artifacts[row.artifactId];
 if(body.launcherSha512!==row.sha512||body.launcherCrc64!==row.crc64||body.aCodeSha512!==artifact.codeSha512||body.aCodeCrc64!==artifact.codeCrc64)Fail('BOOTSTRAP_HASH_MISMATCH');
 const rate=rates.get(row.id)||{count:0,...deadline.After(60000)};
 if(++rate.count>8||pending.size>=MAX_PENDING||rates.size>=1024&&!rates.has(row.id))Fail('KEYLESS_RATE_LIMIT',429);
 rates.set(row.id,rate);
 const app=require('../licensing/peace.desktop-licenses').ParseKey(body.publicKey),candidate=tpmRecovery.Candidate(body.persistentPublicKey,body.machineId,body.keyProvider,db),device=candidate.key,policy=identity.BootstrapPolicy(body.machineId);
 if(app.deviceId!==body.deviceId||device.keyId!==body.persistentKeyId||device.keyId===app.deviceId||policy.epoch!==body.epoch||policy.revision!==body.revision)Fail('KEYLESS_REQUEST_INVALID');
 const begin=Object.fromEntries(BASE.map(k=>[k,body[k]])),fingerprint=sha(require('../protocol/peace.desktop-request-protocol').Stable(body));
 for(const p of pending.values())if(p.begin.launcherId===body.launcherId&&p.begin.requestId===body.requestId){if(p.fingerprint!==fingerprint)Fail('KEYLESS_REQUEST_REUSED',409);CurrentPolicy(p,db);return ChallengeResult(p);}
 const bounds=deadline.After(Math.min(TTL,row.expiresAt-Date.now())),proof=deadline.After(Math.min(PROOF_MS,bounds.expiresAt-Date.now()));
 const p={id:crypto.randomBytes(24).toString('hex'),nonce:crypto.randomBytes(32).toString('base64'),begin,persistentPublicKey:body.persistentPublicKey,persistentKeyId:device.keyId,keyProvider:body.keyProvider,epoch:policy.epoch,revision:policy.revision,machinePolicyGeneration:MachineGeneration(body.machineId),tpmCandidate:candidate.candidate,fingerprint,status:'PROOF_REQUIRED',createdAt:Date.now(),proof,...bounds};
 pending.set(p.id,p);return ChallengeResult(p);
}
const PROOF_FIELDS=['challengeId','appSignature','persistentSignature'];
function Pending(body,{consumed=false,db=store.Load()}={}){
 Fields(body,[...PROOF_FIELDS,...(body.action==='keylessProve'?['tpmEvidence']:body.action==='keylessTpmActivate'?['secret']:[])]);Prune();
 const p=pending.get(body.challengeId);if(!p||deadline.Expired(p)||p.status==='PROOF_REQUIRED'&&deadline.Expired(p.proof)||p.status==='CONSUMED'&&!consumed)Fail('KEYLESS_REQUEST_EXPIRED');
 Launcher(p.begin.launcherId,p.begin.machineId,consumed&&p.status==='CONSUMED',db);
 CurrentPolicy(p,db);
 return p;
}
function VerifyProof(p,body){
 const work=require('../integrity/peace.desktop-proof-work'),canonical=Canonical(p);
 try{if(!work.Verify(p.begin.publicKey,canonical,body.appSignature)||!work.Verify(p.persistentPublicKey,canonical,body.persistentSignature))Fail('KEYLESS_PROOF_INVALID');}
 catch(e){if(e.desktopError)throw e;Fail('KEYLESS_PROOF_INVALID');}
 if(deadline.Expired(p))Fail('KEYLESS_REQUEST_EXPIRED');
}
function PollHint(){
 // Scheduling only, never an authority grant or an extension of the original
 // five-minute challenge. Bounded CSPRNG jitter spreads simultaneous clients.
 const base=2000+Math.min(8,Math.floor(pending.size/32))*250;
 return Math.max(1000,Math.min(5000,base+crypto.randomInt(-250,251)));
}
function StatusResult(p){return {version:1,status:p.status,challengeId:p.id,expiresAt:p.expiresAt,pollAfterMs:PollHint()};}
function Fingerprint(body){return sha(require('../protocol/peace.desktop-request-protocol').Stable(body));}
let tpmRate={count:0,...deadline.After(60000)};
function LimitTpm(p){if(deadline.Expired(tpmRate))tpmRate={count:0,...deadline.After(60000)};if((p.tpmAttempts||0)>=2||tpmRate.count>=64)Fail('KEYLESS_RATE_LIMIT',429);p.tpmAttempts=(p.tpmAttempts||0)+1;tpmRate.count++;}
function Prove(body,prepared){
 const p=Pending(body);VerifyProof(p,body);
 if(!p.tpmCandidate){if(body.tpmEvidence!==undefined)Fail('KEYLESS_REQUEST_INVALID',400);if(p.status==='PROOF_REQUIRED'){p.status='PENDING_APPROVAL';p.provedAt=Date.now();}return StatusResult(p);}
 if(!body.tpmEvidence)Fail('DEVICE_TPM_REQUIRED');
 const fingerprint=Fingerprint(body);
 if(p.tpmFingerprint){if(p.tpmFingerprint!==fingerprint)Fail('KEYLESS_REQUEST_REUSED',409);return p.tpmVerified?StatusResult(p):{...p.activationResponse};}
 const tpm=require('../devices/peace.desktop-tpm-attestation');let verified,secret,activationBlob;
 try{
  if(prepared){if(prepared.id!==p.id||prepared.fingerprint!==fingerprint||prepared.secret.length!==32)Fail('KEYLESS_REQUEST_EXPIRED');verified=prepared.verified;secret=Buffer.from(prepared.secret);activationBlob=verified.activationBlob;}
  else{LimitTpm(p);const nonce=Buffer.from(p.nonce,'base64');try{verified=tpm.VerifyCertify(body.tpmEvidence,nonce,p.persistentPublicKey,identity.State().trust);}finally{nonce.fill(0);}secret=crypto.randomBytes(32);activationBlob=tpm.MakeCredential(verified.ekPublic,verified.akName,secret).toString('base64');}
  CurrentPolicy(p);if(deadline.Expired(p.proof)||verified.notAfter<=Date.now())Fail('KEYLESS_REQUEST_EXPIRED');
  p.tpmResult={rootSha256:verified.rootSha256,notAfter:verified.notAfter};p.tpmSecret=secret;secret=null;p.tpmFingerprint=fingerprint;
  p.activationResponse={version:1,status:'TPM_ACTIVATION_REQUIRED',challengeId:p.id,expiresAt:p.expiresAt,activationBlob,activationCanonical:tpmRecovery.ActivationCanonical(p,p.tpmSecret)};
  return {...p.activationResponse};
 }finally{secret?.fill(0);}
}
function ActivationCanonicalBody(p,body){const secret=require('../devices/peace.desktop-tpm-attestation').B64(body.secret,32,32);try{return tpmRecovery.ActivationCanonical(p,secret);}finally{secret.fill(0);}}
function Activate(body){
 const p=Pending(body),tpm=require('../devices/peace.desktop-tpm-attestation'),secret=tpm.B64(body.secret,32,32);
 try{
  if(p.tpmVerified){if(p.activationProofHash!==Fingerprint(body))Fail('KEYLESS_REQUEST_REUSED',409);return StatusResult(p);}
  if(!p.tpmSecret||!p.tpmResult||!tpm.Equal(secret,p.tpmSecret))Fail('DEVICE_TPM_ACTIVATION_INVALID');
  const canonical=tpmRecovery.ActivationCanonical(p,secret),proof=require('../integrity/peace.desktop-proof-work');
  if(!proof.Verify(p.begin.publicKey,canonical,body.appSignature)||!proof.Verify(p.persistentPublicKey,canonical,body.persistentSignature))Fail('KEYLESS_PROOF_INVALID');
  CurrentPolicy(p);if(deadline.Expired(p.proof)||p.tpmResult.notAfter<=Date.now())Fail('KEYLESS_REQUEST_EXPIRED');
  p.tpmVerified={...p.tpmResult};p.activationProofHash=Fingerprint(body);Wipe(p);delete p.tpmSecret;p.status='PENDING_APPROVAL';p.provedAt=Date.now();return StatusResult(p);
 }finally{secret.fill(0);}
}
// Prepared evidence is held by the network call closure, never accepted from JSON.
async function PrepareTpm(body,absoluteDeadline){
 if(body?.action!=='keylessProve')return null;const p=Pending(body);if(!p.tpmCandidate||p.tpmFingerprint)return null;
 if(!body.tpmEvidence)Fail('DEVICE_TPM_REQUIRED');if(p.tpmPreparing)Fail('KEYLESS_RATE_LIMIT',429);p.tpmPreparing=true;
 let secret,nonce;
 try{
  const work=require('../integrity/peace.desktop-proof-work');await work.Run(ProofTasks(body),()=>VerifyProof(p,body),{deadline:absoluteDeadline,key:'keyless:'+p.id});
  LimitTpm(p);secret=crypto.randomBytes(32);nonce=Buffer.from(p.nonce,'base64');(p.preparingSecrets||=new Set()).add(secret);
  const verified=await require('../runtime/peace.desktop-work-queue').tpmAttestation.run({kind:'tpm-attestation',evidence:body.tpmEvidence,nonce,publicKey:p.persistentPublicKey,trust:identity.State().trust,secret},absoluteDeadline-deadline.Now().tick,{key:'keyless:'+p.id});
  if(pending.get(p.id)!==p||deadline.Expired(p.proof)||verified.notAfter<=Date.now())Fail('KEYLESS_REQUEST_EXPIRED');CurrentPolicy(p);
  return {id:p.id,fingerprint:Fingerprint(body),verified,secret};
 }catch(e){secret?.fill(0);p.preparingSecrets?.delete(secret);throw e;}finally{nonce?.fill(0);p.tpmPreparing=false;}
}
function Status(body){const p=Pending(body);VerifyProof(p,body);if(p.status==='PROOF_REQUIRED')Fail('KEYLESS_PROOF_REQUIRED');return StatusResult(p);}
function Projection(p){return {id:p.id,launcherId:p.begin.launcherId,launcherSha512:p.begin.launcherSha512,appKeyId:p.begin.deviceId,persistentKeyId:p.persistentKeyId,machineId:p.begin.machineId,createdAt:p.createdAt,expiresAt:p.expiresAt,status:p.status,proof:p.tpmVerified?'TPM_CERTIFY_ACTIVATE':'PERSISTENT_KEY_POSSESSION',hardwareAttested:!!p.tpmVerified,...(p.tpmCandidate?{recovery:tpmRecovery.Projection(p)}:{})};}
function ListPending(){Prune();return {requests:[...pending.values()].filter(p=>p.status==='PENDING_APPROVAL').map(Projection),approvalRequired:true,approvalScope:'EACH_LAUNCH_REQUEST',approvalConsumeWindowMs:APPROVAL_MS,hardwareAttested:false};}
function Approve(id,body,actor){
 if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).sort().join(',')!==(body.recovery===undefined?'identityConfirmed,launcherId,persistentKeyId':'identityConfirmed,launcherId,persistentKeyId,recovery')||body.identityConfirmed!==true||typeof actor!=='string'||!actor)Fail('KEYLESS_APPROVAL_MISMATCH',400);
 Prune();const p=pending.get(id);if(!p||!['PENDING_APPROVAL','APPROVED'].includes(p.status)||deadline.Expired(p))Fail('KEYLESS_REQUEST_EXPIRED');
 if(body.persistentKeyId!==p.persistentKeyId||body.launcherId!==p.begin.launcherId)Fail('KEYLESS_APPROVAL_MISMATCH');
 Launcher(p.begin.launcherId,p.begin.machineId);CurrentPolicy(p);
 if(p.tpmCandidate)tpmRecovery.Approve(p,body.recovery);else if(body.recovery!==undefined)Fail('KEYLESS_APPROVAL_MISMATCH',400);
 const actorHash=sha(actor);
 if(p.status==='APPROVED'){
  // A retry observes the same decision; it cannot extend its lease or transfer
  // the approving operator's acknowledgement to a different action owner.
  if(p.approvalActorHash!==actorHash)Fail('KEYLESS_APPROVAL_MISMATCH');
 }else{
  require('../storage/peace.desktop-operation-audit').Run('KEYLESS_BOOTSTRAP_APPROVE',actor,{subject:sha(p.id),...(p.tpmCandidate?{fingerprint:Fingerprint({launcherId:p.begin.launcherId,machineBinding:p.tpmCandidate.bindingId,recovery:body.recovery}),assurance:'TPM_KEY_ATTESTED'}:{assurance:'PERSISTENT_KEY_POSSESSION'})},()=>{if(deadline.Expired(p))Fail('KEYLESS_REQUEST_EXPIRED');CurrentPolicy(p);});
  if(deadline.Expired(p))Fail('KEYLESS_REQUEST_EXPIRED');CurrentPolicy(p);
  p.approvedAt=Date.now();p.approval=deadline.After(Math.min(APPROVAL_MS,Math.max(1,p.expiresAt-p.approvedAt)));
  p.approvalActorHash=actorHash;p.status='APPROVED';
 }
 return {version:1,id:p.id,status:'APPROVED',expiresAt:p.expiresAt,approvalExpiresAt:p.approval.expiresAt,approvalScope:'EACH_LAUNCH_REQUEST',hardwareAttested:!!p.tpmVerified};
}
function Begin(body,beginHandler){
 const p=Pending(body,{consumed:true});VerifyProof(p,body);
 if(!['APPROVED','CONSUMED'].includes(p.status))Fail('KEYLESS_APPROVAL_REQUIRED');
 if(p.status==='CONSUMED'){const flow=store.Load().flows[p.flowId];if(!flow||!['STARTED','DOWNLOADED'].includes(flow.status))Fail('BOOTSTRAP_LAUNCHER_USED',409);}
 const authorization=Object.freeze({});authorizations.set(authorization,{p,body:{...body}});
 try{return beginHandler({action:'begin',...p.begin},authorization);}finally{authorizations.delete(authorization);}
}
function AssertBegin(authorization,row,body,db=store.Load()){
 const value=authorizations.get(authorization);if(!value)Fail('KEYLESS_APPROVAL_REQUIRED');
 const p=Pending(value.body,{consumed:true,db});VerifyProof(p,value.body);
 if(p!==value.p||!['APPROVED','CONSUMED'].includes(p.status)||row.id!==p.begin.launcherId||BASE.some(k=>body[k]!==p.begin[k]))Fail('KEYLESS_APPROVAL_MISMATCH');
 return p;
}
function CommitBegin(authorization,row,body,db){
 const p=AssertBegin(authorization,db.launchers[row.launcherId],body,db);
 // Recheck the server-owned machine generation at the atomic consume point.
 if(row.machinePolicyGeneration!==p.machinePolicyGeneration)Fail('KEYLESS_REQUEST_EXPIRED');
 if(p.tpmCandidate)tpmRecovery.Commit(p,db);
 row.keylessPersistentKeyId=p.persistentKeyId;
 store.AfterCommit(()=>{p.tpmConsumed=!!p.tpmCandidate;Wipe(p);p.status='CONSUMED';p.flowId=row.id;p.recovery=deadline.After(Math.min(RETRY_MS,Math.max(1,p.expiresAt-Date.now())));});
}
function ProofTasks(body){if(!['keylessProve','keylessTpmActivate','keylessStatus','beginKeyless'].includes(body?.action))return [];const p=Pending(body,{consumed:body.action==='beginKeyless'});if(!p.workRate||deadline.Expired(p.workRate))p.workRate={count:0,...deadline.After(60000)};if(++p.workRate.count>60)Fail('KEYLESS_RATE_LIMIT',429);const work=require('../integrity/peace.desktop-proof-work'),canonical=body.action==='keylessTpmActivate'?ActivationCanonicalBody(p,body):Canonical(p);return [work.Job(p.begin.publicKey,canonical,body.appSignature),work.Job(p.persistentPublicKey,canonical,body.persistentSignature)];}
function Execute(body,beginHandler,prepared){switch(body.action){case 'keylessPolicy':return Policy(body);case 'keylessChallenge':return Challenge(body);case 'keylessProve':return Prove(body,prepared);case 'keylessTpmActivate':return Activate(body);case 'keylessStatus':return Status(body);case 'beginKeyless':return Begin(body,beginHandler);default:Fail('KEYLESS_REQUEST_INVALID',400);}}
function Stop(){for(const p of pending.values())Wipe(p);pending.clear();rates.clear();return {stopped:true};}
module.exports={PrepareTpm,FORMAT,FOOTER,Execute,ProofTasks,AssertBegin,CommitBegin,ListPending,Approve,Maintain:Prune,Stop};
