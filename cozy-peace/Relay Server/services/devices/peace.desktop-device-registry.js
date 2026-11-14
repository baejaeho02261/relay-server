'use strict';
// Identification (the existing pseudonymous PC binding) is deliberately separate
// from authentication (signature with the current application key). No serial,
// MAC, EK string, private key or client-selected "TPM verified" bit is accepted.
const crypto=require('node:crypto'),store=require("../bootstrap/peace.desktop-bootstrap-store");
const HASH=/^[A-F0-9]{64}$/,ID=/^[a-f0-9]{64}$/,TERMINAL=['CLOSED','REVOKED','EXPIRED'];
const PROOF_RETENTION_MS=30*86400000;
function Fail(code,status=409){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function BindingId(machineId,db=store.Load()){
 if(!HASH.test(machineId||''))Fail('DEVICE_MACHINE_INVALID',400);
 return crypto.createHmac('sha256',Buffer.from(db.secret,'hex')).update('GAME-DEVICE-LEGACY-PC-V1\n'+machineId).digest('hex');
}
function Empty(){return {version:1,revision:0,bindings:{},receipts:{},proofRetentionDays:30};}
function State(db=store.Load()){return db.deviceRegistry||Empty();}
function Validate(value){
 if(!value||value.version!==1||!Number.isSafeInteger(value.revision)||value.revision<0||!value.bindings||Array.isArray(value.bindings)||Object.keys(value.bindings).length>100000||!value.receipts||Array.isArray(value.receipts)||Object.keys(value.receipts).length>4096||value.proofRetentionDays!==30)throw Error('DEVICE_REGISTRY_INVALID');
 for(const [id,r]of Object.entries(value.bindings)){
  if(!ID.test(id)||!r||r.id!==id||r.identificationScheme!=='LEGACY_PC_HASH_V1'||!['REGISTERED','RETIRED'].includes(r.status)||!Number.isSafeInteger(r.firstSeenAt)||r.firstSeenAt<1||!Number.isSafeInteger(r.lastSeenAt)||r.lastSeenAt<r.firstSeenAt||!Array.isArray(r.proofs)||r.proofs.length>12)throw Error('DEVICE_REGISTRY_INVALID');
  if(r.status==='RETIRED'&&(!Number.isSafeInteger(r.retiredAt)||r.retiredAt<r.firstSeenAt))throw Error('DEVICE_REGISTRY_INVALID');
  for(const p of r.proofs)if(!p||!HASH.test(p.keyId)||!['A','B','O'].includes(p.stage)||p.authenticationScheme!=='EPHEMERAL_APP_RSA2048_V1'||p.assurance!=='APP_KEY_POSSESSION'||!Number.isSafeInteger(p.at)||p.at<r.firstSeenAt||!Number.isSafeInteger(p.epoch)||p.epoch<0)throw Error('DEVICE_REGISTRY_INVALID');
 }
 for(const [id,r]of Object.entries(value.receipts))if(!ID.test(id)||!r||!ID.test(r.fingerprint)||!ID.test(r.oldBindingId)||!ID.test(r.newBindingId)||!Number.isSafeInteger(r.at)||r.at<1)throw Error('DEVICE_REGISTRY_INVALID');
}
function AssertMachineAllowed(machineId,db=store.Load()){
 const id=BindingId(machineId,db);if(State(db).bindings[id]?.status==='RETIRED')Fail('DEVICE_BINDING_RETIRED',403);
}
function Row(db,machineId){
 const id=BindingId(machineId,db);db.deviceRegistry||=Empty();
 if(!db.deviceRegistry.bindings[id]){
  if(Object.keys(db.deviceRegistry.bindings).length>=100000)Fail('DEVICE_REGISTRY_CAPACITY',503);
  db.deviceRegistry.bindings[id]={id,identificationScheme:'LEGACY_PC_HASH_V1',status:'REGISTERED',firstSeenAt:Date.now(),lastSeenAt:Date.now(),proofs:[]};
 }
 return db.deviceRegistry.bindings[id];
}
// Call ONLY inside the same server transaction as a successfully verified
// A finish / B claim / O claim. Merely presenting a public key is not a proof.
function ObserveVerified(db,row,stage){
 if(!row||!HASH.test(row.deviceId||'')||!['A','B','O'].includes(stage))Fail('DEVICE_PROOF_CONTEXT_INVALID',400);
 AssertMachineAllowed(row.machineId,db);const target=Row(db,row.machineId),at=Date.now();
 if(at<target.lastSeenAt)Fail('DEVICE_CLOCK_REVERSED',403);
 target.proofs=target.proofs.filter(p=>at>=p.at&&at-p.at<PROOF_RETENTION_MS&&!(p.keyId===row.deviceId&&p.stage===stage)).slice(-11);
 target.proofs.push({keyId:row.deviceId,stage,authenticationScheme:'EPHEMERAL_APP_RSA2048_V1',assurance:'APP_KEY_POSSESSION',at,epoch:require("../recovery/peace.desktop-recovery").Epoch(db)});
 target.lastSeenAt=at;db.deviceRegistry.revision++;
}
function RetireSessions(db,bindingId){
 const at=Date.now();let count=0;
 for(const row of Object.values(db.overlays||{}))if(BindingId(row.machineId,db)===bindingId&&!TERMINAL.includes(row.status)){
  row.status='REVOKED';row.revokedAt=at;row.reason='DEVICE_REPLACED';require("../overlay/peace.desktop-overlay").RetireForDevice(row);count++;
 }
 for(const row of Object.values(db.flows))if(BindingId(row.machineId,db)===bindingId&&!TERMINAL.includes(row.status)){
  row.status='REVOKED';row.revokedAt=at;row.reason='DEVICE_REPLACED';const launcher=db.launchers[row.launcherId];launcher.status='REVOKED';delete launcher.ticketNonce;delete launcher.profile;launcher.retiredAt||=at;require("../bootstrap/peace.desktop-bootstrap").RetireFlow(row,db);count++;
 }
 return count;
}
function Replace(body,actor='ADMIN'){
 if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).some(k=>!['oldBindingId','newMachineId','expectedRevision','requestId','reasonCode'].includes(k))||!ID.test(body.oldBindingId||'')||!HASH.test(body.newMachineId||'')||!Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId||'')||!['MAINBOARD_REPLACED','TPM_RESET','WINDOWS_REINSTALLED','ADMIN_RECOVERY'].includes(body.reasonCode))Fail('DEVICE_REPLACEMENT_INPUT_INVALID',400);
 const sha=x=>crypto.createHash('sha256').update(x).digest('hex'),key=sha('GAME-DEVICE-REPLACEMENT-V1\n'+actor+'\n'+body.requestId),fingerprint=sha(JSON.stringify(body)),db=store.Load(),state=State(db),prior=state.receipts[key];
 if(prior){if(prior.fingerprint!==fingerprint)Fail('DEVICE_REPLACEMENT_REQUEST_REUSED');return {...prior,duplicate:true};}
 if(Object.keys(state.receipts).length>=4096)Fail('DEVICE_RECEIPT_CAPACITY',503);
 const old=state.bindings[body.oldBindingId],newId=BindingId(body.newMachineId,db);
 if(!old||old.status!=='REGISTERED'||newId===old.id||state.bindings[newId]?.status==='RETIRED')Fail('DEVICE_REPLACEMENT_INVALID');
 if(state.revision!==body.expectedRevision)Fail('DEVICE_REVISION_CONFLICT');
 const result=require("../storage/peace.desktop-operation-audit").Run('DEVICE_REPLACEMENT',actor,{subject:old.id,reasonCode:body.reasonCode},next=>{
  const current=State(next);if(current.revision!==body.expectedRevision)Fail('DEVICE_REVISION_CONFLICT');
  const row=current.bindings[old.id],at=Date.now();if(at<row.lastSeenAt)Fail('DEVICE_CLOCK_REVERSED');row.status='RETIRED';row.retiredAt=at;row.proofs=[];
  const fresh=Row(next,body.newMachineId);require('./peace.desktop-device-identity').ReplaceBinding(next,row.id,fresh.id);const closed=RetireSessions(next,row.id);
  const receipt={oldBindingId:row.id,newBindingId:fresh.id,fingerprint,at,closed,licenseCarryOver:false};current.receipts[key]=receipt;current.revision++;return receipt;
 });
 require('./peace.desktop-device-identity').ClearChallenges();require("../security/peace.desktop-security-authority").InvalidateAll();return result;
}
function Prune(){
 const at=Date.now(),db=store.Load();if(!Object.values(State(db).bindings).some(r=>r.proofs.some(p=>at>=p.at&&at-p.at>=PROOF_RETENTION_MS)))return {removed:0};
 let removed=0;require("../storage/peace.desktop-operation-audit").Run('DEVICE_PROOF_RETENTION','SCHEDULED',{count:Object.keys(State(db).bindings).length},next=>{for(const r of Object.values(next.deviceRegistry.bindings)){const before=r.proofs.length;r.proofs=r.proofs.filter(p=>at<p.at||at-p.at<PROOF_RETENTION_MS);removed+=before-r.proofs.length;}next.deviceRegistry.revision++;});return {removed};
}
function List(){const state=State();return {version:1,revision:state.revision,proofRetentionDays:30,authorizationTombstones:'RETAINED_NO_LICENSE_RESET',tpmAttested:false,items:Object.values(state.bindings).map(r=>({id:r.id,identificationScheme:r.identificationScheme,status:r.status,firstSeenAt:r.firstSeenAt,lastSeenAt:r.lastSeenAt,retiredAt:r.retiredAt||0,proofCount:r.proofs.filter(p=>Date.now()>=p.at&&Date.now()-p.at<PROOF_RETENTION_MS).length,authenticationScheme:'EPHEMERAL_APP_RSA2048_V1',assurance:r.proofs.some(p=>Date.now()>=p.at&&Date.now()-p.at<PROOF_RETENTION_MS)?'APP_KEY_POSSESSION':'IDENTIFIED_ONLY'}))};}
function ClearChallenges(){require('./peace.desktop-device-identity').ClearChallenges();}
module.exports={RetireSessions,BindingId,State,Validate,AssertMachineAllowed,ObserveVerified,Replace,Prune,List,ClearChallenges};
