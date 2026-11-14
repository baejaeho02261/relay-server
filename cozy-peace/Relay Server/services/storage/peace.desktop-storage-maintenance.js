'use strict';
// Result receipts are committed WITH each authority change. File cleanup resumes
// from that result; a lost final response never compacts a new, different cohort.
const crypto=require('node:crypto'),store=require("../bootstrap/peace.desktop-bootstrap-store");
const ACTIONS=['MACHINE_CHECKPOINT','MACHINE_ARCHIVE_RETENTION','OUTBOX_COMPACT','AUDIT_RETENTION'];
function Fail(code,status=409){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Rows(){
 const rows=store.Load().serverStorageMaintenance||{};
 if(!rows||Array.isArray(rows)||Object.keys(rows).length>4096)Fail('SERVER_STORAGE_RECEIPTS_INVALID',503);
 for(const [id,r]of Object.entries(rows)){
  if(!/^[a-f0-9]{64}$/.test(id)||!r||!/^[a-f0-9]{64}$/.test(r.fingerprint||'')||!ACTIONS.includes(r.action)||!['PENDING','RESULT','COMMITTED'].includes(r.state)||!Number.isSafeInteger(r.at)||r.at<1)Fail('SERVER_STORAGE_RECEIPTS_INVALID',503);
  require('./peace.desktop-operation-audit').ValidateOperation(r.operation);
  if(r.state!=='PENDING'&&(!r.result||typeof r.result!=='object'||Array.isArray(r.result)))Fail('SERVER_STORAGE_RECEIPTS_INVALID',503);
 }
 return rows;
}
function Quiescent(){const db=store.Load(),active=Object.values(db.flows).concat(Object.values(db.overlays||{})).some(r=>!['CLOSED','REVOKED','EXPIRED'].includes(r.status));if(active)Fail('SERVER_STORAGE_ACTIVE_SESSIONS');}
function Status(){const receipts=Rows();return {pending:Object.values(receipts).filter(r=>r.state!=='COMMITTED').map(r=>({action:r.action,at:r.at,operationId:r.operation.operationId,stage:r.state})),acl:require('./peace.desktop-storage-acl').Status(),machine:require("../devices/peace.desktop-machine-policy").StorageStatus(),audit:require('./peace.desktop-audit-retention').Status(),outbox:require('./peace.desktop-operation-audit').StorageStatus(),historyPolicy:{spentLicenses:'PERMANENT_TOMBSTONES',revocations:'PERMANENT_TOMBSTONES',requestFingerprints:'RETAINED_FOR_REPLAY_PREVENTION',rawAuditDetails:'CONFIGURED_DAYS',activeArchives:'AUTHENTICATED_SERVER_ONLY'},physicalRestoreTested:false};}
function Apply(body,actor='ADMIN'){
 const retention=['AUDIT_RETENTION','MACHINE_ARCHIVE_RETENTION'].includes(body?.action);
 if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).some(k=>!['requestId','action','days'].includes(k))||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId||'')||!ACTIONS.includes(body.action)||retention&&(!Number.isSafeInteger(body.days)||body.days<(body.action==='MACHINE_ARCHIVE_RETENTION'?7:1)||body.days>3650)||!retention&&body.days!==undefined)Fail('SERVER_STORAGE_INPUT_INVALID',400);
 const hash=x=>crypto.createHash('sha256').update(x).digest('hex'),key=hash('GAME-STORAGE-MAINTENANCE-V1\n'+actor+'\n'+body.requestId),fingerprint=hash(JSON.stringify({action:body.action,days:body.days||0})),old=Rows()[key];
 if(old){if(old.fingerprint!==fingerprint)Fail('SERVER_STORAGE_REQUEST_REUSED');if(old.state==='COMMITTED'){require('./peace.desktop-operation-audit').BestEffortDrain();return {...old.result,duplicate:true};}}
 else if(Object.values(Rows()).some(r=>r.state!=='COMMITTED'))Fail('SERVER_STORAGE_RECOVERY_REQUIRED');
 Quiescent();const audit=require('./peace.desktop-operation-audit');let op=old?.operation;
 if(!old){if(Object.keys(Rows()).length>=4096)Fail('SERVER_STORAGE_RECEIPT_CAPACITY',503);op=audit.Begin('STORAGE_MAINTENANCE',actor,{reasonCode:body.action});try{store.Atomic(db=>{db.serverStorageMaintenance||={};db.serverStorageMaintenance[key]={action:body.action,fingerprint,state:'PENDING',at:Date.now(),operation:op};});}catch(e){audit.Failed(op,e);throw e;}}
 function SaveResult(db,result,plan){const receipt=db.serverStorageMaintenance[key];if(receipt.state!=='PENDING'||receipt.fingerprint!==fingerprint)Fail('SERVER_STORAGE_REQUEST_REUSED');receipt.state='RESULT';receipt.result={...result,action:body.action};if(plan)receipt.plan=plan;}
 try{
  if(Rows()[key].state==='PENDING'){
   if(body.action==='MACHINE_CHECKPOINT'){
    // The native journal checkpoint row stores this operation's exact result,
    // so an interrupted cross-store acknowledgment can safely call it again.
    const result=require("../devices/peace.desktop-machine-policy").Compact(op.operationId);store.Atomic(db=>SaveResult(db,result));
   }else if(body.action==='MACHINE_ARCHIVE_RETENTION'){
    const plan=require("../devices/peace.desktop-machine-policy").PlanPruneSegments(body.days),result={removed:plan.files.length,minimumAgeDays:body.days,checkpointPreserved:true,receiptsPreserved:true};store.Atomic(db=>SaveResult(db,result,plan));
   }else if(body.action==='OUTBOX_COMPACT')audit.Compact({actor,minimum:1,onCommit:SaveResult});
   else require('./peace.desktop-audit-retention').Apply({days:body.days,actor,onCommit:SaveResult});
  }
  const receipt=Rows()[key];
  if(body.action==='MACHINE_ARCHIVE_RETENTION')require("../devices/peace.desktop-machine-policy").PruneSegments(body.days,receipt.plan);
  if(body.action==='AUDIT_RETENTION'){require('./peace.desktop-audit-retention').Cleanup();audit.PruneRetired();require('./peace.desktop-audit-archive').PruneUnreferenced();}
  require('./peace.desktop-audit-archive').Cleanup();
  store.Atomic(db=>{const row=db.serverStorageMaintenance[key];if(row.state!=='RESULT'||row.fingerprint!==fingerprint)Fail('SERVER_STORAGE_REQUEST_REUSED');row.state='COMMITTED';delete row.plan;audit.Attach(db,op);});audit.BestEffortDrain();return {...receipt.result};
 }catch(e){audit.Failed(op,{message:'SERVER_STORAGE_MAINTENANCE_PENDING'});throw e;}
}
module.exports={Apply,Status};
