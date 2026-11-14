'use strict';
// Operation ID is shared by intent / commit / failure. Only allowlisted metadata
// enters the audit trail; not request bodies, tokens, private keys, or HWID.
const crypto=require('node:crypto');
const HASH=/^[a-f0-9]{64}$/,WORD=/^[A-Z][A-Z0-9_]{0,63}$/;
function Fail(code){const e=Error(code);e.desktopError=true;e.status=503;throw e;}
function Safe(meta={}){
 const out={};
 for(const name of ['kind','component','state','reasonCode','bindingScheme','assurance'])if(typeof meta[name]==='string'&&WORD.test(meta[name]))out[name]=meta[name];
 for(const name of ['revision','epoch','count','bytes'])if(Number.isSafeInteger(meta[name])&&meta[name]>=0)out[name]=meta[name];
 for(const name of ['subject','fingerprint','actorHash'])if(HASH.test(meta[name]||''))out[name]=meta[name];
 return out;
}
const sha=text=>crypto.createHash('sha256').update(String(text)).digest('hex');
function Event(operationId,phase,meta,at=Date.now()){
 if(!HASH.test(operationId)||!['INTENT','COMMITTED','FAILED','UNCERTAIN'].includes(phase))Fail('SERVER_AUDIT_INPUT_INVALID');
 return {auditEventId:sha('GAME-SERVER-OP-EVENT-V1\n'+operationId+'\n'+phase),operationId,phase,at,...Safe(meta)};
}
function Emit(event){const result=require("../../storage/audit/peace.audit.js").AppendOperationEvent(event.auditEventId,'DESKTOP_SERVER_OPERATION',event);if(!result?.ok)Fail('SERVER_AUDIT_UNAVAILABLE');return result;}
// Stores with their own authenticated journal retain the intent beside their
// mutation, then replay the exact commit timestamp/identity after restart.
function CommitExternal(op,details={}){ValidateOperation(op);Emit(op.intent);return Emit(Event(op.operationId,'COMMITTED',{...op.meta,...Safe(details)},op.intent.at));}
function Begin(kind,actor,details={}){
 if(!WORD.test(kind))Fail('SERVER_AUDIT_INPUT_INVALID');
 const operationId=crypto.randomBytes(32).toString('hex'),meta=Safe({...details,kind,actorHash:sha(actor||'ADMIN')});
 const event=Event(operationId,'INTENT',meta);Emit(event);return {operationId,meta,intent:event};
}
function Attach(db,op,details={},phase='COMMITTED'){
 if(!['COMMITTED','FAILED','UNCERTAIN'].includes(phase))Fail('SERVER_AUDIT_INPUT_INVALID');
 db.serverAuditOutbox||={};
 // Completed receipts remain in the authenticated state until explicitly
 // checkpointed; never silently drop a failed/unacknowledged commit event.
 if(Object.keys(db.serverAuditOutbox).length>=100000)Fail('SERVER_AUDIT_OUTBOX_CAPACITY');
 const event=Event(op.operationId,phase,{...op.meta,...Safe(details)}),old=db.serverAuditOutbox[event.auditEventId];
 if(old)Fail('SERVER_AUDIT_OPERATION_CONFLICT');db.serverAuditOutbox[event.auditEventId]={intent:op.intent,event,acked:false};
}
function Failed(op,error){try{Emit(Event(op.operationId,(error?.authorityMayBeCommitted===true||error?.published===true||/RESTART_REQUIRED|STORAGE|WITNESS/.test(error?.message||''))?'UNCERTAIN':'FAILED',op.meta,op.intent.at));}catch(_){console.error('SERVER_AUDIT_FAILURE_PENDING');}}
function ValidateOperation(op){
 if(!op||!HASH.test(op.operationId||'')||!op.meta||JSON.stringify(Safe(op.meta))!==JSON.stringify(op.meta)||!op.intent)throw Error('SERVER_AUDIT_OPERATION_INVALID');
 ValidateEvent(op.intent,'INTENT');if(op.operationId!==op.intent.operationId||Object.keys(op.meta).some(k=>op.intent[k]!==op.meta[k]))throw Error('SERVER_AUDIT_OPERATION_INVALID');
}
function ValidateEvent(e,phase){
 if(!e||!HASH.test(e.operationId||'')||e.phase!==phase||e.auditEventId!==sha('GAME-SERVER-OP-EVENT-V1\n'+e.operationId+'\n'+phase)||!Number.isSafeInteger(e.at)||e.at<1||Object.keys(e).some(k=>!['auditEventId','operationId','phase','at',...Object.keys(Safe(e))].includes(k)))throw Error('SERVER_AUDIT_OUTBOX_INVALID');
}
function Validate(rows){
 if(!rows||Array.isArray(rows)||Object.getPrototypeOf(rows)!==Object.prototype||Object.keys(rows).length>100000)throw Error('SERVER_AUDIT_OUTBOX_INVALID');
 for(const [id,row]of Object.entries(rows)){
  if(!['COMMITTED','FAILED','UNCERTAIN'].includes(row?.event?.phase))throw Error('SERVER_AUDIT_OUTBOX_INVALID');
  ValidateEvent(row.event,row.event.phase);ValidateEvent(row.intent,'INTENT');
  if(id!==row.event.auditEventId||row.intent.operationId!==row.event.operationId||row.intent.kind!==row.event.kind||typeof row.acked!=='boolean'||Object.keys(row).some(k=>!['intent','event','acked'].includes(k)))throw Error('SERVER_AUDIT_OUTBOX_INVALID');
 }
}
function Archives(){
 const rows=require("../bootstrap/peace.desktop-bootstrap-store").Load().serverAuditOutboxArchives||[];
 if(!Array.isArray(rows)||rows.length>10000)Fail('SERVER_AUDIT_ARCHIVES_INVALID');
 return rows;
}
function ArchiveRows(descriptor){const rows=require('./peace.desktop-audit-archive').Read(descriptor,'OUTBOX');Validate(rows);if(Object.values(rows).some(r=>!r.acked))Fail('SERVER_AUDIT_ARCHIVES_INVALID');return rows;}
function Compact({actor='SCHEDULED',minimum=256,onCommit}={}){
 if(!Number.isSafeInteger(minimum)||minimum<1||minimum>100000)Fail('SERVER_AUDIT_INPUT_INVALID');
 const store=require("../bootstrap/peace.desktop-bootstrap-store"),db=store.Load(),rows=db.serverAuditOutbox||{},selected=Object.fromEntries(Object.entries(rows).filter(([,r])=>r.acked));Validate(rows);
 if(Object.keys(selected).length<minimum){const result={compacted:false,reason:'BELOW_THRESHOLD',count:0};if(onCommit)store.Atomic(db=>onCommit(db,result));return result;}
 const previous=Archives();if(previous.length>=10000)Fail('SERVER_AUDIT_ARCHIVE_CAPACITY');
 const op=Begin('AUDIT_OUTBOX_COMPACT',actor,{count:Object.keys(selected).length});
 try{
  const descriptor=require('./peace.desktop-audit-archive').Put('OUTBOX',selected),result={compacted:true,count:Object.keys(selected).length,archives:previous.length+1,pendingPreserved:true};
  store.Atomic(next=>{next.serverAuditOutboxArchives=[...previous,descriptor];for(const id of Object.keys(selected)){if(!next.serverAuditOutbox[id]?.acked)Fail('SERVER_AUDIT_OPERATION_CONFLICT');delete next.serverAuditOutbox[id];}Attach(next,op,{count:Object.keys(selected).length});if(onCommit)onCommit(next,result);});
  BestEffortDrain();return result;
 }catch(error){Failed(op,error);throw error;}
}
function PruneRetired(){
 const retention=require('./peace.desktop-audit-retention').Read();if(!retention.sequence)return {removedArchives:0,removedLive:0};
 const audit=require("../../storage/audit/peace.audit.js"),store=require("../bootstrap/peace.desktop-bootstrap-store"),archive=require('./peace.desktop-audit-archive'),db=store.Load();
 const retired=e=>{const old=retention.operations[e.auditEventId];return !!old&&old.fingerprint===audit.EventFingerprint('DESKTOP_SERVER_OPERATION',JSON.stringify({...e,auditEventId:e.auditEventId}));};
 const live=Object.entries(db.serverAuditOutbox||{}).filter(([,r])=>r.acked&&retired(r.intent)&&retired(r.event)).map(([id])=>id),descriptors=Archives().filter(d=>Object.values(ArchiveRows(d)).every(r=>retired(r.intent)&&retired(r.event)));
 if(!live.length&&!descriptors.length)return {removedArchives:0,removedLive:0};
 const op=Begin('AUDIT_METADATA_RETENTION','SCHEDULED',{count:live.length+descriptors.length});let committed=false;
 try{store.Atomic(next=>{for(const id of live)delete next.serverAuditOutbox[id];const names=new Set(descriptors.map(d=>d.file));next.serverAuditOutboxArchives=(next.serverAuditOutboxArchives||[]).filter(d=>!names.has(d.file));for(const descriptor of descriptors)archive.QueueDelete(next,descriptor);Attach(next,op,{count:live.length+descriptors.length});});committed=true;BestEffortDrain();archive.Cleanup();return {removedArchives:descriptors.length,removedLive:live.length};}
 catch(error){Failed(op,committed?{message:'STORAGE_COMMITTED_CLEANUP_PENDING'}:error);throw error;}
}
function StorageStatus(){const rows=require("../bootstrap/peace.desktop-bootstrap-store").Load().serverAuditOutbox||{};Validate(rows);return {active:Object.keys(rows).length,pending:Object.values(rows).filter(r=>!r.acked).length,archives:Archives().length,archivedMetadata:'ALLOWLISTED_HASHED_IDENTITIES',receiptDeletion:false};}
function RecordAccess(kind,actor,details={}){const op=Begin(kind,actor,details);CommitExternal(op);return {operationId:op.operationId};}
let draining=false;
function Drain({reconcile=false}={}){
 if(draining)return {pending:true};draining=true;
 try{
  const store=require("../bootstrap/peace.desktop-bootstrap-store"),rows=store.Load().serverAuditOutbox||{},done=[];
  Validate(rows);
  if(reconcile)for(const descriptor of Archives())for(const row of Object.values(ArchiveRows(descriptor))){Emit(row.intent);Emit(row.event);}
  for(const [id,row]of Object.entries(rows)){if(row.acked&&!reconcile)continue;if(row.intent)Emit(row.intent);Emit(row.event);if(!row.acked)done.push(id);if(!reconcile&&done.length>=256)break;}
  if(done.length)store.Atomic(next=>{for(const id of done)next.serverAuditOutbox[id].acked=true;});
  return {delivered:done.length,pending:Object.values(store.Load().serverAuditOutbox||{}).filter(x=>!x.acked).length};
 }finally{draining=false;}
}
function BestEffortDrain(){try{return Drain();}catch(_){console.error('SERVER_AUDIT_OUTBOX_PENDING');return {pending:true};}}
function Run(kind,actor,details,mutate){
 const op=Begin(kind,actor,details),store=require("../bootstrap/peace.desktop-bootstrap-store");let result;
 try{result=store.Atomic(db=>{const result=mutate(db);Attach(db,op,{revision:db.revision+1});return result;});}
 catch(error){Failed(op,error);throw error;}
 BestEffortDrain();return result;
}
module.exports={Safe,Begin,Attach,Failed,Validate,ValidateOperation,Drain,BestEffortDrain,Run,CommitExternal,Compact,StorageStatus,RecordAccess,PruneRetired};
