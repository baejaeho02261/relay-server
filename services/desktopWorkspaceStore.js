'use strict';
// Server-only operator metadata and resumable work. No credentials or client cache.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const config = require('../config/config');
const DIR = path.join(config.DATA_DIR, 'desktop-workspace');
const FILE = path.join(DIR, 'workspace.json');
let current, poisoned = false;
function Empty() { return {schema:1, revision:0, metadata:{}, jobs:{}, receipts:{}, releaseNotes:{}}; }
function Plain(x) { return !!x && Object.getPrototypeOf(x)===Object.prototype; }
function Fail(code='WORKSPACE_STORAGE_INVALID') { const e=Error(code);e.desktopError=true;e.status=503;throw e; }
function Validate(v) {
  if(!Plain(v)||v.schema!==1||!Number.isSafeInteger(v.revision)||v.revision<0||!['metadata','jobs','receipts'].every(k=>Plain(v[k])))Fail();
  if(v.releaseNotes!==undefined&&(!Plain(v.releaseNotes)||Object.keys(v.releaseNotes).length>1000))Fail();
  for(const [key,note] of Object.entries(v.releaseNotes||{}))if(!/^(?:DA-)?[A-F0-9]{24}:(?:DA-)?[A-F0-9]{24}(?::(?:DA-)?[A-F0-9]{24})?$/.test(key)||!Plain(note)||typeof note.note!=='string'||note.note.length>1000||!Number.isSafeInteger(note.updatedAt)||note.updatedAt<1||typeof note.updatedBy!=='string')Fail();
  if(Object.keys(v.jobs).length>1000||Object.keys(v.receipts).length>1000||Object.keys(v.metadata).length>100000)Fail();
  for(const [id,m] of Object.entries(v.metadata))if(!/^(?:DL-)?[A-F0-9]{24}$/.test(id)||!Plain(m)||typeof m.note!=='string'||m.note.length>500||!Array.isArray(m.tags)||m.tags.length>10||m.tags.some(t=>typeof t!=='string'||t.length>30)||!Number.isSafeInteger(m.revision)||m.revision<1)Fail();
  for(const [id,j] of Object.entries(v.jobs)){
    if(!/^[a-f0-9]{32}$/.test(id)||j.id!==id||!['CREATE','METADATA','EXPORT','CLEANUP'].includes(j.kind)||!['QUEUED','RUNNING','DONE','PARTIAL','CANCELLED'].includes(j.status)||!Array.isArray(j.items)||j.items.length<1||j.items.length>100||!Number.isSafeInteger(j.createdAt))Fail();
    for(const i of j.items)if(!Plain(i)||!['PENDING','RUNNING','DONE','FAILED'].includes(i.status)||!Plain(i.input))Fail();
  }
  return v;
}
function Mark(value,bytes){return {revision:value.revision,sha512:crypto.createHash('sha512').update(bytes).digest('hex')};}
function Same(a,b){return a?.revision===b?.revision&&a?.sha512===b?.sha512;}
function Journal(){const j=require('./desktopBootstrapStore').Load().workspaceJournal;if(!j)return null;
 const valid=x=>x&&Number.isSafeInteger(x.revision)&&x.revision>=0&&/^[a-f0-9]{128}$/.test(x.sha512||'');
 if(j.version!==1||!valid(j.current)||j.pending&&(!valid(j.pending.mark)||j.pending.mark.revision!==j.current.revision+1))Fail();
 if(j.pending)require('./desktopOperationAudit').ValidateOperation(j.pending.operation);return j;
}
function Load() {
 if(poisoned)Fail('WORKSPACE_RESTART_REQUIRED');if(current)return current;
 try {
  const bytes=fs.existsSync(FILE)?require('./durableFile').ReadRegular(FILE,32*1024*1024):Buffer.from(JSON.stringify(Empty())),value=Validate(require('./strictJson').Parse(bytes,{maxBytes:32*1024*1024,maxNodes:2000000})),mark=Mark(value,bytes),journal=Journal(),store=require('./desktopBootstrapStore');
  if(!journal)store.Atomic(db=>{db.workspaceJournal={version:1,current:mark};});
  else if(journal.pending){
   const committed=Same(mark,journal.pending.mark);if(!committed&&!Same(mark,journal.current))Fail('WORKSPACE_ROLLBACK_DETECTED');
   store.Atomic(db=>{db.workspaceJournal={version:1,current:mark};require('./desktopOperationAudit').Attach(db,journal.pending.operation,{revision:mark.revision},committed?'COMMITTED':'FAILED');});
  }else if(!Same(mark,journal.current))Fail('WORKSPACE_ROLLBACK_DETECTED');
  return current=value;
 }catch(e){if(e.desktopError)throw e;Fail();}
}
function Write(value){
 fs.mkdirSync(DIR,{recursive:true,mode:0o700});const stat=fs.lstatSync(DIR);if(!stat.isDirectory()||stat.isSymbolicLink())Fail();
 const bytes=Buffer.from(JSON.stringify(value));if(bytes.length>32*1024*1024)Fail('WORKSPACE_STORAGE_LIMIT');
 try{require('./durableFile').Atomic(FILE,bytes);}catch(e){if(e.published)poisoned=true;Fail(poisoned?'WORKSPACE_RESTART_REQUIRED':'WORKSPACE_SAVE_FAILED');}finally{bytes.fill(0);}
}
function Atomic(fn,{kind='WORKSPACE_CHANGE',actor='SERVER'}={}){
 if(!require('./haCoordinator').CanAcceptTraffic())Fail('RELAY_STANDBY_READ_ONLY');
 const previous=Load(),next=structuredClone(previous),result=fn(next);next.revision=previous.revision+1;Validate(next);
 const store=require('./desktopBootstrapStore'),audit=require('./desktopOperationAudit'),before=Journal().current,bytes=Buffer.from(JSON.stringify(next)),mark=Mark(next,bytes);bytes.fill(0);
 if(Object.keys(store.Load().serverAuditOutbox||{}).length>=99990)Fail('SERVER_AUDIT_OUTBOX_CAPACITY');
 const operation=audit.Begin(kind,actor,{revision:next.revision});
 try {
  store.Atomic(db=>{if(!Same(db.workspaceJournal.current,before)||db.workspaceJournal.pending)Fail('WORKSPACE_CONFLICT');db.workspaceJournal.pending={mark,operation};});
  Write(next);current=next;
  store.Atomic(db=>{db.workspaceJournal={version:1,current:mark};audit.Attach(db,operation,{revision:next.revision});});
 }catch(error){
  if(current===next||poisoned){poisoned=true;audit.Failed(operation,{message:'WORKSPACE_RESTART_REQUIRED'});Fail('WORKSPACE_RESTART_REQUIRED');}
  try{store.Atomic(db=>{if(db.workspaceJournal?.pending?.operation.operationId===operation.operationId){db.workspaceJournal={version:1,current:before};audit.Attach(db,operation,{revision:previous.revision},'FAILED');}});}catch(_){poisoned=true;}
  audit.BestEffortDrain();if(poisoned)Fail('WORKSPACE_RESTART_REQUIRED');throw error;
 }
 audit.BestEffortDrain();return result;
}
module.exports={Load,Atomic,DIR,FILE,Validate};
