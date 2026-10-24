'use strict';
// Only the server's own unreferenced deployment files are eligible. This module
// never scans client PCs, arbitrary paths, keys, manifests, audit logs or backups.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const store=require("../bootstrap/peace.desktop-bootstrap-store"),disk=require('./peace.durable-file'),audit=require('./peace.desktop-operation-audit');
const NAME=/^((?:DA-)?[A-F0-9]{24})\.exe(?:\.[a-f0-9]{24,32}\.tmp)?$/,ID=/^[a-f0-9]{64}$/,HASH=/^[a-f0-9]{128}$/;
const GRACE_MS=7*86400000,MAX_BYTES=64*1024*1024,MAX_SCAN=256,SCAN_BYTES=128*1024*1024;
function Fail(code,status=409){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Directory(){const dir=path.join(store.DIR,'quarantine');fs.mkdirSync(dir,{recursive:true,mode:0o700});const s=fs.lstatSync(dir);if(!s.isDirectory()||s.isSymbolicLink()||fs.realpathSync(dir)!==path.join(fs.realpathSync(store.DIR),'quarantine'))Fail('ORPHAN_PATH_UNSAFE');return dir;}
function Referenced(db,name){
 const m=NAME.exec(name);if(!m)return true;const id=m[1];
 return !!db.artifacts[id]||Object.values(db.active).includes(id)||Object.values(db.launchers).some(r=>r.artifactId===id)||Object.values(db.flows).some(r=>r.releaseId===id||r.overlayReleaseId===id)||Object.values(db.overlays||{}).some(r=>r.releaseId===id)||!!db.workspaceGarbage?.[id];
}
function Fingerprint(file){
 const bytes=disk.ReadRegular(file,MAX_BYTES);try{return {sha512:crypto.createHash('sha512').update(bytes).digest('hex'),size:bytes.length};}finally{bytes.fill(0);}
}
function Validate(rows){
 if(!rows||Array.isArray(rows)||Object.keys(rows).length>100000)throw Error('ORPHAN_STORAGE_INVALID');
 for(const [id,r]of Object.entries(rows)){if(!ID.test(id)||!r||r.id!==id||!NAME.test(r.name)||!HASH.test(r.sha512)||!Number.isSafeInteger(r.size)||r.size<0||r.size>MAX_BYTES||!['PENDING','QUARANTINED','DELETE_PENDING','DELETED'].includes(r.status)||!Number.isSafeInteger(r.createdAt)||r.createdAt<1||r.status!=='PENDING'&&(!Number.isSafeInteger(r.quarantinedAt)||r.quarantinedAt<r.createdAt))throw Error('ORPHAN_STORAGE_INVALID');
  audit.ValidateOperation(r.quarantineOperation);if(['DELETE_PENDING','DELETED'].includes(r.status))audit.ValidateOperation(r.deleteOperation);
 }
}
function RequireIdle(){const db=store.Load();if([Object.values(db.flows),Object.values(db.overlays||{})].flat().some(r=>!['CLOSED','REVOKED','EXPIRED'].includes(r.status)))Fail('ORPHAN_MAINTENANCE_ACTIVE_EXECUTIONS');}
function Scan({after=''}={}){
 RequireIdle();
 if(typeof after!=='string'||after.length>128)Fail('ORPHAN_INPUT_INVALID',400);
 const db=store.Load(),names=fs.readdirSync(store.DIR).filter(n=>NAME.test(n)&&n>after).sort(),items=[];let bytes=0,visited=0,last=after;const began=process.hrtime.bigint();
 for(const name of names.slice(0,MAX_SCAN)){
  if(visited&& (bytes>=SCAN_BYTES||process.hrtime.bigint()-began>250000000n))break;visited++;last=name;
  if(Referenced(db,name))continue;
  try{const fp=Fingerprint(path.join(store.DIR,name));bytes+=fp.size;items.push({name,...fp,eligible:true});}
  catch(_){items.push({name,eligible:false,reason:'UNSAFE_OR_UNREADABLE'});}
 }
 return {items,nextAfter:names.length>visited?last:null,bytesRead:bytes,scope:'UNREFERENCED_SERVER_ARTIFACTS_ONLY',minimumRetentionDays:7};
}
function Check(body){if(!body||typeof body!=='object'||Object.keys(body).some(k=>!['name','sha512'].includes(k))||!NAME.test(body.name||'')||!HASH.test(body.sha512||''))Fail('ORPHAN_INPUT_INVALID',400);}
function Resume(id){
 const row=store.Load().orphanQuarantine?.[id];if(!row||row.status!=='PENDING')return row;
 if(Referenced(store.Load(),row.name))Fail('ORPHAN_NOW_REFERENCED');
 const source=path.join(store.DIR,row.name),target=path.join(Directory(),id+'.bin'),a=fs.existsSync(source),b=fs.existsSync(target);
 if(a&&b||!a&&!b)Fail('ORPHAN_LOCATION_CONFLICT');
 const fp=Fingerprint(a?source:target);if(fp.sha512!==row.sha512||fp.size!==row.size)Fail('ORPHAN_HASH_CHANGED');
 if(a)fs.renameSync(source,target);
 // A retry may see the moved file after the preceding directory fsync failed.
 // Repeat both fences before acknowledging that same durable operation.
 disk.SyncDirectory(store.DIR);disk.SyncDirectory(path.dirname(target));
 store.Atomic(next=>{const r=next.orphanQuarantine[id];if(Referenced(next,r.name)||r.sha512!==row.sha512)Fail('ORPHAN_NOW_REFERENCED');r.status='QUARANTINED';r.quarantinedAt=Math.max(Date.now(),r.createdAt);audit.Attach(next,r.quarantineOperation,{revision:next.revision+1});});audit.BestEffortDrain();
 return store.Load().orphanQuarantine[id];
}
function Quarantine(body,actor='ADMIN'){
 RequireIdle();
 Check(body);if(Referenced(store.Load(),body.name))Fail('ORPHAN_NOW_REFERENCED');
 const id=crypto.createHash('sha256').update('GAME-SERVER-ORPHAN-V1\n'+body.name+'\n'+body.sha512).digest('hex'),old=store.Load().orphanQuarantine?.[id];
 if(old)return Resume(id)||old;
 const fp=Fingerprint(path.join(store.DIR,body.name));if(fp.sha512!==body.sha512)Fail('ORPHAN_HASH_CHANGED');
 const op=audit.Begin('ORPHAN_QUARANTINE',actor,{subject:id,bytes:fp.size});let pending=false;
 try{store.Atomic(db=>{
  if(Referenced(db,body.name))Fail('ORPHAN_NOW_REFERENCED');db.orphanQuarantine||={};if(Object.keys(db.orphanQuarantine).length>=100000)Fail('ORPHAN_CAPACITY',503);
  db.orphanQuarantine[id]={id,name:body.name,sha512:fp.sha512,size:fp.size,status:'PENDING',createdAt:Date.now(),quarantineOperation:op};
 });pending=true;return Resume(id);}
 catch(error){audit.Failed(op,pending?{message:'STORAGE_OPERATION_PENDING'}:error);throw error;}
}
function Delete(body,actor='ADMIN'){
 RequireIdle();
 if(!body||typeof body!=='object'||Object.keys(body).some(k=>!['id','sha512'].includes(k))||!ID.test(body.id||'')||!HASH.test(body.sha512||''))Fail('ORPHAN_INPUT_INVALID',400);
 const row=store.Load().orphanQuarantine?.[body.id];if(!row||row.sha512!==body.sha512)Fail('ORPHAN_NOT_FOUND',404);
 if(row.status==='DELETED')return {id:row.id,deleted:true,duplicate:true};
 if(!['QUARANTINED','DELETE_PENDING'].includes(row.status)||Date.now()<row.quarantinedAt+GRACE_MS||Referenced(store.Load(),row.name))Fail('ORPHAN_RETENTION_OR_REFERENCE');
 const file=path.join(Directory(),row.id+'.bin');
 if(row.status==='QUARANTINED'){
  const fp=Fingerprint(file);if(fp.sha512!==row.sha512||fp.size!==row.size)Fail('ORPHAN_HASH_CHANGED');
  const op=audit.Begin('ORPHAN_DELETE',actor,{subject:row.id,bytes:row.size});
  try{store.Atomic(next=>{if(Referenced(next,row.name))Fail('ORPHAN_NOW_REFERENCED');next.orphanQuarantine[row.id].status='DELETE_PENDING';next.orphanQuarantine[row.id].deleteOperation=op;});}
  catch(error){audit.Failed(op,error);throw error;}
 }
 // Only a durable DELETE_PENDING allows an already-unlinked file to complete.
 const op=store.Load().orphanQuarantine[row.id].deleteOperation;
 try{
  if(fs.existsSync(file)){const fp=Fingerprint(file);if(fp.sha512!==row.sha512||fp.size!==row.size)Fail('ORPHAN_HASH_CHANGED');fs.unlinkSync(file);}
  // DELETE_PENDING alone permits an absent file; absence does not prove its
  // directory entry was flushed by the interrupted unlink attempt.
  disk.SyncDirectory(path.dirname(file));
  store.Atomic(next=>{if(Referenced(next,row.name))Fail('ORPHAN_NOW_REFERENCED');next.orphanQuarantine[row.id].status='DELETED';next.orphanQuarantine[row.id].deletedAt=Date.now();audit.Attach(next,op,{revision:next.revision+1});});
 }catch(error){audit.Failed(op,{message:'STORAGE_OPERATION_PENDING'});throw error;}
 audit.BestEffortDrain();return {id:row.id,deleted:true};
}
function RecoverPending(){let resumed=0;for(const r of Object.values(store.Load().orphanQuarantine||{}))if(r.status==='PENDING'){Resume(r.id);if(++resumed>=256)break;}return {resumed};}
function List(){return {minimumRetentionDays:7,automaticDeletion:false,items:Object.values(store.Load().orphanQuarantine||{}).map(r=>({id:r.id,name:r.name,sha512:r.sha512,size:r.size,status:r.status,createdAt:r.createdAt,quarantinedAt:r.quarantinedAt||0,deletedAt:r.deletedAt||0,deleteEligible:r.status==='QUARANTINED'&&Date.now()>=r.quarantinedAt+GRACE_MS&&!Referenced(store.Load(),r.name)}))};}
module.exports={Validate,Referenced,Scan,Quarantine,Delete,RecoverPending,List,GRACE_MS};
