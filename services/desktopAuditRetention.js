'use strict';
// Retire only a verified chronological prefix. Keep authenticated chain anchors
// and operation fingerprints so deleting old detail never re-authorizes a retry.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const store=require('./desktopBootstrapStore'),archive=require('./desktopAuditArchive'),disk=require('./durableFile');
const config=require('../config/config'),NAME=/^audit-\d{4}-\d{2}-\d{2}\.jsonl$/,HASH=/^[A-F0-9]{64}$/,ID=/^[a-f0-9]{64}$/;
function Fail(code){const e=Error(code);e.desktopError=true;e.status=503;throw e;}
function Empty(){return {version:1,sequence:0,anchor:'',operations:{},files:{},at:0};}
function Read(){
 const desc=store.Load().serverAuditRetention;if(!desc)return Empty();const r=archive.Read(desc,'RETENTION');
 if(r.version!==1||!Number.isSafeInteger(r.sequence)||r.sequence<0||(r.sequence>0&&!HASH.test(r.anchor||''))||!r.operations||Array.isArray(r.operations)||!r.files||Array.isArray(r.files)||!Number.isSafeInteger(r.at)||r.at<1)Fail('AUDIT_RETENTION_INVALID');
 for(const [id,o]of Object.entries(r.operations))if(!ID.test(id)||!o||!HASH.test(o.fingerprint||'')||!HASH.test(o.hash||'')||!Number.isSafeInteger(o.sequence)||o.sequence<1||o.sequence>r.sequence)Fail('AUDIT_RETENTION_INVALID');
 for(const [name,f]of Object.entries(r.files))if(!NAME.test(name)||!f||!Number.isSafeInteger(f.bytes)||f.bytes<1||!/^[a-f0-9]{128}$/.test(f.sha512||''))Fail('AUDIT_RETENTION_INVALID');return r;
}
function StripPrefix(name,bytes,checkpoint=Read()){
 const f=checkpoint.files[name];if(!f||!bytes.length)return bytes;
 const end=bytes.indexOf(10);if(end<0)Fail('AUDIT_RETENTION_TORN_PREFIX');let first;try{first=JSON.parse(bytes.subarray(0,end));}catch(_){Fail('AUDIT_RETENTION_INVALID_PREFIX');}
 if(Number.isSafeInteger(first.sequence)&&first.sequence>checkpoint.sequence)return bytes;
 if(bytes.length<f.bytes||crypto.createHash('sha512').update(bytes.subarray(0,f.bytes)).digest('hex')!==f.sha512)Fail('AUDIT_RETENTION_PREFIX_CHANGED');return bytes.subarray(f.bytes);
}
function Cleanup(){
 const checkpoint=Read();let removedFiles=0;
 for(const name of Object.keys(checkpoint.files)){
  const file=path.join(config.AUDIT_DIR,name);if(!fs.existsSync(file))continue;const before=disk.ReadRegular(file,256*1024*1024),tail=StripPrefix(name,before,checkpoint);if(tail.length===before.length)continue;
  if(tail.length)disk.Atomic(file,tail);else{fs.unlinkSync(file);disk.SyncDirectory(config.AUDIT_DIR);removedFiles++;}
 }
 return {removedFiles};
}
function Apply({days=90,clear=false,actor='SCHEDULED',onCommit}={}){
 if(!Number.isSafeInteger(days)||days<1||days>3650||typeof clear!=='boolean')Fail('AUDIT_RETENTION_INPUT_INVALID');
 archive.Cleanup();const audit=require('../storage/audit'),valid=audit.VerifyAuditChain();if(!valid.ok)Fail('AUDIT_CHAIN_UNAVAILABLE');Cleanup();
 const old=Read(),checkpoint=structuredClone(old),cutoff=new Date(Date.now()-days*86400000).toISOString().slice(0,10),names=fs.readdirSync(config.AUDIT_DIR).filter(n=>NAME.test(n)&&(clear||n.slice(6,16)<cutoff)).sort();
 let removedRecords=0,removedFiles=0,committed=false;const op=require('./desktopOperationAudit').Begin('AUDIT_RETENTION',actor,{count:names.length});
 try{
  for(const name of names){const bytes=disk.ReadRegular(path.join(config.AUDIT_DIR,name),256*1024*1024);if(!bytes.length)continue;
   // Only complete chained rows can be retired. A legacy/non-chain tail is kept.
   const lines=bytes.toString('utf8').trimEnd().split('\n');for(const line of lines){const row=JSON.parse(line);if(!Number.isSafeInteger(row.sequence)||row.sequence!==checkpoint.sequence+1||row.previousHash!==checkpoint.anchor||!HASH.test(row.hash||''))Fail('AUDIT_RETENTION_NONCONTIGUOUS');checkpoint.sequence=row.sequence;checkpoint.anchor=row.hash;
    let detail;try{detail=JSON.parse(row.detail);}catch(_){}if(ID.test(detail?.auditEventId||''))checkpoint.operations[detail.auditEventId]={fingerprint:audit.EventFingerprint(row.type,row.detail),sequence:row.sequence,hash:row.hash};removedRecords++;
   }
   removedFiles++;checkpoint.files[name]={bytes:bytes.length,sha512:crypto.createHash('sha512').update(bytes).digest('hex')};
  }
  if(!removedRecords){const result={ok:true,removedFiles:0,removedRecords:0,sequence:old.sequence};require('./desktopOperationAudit').CommitExternal(op,{count:0});if(onCommit)store.Atomic(db=>onCommit(db,result));return result;}
  checkpoint.at=Date.now();const descriptor=archive.Put('RETENTION',checkpoint),receiptResult={ok:true,removedFiles,removedRecords,sequence:checkpoint.sequence,preservedOperationFingerprints:Object.keys(checkpoint.operations).length};
  store.Atomic(db=>{if(db.serverAuditRetention?.file!==descriptor.file)archive.QueueDelete(db,db.serverAuditRetention);db.serverAuditRetention=descriptor;require('./desktopOperationAudit').Attach(db,op,{count:removedRecords});if(onCommit)onCommit(db,receiptResult);});committed=true;
  // The descriptor is durable before removing any bytes. Startup can complete
  // interrupted cleanup and will not append/replay retired private details.
  const result=Cleanup();audit.LoadRecentAudit();require('./desktopOperationAudit').BestEffortDrain();require('./desktopOperationAudit').PruneRetired();archive.Cleanup();return receiptResult;
 }catch(error){require('./desktopOperationAudit').Failed(op,committed?{message:'STORAGE_COMMITTED_CLEANUP_PENDING'}:error);throw error;}
}
function Status(){const r=Read();return {version:1,retiredSequence:r.sequence,retiredAt:r.at,retainedOperationFingerprints:Object.keys(r.operations).length,privateDetailRestored:false,authorizationHistoryDeleted:false};}
module.exports={Read,StripPrefix,Cleanup,Apply,Status};
