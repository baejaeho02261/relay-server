'use strict';
// Immutable compressed records authenticated by the existing bootstrap authority.
// The descriptor lives in its rollback-protected state, never in a mutable mirror.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),zlib=require('node:zlib');
const store=require('./desktopBootstrapStore'),disk=require('./durableFile'),strict=require('./strictJson');
const MAX=64*1024*1024,DIR=()=>path.join(store.DIR,'audit-archives');
const hash=bytes=>crypto.createHash('sha512').update(bytes).digest('hex');
function Directory(){fs.mkdirSync(DIR(),{recursive:true,mode:0o700});const s=fs.lstatSync(DIR());if(!s.isDirectory()||s.isSymbolicLink())throw Error('AUDIT_ARCHIVE_PATH_INVALID');return DIR();}
function Mac(body,db){return crypto.createHmac('sha512',Buffer.from(db.secret,'hex')).update('GAME-SERVER-AUDIT-ARCHIVE-V1\n'+JSON.stringify(body)).digest('hex');}
function Put(kind,data){
 if(!['RETENTION','OUTBOX'].includes(kind))throw Error('AUDIT_ARCHIVE_KIND_INVALID');const body={version:1,kind,data},db=store.Load(),raw=Buffer.from(JSON.stringify({body,mac:Mac(body,db)}));
 try{if(raw.length>MAX)throw Error('AUDIT_ARCHIVE_CAPACITY');const bytes=zlib.gzipSync(raw,{level:6}),sha512=hash(bytes),file=kind.toLowerCase()+'-'+sha512+'.json.gz',target=path.join(Directory(),file);
  if(!fs.existsSync(target))disk.Atomic(target,bytes,{createOnly:true});else if(hash(disk.ReadRegular(target,MAX))!==sha512)throw Error('AUDIT_ARCHIVE_CONFLICT');
  return {version:1,kind,file,sha512,bytes:bytes.length,plainBytes:raw.length};
 }finally{raw.fill(0);}
}
function Read(descriptor,kind){
 if(!descriptor||descriptor.version!==1||descriptor.kind!==kind||!/^[a-f0-9]{128}$/.test(descriptor.sha512||'')||descriptor.file!==kind.toLowerCase()+'-'+descriptor.sha512+'.json.gz'||!Number.isSafeInteger(descriptor.bytes)||descriptor.bytes<1||descriptor.bytes>MAX||!Number.isSafeInteger(descriptor.plainBytes)||descriptor.plainBytes<1||descriptor.plainBytes>MAX)throw Error('AUDIT_ARCHIVE_INVALID');
 const bytes=disk.ReadRegular(path.join(Directory(),descriptor.file),MAX);if(bytes.length!==descriptor.bytes||hash(bytes)!==descriptor.sha512)throw Error('AUDIT_ARCHIVE_CHANGED');
 const raw=zlib.gunzipSync(bytes,{maxOutputLength:MAX});try{if(raw.length!==descriptor.plainBytes)throw Error('AUDIT_ARCHIVE_INVALID');const value=strict.Parse(raw,{maxBytes:MAX,maxNodes:4000000});if(value.body?.version!==1||value.body.kind!==kind||!disk.SecretEqual(value.mac,Mac(value.body,store.Load())))throw Error('AUDIT_ARCHIVE_INVALID');return value.body.data;}finally{raw.fill(0);}
}
function QueueDelete(db,descriptor){
 if(!descriptor)return;
 if(!['RETENTION','OUTBOX'].includes(descriptor.kind)||descriptor.file!==descriptor.kind.toLowerCase()+'-'+descriptor.sha512+'.json.gz'||!/^[a-f0-9]{128}$/.test(descriptor.sha512||''))throw Error('AUDIT_ARCHIVE_INVALID');
 db.serverAuditArchiveGarbage||={};if(Object.keys(db.serverAuditArchiveGarbage).length>=10000)throw Error('AUDIT_ARCHIVE_CLEANUP_CAPACITY');db.serverAuditArchiveGarbage[descriptor.file]=descriptor;
}
function Cleanup(){
 const rows=store.Load().serverAuditArchiveGarbage||{};if(!rows||Array.isArray(rows)||Object.keys(rows).length>10000)throw Error('AUDIT_ARCHIVE_GARBAGE_INVALID');let removed=0;
 for(const [name,descriptor]of Object.entries(rows)){
  if(name!==descriptor.file||!['RETENTION','OUTBOX'].includes(descriptor.kind)||name!==descriptor.kind.toLowerCase()+'-'+descriptor.sha512+'.json.gz'||!/^[a-f0-9]{128}$/.test(descriptor.sha512||''))throw Error('AUDIT_ARCHIVE_GARBAGE_INVALID');
  const db=store.Load();if(db.serverAuditRetention?.file===name||(db.serverAuditOutboxArchives||[]).some(d=>d.file===name))throw Error('AUDIT_ARCHIVE_STILL_REFERENCED');
  const file=path.join(Directory(),name);if(fs.existsSync(file)){Read(descriptor,descriptor.kind);fs.unlinkSync(file);removed++;}
  // Retry directory durability even when an earlier process already unlinked.
  disk.SyncDirectory(Directory());store.Atomic(next=>{if(next.serverAuditArchiveGarbage[name]?.sha512!==descriptor.sha512)throw Error('AUDIT_ARCHIVE_GARBAGE_CHANGED');delete next.serverAuditArchiveGarbage[name];});
 }
 return {removed,pending:Object.keys(store.Load().serverAuditArchiveGarbage||{}).length};
}
function PruneUnreferenced(days=7){
 if(!Number.isSafeInteger(days)||days<7||days>3650)throw Error('AUDIT_ARCHIVE_RETENTION_INVALID');const db=store.Load(),referenced=new Set([db.serverAuditRetention?.file,...(db.serverAuditOutboxArchives||[]).map(d=>d.file),...Object.keys(db.serverAuditArchiveGarbage||{})]),selected=[],cutoff=Date.now()-days*86400000;
 for(const name of fs.readdirSync(Directory())){const match=/^(retention|outbox)-([a-f0-9]{128})\.json\.gz$/.exec(name);if(!match||referenced.has(name))continue;const file=path.join(Directory(),name),st=fs.lstatSync(file);if(st.mtimeMs>=cutoff)continue;const bytes=disk.ReadRegular(file,MAX);if(bytes.length<18)throw Error('AUDIT_ARCHIVE_INVALID');const descriptor={version:1,kind:match[1].toUpperCase(),file:name,sha512:match[2],bytes:bytes.length,plainBytes:bytes.readUInt32LE(bytes.length-4)};Read(descriptor,descriptor.kind);selected.push(descriptor);if(selected.length>=256)break;}
 if(!selected.length)return {queued:0};const audit=require('./desktopOperationAudit'),op=audit.Begin('AUDIT_ARCHIVE_ORPHAN_RETENTION','SCHEDULED',{count:selected.length});let committed=false;
 try{store.Atomic(next=>{for(const descriptor of selected)QueueDelete(next,descriptor);audit.Attach(next,op,{count:selected.length});});committed=true;audit.BestEffortDrain();Cleanup();return {queued:selected.length};}
 catch(error){audit.Failed(op,committed?{message:'STORAGE_COMMITTED_CLEANUP_PENDING'}:error);throw error;}
}
module.exports={Put,Read,Directory,MAX,QueueDelete,Cleanup,PruneUnreferenced};
