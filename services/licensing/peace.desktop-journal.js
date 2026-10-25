'use strict';
// Server-only single-writer authority. Full snapshots retain spent/revoked keys,
// the original signing secret, and every idempotency receipt; no TTL restores a key.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const config=require("../../config/peace.runtime-configuration"),disk=require("../storage/peace.durable-file"),json=require("../protocol/peace.strict-json");
const FILE=path.join(config.DATA_DIR,'desktop-license-journal.jsonl'),KEY=path.join(config.DATA_DIR,'desktop-license-journal.key');
const SNAP=FILE+'.checkpoint',SEGMENTS=FILE+'.segments',MAX_LOG=256*1024*1024,MAX_SNAPSHOT=128*1024*1024,ZERO='0'.repeat(64);
const RESET_SCOPE='ABO_LICENSES_ISSUANCE_OPERATIONS_V1',MAX_RESET_RECEIPTS=1024;
const digest=x=>crypto.createHash('sha256').update(x).digest('hex');
let auth,head=null,lastRecord=null,poisoned=false;
function Corrupt(){throw Error('DESKTOP_JOURNAL_CORRUPT');}
function AssertHealthy(){if(poisoned)throw Error('DESKTOP_JOURNAL_RESTART_REQUIRED');}
function Checkpoint(){return require('./peace.desktop-journal-head').Create(FILE+'.head',Buffer.from(auth.secret,'hex'),'DESKTOP_JOURNAL');}
function WriteAtomic(file,bytes){disk.Atomic(file,bytes);}
function Auth(bytes){
 if(fs.existsSync(KEY)){
  try{auth=json.Parse(disk.ReadRegular(KEY,4096),{maxBytes:4096});}catch(_){Corrupt();}
  if(auth.version!==1||!/^[a-f0-9]{64}$/.test(auth.secret)||auth.legacyDigest!==undefined&&!/^[a-f0-9]{64}$/.test(auth.legacyDigest))Corrupt();return;
 }
 if(fs.existsSync(SNAP)||bytes?.toString('utf8').split('\n').some(line=>line&&json.Parse(line,{maxBytes:MAX_LOG}).mac))Corrupt();
 auth={version:1,secret:crypto.randomBytes(32).toString('hex'),...(bytes?.length?{legacyDigest:digest(bytes)}:{})};
 fs.mkdirSync(path.dirname(FILE),{recursive:true,mode:0o700});WriteAtomic(KEY,Buffer.from(JSON.stringify(auth)));
}
function Mac(row){return crypto.createHmac('sha256',Buffer.from(auth.secret,'hex')).update('GAME-LICENSE-JOURNAL-V2\n'+row.seq+'\n'+row.prev+'\n'+row.hash).digest('hex');}
function SnapshotMac(body){return crypto.createHmac('sha256',Buffer.from(auth.secret,'hex')).update('GAME-LICENSE-CHECKPOINT-V1\n'+JSON.stringify(body)).digest('hex');}
function Empty(){return {schema:1,revision:0,signingSecret:'',licenses:{},receipts:{}};}
function ResetFingerprint(value){return digest(['GAME-REGISTRATION-RESET-V1',value.scope,value.operationId,String(value.previousRevision),String(value.at),String(value.licensesCleared),String(value.receiptsCleared)].join('\n'));}
function ResetMarkerValid(value){
 return !!value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).length===7&&value.version===1&&value.scope===RESET_SCOPE&&/^[a-f0-9]{64}$/.test(value.operationId||'')&&Number.isSafeInteger(value.previousRevision)&&value.previousRevision>=0&&Number.isSafeInteger(value.at)&&value.at>0&&Number.isSafeInteger(value.licensesCleared)&&value.licensesCleared>=0&&Number.isSafeInteger(value.receiptsCleared)&&value.receiptsCleared>=0;
}
function ResetReceiptValid(id,value){
 if(!/^RESET:[a-f0-9]{64}$/.test(id)||!value||Object.keys(value).length!==8)return false;
 const {fingerprint,resetId,...fields}=value,marker={...fields,operationId:resetId};return ResetMarkerValid(marker)&&id==='RESET:'+resetId&&fingerprint===ResetFingerprint(marker);
}
// `operationId` is reserved by the ordinary license/flow reconciler. Keep the
// maintenance identifier in its own receipt namespace as well as its own key.
function ResetReceipt(marker){const {operationId,...fields}=marker;return {...fields,resetId:operationId,fingerprint:ResetFingerprint(marker)};}
function Apply(result,event,{checkpoint=false}={}){
 if((event.version!==1&&event.version!==2)||(event.version===2)!==(event.reset!==undefined)||!Number.isSafeInteger(event.revision)||event.revision<=result.revision||!Array.isArray(event.licenses)||!event.receipts||typeof event.receipts!=='object'||Array.isArray(event.receipts))Corrupt();
 if(event.signingSecret!==undefined){if(!/^[a-f0-9]{64}$/.test(event.signingSecret)||result.signingSecret&&event.signingSecret!==result.signingSecret)Corrupt();result.signingSecret=event.signingSecret;}
 if(event.reset!==undefined){
  const reset=event.reset,key='RESET:'+reset?.operationId;
  if(!ResetMarkerValid(reset)||event.snapshot!==true||reset.previousRevision+1!==event.revision||!checkpoint&&reset.previousRevision!==result.revision||event.licenses.length!==0||!ResetReceiptValid(key,event.receipts[key])||JSON.stringify(event.receipts[key])!==JSON.stringify(ResetReceipt(reset))||Object.keys(event.receipts).length>MAX_RESET_RECEIPTS)Corrupt();
  if(Object.entries(event.receipts).some(([id,receipt])=>!ResetReceiptValid(id,receipt)))Corrupt();
  if(!checkpoint){
   if(reset.licensesCleared!==Object.keys(result.licenses).length||reset.receiptsCleared!==Object.keys(result.receipts).filter(id=>!id.startsWith('RESET:')).length)Corrupt();
   for(const [id,receipt]of Object.entries(result.receipts))if(id.startsWith('RESET:')&&JSON.stringify(event.receipts[id])!==JSON.stringify(receipt))Corrupt();
  }
  result.licenses={};result.receipts={};
 }
 const ids=new Set();
 for(const license of event.licenses){
  if(!license||typeof license.id!=='string'||['__proto__','prototype','constructor'].includes(license.id)||ids.has(license.id))Corrupt();ids.add(license.id);
  const old=result.licenses[license.id];if(old?.consumed&&!license.consumed||old&&['REVOKED','RELEASED'].includes(old.status)&&license.status==='AVAILABLE')Corrupt();result.licenses[license.id]=license;
 }
 for(const [id,receipt]of Object.entries(event.receipts)){if(id.startsWith('RESET:')&&!ResetReceiptValid(id,receipt))Corrupt();if(result.receipts[id]&&JSON.stringify(result.receipts[id])!==JSON.stringify(receipt))Corrupt();result.receipts[id]=receipt;}
 result.revision=event.revision;
}
function RecordValid(row){return !!row&&Number.isSafeInteger(row.seq)&&row.seq>0&&/^[a-f0-9]{64}$/.test(row.prev||'')&&!!row.body&&row.hash===digest(String(row.seq)+'|'+row.prev+'|'+JSON.stringify(row.body));}
function Snapshot(){
 if(!fs.existsSync(SNAP))return null;
 let value;try{value=json.Parse(disk.ReadRegular(SNAP,MAX_SNAPSHOT),{maxBytes:MAX_SNAPSHOT,maxNodes:8000000});}catch(_){Corrupt();}
 const b=value?.body,r=b?.record,s=b?.segment;
 if(!b||b.version!==1||!RecordValid(r)||r.body.snapshot!==true||!disk.SecretEqual(r.mac,Mac(r))||!disk.SecretEqual(value.mac,SnapshotMac(b))||!s||!Number.isSafeInteger(s.bytes)||s.bytes<1||s.bytes>MAX_LOG||!/^[a-f0-9]{64}$/.test(s.sha256||'')||s.file!=='segment-'+r.seq+'-'+s.sha256+'.jsonl'||b.previous!==null&&!/^[a-f0-9]{64}$/.test(b.previous||''))Corrupt();
 // The current immutable archive is required for audit/recovery, not silently lost.
 const archived=disk.ReadRegular(path.join(SEGMENTS,s.file),MAX_LOG);if(archived.length!==s.bytes||digest(archived)!==s.sha256)Corrupt();
 return value;
}
function Load(){
 AssertHealthy();const result=Empty();let seq=0,previous=ZERO,validBytes=0,start=0;
 if(!fs.existsSync(FILE)){if(fs.existsSync(KEY)||fs.existsSync(SNAP))throw Error('DESKTOP_JOURNAL_MISSING');const witness=require("../recovery/peace.desktop-recovery-witness").Head('DESKTOP_JOURNAL');if(witness)witness.Open({seq,hash:previous});head={seq,hash:previous};lastRecord=null;return {exists:false,state:result};}
 const bytes=disk.ReadRegular(FILE,MAX_LOG),hadAuth=fs.existsSync(KEY),hasSnapshot=fs.existsSync(SNAP);
 let checkpoint=null;
 if(hasSnapshot){
  if(!hadAuth)Corrupt();Auth();checkpoint=Snapshot();lastRecord=checkpoint.body.record;
  Apply(result,lastRecord.body,{checkpoint:true});seq=lastRecord.seq;previous=lastRecord.hash;
  if(bytes.length){
   const end=bytes.indexOf(10);let first;
   if(end<0){
    // Rotation can leave an empty active tail. An interrupted FIRST new append
    // may contain only a prefix; never accept a truncated old archived prefix.
    const prefix=Buffer.from('{"seq":'+(seq+1)+',');
    if(!bytes.subarray(0,Math.min(bytes.length,prefix.length)).equals(prefix.subarray(0,Math.min(bytes.length,prefix.length))))Corrupt();
   }else try{first=json.Parse(bytes.subarray(0,end),{maxBytes:MAX_LOG,maxNodes:8000000});}catch(_){Corrupt();}
   if(first&&first.seq<=seq){const segment=checkpoint.body.segment;if(bytes.length<segment.bytes||digest(bytes.subarray(0,segment.bytes))!==segment.sha256)Corrupt();start=segment.bytes;validBytes=start;}
  }
 }
 const entries=[];
 while(start<bytes.length){
  const end=bytes.indexOf(10,start);if(end<0)break;let row;
  try{row=json.Parse(bytes.subarray(start,end),{maxBytes:MAX_LOG,maxNodes:8000000});}catch(_){Corrupt();}
  if(!RecordValid(row)||row.seq!==seq+1||row.prev!==previous)Corrupt();
  entries.push(row);Apply(result,row.body);seq=row.seq;previous=row.hash;lastRecord=row;validBytes=end+1;start=end+1;
 }
 const completed=bytes.subarray(0,validBytes);if(!auth)Auth(completed);
 const legacy=entries.some(row=>!row.mac);
 if(legacy){
  if(checkpoint||entries.some(row=>row.mac)||auth.legacyDigest!==digest(completed))Corrupt();
  WriteAtomic(FILE,Buffer.from(entries.map(row=>JSON.stringify({...row,mac:Mac(row)})).join('\n')+(entries.length?'\n':'')));
 }else for(const row of entries)if(!disk.SecretEqual(row.mac,Mac(row)))Corrupt();
 Checkpoint().Open({seq,hash:previous},legacy||!hadAuth);
 // Only a validated unfinished trailing append may be removed. Complete damaged
 // records, rollback, missing archives and lost authenticated state fail closed.
 if(!legacy&&validBytes<bytes.length){const fd=fs.openSync(FILE,'r+');try{fs.ftruncateSync(fd,validBytes);fs.fsyncSync(fd);}catch(e){poisoned=true;throw e;}finally{fs.closeSync(fd);}}
 if(auth.legacyDigest!==undefined){delete auth.legacyDigest;WriteAtomic(KEY,Buffer.from(JSON.stringify(auth)));}
 head={seq,hash:previous};return {exists:seq>0,state:result};
}
function Commit(previous,next,{fullSnapshot=false}={}){
 AssertHealthy();if(!head)Load();if(!auth){Auth();Checkpoint().Open(head,true);}
 // Compaction cannot remove security history or replace established secrets.
 if(next.revision!==previous.revision+1||previous.signingSecret&&next.signingSecret!==previous.signingSecret)Corrupt();
 for(const [id,old]of Object.entries(previous.licenses))if(!next.licenses[id]||old.consumed&&!next.licenses[id].consumed||['REVOKED','RELEASED'].includes(old.status)&&next.licenses[id].status==='AVAILABLE')Corrupt();
 for(const [id,old]of Object.entries(previous.receipts))if(JSON.stringify(next.receipts[id])!==JSON.stringify(old))Corrupt();
 for(const [id,receipt]of Object.entries(next.receipts))if(id.startsWith('RESET:')&&(!previous.receipts[id]||!ResetReceiptValid(id,receipt)))Corrupt();
 const event={version:1,revision:next.revision,licenses:Object.values(next.licenses).filter(row=>fullSnapshot||JSON.stringify(previous.licenses[row.id])!==JSON.stringify(row)),receipts:Object.fromEntries(Object.entries(next.receipts).filter(([id,row])=>fullSnapshot||JSON.stringify(previous.receipts[id])!==JSON.stringify(row)))};
 if(fullSnapshot)event.snapshot=true;
 if(next.signingSecret!==previous.signingSecret||!head.seq||fullSnapshot)if(next.signingSecret)event.signingSecret=next.signingSecret;
 AppendEvent(event);
}
// An explicit installation operation may discard registration projections, but
// never rewinds the authenticated history, witness, secrets or spent reset IDs.
// Ordinary license writes retain their non-removal rules in Commit above.
function Reset(previous,operationId){
 AssertHealthy();if(!/^[a-f0-9]{64}$/.test(operationId||''))throw Error('DESKTOP_RESET_ID_INVALID');
 const current=Load().state,key='RESET:'+operationId,old=current.receipts[key];
 if(old){if(!ResetReceiptValid(key,old))Corrupt();return structuredClone(current);}
 if(!previous||previous.schema!==1||previous.revision!==current.revision||previous.signingSecret!==current.signingSecret||JSON.stringify(previous.licenses)!==JSON.stringify(current.licenses)||JSON.stringify(previous.receipts)!==JSON.stringify(current.receipts))throw Error('DESKTOP_RESET_REVISION_CONFLICT');
 const kept=Object.fromEntries(Object.entries(current.receipts).filter(([id])=>id.startsWith('RESET:')));
 if(Object.entries(kept).some(([id,receipt])=>!ResetReceiptValid(id,receipt)))Corrupt();
 if(Object.keys(kept).length>=MAX_RESET_RECEIPTS)throw Error('DESKTOP_RESET_RECEIPT_CAPACITY');
 const reset={version:1,scope:RESET_SCOPE,operationId,previousRevision:current.revision,at:Date.now(),licensesCleared:Object.keys(current.licenses).length,receiptsCleared:Object.keys(current.receipts).length-Object.keys(kept).length};
 const receipts={...kept,[key]:ResetReceipt(reset)},next={schema:1,revision:current.revision+1,signingSecret:current.signingSecret,licenses:{},receipts};
 // Version 2 makes pre-reset application code fail closed rather than ignore
 // the reset marker and replay the historical license projection as live.
 const event={version:2,revision:next.revision,snapshot:true,reset,licenses:[],receipts,...(next.signingSecret?{signingSecret:next.signingSecret}:{})};
 AppendEvent(event);return structuredClone(next);
}
function AppendEvent(event){
 AssertHealthy();if(!head)Load();if(!auth){Auth();Checkpoint().Open(head,true);}
 const seq=head.seq+1,prev=head.hash,hash=digest(String(seq)+'|'+prev+'|'+JSON.stringify(event)),record={seq,prev,body:event,hash};record.mac=Mac(record);
 const line=Buffer.from(JSON.stringify(record)+'\n');if(line.length>MAX_SNAPSHOT/2)throw Error('DESKTOP_JOURNAL_RECORD_LIMIT');
 fs.mkdirSync(path.dirname(FILE),{recursive:true,mode:0o700});const existed=fs.existsSync(FILE),fd=fs.openSync(FILE,'a',0o600);let before,durable=false;
 try{
  before=fs.fstatSync(fd).size;if(before+line.length>MAX_LOG)throw Error('DESKTOP_JOURNAL_CHECKPOINT_REQUIRED');
  Checkpoint().Prepare(head,{seq,hash});let written=0;
  while(written<line.length){const n=fs.writeSync(fd,line,written,line.length-written);if(n<=0)throw Error('DESKTOP_JOURNAL_WRITE_STALLED');written+=n;}
  fs.fsyncSync(fd);durable=true;if(!existed)disk.SyncDirectory(path.dirname(FILE));Checkpoint().Settle({seq,hash});
 }catch(error){
  if(durable)poisoned=true;
  else if(before!==undefined)try{fs.ftruncateSync(fd,before);fs.fsyncSync(fd);Checkpoint().Settle(head);}catch(_){poisoned=true;}
  throw error;
 }finally{fs.closeSync(fd);}
 head={seq,hash};lastRecord=record;
}
function Rotate(){
 AssertHealthy();Load();if(!lastRecord?.body.snapshot)throw Error('DESKTOP_JOURNAL_SNAPSHOT_REQUIRED');
 const bytes=disk.ReadRegular(FILE,MAX_LOG);if(!bytes.length)return {compacted:true,alreadyCompacted:true,sequence:head.seq};
 fs.mkdirSync(SEGMENTS,{recursive:true,mode:0o700});const st=fs.lstatSync(SEGMENTS);if(!st.isDirectory()||st.isSymbolicLink())Corrupt();
 const sha256=digest(bytes),segment={file:'segment-'+head.seq+'-'+sha256+'.jsonl',sha256,bytes:bytes.length},previous=fs.existsSync(SNAP)?digest(disk.ReadRegular(SNAP,MAX_SNAPSHOT)):null;
 const archive=path.join(SEGMENTS,segment.file);if(!fs.existsSync(archive))disk.Atomic(archive,bytes,{createOnly:true});else if(digest(disk.ReadRegular(archive,MAX_LOG))!==sha256)Corrupt();
 const body={version:1,record:lastRecord,segment,previous},raw=Buffer.from(JSON.stringify({body,mac:SnapshotMac(body)}));if(raw.length>MAX_SNAPSHOT)throw Error('DESKTOP_JOURNAL_CHECKPOINT_LIMIT');
 const immutable=path.join(SEGMENTS,'checkpoint-'+digest(raw)+'.json');
 if(!fs.existsSync(immutable))disk.Atomic(immutable,raw,{createOnly:true});else if(digest(disk.ReadRegular(immutable,MAX_SNAPSHOT))!==digest(raw))Corrupt();
 // Pointer first, then empty active tail. Restart accepts either exact archived
 // prefix or a tail starting after the snapshot; never guesses at a partial prefix.
 try{disk.Atomic(SNAP,raw);disk.Atomic(FILE,Buffer.alloc(0));}catch(e){poisoned=true;throw e;}
 return {compacted:true,sequence:head.seq,archivedBytes:bytes.length,checkpointBytes:raw.length,licenses:lastRecord.body.licenses.length,receipts:Object.keys(lastRecord.body.receipts).length};
}
function CheckpointStatus(revision){
 AssertHealthy();if(!Number.isSafeInteger(revision)||revision<1)throw Error('DESKTOP_JOURNAL_CHECKPOINT_REVISION_INVALID');
 Load();const checkpoint=Snapshot(),stored=checkpoint?.body.record.body.revision||0;
 if(stored>=revision)return {compacted:true,alreadyCompacted:true,sequence:checkpoint.body.record.seq};
 // A committed full-state receipt can survive a crash before Rotate. Only that
 // exact latest snapshot may resume; never rotate a different caller's changes.
 const resumable=lastRecord?.body.snapshot===true&&lastRecord.body.revision===revision;
 return {compacted:false,resumable,checkpointRequired:!resumable};
}
function Status(){AssertHealthy();if(!head)Load();return {sequence:head.seq,activeBytes:fs.existsSync(FILE)?fs.statSync(FILE).size:0,maximumActiveBytes:MAX_LOG,checkpointRecommendedBytes:32*1024*1024,checkpointPresent:fs.existsSync(SNAP),automaticDeletion:false,historyRetention:'ALL_CONSUMED_REVOKED_AND_RECEIPTS',snapshotFormat:'GAME-LICENSE-CHECKPOINT-V1'};}
module.exports={Load,Commit,Reset,Rotate,CheckpointStatus,Status,FILE,KEY,SNAP,SEGMENTS,AssertHealthy};
