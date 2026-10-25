'use strict';
// Server-owned machine policy. The client sends only a domain-hashed machine
// identifier, not raw firmware/registry IDs. This binds issuance across ephemeral
// RSA keys but is not hardware attestation: a privileged client can spoof it.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),config=require("../../config/peace.runtime-configuration"),disk=require("../storage/peace.durable-file"),strict=require("../protocol/peace.strict-json");
const MAX_JOURNAL=128*1024*1024,MAX_SNAPSHOT=64*1024*1024;
const DIR=path.join(config.DATA_DIR,'desktop-machine-policy'),KEY=path.join(DIR,'authority.key'),FILE=path.join(DIR,'journal.jsonl');
const SNAP=FILE+'.checkpoint',SEGMENTS=FILE+'.segments';
let lastRecord=null;
function Checkpoint(){return require("../licensing/peace.desktop-journal-head").Create(FILE+'.head',secret,'DESKTOP_MACHINE_POLICY');}
let loaded=false,secret,head='0'.repeat(64),revision=0,rows=new Map(),receipts=new Map(),registrationResets=new Map(),poisoned=false;
function Fail(code,status=403){const error=Error(code);error.desktopError=true;error.status=status;throw error;}
function Validate(machineId){if(typeof machineId!=='string'||!/^[A-F0-9]{64}$/.test(machineId))Fail('DESKTOP_MACHINE_INVALID',400);return machineId;}
function Corrupt(){throw Error('DESKTOP_MACHINE_POLICY_CORRUPT');}
function SyncDir(){if(process.platform==='win32')return;const fd=fs.openSync(DIR,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Mac(seq,prev,body){return crypto.createHmac('sha256',secret).update('GAME-MACHINE-POLICY-V1\n'+seq+'\n'+prev+'\n'+JSON.stringify(body)).digest('hex');}
function StateBody(){return {version:3,kind:'CHECKPOINT',rows:Object.fromEntries(rows),receipts:Object.fromEntries(receipts),...(registrationResets.size?{registrationResets:Object.fromEntries(registrationResets)}:{})};}
function ValidReset(value,limit){return value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')==='at,bindings,receipts,sequence'&&Number.isSafeInteger(value.at)&&value.at>0&&Number.isSafeInteger(value.sequence)&&value.sequence>0&&value.sequence<limit&&Number.isSafeInteger(value.bindings)&&value.bindings>=0&&Number.isSafeInteger(value.receipts)&&value.receipts>=0;}
function Apply(entry){
 const body=entry?.body;
 if(!entry||!Number.isSafeInteger(entry.seq)||entry.seq!==revision+1||entry.prev!==head||!body||!disk.SecretEqual(entry.mac,Mac(entry.seq,entry.prev,body)))Corrupt();
 if(body.version===4&&body.kind==='REGISTRATION_RESET'){
  if(Object.keys(body).sort().join(',')!=='at,kind,operationId,previousSequence,removedBindings,removedReceipts,version'||!/^[a-f0-9]{64}$/.test(body.operationId||'')||registrationResets.has(body.operationId)||registrationResets.size>=1024||body.previousSequence!==revision||!Number.isSafeInteger(body.at)||body.at<1||body.removedBindings!==rows.size||body.removedReceipts!==receipts.size)Corrupt();
  registrationResets.set(body.operationId,{at:body.at,sequence:entry.seq,bindings:rows.size,receipts:receipts.size});rows=new Map();receipts=new Map();
 }else if(body.version===3&&body.kind==='CHECKPOINT'){
  if(body.maintenance&&(!/^[a-f0-9]{64}$/.test(body.maintenance.operationId||'')||body.maintenance.result?.sequence!==entry.seq||body.maintenance.result?.compacted!==true||!Number.isSafeInteger(body.maintenance.result.archivedBytes)||body.maintenance.result.archivedBytes<1))Corrupt();
  if(!body.rows||Array.isArray(body.rows)||!body.receipts||Array.isArray(body.receipts))Corrupt();
  for(const [id,row]of Object.entries(body.rows))if(!/^[A-F0-9]{64}$/.test(id)||row.machineId!==id||typeof row.blocked!=='boolean'||!Number.isSafeInteger(row.generation)||row.generation<0||!Number.isSafeInteger(row.revision)||row.revision<1||row.revision>=entry.seq||!Number.isSafeInteger(row.changedAt)||row.changedAt<1||typeof row.reason!=='string'||typeof row.changedBy!=='string')Corrupt();
  for(const [id,r]of Object.entries(body.receipts)){if(!/^[a-f0-9]{64}:[-A-Za-z0-9_]{8,80}$/.test(id)||!r||!/^[a-f0-9]{64}$/.test(r.fingerprint)||!/^[A-F0-9]{64}$/.test(r.machineId))Corrupt();if(r.operation)require("../storage/peace.desktop-operation-audit").ValidateOperation(r.operation);}
  // A live stream checkpoint cannot remove a generation or change a receipt.
  for(const [id,r]of rows)if(JSON.stringify(body.rows[id])!==JSON.stringify(r))Corrupt();
  for(const [id,r]of receipts)if(JSON.stringify(body.receipts[id])!==JSON.stringify(r))Corrupt();
  const resets=body.registrationResets||{};if(!resets||Object.getPrototypeOf(resets)!==Object.prototype||Object.keys(resets).length>1024)Corrupt();
  for(const [id,r]of Object.entries(resets))if(!/^[a-f0-9]{64}$/.test(id)||!ValidReset(r,entry.seq))Corrupt();
  for(const [id,r]of registrationResets)if(JSON.stringify(resets[id])!==JSON.stringify(r))Corrupt();
  registrationResets=new Map(Object.entries(resets));
  rows=new Map(Object.entries(body.rows));receipts=new Map(Object.entries(body.receipts));
 }else{
  if(typeof body.machineId!=='string'||!/^[A-F0-9]{64}$/.test(body.machineId)||typeof body.blocked!=='boolean'||!Number.isSafeInteger(body.generation)||body.generation<0||!Number.isSafeInteger(body.changedAt)||body.changedAt<1||typeof body.reason!=='string'||typeof body.changedBy!=='string'||typeof body.receiptKey!=='string'||!/^[a-f0-9]{64}$/.test(body.fingerprint))Corrupt();
  const old=rows.get(body.machineId);if(body.version!==undefined&&body.version!==2||body.generation!==(old?.generation||0)+(body.version===2?1:body.blocked?1:0)||receipts.has(body.receiptKey))Corrupt();
  if(body.operation)require("../storage/peace.desktop-operation-audit").ValidateOperation(body.operation);
  rows.set(body.machineId,{machineId:body.machineId,blocked:body.blocked,generation:body.generation,reason:body.reason,changedAt:body.changedAt,changedBy:body.changedBy,revision:entry.seq});receipts.set(body.receiptKey,{fingerprint:body.fingerprint,machineId:body.machineId,...(body.operation?{operation:body.operation,revision:entry.seq}:{})});
 }
 revision=entry.seq;head=entry.mac;lastRecord=entry;
}
function ReadSnapshot(){
 if(!fs.existsSync(SNAP))return null;const envelope=strict.Parse(disk.ReadRegular(SNAP,MAX_SNAPSHOT),{maxBytes:MAX_SNAPSHOT,maxNodes:4000000}),b=envelope.body,r=b?.record,a=b?.archive;
 if(!b||b.version!==1||!r||r.body?.kind!=='CHECKPOINT'||r.body.version!==3||!Number.isSafeInteger(r.seq)||r.seq<1||!/^[a-f0-9]{64}$/.test(r.prev||'')||!disk.SecretEqual(r.mac,Mac(r.seq,r.prev,r.body))||!disk.SecretEqual(envelope.mac,crypto.createHmac('sha256',secret).update('GAME-MACHINE-CHECKPOINT-V1\n'+JSON.stringify(b)).digest('hex'))||!a||!/^[a-f0-9]{128}$/.test(a.sha512||'')||a.file!=='segment-'+r.seq+'-'+a.sha512+'.jsonl'||!Number.isSafeInteger(a.bytes)||a.bytes<1||a.bytes>MAX_JOURNAL)Corrupt();
 const bytes=disk.ReadRegular(path.join(SEGMENTS,a.file),MAX_JOURNAL);if(bytes.length!==a.bytes||crypto.createHash('sha512').update(bytes).digest('hex')!==a.sha512)Corrupt();return b;
}
function Load(){
 if(poisoned)throw Error('DESKTOP_MACHINE_POLICY_RESTART_REQUIRED');if(loaded)return;let created=false,incomplete=-1;if(config.HA_ENABLED)throw Error('DESKTOP_MACHINE_POLICY_SINGLE_WRITER_REQUIRED');fs.mkdirSync(DIR,{recursive:true,mode:0o700});
 if(!fs.existsSync(KEY)){
  if(fs.existsSync(FILE)||fs.existsSync(SNAP))Corrupt();created=true;disk.Atomic(KEY,crypto.randomBytes(32),{createOnly:true});disk.Atomic(FILE,Buffer.alloc(0),{createOnly:true});
 }else if(!fs.existsSync(FILE))Corrupt();
 secret=disk.ReadRegular(KEY,32);if(secret.length!==32)Corrupt();rows=new Map();receipts=new Map();registrationResets=new Map();revision=0;head='0'.repeat(64);lastRecord=null;
 const snapshot=ReadSnapshot(),bytes=disk.ReadRegular(FILE,MAX_JOURNAL);let start=0,complete=0;
 if(snapshot){revision=snapshot.record.seq-1;head=snapshot.record.prev;Apply(snapshot.record);
  const end=bytes.indexOf(10);if(end>=0){let first;try{first=strict.Parse(bytes.subarray(0,end),{maxBytes:MAX_SNAPSHOT,maxNodes:4000000});}catch(_){Corrupt();}if(first.seq<=revision){const a=snapshot.archive;if(bytes.length<a.bytes||crypto.createHash('sha512').update(bytes.subarray(0,a.bytes)).digest('hex')!==a.sha512)Corrupt();start=a.bytes;complete=start;}}
  else if(bytes.length){const prefix=Buffer.from('{"seq":'+(revision+1)+',');if(!bytes.subarray(0,Math.min(bytes.length,prefix.length)).equals(prefix.subarray(0,Math.min(bytes.length,prefix.length))))Corrupt();}
 }
 while(start<bytes.length){const end=bytes.indexOf(10,start);if(end<0)break;let entry;try{entry=strict.Parse(bytes.subarray(start,end),{maxBytes:MAX_SNAPSHOT,maxNodes:4000000});}catch(_){Corrupt();}Apply(entry);start=end+1;complete=start;}
 if(complete<bytes.length)incomplete=complete;Checkpoint().Open({seq:revision,hash:head},created);
 if(incomplete>=0){const fd=fs.openSync(FILE,'r+');try{fs.ftruncateSync(fd,incomplete);fs.fsyncSync(fd);}catch(error){poisoned=true;throw error;}finally{fs.closeSync(fd);}}loaded=true;
}
function Append(body){
 const seq=revision+1,mac=Mac(seq,head,body),entry={seq,prev:head,body,mac},line=Buffer.from(JSON.stringify(entry)+'\n');if(line.length>MAX_SNAPSHOT/2)throw Error('DESKTOP_MACHINE_SNAPSHOT_LIMIT');
 const fd=fs.openSync(FILE,'a',0o600);let before,durable=false;try{before=fs.fstatSync(fd).size;if(before+line.length>MAX_JOURNAL)throw Error('DESKTOP_MACHINE_JOURNAL_MAINTENANCE_REQUIRED');Checkpoint().Prepare({seq:revision,hash:head},{seq,hash:mac});let offset=0;while(offset<line.length){const written=fs.writeSync(fd,line,offset,line.length-offset);if(written<=0)throw Error('DESKTOP_MACHINE_WRITE_STALLED');offset+=written;}fs.fsyncSync(fd);durable=true;Checkpoint().Settle({seq,hash:mac});}catch(error){if(durable){poisoned=true;error.authorityMayBeCommitted=true;}else if(before!==undefined)try{fs.ftruncateSync(fd,before);fs.fsyncSync(fd);Checkpoint().Settle({seq:revision,hash:head});}catch(_){poisoned=true;}throw error;}finally{fs.closeSync(fd);}Apply(entry);
}
function Compact(operationId=''){
 Load();if(operationId&&!/^[a-f0-9]{64}$/.test(operationId))Fail('DESKTOP_MACHINE_RETENTION_INVALID',400);
 let bytes=disk.ReadRegular(FILE,MAX_JOURNAL),target=null,end=0;
 // The durable checkpoint itself is the result receipt. Locate that exact row
 // after a lost response, even when later PC-policy writes followed it.
 if(operationId){let start=0;while(start<bytes.length){const e=bytes.indexOf(10,start);if(e<0)Corrupt();const row=strict.Parse(bytes.subarray(start,e),{maxBytes:MAX_SNAPSHOT,maxNodes:4000000});if(row.body?.maintenance?.operationId===operationId){target=row;end=e+1;break;}start=e+1;}
  if(!target){const old=ReadSnapshot();if(old?.record.body.maintenance?.operationId===operationId)return {...old.record.body.maintenance.result};}
 }
 if(!target){
  if(!operationId&&lastRecord?.body.kind==='CHECKPOINT'){target=lastRecord;end=bytes.length;}
  else {const body=StateBody();if(operationId){const result={compacted:true,sequence:revision+1,archivedBytes:0,bindings:rows.size,receipts:receipts.size};body.maintenance={operationId,result};let size=-1;while(result.archivedBytes!==size){size=result.archivedBytes;result.archivedBytes=bytes.length+Buffer.byteLength(JSON.stringify({seq:revision+1,prev:head,body,mac:Mac(revision+1,head,body)})+'\n');}}
   Append(body);target=lastRecord;bytes=disk.ReadRegular(FILE,MAX_JOURNAL);end=bytes.length;
  }
 }
 if(!bytes.length)return {compacted:true,sequence:revision,alreadyCompacted:true};
 const prefix=bytes.subarray(0,end),tail=bytes.subarray(end);fs.mkdirSync(SEGMENTS,{recursive:true,mode:0o700});const st=fs.lstatSync(SEGMENTS);if(!st.isDirectory()||st.isSymbolicLink())Corrupt();
 const sha512=crypto.createHash('sha512').update(prefix).digest('hex'),archive={file:'segment-'+target.seq+'-'+sha512+'.jsonl',sha512,bytes:prefix.length},file=path.join(SEGMENTS,archive.file);
 if(!fs.existsSync(file))disk.Atomic(file,prefix,{createOnly:true});else if(crypto.createHash('sha512').update(disk.ReadRegular(file,MAX_JOURNAL)).digest('hex')!==sha512)Corrupt();
 const body={version:1,record:target,archive},mac=crypto.createHmac('sha256',secret).update('GAME-MACHINE-CHECKPOINT-V1\n'+JSON.stringify(body)).digest('hex');
 try{disk.Atomic(SNAP,Buffer.from(JSON.stringify({body,mac})));disk.Atomic(FILE,tail);}catch(error){poisoned=true;error.authorityMayBeCommitted=true;throw error;}
 return target.body.maintenance?{...target.body.maintenance.result}:{compacted:true,sequence:target.seq,archivedBytes:prefix.length,bindings:rows.size,receipts:receipts.size};
}
function PlanPruneSegments(days=90){
 Load();if(!Number.isSafeInteger(days)||days<7||days>3650)Fail('DESKTOP_MACHINE_RETENTION_INVALID',400);const snapshot=ReadSnapshot(),files=[];if(!snapshot)return {version:1,days,files};const cutoff=Date.now()-days*86400000;
 for(const name of fs.readdirSync(SEGMENTS)){const match=/^segment-([1-9][0-9]*)-([a-f0-9]{128})\.jsonl$/.exec(name);if(!match||name===snapshot.archive.file||Number(match[1])>snapshot.record.seq)continue;const file=path.join(SEGMENTS,name),st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)Corrupt();if(st.mtimeMs>=cutoff)continue;const bytes=disk.ReadRegular(file,MAX_JOURNAL);if(crypto.createHash('sha512').update(bytes).digest('hex')!==match[2])Corrupt();files.push({name,sha512:match[2]});}return {version:1,days,files};
}
function PruneSegments(days=90,plan=PlanPruneSegments(days)){
 Load();if(plan.version!==1||plan.days!==days||!Array.isArray(plan.files)||plan.files.length>100000)Corrupt();const snapshot=ReadSnapshot();
 for(const f of plan.files){if(!/^segment-[1-9][0-9]*-[a-f0-9]{128}\.jsonl$/.test(f.name||'')||!f.name.endsWith('-'+f.sha512+'.jsonl')||f.name===snapshot?.archive.file)Corrupt();const file=path.join(SEGMENTS,f.name);if(!fs.existsSync(file))continue;const bytes=disk.ReadRegular(file,MAX_JOURNAL);if(crypto.createHash('sha512').update(bytes).digest('hex')!==f.sha512)Corrupt();fs.unlinkSync(file);}
 if(fs.existsSync(SEGMENTS))disk.SyncDirectory(SEGMENTS);return {removed:plan.files.length,minimumAgeDays:days,checkpointPreserved:true,receiptsPreserved:true};
}
function ReconcileAudit(){Load();let repaired=0;const audit=require("../storage/peace.desktop-operation-audit");for(const r of receipts.values())if(r.operation){const out=audit.CommitExternal(r.operation,{revision:r.revision});if(out.duplicate!==true)repaired++;}return repaired;}
function StorageStatus(){Load();return {sequence:revision,activeBytes:fs.statSync(FILE).size,maximumActiveBytes:MAX_JOURNAL,checkpointPresent:fs.existsSync(SNAP),historyRetention:'CURRENT_GENERATIONS_AND_ALL_RECEIPTS',archiveDeletion:'EXPLICIT_CHECKPOINTED_SEGMENTS_AFTER_7_DAYS'};}
// Startup maintenance only. Existing HTTP mutations cannot create this event.
// Its signed receipt survives compaction so a retry never erases later PCs.
function ResetRegistrations(operationId){
 require('../operations/peace.registration-reset-stores').AssertAuthorized(operationId);Load();if(poisoned)throw Error('DESKTOP_MACHINE_POLICY_RESTART_REQUIRED');
 const prior=registrationResets.get(operationId);if(prior)return {...prior,duplicate:true};
 if(registrationResets.size>=1024)Fail('REGISTRATION_RESET_RECEIPT_CAPACITY',409);
 Append({version:4,kind:'REGISTRATION_RESET',operationId,at:Date.now(),previousSequence:revision,removedBindings:rows.size,removedReceipts:receipts.size});
 licenseSnapshot=undefined;licenseRevision=-1;consumedIndex.clear();return {...registrationResets.get(operationId),duplicate:false};
}
function RegistrationStatus(){Load();return {bindings:rows.size,receipts:receipts.size,sequence:revision,resetReceipts:registrationResets.size};}
// The committed license record is also the automatic PC lock. No second journal
// write exists between consuming a key and blocking other sessions. An explicit
// admin unblock advances the generation, leaving every prior key/session spent.
function Base(machineId){Validate(machineId);Load();return rows.get(machineId)||{machineId,blocked:false,generation:0,reason:'',changedAt:0,changedBy:'',revision:0};}
let licenseSnapshot,licenseRevision=-1,consumedIndex=new Map();
function Consumed(machineId,generation){
 const db=require("../licensing/peace.desktop-licenses").DB();
 if(licenseSnapshot!==db||licenseRevision!==db.revision){const index=new Map();for(const row of Object.values(db.licenses)){if(!row.consumed||!row.machineId)continue;const key=row.machineId+':'+row.machinePolicyGeneration;if(!index.has(key))index.set(key,[]);index.get(key).push(row);}for(const values of index.values())values.sort((a,b)=>(a.activatedAt||0)-(b.activatedAt||0)||a.id.localeCompare(b.id));licenseSnapshot=db;licenseRevision=db.revision;consumedIndex=index;}
 return consumedIndex.get(machineId+':'+generation)||[];
}
function Public(machineId){
 const base=Base(machineId),uses=Consumed(machineId,base.generation),owner=uses[0];
 if(base.blocked)return {...base,source:'ADMIN',licenseId:'',allowedSessionId:'',lastVerifiedAt:0};
 if(!owner)return {...base,source:'NONE',licenseId:'',allowedSessionId:'',lastVerifiedAt:0};
 const activity=require("../bootstrap/peace.desktop-bootstrap").LicenseActivity(owner.id);
 // Multiple legacy uses in a single epoch cannot silently pick an owner. They
 // remain locked until explicitly unblocked, rather than reviving sessions.
 return {...base,blocked:true,source:'SINGLE_USE',licenseId:owner.id,allowedSessionId:uses.length===1?owner.bootstrapSessionId||'':'',reason:'1회용 라이선스 사용으로 이 PC의 새 실행이 차단되었습니다.',changedAt:owner.activatedAt||owner.issuedAt,changedBy:'LICENSE_CONSUMPTION',lastVerifiedAt:Math.max(activity?.lastVerifiedAt||0,owner.activatedAt||0)};
}
function Generation(machineId){return Base(machineId).generation;}
function AssertAllowed(machineId,generation,sessionId){
 const row=Public(machineId);
 if(generation!==undefined&&generation!==row.generation)Fail('DESKTOP_MACHINE_SESSION_REVOKED');
 if(row.blocked&&!(row.source==='SINGLE_USE'&&sessionId&&sessionId===row.allowedSessionId))Fail('DESKTOP_MACHINE_BLOCKED');
 return row;
}
function List(){Load();const licenses=Object.values(require("../licensing/peace.desktop-licenses").DB().licenses),ids=new globalThis.Set([...rows.keys(),...licenses.filter(row=>row.consumed&&row.machineId).map(row=>row.machineId)]);return {items:[...ids].map(Public).sort((a,b)=>b.changedAt-a.changedAt),revision,licenseRevision:require("../licensing/peace.desktop-licenses").DB().revision,serverTime:Date.now()};}
function Set(machineId,blocked,body,actor){
 Validate(machineId);Load();if(blocked)Fail('DESKTOP_MACHINE_AUTOMATIC_ONLY',410);if(poisoned)throw Error('DESKTOP_MACHINE_POLICY_RESTART_REQUIRED');if(!require("../network/peace.ha-coordinator").CanAcceptTraffic())Fail('SERVICE_DISABLED',503);
 if(!body||typeof body!=='object'||Array.isArray(body)||typeof body.reason!=='string'||body.reason.trim().length<3||body.reason.length>300||/[\u0000-\u001f\u007f]/.test(body.reason)||typeof body.requestId!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId))Fail('INPUT_INVALID',400);
 const changedBy=String(actor||'ADMIN').slice(0,120),receiptKey=crypto.createHash('sha256').update(changedBy).digest('hex')+':'+body.requestId,fingerprint=crypto.createHash('sha256').update(JSON.stringify({machineId,blocked,reason:body.reason.trim()})).digest('hex'),receipt=receipts.get(receiptKey);
 if(receipt){if(receipt.fingerprint!==fingerprint)Fail('DESKTOP_REQUEST_REUSED',409);if(receipt.operation)require("../storage/peace.desktop-operation-audit").CommitExternal(receipt.operation,{revision:receipt.revision});return {machine:Public(machineId),revision,serverTime:Date.now()};}
 const audit=require("../storage/peace.desktop-operation-audit"),operation=audit.Begin('MACHINE_POLICY_CHANGE',actor,{subject:require('./peace.desktop-device-registry').BindingId(machineId)});
 const old=Base(machineId),event={version:2,machineId,blocked:false,generation:old.generation+1,reason:body.reason.trim(),changedAt:Date.now(),changedBy,receiptKey,fingerprint,operation};
 try{Append(event);}catch(error){audit.Failed(operation,error);throw error;}
 audit.CommitExternal(operation,{revision});return {machine:Public(machineId),revision,serverTime:Date.now()};
}
module.exports={Validate,AssertAllowed,Generation,Public,List,Set,Load,FILE,KEY,SNAP,SEGMENTS,Compact,ReconcileAudit,StorageStatus,PruneSegments,PlanPruneSegments,ResetRegistrations,RegistrationStatus};
