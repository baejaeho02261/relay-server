'use strict';
// Server-owned machine policy. The client sends only a domain-hashed machine
// identifier, not raw firmware/registry IDs. This binds issuance across ephemeral
// RSA keys but is not hardware attestation: a privileged client can spoof it.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),config=require('../config/config');
const DIR=path.join(config.DATA_DIR,'desktop-machine-policy'),KEY=path.join(DIR,'authority.key'),FILE=path.join(DIR,'journal.jsonl');
function Checkpoint(){return require('./desktopJournalHead').Create(FILE+'.head',secret,'DESKTOP_MACHINE_POLICY');}
let loaded=false,secret,head='0'.repeat(64),revision=0,rows=new Map(),receipts=new Map(),poisoned=false;
function Fail(code,status=403){const error=Error(code);error.desktopError=true;error.status=status;throw error;}
function Validate(machineId){if(typeof machineId!=='string'||!/^[A-F0-9]{64}$/.test(machineId))Fail('DESKTOP_MACHINE_INVALID',400);return machineId;}
function Corrupt(){throw Error('DESKTOP_MACHINE_POLICY_CORRUPT');}
function SyncDir(){if(process.platform==='win32')return;const fd=fs.openSync(DIR,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Mac(seq,prev,body){return crypto.createHmac('sha256',secret).update('GAME-MACHINE-POLICY-V1\n'+seq+'\n'+prev+'\n'+JSON.stringify(body)).digest('hex');}
function Load(){
 if(loaded)return;let created=false;if(config.HA_ENABLED)throw Error('DESKTOP_MACHINE_POLICY_SINGLE_WRITER_REQUIRED');fs.mkdirSync(DIR,{recursive:true,mode:0o700});
 if(!fs.existsSync(KEY)){
  if(fs.existsSync(FILE))Corrupt();created=true;const fd=fs.openSync(KEY,'wx',0o600);try{fs.writeFileSync(fd,crypto.randomBytes(32));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}const journal=fs.openSync(FILE,'wx',0o600);try{fs.fsyncSync(journal);}finally{fs.closeSync(journal);}SyncDir();
 }else if(!fs.existsSync(FILE))Corrupt();
 const keyStat=fs.lstatSync(KEY);if(!keyStat.isFile()||keyStat.isSymbolicLink())Corrupt();secret=fs.readFileSync(KEY);if(secret.length!==32)Corrupt();
 rows=new Map();receipts=new Map();revision=0;head='0'.repeat(64);
 if(fs.existsSync(FILE)){
  const stat=fs.lstatSync(FILE);if(!stat.isFile()||stat.isSymbolicLink())Corrupt();const bytes=fs.readFileSync(FILE);let start=0,complete=0;
  while(start<bytes.length){const end=bytes.indexOf(10,start);if(end<0)break;let entry;try{entry=JSON.parse(bytes.subarray(start,end).toString('utf8'));}catch(_){Corrupt();}
   const body=entry?.body;if(entry?.seq!==revision+1||entry?.prev!==head||!body||entry.mac!==Mac(entry.seq,entry.prev,body)||typeof body.machineId!=='string'||!/^[A-F0-9]{64}$/.test(body.machineId)||typeof body.blocked!=='boolean'||!Number.isSafeInteger(body.generation)||body.generation<0||!Number.isSafeInteger(body.changedAt)||body.changedAt<1||typeof body.reason!=='string'||typeof body.changedBy!=='string'||typeof body.receiptKey!=='string'||!/^[a-f0-9]{64}$/.test(body.fingerprint))Corrupt();
   const old=rows.get(body.machineId);if(body.version!==undefined&&body.version!==2||body.generation!==(old?.generation||0)+(body.version===2?1:body.blocked?1:0))Corrupt();if(receipts.has(body.receiptKey))Corrupt();
   rows.set(body.machineId,{machineId:body.machineId,blocked:body.blocked,generation:body.generation,reason:body.reason,changedAt:body.changedAt,changedBy:body.changedBy,revision:entry.seq});receipts.set(body.receiptKey,{fingerprint:body.fingerprint,machineId:body.machineId});revision=entry.seq;head=entry.mac;start=end+1;complete=start;
  }
  if(complete<bytes.length){const fd=fs.openSync(FILE,'r+');try{fs.ftruncateSync(fd,complete);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 }Checkpoint().Open({seq:revision,hash:head},created);loaded=true;
}
// The committed license record is also the automatic PC lock. No second journal
// write exists between consuming a key and blocking other sessions. An explicit
// admin unblock advances the generation, leaving every prior key/session spent.
function Base(machineId){Validate(machineId);Load();return rows.get(machineId)||{machineId,blocked:false,generation:0,reason:'',changedAt:0,changedBy:'',revision:0};}
let licenseSnapshot,licenseRevision=-1,consumedIndex=new Map();
function Consumed(machineId,generation){
 const db=require('./desktopLicenses').DB();
 if(licenseSnapshot!==db||licenseRevision!==db.revision){const index=new Map();for(const row of Object.values(db.licenses)){if(!row.consumed||!row.machineId)continue;const key=row.machineId+':'+row.machinePolicyGeneration;if(!index.has(key))index.set(key,[]);index.get(key).push(row);}for(const values of index.values())values.sort((a,b)=>(a.activatedAt||0)-(b.activatedAt||0)||a.id.localeCompare(b.id));licenseSnapshot=db;licenseRevision=db.revision;consumedIndex=index;}
 return consumedIndex.get(machineId+':'+generation)||[];
}
function Public(machineId){
 const base=Base(machineId),uses=Consumed(machineId,base.generation),owner=uses[0];
 if(base.blocked)return {...base,source:'ADMIN',licenseId:'',allowedSessionId:'',lastVerifiedAt:0};
 if(!owner)return {...base,source:'NONE',licenseId:'',allowedSessionId:'',lastVerifiedAt:0};
 const activity=require('./desktopBootstrap').LicenseActivity(owner.id);
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
function List(){Load();const licenses=Object.values(require('./desktopLicenses').DB().licenses),ids=new globalThis.Set([...rows.keys(),...licenses.filter(row=>row.consumed&&row.machineId).map(row=>row.machineId)]);return {items:[...ids].map(Public).sort((a,b)=>b.changedAt-a.changedAt),revision,licenseRevision:require('./desktopLicenses').DB().revision,serverTime:Date.now()};}
function Set(machineId,blocked,body,actor){
 Validate(machineId);Load();if(blocked)Fail('DESKTOP_MACHINE_AUTOMATIC_ONLY',410);if(poisoned)throw Error('DESKTOP_MACHINE_POLICY_RESTART_REQUIRED');if(!require('./haCoordinator').CanAcceptTraffic())Fail('SERVICE_DISABLED',503);
 if(!body||typeof body!=='object'||Array.isArray(body)||typeof body.reason!=='string'||body.reason.trim().length<3||body.reason.length>300||/[\u0000-\u001f\u007f]/.test(body.reason)||typeof body.requestId!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId))Fail('INPUT_INVALID',400);
 const changedBy=String(actor||'ADMIN').slice(0,120),receiptKey=crypto.createHash('sha256').update(changedBy).digest('hex')+':'+body.requestId,fingerprint=crypto.createHash('sha256').update(JSON.stringify({machineId,blocked,reason:body.reason.trim()})).digest('hex'),receipt=receipts.get(receiptKey);
 if(receipt){if(receipt.fingerprint!==fingerprint)Fail('DESKTOP_REQUEST_REUSED',409);return {machine:Public(machineId),revision,serverTime:Date.now()};}
 const old=Base(machineId),event={version:2,machineId,blocked:false,generation:old.generation+1,reason:body.reason.trim(),changedAt:Date.now(),changedBy,receiptKey,fingerprint},seq=revision+1,mac=Mac(seq,head,event),line=Buffer.from(JSON.stringify({seq,prev:head,body:event,mac})+'\n');
 const existed=fs.existsSync(FILE),fd=fs.openSync(FILE,'a',0o600);let before;try{before=fs.fstatSync(fd).size;Checkpoint().Prepare({seq:revision,hash:head},{seq,hash:mac});let offset=0;while(offset<line.length)offset+=fs.writeSync(fd,line,offset,line.length-offset);fs.fsyncSync(fd);if(!existed)SyncDir();Checkpoint().Settle({seq,hash:mac});}catch(error){if(before!==undefined)try{fs.ftruncateSync(fd,before);fs.fsyncSync(fd);Checkpoint().Settle({seq:revision,hash:head});}catch(_){poisoned=true;}throw error;}finally{fs.closeSync(fd);}
 revision=seq;head=mac;rows.set(machineId,{machineId,blocked,generation:event.generation,reason:event.reason,changedAt:event.changedAt,changedBy,revision:seq});receipts.set(receiptKey,{fingerprint,machineId});return {machine:Public(machineId),revision,serverTime:Date.now()};
}
module.exports={Validate,AssertAllowed,Generation,Public,List,Set,Load,FILE,KEY};
