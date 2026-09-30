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
   const old=rows.get(body.machineId);if(body.generation!==(old?.generation||0)+(body.blocked?1:0))Corrupt();if(receipts.has(body.receiptKey))Corrupt();
   rows.set(body.machineId,{machineId:body.machineId,blocked:body.blocked,generation:body.generation,reason:body.reason,changedAt:body.changedAt,changedBy:body.changedBy,revision:entry.seq});receipts.set(body.receiptKey,{fingerprint:body.fingerprint,machineId:body.machineId});revision=entry.seq;head=entry.mac;start=end+1;complete=start;
  }
  if(complete<bytes.length){const fd=fs.openSync(FILE,'r+');try{fs.ftruncateSync(fd,complete);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 }Checkpoint().Open({seq:revision,hash:head},created);loaded=true;
}
function Public(machineId){Validate(machineId);Load();return {...(rows.get(machineId)||{machineId,blocked:false,generation:0,reason:'',changedAt:0,changedBy:'',revision:0})};}
function Generation(machineId){return Public(machineId).generation;}
function AssertAllowed(machineId,generation){const row=Public(machineId);if(row.blocked)Fail('DESKTOP_MACHINE_BLOCKED');if(generation!==undefined&&generation!==row.generation)Fail('DESKTOP_MACHINE_SESSION_REVOKED');return row;}
function List(){Load();return {items:[...rows.values()].map(row=>({...row})).sort((a,b)=>b.changedAt-a.changedAt),revision,serverTime:Date.now()};}
function Set(machineId,blocked,body,actor){
 Validate(machineId);Load();if(poisoned)throw Error('DESKTOP_MACHINE_POLICY_RESTART_REQUIRED');if(!require('./haCoordinator').CanAcceptTraffic())Fail('SERVICE_DISABLED',503);
 if(!body||typeof body!=='object'||Array.isArray(body)||typeof body.reason!=='string'||body.reason.trim().length<3||body.reason.length>300||/[\u0000-\u001f\u007f]/.test(body.reason)||typeof body.requestId!=='string'||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId))Fail('INPUT_INVALID',400);
 const changedBy=String(actor||'ADMIN').slice(0,120),receiptKey=crypto.createHash('sha256').update(changedBy).digest('hex')+':'+body.requestId,fingerprint=crypto.createHash('sha256').update(JSON.stringify({machineId,blocked,reason:body.reason.trim()})).digest('hex'),receipt=receipts.get(receiptKey);
 if(receipt){if(receipt.fingerprint!==fingerprint)Fail('DESKTOP_REQUEST_REUSED',409);return {machine:Public(machineId),revision,serverTime:Date.now()};}
 const old=Public(machineId),event={machineId,blocked,generation:old.generation+(blocked?1:0),reason:body.reason.trim(),changedAt:Date.now(),changedBy,receiptKey,fingerprint},seq=revision+1,mac=Mac(seq,head,event),line=Buffer.from(JSON.stringify({seq,prev:head,body:event,mac})+'\n');
 const existed=fs.existsSync(FILE),fd=fs.openSync(FILE,'a',0o600);let before;try{before=fs.fstatSync(fd).size;Checkpoint().Prepare({seq:revision,hash:head},{seq,hash:mac});let offset=0;while(offset<line.length)offset+=fs.writeSync(fd,line,offset,line.length-offset);fs.fsyncSync(fd);if(!existed)SyncDir();Checkpoint().Settle({seq,hash:mac});}catch(error){if(before!==undefined)try{fs.ftruncateSync(fd,before);fs.fsyncSync(fd);Checkpoint().Settle({seq:revision,hash:head});}catch(_){poisoned=true;}throw error;}finally{fs.closeSync(fd);}
 revision=seq;head=mac;rows.set(machineId,{machineId,blocked,generation:event.generation,reason:event.reason,changedAt:event.changedAt,changedBy,revision:seq});receipts.set(receiptKey,{fingerprint,machineId});return {machine:Public(machineId),revision,serverTime:Date.now()};
}
module.exports={Validate,AssertAllowed,Generation,Public,List,Set,Load,FILE,KEY};
