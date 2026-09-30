'use strict';
// This append-only fsynced journal is the desktop source of truth. A generic
// admin database restore cannot revive a consumed or revoked registration key.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),config=require('../config/config');
const FILE=path.join(config.DATA_DIR,'desktop-license-journal.jsonl'),KEY=path.join(config.DATA_DIR,'desktop-license-journal.key');
let auth;
function Checkpoint(){return require('./desktopJournalHead').Create(FILE+'.head',Buffer.from(auth.secret,'hex'),'DESKTOP_JOURNAL');}
function SyncDir(){if(process.platform==='win32')return;const fd=fs.openSync(path.dirname(FILE),'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function WriteAtomic(file,bytes){const tmp=file+'.'+crypto.randomBytes(12).toString('hex')+'.tmp';let fd;try{fd=fs.openSync(tmp,'wx',0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;fs.renameSync(tmp,file);SyncDir();}finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(tmp);}catch(_){}}}
function Auth(bytes){
 if(fs.existsSync(KEY)){const stat=fs.lstatSync(KEY);if(!stat.isFile()||stat.isSymbolicLink())Corrupt();try{auth=JSON.parse(fs.readFileSync(KEY,'utf8'));}catch(_){Corrupt();}if(auth.version!==1||!/^[a-f0-9]{64}$/.test(auth.secret)||auth.legacyDigest!==undefined&&!/^[a-f0-9]{64}$/.test(auth.legacyDigest))Corrupt();return;}
 if(bytes&&bytes.toString('utf8').split('\n').some(line=>line&&JSON.parse(line).mac))Corrupt();
 auth={version:1,secret:crypto.randomBytes(32).toString('hex'),...(bytes?.length?{legacyDigest:digest(bytes)}:{})};fs.mkdirSync(path.dirname(FILE),{recursive:true,mode:0o700});WriteAtomic(KEY,Buffer.from(JSON.stringify(auth)));
}
function Mac(row){return crypto.createHmac('sha256',Buffer.from(auth.secret,'hex')).update('GAME-LICENSE-JOURNAL-V2\n'+row.seq+'\n'+row.prev+'\n'+row.hash).digest('hex');}
let head=null,poisoned=false;
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
function Empty(){return {schema:1,revision:0,signingSecret:'',licenses:{},receipts:{}};}
function Corrupt(){throw Error('DESKTOP_JOURNAL_CORRUPT');}
function Load(){
 const result=Empty();let seq=0,previous='0'.repeat(64),validBytes=0;
 if(!fs.existsSync(FILE)){if(fs.existsSync(KEY))throw Error('DESKTOP_JOURNAL_MISSING');head={seq,hash:previous};return {exists:false,state:result};}
 const stat=fs.lstatSync(FILE);if(!stat.isFile()||stat.isSymbolicLink())Corrupt();const bytes=fs.readFileSync(FILE);let start=0;const entries=[];
 while(start<bytes.length){
  const end=bytes.indexOf(10,start);if(end<0)break;
  let row;try{row=JSON.parse(bytes.subarray(start,end).toString('utf8'));}catch(_){Corrupt();}
  if(!row||row.seq!==seq+1||row.prev!==previous||!row.body||row.hash!==digest(String(row.seq)+'|'+row.prev+'|'+JSON.stringify(row.body)))Corrupt();
  entries.push(row);const event=row.body;if(event.version!==1||!Number.isSafeInteger(event.revision)||event.revision<=result.revision||!Array.isArray(event.licenses)||!event.receipts||typeof event.receipts!=='object'||Array.isArray(event.receipts))Corrupt();
  if(event.signingSecret!==undefined){if(!/^[a-f0-9]{64}$/.test(event.signingSecret)||result.signingSecret&&event.signingSecret!==result.signingSecret)Corrupt();result.signingSecret=event.signingSecret;}
  for(const license of event.licenses){if(!license||typeof license.id!=='string')Corrupt();const old=result.licenses[license.id];if(old?.consumed&&!license.consumed||old&&['REVOKED','RELEASED'].includes(old.status)&&license.status==='AVAILABLE')Corrupt();result.licenses[license.id]=license;}
  for(const [id,receipt]of Object.entries(event.receipts)){if(result.receipts[id]&&JSON.stringify(result.receipts[id])!==JSON.stringify(receipt))Corrupt();result.receipts[id]=receipt;}
  result.revision=event.revision;seq=row.seq;previous=row.hash;validBytes=end+1;start=end+1;
 }
 // A crash can leave only an unfinished trailing append; never discard a
 // completed corrupt record, and never accept its partial operation.
 if(validBytes<bytes.length){const fd=fs.openSync(FILE,'r+');try{fs.ftruncateSync(fd,validBytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 const completed=bytes.subarray(0,validBytes),hadAuth=fs.existsSync(KEY);Auth(completed);
 const legacy=entries.some(row=>!row.mac);
 if(legacy){
  if(entries.some(row=>row.mac)||auth.legacyDigest!==digest(completed))Corrupt();
  WriteAtomic(FILE,Buffer.from(entries.map(row=>JSON.stringify({...row,mac:Mac(row)})).join('\n')+(entries.length?'\n':'')));
 }else for(const row of entries)if(row.mac!==Mac(row))Corrupt();
 Checkpoint().Open({seq,hash:previous},legacy||!hadAuth);
 if(auth.legacyDigest!==undefined){delete auth.legacyDigest;WriteAtomic(KEY,Buffer.from(JSON.stringify(auth)));}
 head={seq,hash:previous};return {exists:seq>0,state:result};
}
function Commit(previous,next){
 if(poisoned)throw Error('DESKTOP_JOURNAL_RESTART_REQUIRED');
 if(!head)Load();if(!auth){Auth();Checkpoint().Open(head,true);}
 const event={version:1,revision:next.revision,licenses:Object.values(next.licenses).filter(row=>JSON.stringify(previous.licenses[row.id])!==JSON.stringify(row)),receipts:Object.fromEntries(Object.entries(next.receipts).filter(([id,row])=>JSON.stringify(previous.receipts[id])!==JSON.stringify(row)))};
 if(next.signingSecret!==previous.signingSecret)event.signingSecret=next.signingSecret;
 if(!head.seq&&next.signingSecret)event.signingSecret=next.signingSecret;
 const seq=head.seq+1,prev=head.hash,hash=digest(String(seq)+'|'+prev+'|'+JSON.stringify(event)),record={seq,prev,body:event,hash},line=Buffer.from(JSON.stringify({...record,mac:Mac(record)})+'\n');
 fs.mkdirSync(path.dirname(FILE),{recursive:true,mode:0o700});
 const existed=fs.existsSync(FILE),fd=fs.openSync(FILE,'a',0o600);let before;
 try{
  before=fs.fstatSync(fd).size;Checkpoint().Prepare(head,{seq,hash});let written=0;while(written<line.length)written+=fs.writeSync(fd,line,written,line.length-written);fs.fsyncSync(fd);
  if(!existed&&process.platform!=='win32'){const dir=fs.openSync(path.dirname(FILE),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}
  Checkpoint().Settle({seq,hash});
 }catch(error){if(before!==undefined)try{fs.ftruncateSync(fd,before);fs.fsyncSync(fd);Checkpoint().Settle(head);}catch(_){poisoned=true;}throw error;}
 finally{fs.closeSync(fd);}
 head={seq,hash};
}
module.exports={Load,Commit,FILE,KEY};
