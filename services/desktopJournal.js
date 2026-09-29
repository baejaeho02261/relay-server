'use strict';
// This append-only fsynced journal is the desktop source of truth. A generic
// admin database restore cannot revive a consumed or revoked registration key.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),config=require('../config/config');
const FILE=path.join(config.DATA_DIR,'desktop-license-journal.jsonl');
let head=null,poisoned=false;
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
function Empty(){return {schema:1,revision:0,signingSecret:'',licenses:{},receipts:{}};}
function Corrupt(){throw Error('DESKTOP_JOURNAL_CORRUPT');}
function Load(){
 const result=Empty();let seq=0,previous='0'.repeat(64),validBytes=0;
 if(!fs.existsSync(FILE)){head={seq,hash:previous};return {exists:false,state:result};}
 const bytes=fs.readFileSync(FILE);let start=0;
 while(start<bytes.length){
  const end=bytes.indexOf(10,start);if(end<0)break;
  let row;try{row=JSON.parse(bytes.subarray(start,end).toString('utf8'));}catch(_){Corrupt();}
  if(!row||row.seq!==seq+1||row.prev!==previous||!row.body||row.hash!==digest(String(row.seq)+'|'+row.prev+'|'+JSON.stringify(row.body)))Corrupt();
  const event=row.body;if(event.version!==1||!Number.isSafeInteger(event.revision)||event.revision<=result.revision||!Array.isArray(event.licenses)||!event.receipts||typeof event.receipts!=='object'||Array.isArray(event.receipts))Corrupt();
  if(event.signingSecret!==undefined){if(!/^[a-f0-9]{64}$/.test(event.signingSecret)||result.signingSecret&&event.signingSecret!==result.signingSecret)Corrupt();result.signingSecret=event.signingSecret;}
  for(const license of event.licenses){if(!license||typeof license.id!=='string')Corrupt();const old=result.licenses[license.id];if(old?.consumed&&!license.consumed||old&&['REVOKED','RELEASED'].includes(old.status)&&license.status==='AVAILABLE')Corrupt();result.licenses[license.id]=license;}
  for(const [id,receipt]of Object.entries(event.receipts)){if(result.receipts[id]&&JSON.stringify(result.receipts[id])!==JSON.stringify(receipt))Corrupt();result.receipts[id]=receipt;}
  result.revision=event.revision;seq=row.seq;previous=row.hash;validBytes=end+1;start=end+1;
 }
 // A crash can leave only an unfinished trailing append; never discard a
 // completed corrupt record, and never accept its partial operation.
 if(validBytes<bytes.length){const fd=fs.openSync(FILE,'r+');try{fs.ftruncateSync(fd,validBytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 head={seq,hash:previous};return {exists:seq>0,state:result};
}
function Commit(previous,next){
 if(poisoned)throw Error('DESKTOP_JOURNAL_RESTART_REQUIRED');
 if(!head)Load();
 const event={version:1,revision:next.revision,licenses:Object.values(next.licenses).filter(row=>JSON.stringify(previous.licenses[row.id])!==JSON.stringify(row)),receipts:Object.fromEntries(Object.entries(next.receipts).filter(([id,row])=>JSON.stringify(previous.receipts[id])!==JSON.stringify(row)))};
 if(next.signingSecret!==previous.signingSecret)event.signingSecret=next.signingSecret;
 if(!head.seq&&next.signingSecret)event.signingSecret=next.signingSecret;
 const seq=head.seq+1,prev=head.hash,hash=digest(String(seq)+'|'+prev+'|'+JSON.stringify(event)),line=Buffer.from(JSON.stringify({seq,prev,body:event,hash})+'\n');
 fs.mkdirSync(path.dirname(FILE),{recursive:true,mode:0o700});
 const existed=fs.existsSync(FILE),fd=fs.openSync(FILE,'a',0o600);let before;
 try{
  before=fs.fstatSync(fd).size;let written=0;while(written<line.length)written+=fs.writeSync(fd,line,written,line.length-written);fs.fsyncSync(fd);
  if(!existed&&process.platform!=='win32'){const dir=fs.openSync(path.dirname(FILE),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}
 }catch(error){if(before!==undefined)try{fs.ftruncateSync(fd,before);fs.fsyncSync(fd);}catch(_){poisoned=true;}throw error;}
 finally{fs.closeSync(fd);}
 head={seq,hash};
}
module.exports={Load,Commit,FILE};
