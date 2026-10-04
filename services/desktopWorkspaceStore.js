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
  if(Object.keys(v.jobs).length>1000||Object.keys(v.receipts).length>1000||Object.keys(v.metadata).length>100000)Fail();
  for(const [id,m] of Object.entries(v.metadata))if(!/^(?:DL-)?[A-F0-9]{24}$/.test(id)||!Plain(m)||typeof m.note!=='string'||m.note.length>500||!Array.isArray(m.tags)||m.tags.length>10||m.tags.some(t=>typeof t!=='string'||t.length>30)||!Number.isSafeInteger(m.revision)||m.revision<1)Fail();
  for(const [id,j] of Object.entries(v.jobs)){
    if(!/^[a-f0-9]{32}$/.test(id)||j.id!==id||!['CREATE','METADATA','EXPORT','CLEANUP'].includes(j.kind)||!['QUEUED','RUNNING','DONE','PARTIAL','CANCELLED'].includes(j.status)||!Array.isArray(j.items)||j.items.length<1||j.items.length>100||!Number.isSafeInteger(j.createdAt))Fail();
    for(const i of j.items)if(!Plain(i)||!['PENDING','RUNNING','DONE','FAILED'].includes(i.status)||!Plain(i.input))Fail();
  }
  return v;
}
function Load() {
  if(poisoned)Fail('WORKSPACE_RESTART_REQUIRED');
  if(current)return current;
  try{
    if(!fs.existsSync(FILE))return current=Empty();
    const st=fs.lstatSync(FILE);if(!st.isFile()||st.isSymbolicLink()||st.size>32*1024*1024)Fail();
    return current=Validate(JSON.parse(fs.readFileSync(FILE,'utf8')));
  }catch(e){if(e.desktopError)throw e;Fail();}
}
function Write(value){
  fs.mkdirSync(DIR,{recursive:true,mode:0o700});
  const tmp=path.join(DIR,'.workspace-'+crypto.randomBytes(12).toString('hex')+'.tmp');let fd,published=false;
  try{
    fd=fs.openSync(tmp,'wx',0o600);fs.writeFileSync(fd,JSON.stringify(value));fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    fs.renameSync(tmp,FILE);published=true;
    if(process.platform!=='win32'){const dir=fs.openSync(DIR,'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}
  }catch(e){if(published)poisoned=true;Fail(published?'WORKSPACE_RESTART_REQUIRED':'WORKSPACE_SAVE_FAILED');}
  finally{if(fd!==undefined)try{fs.closeSync(fd);}catch(_){}try{fs.unlinkSync(tmp);}catch(_){} }
}
function Atomic(fn){
  if(!require('./haCoordinator').CanAcceptTraffic())Fail('RELAY_STANDBY_READ_ONLY');
  const prev=Load(),next=structuredClone(prev),result=fn(next);next.revision=prev.revision+1;Validate(next);
  try{Write(next);current=next;}catch(e){if(poisoned)current=next;throw e;}return result;
}
module.exports={Load,Atomic,DIR,FILE,Validate};
