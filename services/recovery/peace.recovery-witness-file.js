'use strict';
// Pure, synchronous single-writer witness store. Production obtains its own OS
// lock before constructing this object. Keep the directory outside DATA_DIR and
// outside its backup/restore job. A second directory on a restored disk is NOT
// an independent trust boundary. No reset/rewind/delete-head API is provided.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const disk=require("../storage/peace.durable-file"),strict=require("../protocol/peace.strict-json");
const ZERO='0'.repeat(64),HEAD=/^[a-f0-9]{64}$/,NAME=/^[A-Z][A-Z0-9_]{2,63}$/;
const valid=x=>x&&Number.isSafeInteger(x.seq)&&x.seq>=0&&HEAD.test(x.hash);
const equal=(a,b)=>a?.seq===b?.seq&&a?.hash===b?.hash;
class WitnessFile{
  constructor(directory){this.directory=directory;this.file=path.join(directory,'witness.json');this.key=path.join(directory,'witness.key');this.poisoned=false;}
  read(){
    if(this.poisoned)throw Error('RECOVERY_WITNESS_RESTART_REQUIRED');
    const key=disk.ReadRegular(this.key,32);if(key.length!==32)throw Error('RECOVERY_WITNESS_KEY_INVALID');
    try{
      const row=strict.Parse(disk.ReadRegular(this.file,1024*1024),{maxBytes:1024*1024});
      const mac=crypto.createHmac('sha256',key).update('GAME-RECOVERY-WITNESS-V1\n'+JSON.stringify(row.body)).digest('hex');
      const body=row.body;
      if(!disk.SecretEqual(mac,row.mac)||!body||body.version!==1||!HEAD.test(body.installationId)||!Number.isSafeInteger(body.revision)||body.revision<0||!body.heads||Array.isArray(body.heads))throw Error('RECOVERY_WITNESS_INVALID');
      for(const [name,head] of Object.entries(body.heads))if(!NAME.test(name)||!valid(head.current)||(head.pending!==undefined&&(!valid(head.pending)||head.pending.seq!==head.current.seq+1)))throw Error('RECOVERY_WITNESS_INVALID');
      return body;
    }finally{key.fill(0);}
  }
  write(body,createOnly=false){
    if(this.poisoned)throw Error('RECOVERY_WITNESS_RESTART_REQUIRED');
    const key=disk.ReadRegular(this.key,32);
    try{const mac=crypto.createHmac('sha256',key).update('GAME-RECOVERY-WITNESS-V1\n'+JSON.stringify(body)).digest('hex');disk.Atomic(this.file,Buffer.from(JSON.stringify({body,mac})),{createOnly});}
    catch(error){if(error.published)this.poisoned=true;throw error;}
    finally{key.fill(0);}
  }
  enroll(heads){
    if(fs.existsSync(this.file)||fs.existsSync(this.key))throw Error('RECOVERY_WITNESS_ALREADY_ENROLLED');
    if(!heads||!Object.keys(heads).length)throw Error('RECOVERY_WITNESS_EMPTY');
    const entries={};for(const [name,head]of Object.entries(heads)){if(!NAME.test(name)||!valid(head))throw Error('RECOVERY_WITNESS_HEAD_INVALID');entries[name]={current:{...head}};}
    // Partial first-time initialization is deliberately not auto-retried. No
    // runtime caller may adopt an older backup after an ambiguous enrollment.
    disk.Atomic(this.key,crypto.randomBytes(32),{createOnly:true});
    const body={version:1,installationId:crypto.randomBytes(32).toString('hex'),revision:0,heads:entries};this.write(body,true);return this.status();
  }
  head(name){const body=this.read();if(!NAME.test(name)||!body.heads[name])throw Error('RECOVERY_WITNESS_NOT_ENROLLED');return body.heads[name];}
  open(name,actual){
    if(!valid(actual))throw Error('RECOVERY_WITNESS_HEAD_INVALID');
    const body=this.read(),head=body.heads[name];if(!head)throw Error('RECOVERY_WITNESS_NOT_ENROLLED');
    if(!equal(head.current,actual)&&!equal(head.pending,actual))throw Error('RECOVERY_ROLLBACK_DETECTED');
    if(head.pending){body.heads[name]={current:{...actual}};body.revision++;this.write(body);}
  }
  prepare(name,current,next){
    if(!valid(current)||!valid(next)||next.seq!==current.seq+1)throw Error('RECOVERY_WITNESS_HEAD_INVALID');
    const body=this.read(),head=body.heads[name];
    if(!head||head.pending||!equal(head.current,current))throw Error('RECOVERY_WITNESS_CONFLICT');
    body.heads[name]={current:{...current},pending:{...next}};body.revision++;this.write(body);
  }
  settle(name,actual){this.open(name,actual);}
  assertCurrent(name,actual){const head=this.head(name);if(!equal(head.current,actual)||head.pending)throw Error('RECOVERY_WITNESS_UNSETTLED');}
  status(){const b=this.read();return {status:'CONFIGURED',installationId:b.installationId,revision:b.revision,heads:Object.fromEntries(Object.entries(b.heads).map(([name,h])=>[name,{sequence:h.current.seq,pending:!!h.pending}]))};}
}
module.exports={WitnessFile,ZERO,ValidHead:valid,EqualHead:equal};
