'use strict';
// Fsynced, authenticated high-water mark. A pending append may resolve to either
// pre-commit or post-commit history after a crash; a settled history cannot be
// truncated independently. Restoring an entire old server disk remains rollback.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
function Create(file,secret,domain){
 const fail=()=>{throw Error(domain+'_CORRUPT');},equal=(a,b)=>a?.seq===b?.seq&&a?.hash===b?.hash,valid=x=>x&&Number.isSafeInteger(x.seq)&&x.seq>=0&&/^[a-f0-9]{64}$/.test(x.hash);
 const mac=body=>crypto.createHmac('sha256',secret).update(domain+'-HEAD-V1\n'+JSON.stringify(body)).digest('hex');
 function read(){if(!fs.existsSync(file))return null;const stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>1024)fail();let row;try{row=JSON.parse(fs.readFileSync(file,'utf8'));}catch(_){fail();}if(!row||!row.body||row.body.version!==1||!valid(row.body.current)||row.body.pending!==undefined&&(!valid(row.body.pending)||row.body.pending.seq!==row.body.current.seq+1)||row.mac!==mac(row.body))fail();return row.body;}
 function write(body){const temp=file+'.'+crypto.randomBytes(12).toString('hex')+'.tmp';let fd;try{fd=fs.openSync(temp,'wx',0o600);fs.writeFileSync(fd,JSON.stringify({body,mac:mac(body)}));fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;fs.renameSync(temp,file);if(process.platform!=='win32'){const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}}finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temp);}catch(_){}}}
 function Open(actual,allowMissing=false){const old=read();if(!old){if(!allowMissing)fail();write({version:1,current:actual});return;}if(!equal(old.current,actual)&&!equal(old.pending,actual))fail();if(old.pending)write({version:1,current:actual});}
 function Prepare(current,next){const old=read();if(!old||old.pending||!equal(old.current,current))fail();write({version:1,current,pending:next});}
 function Settle(actual){const old=read();if(!old||!equal(old.pending,actual)&&!equal(old.current,actual))fail();write({version:1,current:actual});}
 return {Open,Prepare,Settle};
}
module.exports={Create};
