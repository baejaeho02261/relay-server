"use strict";
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),disk=require("../../services/storage/peace.durable-file");
const digest=b=>crypto.createHash('sha512').update(b).digest('hex');
function Export(directory,out){
 if(!path.isAbsolute(directory)||!path.isAbsolute(out)||fs.existsSync(out))throw Error('RECOVERY_EXPORT_PATH_INVALID');
 if(process.env.DESKTOP_RECOVERY_WITNESS_URL||process.env.DESKTOP_RECOVERY_WITNESS_DIR)throw Error('RECOVERY_ALREADY_CONFIGURED_USE_VERIFIED_MIGRATION');
 const root=fs.realpathSync(directory);
 for(const name of ['desktop-bootstrap/authority.json','desktop-bootstrap/authority.json.head','desktop-license-journal.jsonl.head','desktop-machine-policy/journal.jsonl.head','desktop-integrity-reports/reports.json.head']){
  const st=fs.lstatSync(path.join(root,name));if(!st.isFile()||st.isSymbolicLink())throw Error('RECOVERY_CURRENT_STORE_REQUIRED');
 }
 process.env.DATA_DIR=root;process.env.HA_ENABLED='0';
 require("../../services/storage/peace.desktop-single-writer").Acquire(directory,{haEnabled:false});
 const heads=require('./peace.recovery-maintenance').LoadStores();const bytes=Buffer.from(JSON.stringify({version:1,kind:'REVIEWED_CURRENT_AUTHORITY_HEADS',exportedAt:new Date().toISOString(),heads},null,2));
 disk.Atomic(out,bytes,{createOnly:true});return {sha512:digest(bytes),source:'OPERATOR_CONFIRMED_CURRENT_STORE',containsPrivateKeys:false};
}
function Enroll(directory,input,expected){
 if(!path.isAbsolute(directory)||!path.isAbsolute(input)||!/^[a-f0-9]{128}$/.test(expected||''))throw Error('RECOVERY_ENROLL_INPUT_INVALID');
 const bytes=disk.ReadRegular(input,16384);if(digest(bytes)!==expected)throw Error('RECOVERY_ENROLL_HASH_MISMATCH');
 const row=require("../../services/protocol/peace.strict-json").Parse(bytes,{maxBytes:16384,maxDepth:6,maxNodes:256});
 const p=require("../../services/recovery/peace.remote-witness-protocol");if(row.version!==1||row.kind!=='REVIEWED_CURRENT_AUTHORITY_HEADS'||!row.heads||Object.keys(row.heads).sort().join()!==[...p.DOMAINS].sort().join())throw Error('RECOVERY_ENROLL_INPUT_INVALID');
 const dir=fs.realpathSync(directory);require("../../services/storage/peace.desktop-single-writer").AcquireWitness(dir,{haEnabled:false});
 return new(require("../../services/recovery/peace.recovery-witness-file").WitnessFile)(dir).enroll(row.heads);
}
if(require.main===module){try{const [cmd,...a]=process.argv.slice(2);let result;
 if(cmd==='export'&&a.length===3&&a[2]==='--confirm-current-stopped-authority')result=Export(a[0],a[1]);
 else if(cmd==='enroll'&&a.length===4&&a[3]==='--confirm-independent-trusted-heads')result=Enroll(a[0],a[1],a[2]);
 else throw Error('RECOVERY_ADMIN_ARGUMENTS_INVALID');console.log(JSON.stringify(result,null,2));
 }catch(e){console.error(/^[A-Z_]+$/.test(e.message)?e.message:'RECOVERY_ADMIN_FAILED');process.exitCode=1;}}
module.exports={Export,Enroll};
