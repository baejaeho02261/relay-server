#!/usr/bin/env node
'use strict';
// Offline DATA-container inspection/extraction. Never executes an EXE/script.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const format=require("../../services/artifacts/peace.custom-package-format"),{ReadRegular}=require("../../services/artifacts/peace.custom-package-jobs");
function bad(message){throw Error(message);}
function absolute(p){if(!p||!path.isAbsolute(p))bad('CUSTOM_PACKAGE_ABSOLUTE_PATH_REQUIRED');return path.resolve(p);}
function parentSafe(p){let c=path.parse(p).root;for(const part of p.slice(c.length).split(path.sep).filter(Boolean)){c=path.join(c,part);const s=fs.lstatSync(c);if(s.isSymbolicLink()||!s.isDirectory())bad('CUSTOM_PACKAGE_PARENT_INVALID');}}
function keyRead(p){p=absolute(p);const k=ReadRegular(p,32);if(k.length!==32||(process.platform!=='win32'&&(fs.statSync(p).mode&0o077))){k.fill(0);bad('CUSTOM_PACKAGE_KEY_INVALID');}return k;}
function Main(args){
 const [cmd,a,b,c]=args;
 if(cmd==='keygen'&&args.length===2){const p=absolute(a);parentSafe(path.dirname(p));const k=crypto.randomBytes(32);let fd;
  try{fd=fs.openSync(p,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY|(fs.constants.O_NOFOLLOW||0),0o600);fs.writeFileSync(fd,k);fs.fsyncSync(fd);console.log('CUSTOM_PACKAGE_KEY_CREATED: keep this key on a protected server/offline backup. It is never printed.');}
  finally{if(fd!==undefined)fs.closeSync(fd);k.fill(0);}return;
 }
 if(!['verify','unpack'].includes(cmd)||args.length!==(cmd==='verify'?3:4))bad("Usage: node tools/artifacts/peace.custom-package.js keygen <absolute-new-key-file> | verify <absolute-package.gcpack> <absolute-key-file> | unpack <absolute-package.gcpack> <absolute-key-file> <absolute-new-output-dir>");
 const key=keyRead(b);let box,opened;
 try{
  box=ReadRegular(absolute(a),format.MAX+112);opened=format.Open(box,key);
  if(cmd==='unpack'){
   const dest=absolute(c);parentSafe(path.dirname(dest));fs.mkdirSync(dest,{mode:0o700});
   // Use only a NEW directory; existing destinations and links are rejected.
   for(const f of opened.files){const target=path.join(dest,f.name);if(!target.startsWith(dest+path.sep))bad('CUSTOM_PACKAGE_ENTRY_INVALID');fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o700});parentSafe(path.dirname(target));const fd=fs.openSync(target,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY|(fs.constants.O_NOFOLLOW||0),0o600);try{fs.writeFileSync(fd,f.bytes);}finally{fs.closeSync(fd);}}
  }
  console.log(JSON.stringify({ok:true,format:'GAME-CUSTOM-PACKAGE-V1',operation:cmd,fileCount:opened.files.length,metadata:opened.metadata,sha512:crypto.createHash('sha512').update(box).digest('hex'),selfExecutable:false,allFunctionsVirtualized:false},null,2));
 }finally{key.fill(0);box?.fill(0);if(opened)for(const f of opened.files)f.bytes.fill(0);}
}
if(require.main===module){try{Main(process.argv.slice(2));}catch(e){console.error(/^(CUSTOM_PACKAGE_|Usage:)/.test(e.message)?e.message:'CUSTOM_PACKAGE_IO_FAILED');process.exitCode=1;}}
module.exports={Main};
