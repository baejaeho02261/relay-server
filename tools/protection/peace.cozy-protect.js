#!/usr/bin/env node
'use strict';
// Patches only the initialized data slot compiled with the static Cozy VM.
// No uploaded executable, profile code, shell, compiler or child process runs.
const fs=require('node:fs'),path=require('node:path'),engine=require('../../services/artifacts/peace.cozy-protection-engine');
const USAGE='Usage: node tools/protection/peace.cozy-protect.js pack A|B|O <absolute-input.exe> <absolute-new-output.exe> [absolute-profile.json] | inspect <absolute-input.exe>';
function Fail(code){throw Error('COZY_PROTECTION_'+code);}
function Absolute(file){if(typeof file!=='string'||!path.isAbsolute(file))Fail('ABSOLUTE_PATH_REQUIRED');return path.resolve(file);}
function SafeParent(file){let cursor=path.parse(file).root;for(const part of path.dirname(file).slice(cursor.length).split(path.sep).filter(Boolean)){cursor=path.join(cursor,part);const s=fs.lstatSync(cursor);if(!s.isDirectory()||s.isSymbolicLink())Fail('PATH_INVALID');}}
function Read(file,maximum){file=Absolute(file);SafeParent(file);const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>maximum)Fail('FILE_INVALID');const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));try{const before=fs.fstatSync(fd);if(!before.isFile()||before.nlink!==1||before.size>maximum)Fail('FILE_INVALID');const bytes=Buffer.alloc(before.size);let offset=0;while(offset<bytes.length){const n=fs.readSync(fd,bytes,offset,bytes.length-offset,offset);if(!n)Fail('FILE_CHANGED');offset+=n;}const extra=Buffer.alloc(1),after=fs.fstatSync(fd);if(fs.readSync(fd,extra,0,1,offset)!==0||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)Fail('FILE_CHANGED');return bytes;}finally{fs.closeSync(fd);}}
function Main(args){
 if(args[0]==='inspect'&&args.length===2){const bytes=Read(args[1],64*1024*1024);try{const metadata=engine.Inspect(bytes);console.log(JSON.stringify({ok:true,ownProtection:metadata,windowsVerified:false}));return;}finally{bytes.fill(0);}}
 if(args[0]!=='pack'||![4,5].includes(args.length))Fail('USAGE');
 const role=args[1],input=Absolute(args[2]),output=Absolute(args[3]);if(input===output)Fail('NEW_OUTPUT_REQUIRED');SafeParent(output);let bytes,profileBytes,result,fd,created=false;
 try{bytes=Read(input,64*1024*1024);let profile;if(args[4]){profileBytes=Read(args[4],128*1024);profile=JSON.parse(profileBytes.toString('utf8'));}result=engine.Pack(bytes,role,profile);fd=fs.openSync(output,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY|(fs.constants.O_NOFOLLOW||0),0o600);created=true;fs.writeFileSync(fd,result.bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;if(process.platform!=='win32'){const parent=fs.openSync(path.dirname(output),'r');try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}}console.log(JSON.stringify({ok:true,inputSha512:result.inputSha512,sha512:result.sha512,profileSha512:result.profileSha512,toolSha512:result.toolSha512,ownProtection:result.ownProtection,windowsVerified:false}));}
 catch(e){if(fd!==undefined){try{fs.closeSync(fd);}catch(_){}fd=undefined;}if(created)try{fs.unlinkSync(output);}catch(_){}throw e;}
 finally{bytes?.fill(0);profileBytes?.fill(0);result?.bytes.fill(0);}
}
if(require.main===module){try{Main(process.argv.slice(2));}catch(e){console.error(/^COZY_PROTECTION_[A-Z_]+$/.test(e.message||'')?e.message:'COZY_PROTECTION_OPERATION_FAILED');if(e.message==='COZY_PROTECTION_USAGE')console.error(USAGE);process.exitCode=1;}}
module.exports={Main};
