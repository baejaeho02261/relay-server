#!/usr/bin/env node
'use strict';
// Read-only inspection. New policy binding is an authenticated server operation.
// No uploaded executable, profile code, shell, compiler or child process runs.
const fs=require('node:fs'),path=require('node:path'),engine=require('../../services/artifacts/peace.cozy-protection-engine');
const USAGE='Usage: node tools/protection/peace.cozy-protect.js inspect <absolute-input.exe>';
function Fail(code){throw Error('COZY_PROTECTION_'+code);}
function Absolute(file){if(typeof file!=='string'||!path.isAbsolute(file))Fail('ABSOLUTE_PATH_REQUIRED');return path.resolve(file);}
function SafeParent(file){let cursor=path.parse(file).root;for(const part of path.dirname(file).slice(cursor.length).split(path.sep).filter(Boolean)){cursor=path.join(cursor,part);const s=fs.lstatSync(cursor);if(!s.isDirectory()||s.isSymbolicLink())Fail('PATH_INVALID');}}
function Read(file,maximum){file=Absolute(file);SafeParent(file);const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>maximum)Fail('FILE_INVALID');const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));try{const before=fs.fstatSync(fd);if(!before.isFile()||before.nlink!==1||before.size>maximum)Fail('FILE_INVALID');const bytes=Buffer.alloc(before.size);let offset=0;while(offset<bytes.length){const n=fs.readSync(fd,bytes,offset,bytes.length-offset,offset);if(!n)Fail('FILE_CHANGED');offset+=n;}const extra=Buffer.alloc(1),after=fs.fstatSync(fd);if(fs.readSync(fd,extra,0,1,offset)!==0||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)Fail('FILE_CHANGED');return bytes;}finally{fs.closeSync(fd);}}
function Main(args){
 if(args[0]==='inspect'&&args.length===2){const bytes=Read(args[1],64*1024*1024);try{const metadata=engine.Inspect(bytes);console.log(JSON.stringify({ok:true,ownProtection:metadata,windowsVerified:false}));return;}finally{bytes.fill(0);}}
 if(args[0]==='pack')Fail('LEGACY_PACKING_RETIRED_USE_SERVER_POLICY');
 Fail('USAGE');
}
if(require.main===module){try{Main(process.argv.slice(2));}catch(e){console.error(/^COZY_PROTECTION_[A-Z_]+$/.test(e.message||'')?e.message:'COZY_PROTECTION_OPERATION_FAILED');if(e.message==='COZY_PROTECTION_USAGE')console.error(USAGE);process.exitCode=1;}}
module.exports={Main};
