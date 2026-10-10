 'use strict';
// Read-only final-byte inspection. This NEVER claims indirect-call coverage from
// a /guard option or accepts a CFG flag without a bounded GFID table.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {PeCapabilities}=require('../services/peCapabilities'),integrity=require('../services/desktopIntegrity');
function Audit(files){return {version:1,measuredAt:new Date().toISOString(),kind:'FINAL_FILE_INSPECTION_NOT_RUNTIME_ATTESTATION',
 artifacts:Object.fromEntries(['A','B','O'].map((role,index)=>{const file=files[index],info=fs.lstatSync(file);if(!info.isFile()||info.isSymbolicLink()||info.size>64*1024*1024)throw Error('AUDIT_FILE_INVALID');
 const fd=fs.openSync(file,'r');let bytes;try{const before=fs.fstatSync(fd);bytes=fs.readFileSync(fd);const after=fs.fstatSync(fd);if(bytes.length!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw Error('AUDIT_FILE_CHANGED');}finally{fs.closeSync(fd);}
 const code=integrity.CodeImage(bytes),capabilities=PeCapabilities(bytes);if(capabilities.cfg.status==='INVALID')throw Error('AUDIT_CFG_INVALID');
 return [role,{sha512:crypto.createHash('sha512').update(bytes).digest('hex'),bytes:bytes.length,codeSha512:code.sha512,capabilities,windowsRuntime:'NOT_RUN_BY_THIS_TOOL'}];}))};}
if(require.main===module){try{const args=process.argv.slice(2);if(args.length!==4)throw Error('USAGE: node audit-final-artifacts.js A.exe B.exe O.exe output.json');const result=Audit(args.slice(0,3));fs.writeFileSync(path.resolve(args[3]),JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));}catch(error){console.error(error.message);process.exitCode=1;}}
module.exports={Audit};
