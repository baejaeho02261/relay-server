 'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Read-only final-byte inspection. This NEVER claims indirect-call coverage from
// a /guard option or accepts a CFG flag without a bounded GFID table.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {PeCapabilities}=require("../../services/artifacts/peace.pe-capabilities"),integrity=require("../../services/integrity/peace.desktop-integrity");
function Audit(files){
 if(!Array.isArray(files)||files.length!==3)throw Error('AUDIT_ARGUMENT_INVALID');
 const reader=require("../../services/artifacts/peace.bounded-artifact-read"),expected=reader.Read(path.resolve(MODULE_RESOURCE_ROOT,"../../Railway/Cozy.Projects/Cozy.Overlay/Cozy.Overlay.manifest"),65536);
 return {version:1,measuredAt:new Date().toISOString(),kind:'FINAL_FILE_INSPECTION_NOT_RUNTIME_ATTESTATION',
 artifacts:Object.fromEntries(['A','B','O'].map((role,index)=>{
  const bytes=reader.Read(files[index]),code=integrity.CodeImage(bytes),capabilities=PeCapabilities(bytes);
  if(capabilities.cfg.status==='INVALID')throw Error('AUDIT_CFG_INVALID');
  const overlayManifest=role==='O'?require("../../services/artifacts/peace.pe-manifest").AssertExpected(bytes,expected):undefined;
  return [role,{sha512:crypto.createHash('sha512').update(bytes).digest('hex'),bytes:bytes.length,codeSha512:code.sha512,capabilities,...(overlayManifest?{overlayManifest}:{}),windowsRuntime:'NOT_RUN_BY_THIS_TOOL'}];
 }))};
}
if(require.main===module){try{const args=process.argv.slice(2);if(args.length!==4)throw Error('USAGE: node peace.audit-final-artifacts.js A.exe B.exe O.exe output.json');const result=Audit(args.slice(0,3));fs.writeFileSync(path.resolve(args[3]),JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));}catch(error){console.error(error.message);process.exitCode=1;}}
module.exports={Audit};
