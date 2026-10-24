'use strict';
// Synthetic tool bytes for Linux contract tests, never usable release approval.
const fs=require('node:fs'),path=require('node:path');
function fixture(root){
 const tools={};
 for(const role of ['node','npm','msbuild','pwsh','powershell','python','openssl','cl','link','lib','cmd']){
  const directory=path.join(root,'synthetic-tools',role);fs.mkdirSync(directory,{recursive:true});
  tools[role]=path.join(directory,role+(role==='npm'?'.cmd':'.exe'));fs.writeFileSync(tools[role],'SYNTHETIC '+role);fs.writeFileSync(path.join(directory,'support.dll'),'SYNTHETIC support '+role);
 }
 return tools;
}
function recipes(web){for(const name of ['toolchain/peace.build-input-lock.js','pipeline/Invoke-WindowsCI.ps1','pipeline/Windows-Stage.ps1','pipeline/CiCommon.ps1']){const file=path.join(web,'ci',...name.split('/'));fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,'SYNTHETIC recipe '+name);}}
module.exports={fixture,recipes};
