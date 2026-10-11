'use strict';
// Final metadata inspection is not instrumentation coverage. Classic Delphi
// output without a verified guarded-callsite audit cannot authorize strict CFG.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const pe=require('../services/peCapabilities');
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
function Inspect(directory,buildInputSha512){if(!/^[a-f0-9]{128}$/.test(buildInputSha512||''))throw Error('CI_BUILD_LOCK_REQUIRED');const artifacts={};for(const role of ['A','B','O']){const file=path.join(directory,role+'.exe'),s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.size>64*1024*1024)throw Error('CI_CFG_ARTIFACT_INVALID');const b=fs.readFileSync(file),caps=pe.PeCapabilities(b);artifacts[role]={sha512:sha(b),metadataValid:caps.compiledCfg===true,instrumentation:caps.compiledCfg?'METADATA_ONLY_UNVERIFIED':'NOT_INSTRUMENTED',strictProfileSupported:false};}return{version:1,kind:'FINAL_CFG_CAPABILITY_NOT_INSTRUMENTATION_PROOF',buildInputSha512,artifacts};}
if(require.main===module){try{const[dir,lock,out]=process.argv.slice(2),input=require('../services/strictJson').Parse(fs.readFileSync(lock));if(input.status!=='PASS')throw Error('CI_BUILD_LOCK_REQUIRED');const result=Inspect(dir,input.inputSha512);fs.writeFileSync(out,JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));}catch(e){console.error(/^CI_[A-Z_]+$/.test(e.message)?e.message:'CI_CFG_INSPECTION_FAILED');process.exitCode=1;}}
module.exports={Inspect};
