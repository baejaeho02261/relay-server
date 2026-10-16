'use strict';
// Own execution scratch only. Preserve bounded public results; never erase a
// supplied executable, backup, input document, OS history or a production store.
const fs=require('node:fs'),path=require('node:path');
const read=(file,max=16*1024*1024)=>require('../services/boundedArtifactRead').Read(file,max);
const norm=file=>process.platform==='win32'?path.resolve(file).toLowerCase():path.resolve(file);
const inside=(file,root)=>norm(file).startsWith(norm(root)+path.sep);
function OwnedRoot(value){
 if(typeof value!=='string'||!path.isAbsolute(value)||path.dirname(value)===value)throw Error('EXECUTION_SCRATCH_ROOT_INVALID');
 const stat=fs.lstatSync(value);if(!stat.isDirectory()||stat.isSymbolicLink())throw Error('EXECUTION_SCRATCH_LINK_REJECTED');
 for(let dir=path.resolve(value);path.dirname(dir)!==dir;dir=path.dirname(dir))if(fs.lstatSync(dir).isSymbolicLink())throw Error('EXECUTION_SCRATCH_LINK_REJECTED');
 const root=fs.realpathSync(value),marker=path.join(root,'ci-owned-marker'),m=fs.lstatSync(marker);
 if(!m.isFile()||m.isSymbolicLink()||m.nlink!==1||read(marker,128).toString()!=='GAME_WINDOWS_CI_V1')throw Error('EXECUTION_SCRATCH_MARKER_INVALID');
 return root;
}
function Remove(root){
 const owned=OwnedRoot(root),walk=[owned];let count=0;
 while(walk.length){for(const item of fs.readdirSync(walk.pop(),{withFileTypes:true})){if(++count>100000)throw Error('EXECUTION_SCRATCH_ENTRY_LIMIT');const file=path.join(item.parentPath||item.path,item.name),s=fs.lstatSync(file);if(s.isSymbolicLink())throw Error('EXECUTION_SCRATCH_LINK_REJECTED');if(s.isDirectory())walk.push(file);else if(!s.isFile())throw Error('EXECUTION_SCRATCH_SPECIAL_FILE_REJECTED');else if(s.nlink!==1)throw Error('EXECUTION_SCRATCH_HARDLINK_REJECTED');}}
 fs.rmSync(owned,{recursive:true,force:false,maxRetries:3,retryDelay:100});
 if(fs.existsSync(owned))throw Error('EXECUTION_SCRATCH_CLEANUP_FAILED');
}
function Publish(run,privateRoot,pending,output){
 const roots=[OwnedRoot(run),...(privateRoot===null?[]:[OwnedRoot(privateRoot)])],created=[],buffers=[];
 if(roots.some(root=>norm(process.cwd())===norm(root)||inside(process.cwd(),root)))throw Error('EXECUTION_SCRATCH_WORKING_DIRECTORY');
 if(roots.length===2&&(norm(roots[0])===norm(roots[1])||inside(roots[0],roots[1])||inside(roots[1],roots[0])))throw Error('EXECUTION_SCRATCH_OVERLAP');
 if(!path.isAbsolute(output)||roots.some(root=>norm(output)===norm(root)||inside(output,root))||!inside(pending,roots[0]))throw Error('EXECUTION_PUBLIC_PATH_INVALID');
 if(fs.existsSync(output))throw Error('EXECUTION_PUBLIC_RESULT_EXISTS');
 const main=read(pending),value=JSON.parse(main.toString('utf8').replace(/^\uFEFF/,''));buffers.push(main);
 const files=[];
 for(const [field,suffix]of [['leaseEvidenceFile','-lease-evidence.json'],['publicVerificationFile','-verification.json'],['leaseVerificationFile','-lease-verification.json']])if(value[field]){
  const target=path.join(path.dirname(output),path.basename(output,'.json')+suffix),source=path.join(path.dirname(pending),path.basename(pending,'.json')+suffix);
  if(norm(value[field])!==norm(target)||fs.existsSync(target))throw Error('EXECUTION_PUBLIC_RESULT_EXISTS');
  const bytes=read(source);buffers.push(bytes);files.push({target,bytes});
 }
 files.push({target:output,bytes:main});
 try{
  // Read and hash final inputs first, stop every owned job, then remove all
  // private copies and logs before exposing any PASS or verification record.
  let failure;for(const root of roots.reverse())try{Remove(root);}catch(e){failure=e;}
  if(failure)throw Error('EXECUTION_SCRATCH_CLEANUP_FAILED');
  for(const file of files){const fd=fs.openSync(file.target,'wx',0o600);created.push(file.target);try{fs.writeFileSync(fd,file.bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
  return {outcome:value.outcome,privateScratchRemoved:true};
 }catch(e){let cleanupFailed=false;for(const file of created.reverse())try{fs.unlinkSync(file);}catch(_){cleanupFailed=true;}if(cleanupFailed)throw Error('EXECUTION_PUBLICATION_CLEANUP_FAILED');throw e;}
 finally{for(const bytes of buffers)bytes.fill(0);}
}
function Failure(output,kind,reason){
 if(!path.isAbsolute(output)||!['PRODUCT_FAULT_EXECUTION','MANUAL_EXECUTION'].includes(kind)||!/^[-A-Z0-9_]{1,100}$/.test(reason))throw Error('EXECUTION_FAILURE_ARGUMENTS_INVALID');
 const value={version:1,kind,outcome:'FAIL',reason,nativeBuild:'NOT_RUN',ciEvidenceCreated:false,hardwareAttested:false,publicationApproval:false};
 fs.writeFileSync(output,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});return value;
}
if(require.main===module){try{const [action,...args]=process.argv.slice(2);if(action==='publish'&&args.length===4)console.log(JSON.stringify(Publish(...args)));else if(action==='publish-one'&&args.length===3)console.log(JSON.stringify(Publish(args[0],null,args[1],args[2])));else if(action==='failure'&&args.length===3)Failure(...args);else if(action==='cleanup'&&args.length===1){if(fs.existsSync(args[0]))Remove(args[0]);}else throw Error('EXECUTION_SCRATCH_ARGUMENTS_INVALID');}catch(e){console.error(/^[A-Z0-9_]+$/.test(e.message)?e.message:'EXECUTION_SCRATCH_OPERATION_FAILED');process.exitCode=1;}}
module.exports={OwnedRoot,Remove,Publish,Failure};
