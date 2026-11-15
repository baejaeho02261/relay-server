'use strict';
// Optional offline source/artifact archive. Never executes EXEs or issues approval.
// Mandatory checklist generation and report assembly are not provided.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const safety=require("../../services/artifacts/peace.desktop-release-safety"),provenance=require("../../services/artifacts/peace.desktop-release-provenance");
const io=require("../../services/artifacts/peace.bounded-artifact-read");
const hash=x=>crypto.createHash('sha512').update(x).digest('hex');
function Read(file,max=131072){return io.Read(file,max);}
function Json(file,max=131072){const b=Read(file,max),bom=b.subarray(0,3).equals(Buffer.from([239,187,191]));return require("../../services/protocol/peace.strict-json").Parse(bom?b.subarray(3):b,{maxBytes:max,maxNodes:200000});}
function Write(file,value){const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,typeof value==='string'?value:JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Manifest(file){const m=Json(file);if(!m||Object.keys(m).sort().join(',')!=='manifest,manifestId'||m.manifestId!==provenance.ManifestId(m.manifest))throw Error('MANIFEST_INVALID');return m;}
function Inputs(manifestFile,sourceFile,policyFile,a,b,o){const entry=Manifest(manifestFile),source=Read(sourceFile,8*1024*1024),policy=Json(policyFile),bytes={};try{if(hash(source)!==entry.manifest.sourceManifestSha512||provenance.PolicyDigest(policy)!==entry.manifest.policySha512)throw Error('SOURCE_OR_POLICY_MISMATCH');for(const [role,file]of [['A',a],['B',b],['O',o]]){bytes[role]=Read(file,64*1024*1024);if(hash(bytes[role])!==entry.manifest.artifacts[role])throw Error('FINAL_'+role+'_CHANGED');}return {entry,source,policy,bytes};}catch(e){Object.values(bytes).forEach(x=>x.fill(0));throw e;}}
function SafeSource(root,rel){if(typeof rel!=='string'||!rel||rel.includes('\\')||rel.includes(':')||rel.startsWith('/')||rel.split('/').some(x=>!x||x==='.'||x==='..'))throw Error('SOURCE_PATH_INVALID');let p=path.resolve(root);for(const part of rel.split('/')){p=path.join(p,part);if(fs.lstatSync(p).isSymbolicLink())throw Error('SOURCE_LINK_FORBIDDEN');}return p;}
function Freeze(root,manifestFile,policyFile,a,b,o,destination){const sourceFile=path.resolve(root,'Relay Server/maintenance/source-manifest.json'),v=Inputs(manifestFile,sourceFile,policyFile,a,b,o);let created=false;try{const index=require("../../services/protocol/peace.strict-json").Parse(v.source,{maxBytes:8*1024*1024,maxNodes:200000});if(index.version!==2||index.algorithm!=='sha512'||!index.files||Object.keys(index.files).length>20000)throw Error('SOURCE_MANIFEST_INVALID');fs.mkdirSync(destination,{recursive:false,mode:0o700});created=true;for(const [rel,digest]of Object.entries(index.files)){if(!/^[a-f0-9]{128}$/.test(digest))throw Error('SOURCE_MANIFEST_INVALID');const data=Read(SafeSource(root,rel),64*1024*1024);if(hash(data)!==digest)throw Error('SOURCE_FILE_CHANGED');const target=path.join(destination,'source',...rel.split('/'));fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o700});fs.writeFileSync(target,data,{flag:'wx',mode:0o600});data.fill(0);}fs.mkdirSync(path.join(destination,'artifacts'),{mode:0o700});for(const role of safety.ROLES)fs.writeFileSync(path.join(destination,'artifacts',role+'.exe'),v.bytes[role],{flag:'wx',mode:0o600});Write(path.join(destination,'release-manifest.json'),v.entry);fs.writeFileSync(path.join(destination,'source-manifest.json'),v.source,{flag:'wx',mode:0o600});Write(path.join(destination,'policy.json'),v.policy);const receipt={version:1,kind:'FROZEN_RELEASE_INPUTS',manifestId:v.entry.manifestId,sourceManifestSha512:hash(v.source),policySha512:provenance.PolicyDigest(v.policy),artifacts:v.entry.manifest.artifacts,sourceFileCount:Object.keys(index.files).length,capturedAt:Date.now(),testExecution:'NOT_PERFORMED',privateKeysRequested:false};Write(path.join(destination,'freeze-receipt.json'),receipt);return receipt;}catch(e){if(created)fs.rmSync(destination,{recursive:true,force:true});throw e;}finally{Object.values(v.bytes).forEach(x=>x.fill(0));}}
function Evidence(file){return {sha512:hash(Read(file,64*1024*1024)),executionNotInferred:true};}
if(require.main===module)Main(process.argv.slice(2)).then(r=>console.log(JSON.stringify(r,null,2))).catch(e=>{console.error(e.message);process.exitCode=1;});

async function Interactive(){
 const rl=require('node:readline/promises').createInterface({input:process.stdin,output:process.stdout});
 const ask=async q=>(await rl.question(q)).trim().replace(/^"(.*)"$/,'$1');
 try { return Freeze(await ask('Source root: '),await ask('release-manifest.json: '),
   await ask('deployment-policy.json: '),await ask('Final A.exe: '),await ask('Final B.exe: '),
   await ask('Final O.exe: '),await ask('New archive directory (must not exist): ')); }
 finally { rl.close(); }
}
async function Main(args){
 if(args.length===0)return Interactive();
 if(args[0]==='freeze'&&args.length===8)return Freeze(...args.slice(1));
 if(args[0]==='hash'&&args.length===2)return Evidence(args[1]);
 throw Error('Usage: peace.release-snapshot.js [freeze ROOT MANIFEST POLICY A B O NEW_DIRECTORY | hash FILE]');
}
module.exports={Inputs,Freeze,Evidence,Main};
