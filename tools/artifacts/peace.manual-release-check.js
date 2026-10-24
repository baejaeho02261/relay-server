'use strict';

// Offline file inspection only. Never executes A/B/O, initializes server state,
// loads private keys, signs evidence or modifies an existing input.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),readline=require('node:readline');
const ROLES=['A','B','O'],MAX_EXE=64*1024*1024,MAX_SOURCE_TOTAL=512*1024*1024;
const hash=b=>crypto.createHash('sha512').update(b).digest('hex');
const locations=home=>require('./peace.release-tools').locations(home);
function fail(code,file,action){const e=Error(code);Object.assign(e,{safeCode:code,file:file||'',action:action||'Review the named input and retry this inspection.'});throw e;}
function read(file,max,allowEmpty=false){
 let fd;const same=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs;
 try{
  const named=fs.lstatSync(file);if(!named.isFile()||named.isSymbolicLink()||named.nlink!==1||named.size<(allowEmpty?0:1)||named.size>max)fail('MANUAL_INPUT_SIZE_OR_TYPE',file);
  fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const start=fs.fstatSync(fd);
  if(!same(named,start)||start.nlink!==1)fail('MANUAL_INPUT_CHANGED',file);
  // Bound allocation and every read even if another process grows the file.
  const bytes=Buffer.alloc(start.size+1);let total=0;
  while(total<bytes.length){const n=fs.readSync(fd,bytes,total,Math.min(1024*1024,bytes.length-total),total);if(!n)break;total+=n;}
  const end=fs.fstatSync(fd),current=fs.lstatSync(file);
  if(total!==start.size||!same(start,end)||!same(end,current)||!current.isFile()||current.isSymbolicLink()||current.nlink!==1)fail('MANUAL_INPUT_CHANGED',file);
  return bytes.subarray(0,total);
 }catch(e){if(e.code==='ENOENT'||e.code==='ENOTDIR')fail('MANUAL_INPUT_MISSING',file,'Restore this exact matching package file, or select the actual existing input.');throw e;}finally{if(fd!==undefined)fs.closeSync(fd);}
}
function json(file,max=65536){const b=read(file,max);if(b.includes(Buffer.from('PRIVATE KEY')))fail('MANUAL_PRIVATE_KEY_NOT_ALLOWED',file,'Select public approval/policy JSON only. Do not select a private PEM file.');try{return require("../../services/protocol/peace.strict-json").Parse(b.subarray(b[0]===239&&b[1]===187&&b[2]===191?3:0),{maxBytes:max,maxNodes:4000000});}catch(e){if(e.safeCode)throw e;fail('MANUAL_JSON_INVALID',file,'Use the complete JSON produced/exported by the matching tool; do not edit signatures.');}}
function sourcePath(root,file){
 const relative=path.relative(root,file);if(!relative||relative.startsWith('..'+path.sep)||relative==='..'||path.isAbsolute(relative))fail('MANUAL_SOURCE_PATH_INVALID',file);
 let current=root;const parts=relative.split(path.sep);
 for(let i=-1;i<parts.length;i++){
  if(i>=0)current=path.join(current,parts[i]);let entry;try{entry=fs.lstatSync(current);}catch(e){if(e.code==='ENOENT'||e.code==='ENOTDIR')fail('MANUAL_SOURCE_FILE_MISSING',current,'Restore the complete matching source package. Do not remove its manifest entry.');throw e;}
  if(entry.isSymbolicLink())fail('MANUAL_SOURCE_LINK_NOT_ALLOWED',current,'Use regular files/directories inside the complete package, without symlinks or junctions.');
  if(i<parts.length-1?!entry.isDirectory():!entry.isFile()||entry.nlink!==1)fail('MANUAL_SOURCE_FILE_INVALID',current);
 }
 const actual=path.relative(fs.realpathSync(root),fs.realpathSync(file));if(actual==='..'||actual.startsWith('..'+path.sep)||path.isAbsolute(actual))fail('MANUAL_SOURCE_PATH_INVALID',file);
}
function inventory(home,watched=new Map()){
 const layout=locations(home),root=path.dirname(layout.native),metadata=layout.canonicalSource;sourcePath(root,metadata);
 const record=read(metadata,8*1024*1024);let m;try{m=require("../../services/protocol/peace.strict-json").Parse(record,{maxBytes:8*1024*1024,maxNodes:100000});}catch(_){fail('MANUAL_SOURCE_METADATA_INVALID',metadata);}
 if(m.version!==2||m.algorithm!=='sha512'||!m.files||Array.isArray(m.files)||Object.getPrototypeOf(m.files)!==Object.prototype||Object.keys(m.files).length<1||Object.keys(m.files).length>10000)fail('MANUAL_SOURCE_METADATA_INVALID',metadata);
 watched.set(metadata,{sha512:hash(record),max:8*1024*1024,sourceRoot:root});
 let references=0,total=0;const js=[],names=new Set();
 for(const [name,expected]of Object.entries(m.files)){
  const parts=name.split('/');
  if(/[\x00-\x1f\x7f\\:*?"<>|]/.test(name)||path.isAbsolute(name)||parts.some(s=>!s||s==='.'||s==='..'||/[. ]$/.test(s)||/^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/i.test(s)))fail('MANUAL_SOURCE_PATH_INVALID',metadata);
  if(names.has(name.toLowerCase()))fail('MANUAL_SOURCE_PATH_DUPLICATE',metadata);names.add(name.toLowerCase());
  if(typeof expected!=='string'||!/^[a-f0-9]{128}$/.test(expected))fail('MANUAL_SOURCE_METADATA_INVALID',metadata);
  const file=path.join(root,name);sourcePath(root,file);const size=fs.lstatSync(file).size;
  if(size>MAX_EXE||total+size>MAX_SOURCE_TOTAL)fail('MANUAL_SOURCE_SIZE_LIMIT',file);total+=size;
  const bytes=read(file,MAX_EXE,true);sourcePath(root,file);
  if(hash(bytes)!==expected)fail('MANUAL_SOURCE_HASH_MISMATCH',file,'This source differs from the recorded package. Restore the matching source, or review the intentional change and obtain a new reviewed source record/release manifest. This tool never updates the baseline.');
  watched.set(file,{sha512:expected,max:MAX_EXE,allowEmpty:true,sourceRoot:root});
  if(name.endsWith('.js'))js.push([file,bytes]);
 }
 // Resolve literal local requires without executing any production module.
 for(const [file,bytes]of js){const text=bytes.toString('utf8'),module=require('node:module'),resolve=module.createRequire(file).resolve;try{new (require('node:vm').Script)(module.wrap(text.replace(/^#![^\r\n]*/,'')),{filename:file});}catch(_){fail('MANUAL_JAVASCRIPT_SYNTAX',file,'Restore the complete matching source file. This check compiled its syntax without executing it.');}for(const match of text.matchAll(/\brequire\(\s*['"](\.{1,2}\/[^'"\r\n]+)['"]\s*\)/g)){try{const resolved=resolve(match[1]);if(!fs.statSync(resolved).isFile())throw Error('not a file');sourcePath(root,resolved);references++;}catch(e){if(e.safeCode)throw e;fail('MANUAL_LOCAL_MODULE_MISSING',file+' -> '+match[1],'Restore the referenced JS/JSON from the matching full package. npm install does not restore local source files.');}}}
 return {files:Object.keys(m.files).length,bytes:total,javascriptFiles:js.length,javascriptSyntaxChecked:true,literalLocalReferences:references,sourceHashesCompared:true,sourceManifestSha512:hash(record),coverage:'LISTED_PACKAGE_FILES',unlistedFilesVerified:false,baselineAuthenticity:'NOT_ATTESTED',compiledSourceProvenance:'NOT_PROVEN_BY_MANUAL_INSPECTION'};
}
function debugCheck(bytes,file){
 if(require("../../services/artifacts/peace.pe-build-configuration").HasProductFaultMarker(bytes))fail('SECURITY_TEST_BUILD_NOT_PUBLISHABLE',file,'Select a normal final Release build, not a dedicated fault-test executable.');
 const actual=require("../../services/artifacts/peace.pe-build-configuration").ReadBuildConfiguration(bytes);
 if(actual.configuration==='DEBUG')fail('MANUAL_DEBUG_ARTIFACT',file,'Rebuild Win64 Release in the IDE and select the new final EXE. Renaming a Debug file does not change its build marker.');
 if(actual.configuration!=='RELEASE')fail('MANUAL_BUILD_CONFIGURATION_UNVERIFIED',file,'This older/unmarked EXE cannot prove the declared build configuration. Rebuild with the current project and choose Win64 Release.');
 const pe=bytes.readUInt32LE(60),opt=pe+24,dirs=bytes.readUInt32LE(opt+108);
 if(dirs>6&&(bytes.readUInt32LE(opt+160)!==0||bytes.readUInt32LE(opt+164)!==0))fail('MANUAL_DEBUG_DIRECTORY_PRESENT',file,'Use the project Win64 Release configuration with debug information disabled; reapprove final bytes after rebuilding.');
 return {...actual,debugDirectory:false,compilerOptimizationProven:false};
}
function versionAtLeast(value,floor){const a=value.split('.').map(Number),b=floor.split('.').map(Number);for(let i=0;i<Math.max(a.length,b.length);i++){if((a[i]||0)!==(b[i]||0))return (a[i]||0)>(b[i]||0);}return true;}
function buildInputs(home,watched,bds=process.env.BDS){
 const file=path.join(home,'reviewed-build-inputs.json');
 if(!bds||!path.isAbsolute(bds))fail('MANUAL_BUILD_INPUT_BDS_REQUIRED',file,'Set BDS to the actual classic Win64 RAD Studio installation, or omit /verify-build-inputs and leave compiler inputs explicitly unverified.');
 const bytes=read(file,32*1024*1024);let expected;const lock=require("../../ci/toolchain/peace.build-input-lock");
 try{expected=lock.validate(require("../../services/protocol/peace.strict-json").Parse(bytes,{maxBytes:32*1024*1024,maxNodes:1000000}));if(!Object.keys(expected.files).length)throw Error('CI_BUILD_LOCK_EMPTY');}
 catch(_){fail('MANUAL_REVIEWED_BUILD_INPUTS_INVALID',file,'Use the existing independently reviewed build-input record. No record is generated or approved by this inspection.');}
 let observed,verified;
 try{const layout=locations(home);observed=lock.collect(layout.native,path.dirname(path.dirname(layout.canonicalSource)),bds);verified=lock.verify(expected,observed);}
 catch(e){fail('MANUAL_BUILD_INPUTS_MISMATCH',file,'Current compiler/SDK/RTL/cozy.bridge/runtime bytes could not be matched to the reviewed record ('+(/^CI_[A-Z_]+$/.test(e.message)?e.message:'INPUT_READ_FAILED')+'). Restore the reviewed inputs, or independently review intentional changes before creating a replacement record.');}
 watched.set(file,{sha512:hash(bytes),max:32*1024*1024});
 return {status:'CURRENT_FILES_MATCH_REVIEWED_RECORD',observedAt:new Date().toISOString(),files:verified.files,inputSha512:verified.inputSha512,sdkHeaderSha512:verified.sdkHeaderSha512,storedObservationUsed:false,compilerAuthenticity:'NOT_ATTESTED',compiledInputCausality:'NOT_PROVEN',ciEvidence:false};
}
function inspect(home,selections,{preManifest=false,verifyBuildInputs=false,bds=process.env.BDS}={}){
 const result={version:1,kind:'MANUAL_RELEASE_FILE_INSPECTION',checkedAt:new Date().toISOString(),phase:preManifest?'APPROVALS_BEFORE_MANIFEST':'FINAL_MANIFEST',outcome:'FAIL',windowsExecuted:false,ciEvidence:false,serverContacted:false,serverPublicationApproved:false,hardwareAttested:false,steps:[],artifacts:{}};
 let stage='source-hashes-and-references',currentFile='';
 const watched=new Map(),capture=(file,max)=>{const b=read(file,max),digest=hash(b),previous=watched.get(file);if(previous&&previous.sha512!==digest)fail('MANUAL_INPUT_CHANGED',file,'A previously measured input changed during inspection. Finish edits before retrying.');watched.set(file,{...previous,sha512:digest,max});return b;};
 try{
  result.source=inventory(home,watched);result.steps.push({stage,outcome:'PASS'});
  stage='reviewed-build-inputs';result.buildInputs=verifyBuildInputs?buildInputs(home,watched,bds):{status:'NOT_CHECKED',reason:'OPTIONAL_CURRENT_INPUT_COMPARISON_NOT_REQUESTED',compilerAuthenticity:'NOT_ATTESTED',compiledInputCausality:'NOT_PROVEN'};result.steps.push({stage,outcome:verifyBuildInputs?'PASS':'NOT_RUN'});
  stage='spec-and-policy';const specPath=path.join(home,'spec.json'),policyPath=path.join(home,'deployment-policy.json');capture(specPath,65536);capture(policyPath,65536);
  const spec=require('./peace.release-tools').validateSpec(json(specPath)),policy=json(policyPath);
  if(!/^\d{1,9}(?:\.\d{1,9}){0,3}$/.test(spec.releaseName))fail('MANUAL_RELEASE_VERSION_INVALID',specPath,'Use the numeric version entered for all A/B/O approvals.');
  if(policy.version!==1||!Number.isSafeInteger(policy.revision)||policy.revision<0||typeof policy.requireReleaseSignature!=='boolean'||!Array.isArray(policy.trustedReleaseKeys)||!policy.trustedReleaseKeys.length||!Array.isArray(policy.revokedSha512))fail('MANUAL_POLICY_INVALID',policyPath,'Export the current server deployment policy with the EXE approval public key registered.');
  if(!policy.requireReleaseSignature)fail('MANUAL_SIGNATURE_POLICY_REQUIRED',policyPath,'Keep EXE signature enforcement enabled on the server, then export its current policy.');
  result.releaseVersion=spec.releaseName;result.policyRevision=policy.revision;result.steps.push({stage,outcome:'PASS'});
  if(!Array.isArray(selections)||selections.length!==3)fail('MANUAL_SELECTION_REQUIRED','', 'Select one EXE and its approval JSON for each A, B and O.');
  const seen=new Set(),integrity=require("../../services/integrity/peace.desktop-integrity"),p=require("../../services/artifacts/peace.desktop-release-provenance");
  for(let i=0;i<3;i++){
   const role=ROLES[i];stage=role+'-approval-and-final-bytes';const exe=path.resolve(selections[i].exe),approvalFile=path.resolve(selections[i].approval);currentFile=exe;
   if(path.extname(exe).toLowerCase()!=='.exe'||path.extname(approvalFile).toLowerCase()!=='.json')fail('MANUAL_FILE_SELECTION_INVALID',exe,'Select .exe and matching .approval.json, not a private key.');
   const real=fs.realpathSync(exe),key=process.platform==='win32'?real.toLowerCase():real;if(seen.has(key))fail('MANUAL_DUPLICATE_ARTIFACT',exe);seen.add(key);
   const bytes=capture(exe,MAX_EXE);capture(approvalFile,65536);const a=json(approvalFile),sha512=hash(bytes),code=integrity.CodeImage(bytes),cap=require("../../services/artifacts/peace.pe-capabilities").PeCapabilities(bytes);
   if(cap.cfg.status==='INVALID')fail('MANUAL_PE_CFG_INVALID',exe,'Use a valid final Release EXE; do not edit PE metadata after signing.');
   const build=debugCheck(bytes,exe);
   if(a.component!==role||a.version!==spec.releaseName)fail('MANUAL_APPROVAL_ROLE_VERSION_MISMATCH',approvalFile,'Select the matching role/version approval, or generate a new approval for this final EXE.');
   if(a.sha512!==sha512)fail('MANUAL_APPROVAL_HASH_MISMATCH',exe,'Run Create_Approval and Check_Approval for the changed final EXE, then create a new manifest.');
   const record=policy.trustedReleaseKeys.find(k=>k.keyId===a.approval?.keyId);
   if(!record||a.trustedKey?.keyId!==record.keyId)fail('MANUAL_APPROVAL_SIGNER_NOT_TRUSTED',approvalFile,'Register the existing EXE approval public key, apply the policy and export current deployment-policy.json.');
   let publicKey;try{publicKey=p.PublicKey(record.publicKey);if(p.KeyId(publicKey)!==record.keyId||p.KeyId(p.PublicKey(a.trustedKey.publicKey))!==record.keyId)throw Error();}catch(_){fail('MANUAL_APPROVAL_PUBLIC_KEY_INVALID',approvalFile);}
   if(typeof a.approval.signature!=='string'||!(/^[A-Za-z0-9+/]{86}==$/.test(a.approval.signature))||!crypto.verify(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,spec.releaseName,sha512].join('\n')),publicKey,Buffer.from(a.approval.signature,'base64')))fail('MANUAL_APPROVAL_SIGNATURE_INVALID',approvalFile,'Select the original complete approval JSON. Never edit its signature or hash.');
   if(policy.revokedSha512.includes(sha512))fail('MANUAL_ARTIFACT_REVOKED',exe,'Use a permitted new release; do not remove server revocation history.');
   const floor=policy['minVersion'+role];if(typeof floor!=='string'||!/^\d{1,9}(?:\.\d{1,9}){0,3}$/.test(floor)||!versionAtLeast(spec.releaseName,floor))fail('MANUAL_ARTIFACT_VERSION_BELOW_POLICY',exe,'Build and approve a version meeting the exported role minimum.');
   if(!cap.authorityVersion)fail('MANUAL_CLIENT_PROTOCOL_UNSUPPORTED',exe,'Build the current matching A/B/O source package.');
   if(policy.requireCfg&&!cap.compiledCfg)fail('MANUAL_CFG_POLICY_UNMET',exe,'The chosen build does not contain the CFG metadata required by this policy.');
   if(role==='O'){const expectedFile=path.join(locations(home).native,'Cozy.Projects','Cozy.Overlay','Cozy.Overlay.manifest');require("../../services/artifacts/peace.pe-manifest").AssertExpected(bytes,capture(expectedFile,65536));}
   result.artifacts[role]={file:exe,approvalFile,sha512,bytes:bytes.length,codeSha512:code.sha512,version:a.version,signerKeyId:record.keyId,build,signatureVerified:true};result.steps.push({stage,outcome:'PASS'});
  }
  if(!preManifest){stage='manifest';const manifestFile=path.join(home,'release-manifest.json');currentFile=manifestFile;capture(manifestFile,65536);capture(path.join(home,'source-manifest.json'),8*1024*1024);capture(locations(home).canonicalSource,8*1024*1024);try{result.manifestId=require('./peace.release-tools').checkManifest(home,selections.map(s=>s.exe)).manifestId;}catch(e){if(/^Manifest no longer matches:/.test(e.message))fail('MANUAL_MANIFEST_MISMATCH',manifestFile,'This manifest does not match the final EXEs/spec/current policy/source record. Archive it and create a new manifest after approvals.');if(/snapshot was not overwritten/.test(e.message))fail('MANUAL_SOURCE_SNAPSHOT_MISMATCH',path.join(home,'source-manifest.json'),'Archive the previous release source snapshot with its manifest. Create a new manifest using this complete matching package.');throw e;}result.steps.push({stage,outcome:'PASS'});}
  stage='final-input-recheck';for(const [file,expected]of watched){if(expected.sourceRoot)sourcePath(expected.sourceRoot,file);if(hash(read(file,expected.max,expected.allowEmpty))!==expected.sha512)fail('MANUAL_INPUT_CHANGED',file,'An input changed during inspection. Finish builds/approvals before retrying.');if(expected.sourceRoot)sourcePath(expected.sourceRoot,file);}result.steps.push({stage,outcome:'PASS'});result.outcome='PASS';
 }catch(e){const missing=e.code==='ENOENT'||e.code==='ENOTDIR';result.error={stage,code:e.safeCode||(/^[A-Z][A-Z0-9_]{1,100}$/.test(e.message||'')?e.message:missing?'MANUAL_INPUT_MISSING':'MANUAL_CHECK_FAILED'),file:e.file||e.path||currentFile,action:e.action||(missing?'Restore/select the missing file.':stage==='manifest'?'Finish approvals and export current policy, then generate a new matching manifest.':'Review this input and use the exact current package/final EXE.')};result.steps.push({stage,outcome:'FAIL'});}
 return result;
}
async function prompt(home){const rl=readline.createInterface({input:process.stdin,crlfDelay:Infinity}),lines=rl[Symbol.asyncIterator](),rows=[];try{for(const role of ROLES){const row={};for(const [name,label]of [['exe','final Release EXE'],['approval','matching approval JSON']]){process.stdout.write(role+' '+label+' full path: ');const line=await lines.next();if(line.done)fail('MANUAL_CANCELLED');row[name]=line.value.trim().replace(/^"(.*)"$/,'$1');if(!row[name])fail('MANUAL_SELECTION_REQUIRED');}rows.push(row);}return rows;}finally{rl.close();}}
async function main(args,home=__dirname){let preManifest=false,verifyBuildInputs=false;while(['--pre-manifest','/pre-manifest','--verify-build-inputs','/verify-build-inputs'].includes(args[0])){if(args[0].endsWith('pre-manifest'))preManifest=true;else verifyBuildInputs=true;args=args.slice(1);}if(args.length!==0&&args.length!==6)fail('MANUAL_ARGUMENT_INVALID','','Usage: Check_Manual_Release.bat [/pre-manifest] [/verify-build-inputs] [A.exe A.approval.json B.exe B.approval.json O.exe O.approval.json]');
 console.log('Read-only manual release inspection. No CI, compiler execution, private key or server mutation.');console.log('Source checks: SHA-512 of every listed package file, JS syntax and literal local references. No automatic baseline updates. Baseline authenticity and actual IDE compiled-source provenance are NOT attested.');console.log('Release outputs: '+['Cozy.Launcher','Cozy.Client','Cozy.Overlay'].map(project=>path.join(locations(home).native,'Cozy.Projects',project,project+'.exe')).join('; '));
 const rows=args.length?ROLES.map((_,i)=>({exe:args[i*2],approval:args[i*2+1]})):await prompt(home),result=inspect(home,rows,{preManifest,verifyBuildInputs});
 const file=path.join(home,'manual-release-check-'+new Date().toISOString().replace(/[:.]/g,'-')+'-'+crypto.randomBytes(4).toString('hex')+'.json');fs.writeFileSync(file,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
 for(const step of result.steps)console.log(step.outcome+': '+step.stage);if(result.error){console.error('ERROR: '+result.error.code+'\nFile: '+result.error.file+'\nAction: '+result.error.action);process.exitCode=1;}
 console.log('Result JSON: '+file);console.log(result.outcome==='PASS'?(preManifest?'Final approvals match. Next: Create_Release_Manifest, then Check_Manual_Release without /pre-manifest.':'Final files/approvals/manifest match. Server still validates registration, policy and permission before publication.'):'No successful inspection or server approval is claimed.');console.log('Windows execution / CI / hardware attestation: NOT_RUN.');return result;
}
if(require.main===module)main(process.argv.slice(2)).catch(e=>{console.error('ERROR: '+(e.safeCode||'MANUAL_CHECK_FAILED')+'\n'+(e.action||'Review the selected public files.'));process.exitCode=1;});
module.exports={inspect,inventory,debugCheck,main,buildInputs,read,sourcePath};
