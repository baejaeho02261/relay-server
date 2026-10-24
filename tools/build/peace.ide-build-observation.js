'use strict';
// Optional local evidence. Hooks are declarations, not an independent witness.
// External Process Monitor data corroborates recorded reads/writes only. A
// separately retained digest detects later edits; neither proves log authenticity.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const strict=require("../../services/protocol/peace.strict-json"),bounded=require("../artifacts/peace.manual-release-check");
const MAX=64*1024*1024,ROLES={A:["Cozy.Launcher",'launcher'],B:["Cozy.Client",'client'],O:["Cozy.Overlay",'overlay']};
const hash=b=>crypto.createHash('sha512').update(b).digest('hex');
const canonical=v=>JSON.stringify(v);
function fail(code){throw Error('IDE_OBSERVATION_'+code);}
function regular(file,max=MAX,empty=false){return bounded.read(file,max,empty);}
function parse(bytes){return strict.Parse(bytes,{maxBytes:32*1024*1024,maxNodes:1000000});}
function json(file){return parse(regular(file,32*1024*1024));}
function safeDirectory(dir){
 const full=path.resolve(dir);let cursor=path.parse(full).root;
 for(const part of path.relative(cursor,full).split(path.sep).filter(Boolean)){cursor=path.join(cursor,part);const s=fs.lstatSync(cursor);if(!s.isDirectory()||s.isSymbolicLink())fail('DIRECTORY_LINK_OR_TYPE');}
 return full;
}
function writeNew(file,bytes){safeDirectory(path.dirname(file));const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function writeJson(file,value){writeNew(file,canonical(value)+'\n');return value;}
function fileRecord(file,max=512*1024*1024){
 safeDirectory(path.dirname(file));const start=fs.lstatSync(file),same=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs;
 if(!start.isFile()||start.isSymbolicLink()||start.nlink!==1||start.size>max)fail('FILE_SIZE_OR_TYPE');
 const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0)),h=crypto.createHash('sha512'),buffer=Buffer.alloc(1024*1024);let total=0;
 try{if(!same(start,fs.fstatSync(fd)))fail('FILE_CHANGED');let n;while((n=fs.readSync(fd,buffer,0,Math.min(buffer.length,start.size-total+1),total))){total+=n;if(total>start.size)fail('FILE_CHANGED');h.update(buffer.subarray(0,n));}if(total!==start.size||!same(start,fs.fstatSync(fd))||!same(start,fs.lstatSync(file)))fail('FILE_CHANGED');return{path:path.resolve(file),bytes:total,sha512:h.digest('hex')};}finally{buffer.fill(0);fs.closeSync(fd);}
}
function key(file){return path.resolve(file).replace(/\\/g,'/').toLowerCase();}
function traceKey(file){return String(file).replace(/\\/g,'/').replace(/\/+$/,'').toLowerCase();}
function environment(){
 // Record exact inherited values only for build-related, nonsecret names. Other
 // values (including tokens/passwords) never leave the process, even as hashes.
 const names=['BDS','BDSCOMMONDIR','FrameworkDir','FrameworkVersion','PATH','LIB','INCLUDE','TEMP','TMP','LANG','LC_ALL','GAME_IMGUI_BCC64'];
 return {source:'HOOK_CHILD_INHERITED_ENVIRONMENT',compilerEnvironmentObserved:false,values:Object.fromEntries(names.filter(n=>process.env[n]!==undefined).map(n=>[n,process.env[n]]))};
}
function roleProject(native,role,extension){if(!ROLES[role])fail('RELEASE_ROLE_REQUIRED');const name=ROLES[role][0];return path.join(native,'Cozy.Projects',name,name+extension);}
const IMGUI_OBJECT='Cozy.BuildOutputs/Cozy.ImGui/Cozy.game_imgui_bridge.o';
function generatedNames(native){return [...Object.keys(ROLES).map(role=>roleProject(native,role,'Resources.res')),path.join(native,...IMGUI_OBJECT.split('/'))];}
function generatedSnapshot(s){const files={};for(const f of generatedNames(s.native))if(fs.existsSync(f))files[key(f)]=fileRecord(f);return{files,sha512:hash(Buffer.from(canonical(files))),scope:'GENERATED_REFERENCES_SNAPSHOTTED_BEFORE_COMPILER_TARGET'};}
function snapshot(native,bds){
 const files={};let total=0,count=0;
 const generated=new Set(generatedNames(native).map(key));
 const extensions=/\.(?:pas|inc|dpr|dproj|groupproj|targets|props|cs|res|rc|manifest|obj|o|a|lib|dcu|dcp|dll|exe|bpl|cfg|rsp|cmds|h|hpp|cpp|c|bat|ps1|json|js)$/i;
 function tree(dir,isNative){safeDirectory(dir);for(const entry of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){
  const file=path.join(dir,entry.name);if(entry.isSymbolicLink()||!entry.isDirectory()&&!entry.isFile())fail('SNAPSHOT_LINK_OR_TYPE');
  if(entry.isDirectory()){if(isNative&&dir===native&&['build','bin','.git'].includes(entry.name.toLowerCase()))continue;tree(file,isNative);}
  else if(extensions.test(entry.name)&&!generated.has(key(file))){if(++count>100000)fail('SNAPSHOT_FILE_LIMIT');const record=fileRecord(file);total+=record.bytes;if(total>32*1024**3)fail('SNAPSHOT_BYTE_LIMIT');const k=key(file);if(files[k])fail('SNAPSHOT_CASE_COLLISION');files[k]=record;}
 }}
 tree(native,true);for(const dir of ['bin',...(fs.existsSync(path.join(bds,'bin64'))?['bin64']:[]),'include',path.join('lib','win64','release')])tree(path.join(bds,dir),false);
 const ordered=Object.fromEntries(Object.keys(files).sort().map(k=>[k,files[k]]));
 return{files:ordered,count,totalBytes:total,sha512:hash(Buffer.from(canonical(ordered))),scope:'CANDIDATE_SOURCE_AND_REFERENCE_FILES_NOT_OBSERVED_CONSUMPTION'};
}
function prepare(native,bds,run){
 if(process.platform!=='win32')fail('WINDOWS_NOT_RUN');
 native=safeDirectory(native);bds=safeDirectory(bds);run=path.resolve(run);
 for(const root of [native,bds]){const relative=path.relative(root,run);if(!path.isAbsolute(relative)&&relative!=='..'&&!relative.startsWith('..'+path.sep))fail('RUN_MUST_BE_OUTSIDE_SOURCE');}
 safeDirectory(path.dirname(run));fs.mkdirSync(run);const inputs=snapshot(native,bds);
 return writeJson(path.join(run,'session.json'),{version:1,kind:'IDE_BUILD_OBSERVATION_SESSION',id:crypto.randomBytes(24).toString('hex'),createdAt:new Date().toISOString(),native,bds,inputs,tool:fileRecord(__filename),runtime:fileRecord(process.execPath),independentAttestation:false,windowsBuildExecuted:false});
}
function session(run){safeDirectory(run);const s=json(path.join(run,'session.json'));if(s.version!==1||s.kind!=='IDE_BUILD_OBSERVATION_SESSION'||!/^[0-9a-f]{48}$/.test(s.id)||!s.inputs?.files||s.inputs.sha512!==hash(Buffer.from(canonical(s.inputs.files))))fail('SESSION_INVALID');safeDirectory(s.native);safeDirectory(s.bds);return s;}
function recheck(s){const now=snapshot(s.native,s.bds);if(now.sha512!==s.inputs.sha512)fail('INPUTS_CHANGED');return now;}
function stagePath(s,role,config){if(!ROLES[role]||config!=='Release')fail('RELEASE_ROLE_REQUIRED');return path.join(s.native,'build','stage',ROLES[role][1],'Win64',config,ROLES[role][0]+'.exe');}
function marker(run,role,phase,id){const file=path.join(run,role+'-'+phase+'-'+id+'.marker');writeNew(file,Buffer.from(id+'\n'));regular(file,1024);return file;}
function before(run,role,config,properties){
 const s=session(run),staged=stagePath(s,role,config);recheck(s);safeDirectory(path.dirname(staged));
 if(fs.existsSync(path.join(run,role+'-before.json')))fail('ROLE_ALREADY_USED');
 // Only a generated, isolation-validated role path is ever removed. A failed
 // build cannot inherit last week's EXE, including trial dcc exit=0/no-output.
 if(fs.existsSync(staged)){regular(staged);fs.unlinkSync(staged);}
 const values=typeof properties==='string'?json(properties):properties;
 if(!values||key(values.project||'')!==key(roleProject(s.native,role,'.dproj'))||values.configuration!==config||values.platform!=='Win64')fail('EVALUATED_PROJECT_MISMATCH');
 if(fileRecord(process.execPath).sha512!==s.runtime.sha512||fileRecord(__filename).sha512!==s.tool.sha512)fail('OBSERVER_CHANGED');
 const receipt={version:1,kind:'IDE_BEFORE_HOOK_DECLARATION',sessionSha512:hash(regular(path.join(run,'session.json'))),sessionId:s.id,role,configuration:config,staged,pid:process.pid,time:new Date().toISOString(),properties:values,environment:environment(),inputsSha512:s.inputs.sha512,source:'MSBUILD_EVALUATED_PROPERTIES_NOT_COMPILER_ARGUMENTS',independentAttestation:false};
 receipt.marker=marker(run,role,'before',s.id);return writeJson(path.join(run,role+'-before.json'),receipt);
}
function ready(run,role,config,properties){
 const s=session(run),b=json(path.join(run,role+'-before.json'));if(b.role!==role||b.configuration!==config||b.sessionId!==s.id)fail('BEFORE_INVALID');recheck(s);
 const values=typeof properties==='string'?json(properties):properties;if(!values||key(values.project||'')!==key(roleProject(s.native,role,'.dproj'))||values.configuration!==config||values.platform!=='Win64')fail('EVALUATED_PROJECT_MISMATCH');
 const generated=generatedSnapshot(s),required=[roleProject(s.native,role,'Resources.res'),...(role==='O'?[path.join(s.native,...IMGUI_OBJECT.split('/'))]:[])];
 for(const file of required)if(!generated.files[key(file)])fail('GENERATED_REFERENCE_MISSING');
 const result={version:1,kind:'IDE_BEFORE_COMPILER_HOOK_DECLARATION',sessionId:s.id,role,pid:process.pid,time:new Date().toISOString(),beforeSha512:hash(regular(path.join(run,role+'-before.json'))),generated,properties:values,environment:environment(),compilerArgumentsObserved:false,independentAttestation:false};result.marker=marker(run,role,'ready',s.id);return writeJson(path.join(run,role+'-ready.json'),result);
}
function generatedDcus(s,role,config){
 const root=path.join(s.native,'build',role,'Win64',config,'dcu'),files={};if(fs.existsSync(root)){safeDirectory(root);let count=0;const tree=dir=>{for(const e of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(e.isSymbolicLink())fail('GENERATED_DCU_LINK');if(e.isDirectory())tree(file);else if(e.isFile()&&/\.dcu$/i.test(e.name)){if(++count>10000)fail('GENERATED_DCU_LIMIT');files[key(file)]=fileRecord(file);}}};tree(root);}return{root,files,scope:'AFTER_BUILD_HASH_NOT_BYTES_AT_READ'};
}
function pe64(bytes){
 if(bytes.length<512||bytes.readUInt16LE(0)!==0x5a4d)fail('NATIVE_OUTPUT_NOT_PE64');const pe=bytes.readUInt32LE(60);
 if(pe<64||pe+24>bytes.length||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664||bytes.readUInt16LE(pe+24)!==0x20b)fail('NATIVE_OUTPUT_NOT_PE64');return pe;
}
function after(run,role){
 const s=session(run),beforeFile=path.join(run,role+'-before.json'),b=json(beforeFile),readyFile=path.join(run,role+'-ready.json'),r=json(readyFile);if(b.sessionId!==s.id||b.staged!==stagePath(s,role,b.configuration)||r.sessionId!==s.id||r.beforeSha512!==hash(regular(beforeFile)))fail('BEFORE_INVALID');
 if(!fs.existsSync(b.staged))fail('NATIVE_OUTPUT_MISSING');const bytes=regular(b.staged);pe64(bytes);recheck(s);
 if(generatedSnapshot(s).sha512!==r.generated.sha512)fail('GENERATED_REFERENCES_CHANGED');
 const image=path.join(run,role+'-native-output.exe');writeNew(image,bytes);
 const result={version:1,kind:'IDE_AFTER_HOOK_DECLARATION',sessionId:s.id,beforeSha512:hash(regular(beforeFile)),readySha512:hash(regular(readyFile)),role,configuration:b.configuration,pid:process.pid,time:new Date().toISOString(),nativeOutput:{path:image,bytes:bytes.length,sha512:hash(bytes)},captureBoundary:'FIRST_AVAILABLE_POSTBUILD_OR_PUBLISH_HOOK',generatedDcus:generatedDcus(s,role,b.configuration),inputsSha512:s.inputs.sha512,freshStagedOutputRequired:true,compilerExitCode:'NOT_OBSERVED_INTERNAL_IDE',independentAttestation:false};
 result.marker=marker(run,role,'after',s.id);return writeJson(path.join(run,role+'-after.json'),result);
}
// Strict RFC4180-style parsing; accepts UTF-8/UTF-16LE exports, multiline quoted
// command lines and escaped quotes. Bounds precede allocation and row growth.
function csv(bytes){
 if(bytes.length>MAX)fail('TRACE_SIZE');let text=bytes[0]===255&&bytes[1]===254?bytes.subarray(2).toString('utf16le'):bytes.toString('utf8').replace(/^\uFEFF/,'');
 if(text.includes('\0'))fail('TRACE_ENCODING');const rows=[];let row=[],field='',quoted=false,closed=false;
 const pushField=()=>{row.push(field);field='';closed=false;if(row.length>64)fail('TRACE_COLUMNS');};
 const pushRow=()=>{pushField();if(row.some(x=>x!==''))rows.push(row);row=[];if(rows.length>300000)fail('TRACE_ROWS');};
 for(let i=0;i<text.length;i++){const c=text[i];if(quoted){if(c==='"'){if(text[i+1]==='"'){field+='"';i++;}else{quoted=false;closed=true;}}else field+=c;}
  else if(c==='"'){if(field||closed)fail('TRACE_CSV');quoted=true;}
  else if(c===',')pushField();else if(c==='\r'||c==='\n'){if(c==='\r'&&text[i+1]==='\n')i++;pushRow();}
  else{if(closed)fail('TRACE_CSV');field+=c;}if(field.length>65536)fail('TRACE_FIELD_SIZE');
 }
 if(quoted)fail('TRACE_CSV');if(field||row.length||closed)pushRow();if(rows.length<2)fail('TRACE_EMPTY');
 const names=rows.shift();if(new Set(names).size!==names.length)fail('TRACE_COLUMNS');for(const name of ['Process Name','PID','Operation','Path','Result','Detail','Image Path','Command Line'])if(!names.includes(name))fail('TRACE_REQUIRED_COLUMNS');
 return rows.map(r=>{if(r.length!==names.length)fail('TRACE_COLUMNS');return Object.fromEntries(names.map((n,i)=>[n,r[i]]));});
}
function positiveLength(detail){const m=String(detail).match(/(?:^|, )Length: ([\d,]+)(?:, |$)/);if(!m)return false;const size=Number(m[1].replace(/,/g,''));return Number.isSafeInteger(size)&&size>0&&size<=512*1024*1024;}
function corroborate(run,role,traceFile,pid){
 if(!/^[1-9]\d{0,9}$/.test(String(pid)))fail('TRACE_PID');const s=session(run),b=json(path.join(run,role+'-before.json')),r=json(path.join(run,role+'-ready.json')),a=json(path.join(run,role+'-after.json'));
 const trace=regular(traceFile),rows=csv(trace);const markerAt=(marker,hookPid)=>rows.map((r,i)=>({r,i})).filter(({r})=>r.PID===String(hookPid)&&r.Operation==='ReadFile'&&r.Result==='SUCCESS'&&traceKey(r.Path)===traceKey(marker)&&positiveLength(r.Detail));
 const first=markerAt(r.marker,r.pid),last=markerAt(a.marker,a.pid);if(!first.length||!last.length||first[0].i>=last[0].i)fail('TRACE_MARKERS_MISSING_OR_ORDER');
 const start=first[0].i,end=last[0].i,events=rows.slice(start+1,end).filter(r=>r.PID===String(pid)),observed={},outsideImages=new Set(),writes=new Set();let outputWritten=false,mainRead=false,identity=null;
 for(const event of events){
  const image=traceKey(event['Image Path']),processName=String(event['Process Name']).toLowerCase(),command=event['Command Line'];
  if(!['bds.exe','bds64.exe','dcc64.exe'].includes(processName)||!['bin','bin64'].some(dir=>image===traceKey(path.join(s.bds,dir,processName)))||!command)fail('TRACE_PROCESS_IDENTITY');
  const current={pid:Number(pid),imagePath:event['Image Path'],processName,commandLine:command};if(identity&&canonical(identity)!==canonical(current))fail('TRACE_PID_REUSED');identity=current;
  if(event.Result!=='SUCCESS')continue;
  if(event.Operation==='WriteFile'&&positiveLength(event.Detail)){writes.add(traceKey(event.Path));if(traceKey(event.Path)===traceKey(b.staged))outputWritten=true;}
  if(!['ReadFile','Load Image'].includes(event.Operation)||event.Operation==='ReadFile'&&!positiveLength(event.Detail))continue;
  const k=traceKey(event.Path);if(!/\.(?:pas|inc|dpr|dproj|targets|props|res|rc|manifest|obj|o|a|lib|dcu|dcp|dll|exe|bpl|cfg|rsp|cmds|h|hpp|cpp|c)$/i.test(k))continue;
  const generatedDcu=a.generatedDcus?.files[k],expected=s.inputs.files[k]||r.generated.files[k]||generatedDcu;
  // Windows OS DLL loads remain an explicit outside-snapshot category. Source,
  // object, configuration or RTL reads outside the snapshot always fail closed.
  if(!expected){if(/\.(?:dll|exe)$/i.test(k)&&!k.startsWith(traceKey(s.native)+'/')&&!k.startsWith(traceKey(s.bds)+'/')){outsideImages.add(event.Path);continue;}fail('TRACE_UNSNAPSHOTTED_INPUT');}
  if(generatedDcu&&(!k.startsWith(traceKey(path.join(s.native,'build',role,'Win64',b.configuration,'dcu'))+'/')||!writes.has(k)))fail('TRACE_DCU_READ_WITHOUT_PRIOR_WRITE');
  if(k===traceKey(roleProject(s.native,role,'.dpr'))&&event.Operation==='ReadFile')mainRead=true;
  observed[k]={...expected,operation:event.Operation,inputClass:generatedDcu?'GENERATED_DCU_WITH_PRIOR_RECORDED_WRITE':r.generated.files[k]?'GENERATED_REFERENCE_SNAPSHOTTED_BEFORE_COMPILER':'IMMUTABLE_CANDIDATE',bytesAtRead:'NOT_OBSERVED'};
 }
 if(!mainRead||!outputWritten||!identity)fail('TRACE_BUILD_IO_NOT_CORROBORATED');
 return{version:1,kind:'EXTERNAL_PROCESS_MONITOR_CORROBORATION',trace:fileRecord(traceFile),process:identity,markerRows:{start,end},observedInputs:observed,readOrImageCount:Object.keys(observed).length,outsideSnapshotImages:[...outsideImages].sort(),mainSourceRead:true,stagedOutputWrite:true,rawTraceAuthenticity:'NOT_ATTESTED',traceCompleteness:'NOT_PROVEN',compilerSemanticUse:'NOT_PROVEN',compilerEnvironment:'NOT_OBSERVED',compilerArguments:identity.processName==='dcc64.exe'?'EXTERNAL_PROCESS_COMMAND_LINE':'INTERNAL_IDE_COMPILER_NO_SEPARATE_COMMAND_LINE',source:'EXTERNAL_TRACE_EXPORT_NOT_HOOK_MANIFEST'};
}
function checksum(bytes,offset){let sum=0;for(let i=0;i<bytes.length;i+=2){let word=i>=offset&&i<offset+4?0:bytes[i];if(i+1<bytes.length&&!(i+1>=offset&&i+1<offset+4))word|=bytes[i+1]<<8;sum+=word;sum=(sum&65535)+(sum>>>16);}sum=(sum&65535)+(sum>>>16);return ((sum&65535)+(sum>>>16)+bytes.length)>>>0;}
function normalizedRelation(original,final,role){
 if(original.equals(final))return{kind:'IDENTICAL_BYTES',changed:false};if(role!=='O'||original.length!==final.length)fail('FINAL_BYTES_UNLINKED');
 const pe=pe64(original),opt=pe+24,size=original.readUInt16LE(pe+20),count=original.readUInt16LE(pe+6),table=opt+size;
 if(size<144||opt+size>original.length||count<1||count>96||table+count*40>original.length||original.readUInt32LE(opt+108)<4)fail('NORMALIZATION_PE_INVALID');
 const rva=original.readUInt32LE(opt+136),length=original.readUInt32LE(opt+140);if(!rva||!length||length%12||length>16*1024*1024)fail('NORMALIZATION_PE_INVALID');
 const matches=[];for(let i=0;i<count;i++){const at=table+i*40,start=original.readUInt32LE(at+12),raw=original.readUInt32LE(at+20),span=Math.min(original.readUInt32LE(at+8),original.readUInt32LE(at+16));if(rva>=start&&rva+length<=start+span&&raw+rva-start+length<=original.length)matches.push(raw+rva-start);}
 if(matches.length!==1)fail('NORMALIZATION_PE_INVALID');const at=matches[0],records=[];for(let p=at;p<at+length;p+=12)records.push({begin:original.readUInt32LE(p),end:original.readUInt32LE(p+4),p});records.sort((x,y)=>x.begin-y.begin);
 for(let i=0;i<records.length;i++)if(records[i].end<=records[i].begin||i&&records[i].begin<records[i-1].end)fail('NORMALIZATION_OVERLAP');
 const replay=Buffer.from(original);records.forEach((r,i)=>original.copy(replay,at+i*12,r.p,r.p+12));if(replay.equals(original))fail('FINAL_BYTES_UNLINKED');
 if(original.readUInt32LE(opt+64))replay.writeUInt32LE(checksum(replay,opt+64),opt+64);if(!replay.equals(final))fail('FINAL_BYTES_UNLINKED');
 // Full final release validity remains independently checked by existing PE
 // validators/manual inspection. This relation proves only the exact byte edit.
 return{kind:'EXACT_EXCEPTION_TABLE_SORT_AND_EXISTING_NONZERO_CHECKSUM',changed:true,records:records.length,fullPeValidity:'REQUIRES_EXISTING_RELEASE_INSPECTION'};
}
function approved(role,bytes,approvalFile,policyFile,approvalData,policyData){
 const a=approvalData||json(approvalFile),policy=policyData||json(policyFile),p=require("../../services/artifacts/peace.desktop-release-provenance"),digest=hash(bytes);
 if(a.component!==role||a.sha512!==digest||!/^\d{1,9}(?:\.\d{1,9}){0,3}$/.test(a.version)||policy.requireReleaseSignature!==true||!Array.isArray(policy.trustedReleaseKeys)||!Array.isArray(policy.revokedSha512)||policy.revokedSha512.includes(digest))fail('APPROVAL_BINDING');
 const trusted=policy.trustedReleaseKeys.find(k=>k.keyId===a.approval?.keyId);if(!trusted||a.trustedKey?.keyId!==trusted.keyId)fail('APPROVAL_TRUST');
 const pub=p.PublicKey(trusted.publicKey);if(p.KeyId(pub)!==trusted.keyId||p.KeyId(p.PublicKey(a.trustedKey.publicKey))!==trusted.keyId||typeof a.approval.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(a.approval.signature)||!crypto.verify(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,a.version,digest].join('\n')),pub,Buffer.from(a.approval.signature,'base64')))fail('APPROVAL_SIGNATURE');
 return{version:a.version,keyId:trusted.keyId,signatureVerified:true,policyRevision:policy.revision};
}
function seal(run,role,finalFile,approvalFile,policyFile,traceFile,pid){
 session(run);const names={session:path.join(run,'session.json'),before:path.join(run,role+'-before.json'),ready:path.join(run,role+'-ready.json'),after:path.join(run,role+'-after.json'),nativeOutput:path.join(run,role+'-native-output.exe'),final:finalFile,approval:approvalFile,policy:policyFile,...(traceFile?{trace:traceFile}:{})},files={},contents={};
 for(const [name,file]of Object.entries(names)){const bytes=regular(file);contents[name]=bytes;files[name]={path:path.resolve(file),bytes:bytes.length,sha512:hash(bytes)};}
 const s=parse(contents.session),b=parse(contents.before),a=parse(contents.after),raw=contents.nativeOutput,final=contents.final;
 const r=parse(contents.ready);if(b.sessionSha512!==files.session.sha512||a.beforeSha512!==files.before.sha512||a.readySha512!==files.ready.sha512||r.beforeSha512!==files.before.sha512||r.sessionId!==s.id||b.sessionId!==s.id||a.sessionId!==s.id||a.nativeOutput.sha512!==hash(raw)||a.inputsSha512!==s.inputs.sha512||b.role!==role||a.role!==role||r.role!==role||a.configuration!=='Release'||b.configuration!=='Release')fail('CHAIN_MISMATCH');
 pe64(final);const relation=normalizedRelation(raw,final,role),approval=approved(role,final,approvalFile,policyFile,parse(contents.approval),parse(contents.policy)),trace=traceFile?corroborate(run,role,traceFile,pid):{status:'NOT_RUN',reason:'EXTERNAL_TRACE_NOT_SUPPLIED'};
 const result={version:1,kind:'IDE_FINAL_BYTE_LINK',sessionId:s.id,role,createdAt:new Date().toISOString(),files,relation,approval,trace,independentProvenance:'NOT_PROVEN',windowsExecution:'HOOK_RECEIPTS_REQUIRE_EXTERNAL_CORROBORATION',ciEvidence:false,hardwareAttested:false,anchorRequirement:'RETAIN_SEAL_SHA512_OUTSIDE_BUILD_ACCOUNT_BEFORE_REVIEW'};
 // Recheck every input after parsing/verification; partial records are never a
 // successful seal, and existing records cannot be silently overwritten.
 for(const record of Object.values(result.files))if(fileRecord(record.path).sha512!==record.sha512)fail('CHAIN_INPUT_CHANGED');
 const out=path.join(run,role+'-sealed.json');writeJson(out,result);return{seal:out,sha512:hash(regular(out)),result};
}
function verify(sealFile,expectedDigest,finalFile,approvalFile,policyFile){
 if(!/^[a-f0-9]{128}$/.test(expectedDigest||''))fail('EXTERNAL_DIGEST_REQUIRED');const bytes=regular(sealFile,32*1024*1024);if(hash(bytes)!==expectedDigest)fail('SEAL_DIGEST_MISMATCH');const s=parse(bytes);
 if(s.version!==1||s.kind!=='IDE_FINAL_BYTE_LINK'||!ROLES[s.role]||s.independentProvenance!=='NOT_PROVEN')fail('SEAL_INVALID');
 for(const name of ['session','before','ready','after','nativeOutput','final','approval','policy'])if(!s.files[name]||!/^[a-f0-9]{128}$/.test(s.files[name].sha512))fail('SEAL_INVALID');
 const inputs={};for(const [name,file]of [['final',finalFile],['approval',approvalFile],['policy',policyFile]]){inputs[name]=regular(file);if(hash(inputs[name])!==s.files[name].sha512)fail('SEALED_FILE_MISMATCH');}
 // Retained raw inputs are part of the archive, not optional decoration around
 // an editable summary. Detect later replacement of trace/receipt/output too.
 for(const [name,record]of Object.entries(s.files)){if(['final','approval','policy'].includes(name))continue;inputs[name]=regular(record.path);if(hash(inputs[name])!==record.sha512)fail('SEALED_ARCHIVE_MISMATCH');}
 if(canonical(normalizedRelation(inputs.nativeOutput,inputs.final,s.role))!==canonical(s.relation))fail('SEALED_RELATION_MISMATCH');
 approved(s.role,inputs.final,approvalFile,policyFile,parse(inputs.approval),parse(inputs.policy));
 for(const [name,file]of [['final',finalFile],['approval',approvalFile],['policy',policyFile]])if(fileRecord(file).sha512!==s.files[name].sha512)fail('SEALED_FILE_MISMATCH');
 return{status:'ANCHORED_RECORD_AND_FINAL_APPROVAL_MATCH',role:s.role,sealSha512:expectedDigest,traceCorroborated:s.trace?.kind==='EXTERNAL_PROCESS_MONITOR_CORROBORATION',independentProvenance:'NOT_PROVEN',anchorTrust:'CALLER_MUST_SUPPLY_INDEPENDENTLY_RETAINED_DIGEST',ciEvidence:false};
}
function main(args){const [command,...a]=args;let result;
 if(command==='prepare'&&a.length===3)result=prepare(...a);else if(command==='before'&&a.length===4)result=before(...a);else if(command==='ready'&&a.length===4)result=ready(...a);else if(command==='after'&&a.length===2)result=after(...a);else if(command==='seal'&&[5,7].includes(a.length))result=seal(...a);else if(command==='verify'&&a.length===5)result=verify(...a);
 else fail('ARGUMENTS_USAGE_prepare_NATIVE_BDS_NEW_RUN_before_RUN_ROLE_CONFIG_PROPERTIES_after_RUN_ROLE_seal_RUN_ROLE_FINAL_APPROVAL_POLICY_optional_TRACE_PID_verify_SEAL_EXTERNAL_SHA512_FINAL_APPROVAL_POLICY');
 console.log(JSON.stringify(command==='prepare'?{session:path.join(a[2],'session.json'),sessionId:result.id,inputFiles:result.inputs.count,inputsSha512:result.inputs.sha512,independentAttestation:false}:command==='seal'?{seal:result.seal,sha512:result.sha512,independentProvenance:'NOT_PROVEN',trace:result.result.trace.kind||'NOT_RUN'}:result,null,2));return result;
}
if(require.main===module)try{main(process.argv.slice(2));}catch(e){console.error(/^IDE_OBSERVATION_[A-Z0-9_]+$/.test(e.message)?e.message:e.safeCode?e.safeCode+': '+(e.file||'')+' '+(e.action||''):'IDE_OBSERVATION_FAILED: inspect the input paths/receipts; no evidence was attested.');process.exitCode=1;}
module.exports={prepare,snapshot,before,ready,after,csv,corroborate,normalizedRelation,approved,seal,verify,main,hash,stagePath};
