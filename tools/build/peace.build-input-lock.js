'use strict';
// A reviewed allowlist of real compiler, RTL, SDK/header and bridge bytes. Observation
// never approves itself. Build verification requires a separately supplied lock before building.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const strict=require("../../services/protocol/peace.strict-json");
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
function read(file,max=64*1024*1024){const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.size>max)throw Error('WINDOWS_TEST_BUILD_INPUT_INVALID');const b=fs.readFileSync(file),a=fs.lstatSync(file);if(b.length!==s.size||a.size!==s.size||a.mtimeMs!==s.mtimeMs||a.ctimeMs!==s.ctimeMs)throw Error('WINDOWS_TEST_BUILD_INPUT_CHANGED');return b;}
function json(file){return strict.Parse(read(file,32*1024*1024),{maxBytes:32*1024*1024,maxNodes:1000000});}
const TOOL_NAMES = Object.freeze(['node','npm','msbuild','pwsh','powershell','python','openssl','cl','link','lib','cmd']);
function executable(name,explicit){
 const candidates=explicit?[path.resolve(explicit)]:String(process.env.PATH||'').split(path.delimiter).filter(Boolean).map(dir=>path.join(dir,name));
 for(const file of candidates){try{const stat=fs.lstatSync(file);if(stat.isFile()&&!stat.isSymbolicLink())return path.resolve(file);}catch(e){if(e.code!=='ENOENT'&&e.code!=='ENOTDIR')throw e;}}
 throw Error('WINDOWS_TEST_BUILD_TOOL_REQUIRED');
}
function discoverTools(node=process.execPath){
 // Resolve commands without running an unverified where.exe, shell or interpreter.
 const result={node:executable('node.exe',node),npm:executable('npm.cmd'),msbuild:executable('msbuild.exe'),pwsh:executable('pwsh.exe'),powershell:executable('powershell.exe',process.env.SystemRoot?path.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe'):undefined),python:executable('python.exe',process.env.NODE_GYP_FORCE_PYTHON||process.env.npm_config_python||process.env.PYTHON),openssl:executable('openssl.exe'),cl:executable('cl.exe'),link:executable('link.exe'),lib:executable('lib.exe'),cmd:executable('cmd.exe',process.env.ComSpec)};
 return result;
}
function collectToolInputs(tools,add,tree){
 if(!tools||Object.keys(tools).sort().join(',')!==[...TOOL_NAMES].sort().join(','))throw Error('WINDOWS_TEST_BUILD_TOOLS_INVALID');
 const roots=new Map(),systemRoot=process.env.SystemRoot&&path.resolve(process.env.SystemRoot).toLowerCase();
 for(const role of TOOL_NAMES){
  if(typeof tools[role]!=='string'||!path.isAbsolute(tools[role]))throw Error('WINDOWS_TEST_BUILD_TOOLS_INVALID');
  add('toolchain/'+role+'/executable',tools[role]);
  if(role==='cmd')continue; // Hash this exact OS executable, never all of System32.
  const root=path.dirname(tools[role]),fold=root.toLowerCase();
  if(systemRoot&&[systemRoot,path.join(systemRoot,'system32'),path.join(systemRoot,'syswow64')].includes(fold))throw Error('WINDOWS_TEST_BUILD_TOOL_ROOT_INVALID');
  if(!roots.has(fold)){roots.set(fold,role);tree('toolchain/'+role+'/support',root);}
 }
}

function collect(native,web,bds,node=process.execPath,tools){
 const override=process.env.GAME_IMGUI_BCC64;if(override&&path.resolve(override).toLowerCase()!==path.resolve(bds,'bin','bcc64.exe').toLowerCase())throw Error('WINDOWS_TEST_UNAPPROVED_COMPILER_OVERRIDE');
 tools=tools||discoverTools(node);if(path.resolve(tools.node||'')!==path.resolve(node))throw Error('WINDOWS_TEST_BUILD_TOOL_NODE_MISMATCH');
 const files={};let count=0,total=0;
 function add(key,file){if(++count>100000)throw Error('WINDOWS_TEST_BUILD_INPUT_COUNT');const stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>512*1024*1024)throw Error('WINDOWS_TEST_BUILD_INPUT_INVALID');total+=stat.size;if(total>32*1024**3)throw Error('WINDOWS_TEST_BUILD_INPUT_TOTAL');const fd=fs.openSync(file,'r'),h=crypto.createHash('sha512'),buffer=Buffer.alloc(1024*1024);let size=0;try{const start=fs.fstatSync(fd);if(start.size!==stat.size)throw Error('WINDOWS_TEST_BUILD_INPUT_CHANGED');let n;while((n=fs.readSync(fd,buffer,0,buffer.length,null))>0){size+=n;if(size>stat.size)throw Error('WINDOWS_TEST_BUILD_INPUT_CHANGED');h.update(buffer.subarray(0,n));}const end=fs.fstatSync(fd);if(size!==stat.size||end.mtimeMs!==start.mtimeMs||end.ctimeMs!==start.ctimeMs||end.size!==start.size)throw Error('WINDOWS_TEST_BUILD_INPUT_CHANGED');files[key]=h.digest('hex');}finally{fs.closeSync(fd);}}
 function tree(prefix,dir){const s=fs.lstatSync(dir);if(!s.isDirectory()||s.isSymbolicLink())throw Error('WINDOWS_TEST_BUILD_INPUT_DIRECTORY');for(const e of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){if(e.isSymbolicLink()||!e.isFile()&&!e.isDirectory())throw Error('WINDOWS_TEST_BUILD_INPUT_LINK');if(e.isDirectory())tree(prefix+'/'+e.name,path.join(dir,e.name));else add(prefix+'/'+e.name,path.join(dir,e.name));}}
 tree('bds/bin',path.join(bds,'bin'));
 for(const name of ['dcc64.exe','bcc64.exe','brcc32.exe','rsvars.bat','CodeGear.Delphi.Targets'])if(!Object.keys(files).some(k=>k.toLowerCase()===('bds/bin/'+name).toLowerCase()))throw Error('WINDOWS_TEST_CLASSIC_RECIPE_REQUIRED');
 if(fs.existsSync(path.join(bds,'lib','clang')))tree('bds/lib/clang',path.join(bds,'lib','clang'));
 // These are the actual -isystem roots used by classic bcc64, not the unrelated
 // WindowsSDKVersion from an MSVC prompt. Pinning the whole search universe also
 // detects newly added headers that could shadow an existing #include.
 tree('bds/include',path.join(bds,'include'));
 tree('bds/lib/win64/release',path.join(bds,'lib','win64','release'));
 if(!files['bds/include/windows/sdk/d3d11.h'])throw Error('WINDOWS_TEST_CLASSIC_SDK_REQUIRED');
 // Pin every categorized include/bridge file and the exact native build recipe.
 // The generated object directory is deliberately outside these source trees.
 for(const name of ['Cozy.ImGui/Cozy.Vendor','Cozy.ImGui/Cozy.Bridge','Cozy.ImGui/Cozy.Build'])tree('native/'+name,path.join(native,...name.split('/')));
 for(const name of ['Cozy.Build/Cozy.BuildIsolation.targets','Cozy.Build/Cozy.Tasks/Cozy.BuildSearchPaths.cs'])add('native/'+name,path.join(native,...name.split('/')));
 for(const name of ['package.json','package-lock.json'])add('web/'+name,path.join(web,name));
 add('runtime/node.exe',node);
 collectToolInputs(tools,add,tree);
 // Build/test recipes are executable build inputs, not an implicitly trusted observer.
 tree('recipes/tools/build',path.join(web,'tools','build'));
 tree('recipes/tools/windows',path.join(web,'tools','windows'));
 // Native projects/tasks/probe builders now live in functional directories.
 // Do not let a new nested task or response recipe escape the reviewed lock.
 // Generated RES/DCU/EXE/observations are outputs, never immutable lock inputs.
 let recipeDirectories=0;
 function nativeRecipes(dir,relative='',depth=0){
  if(++recipeDirectories>10000||depth>32)throw Error('WINDOWS_TEST_BUILD_INPUT_COUNT');
  const stat=fs.lstatSync(dir);if(!stat.isDirectory()||stat.isSymbolicLink())throw Error('WINDOWS_TEST_BUILD_INPUT_DIRECTORY');
  for(const entry of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){
   if(entry.isSymbolicLink()||!entry.isFile()&&!entry.isDirectory())throw Error('WINDOWS_TEST_BUILD_INPUT_LINK');
   if(!relative&&entry.isDirectory()&&['build','bin','Cozy.BuildOutputs'].includes(entry.name))continue;
   const name=relative?relative+'/'+entry.name:entry.name,file=path.join(dir,entry.name);
   if(entry.isDirectory())nativeRecipes(file,name,depth+1);
   else if(/\.(?:targets|cs|dproj|props|groupproj|bat|ps1|rc|manifest)$/i.test(entry.name))add('recipes/native/'+name,file);
  }
 }
 nativeRecipes(native);
 const ordered=Object.fromEntries(Object.keys(files).sort().map(k=>[k,files[k]]));
 const sdk=Object.fromEntries(Object.entries(ordered).filter(([k])=>k.startsWith('bds/include/windows/sdk/')));
 return{version:1,kind:'REVIEWED_CLASSIC_WIN64_BUILD_INPUTS',sdkHeaderSha512:sha(Buffer.from(JSON.stringify(sdk))),inputSha512:sha(Buffer.from(JSON.stringify(ordered))),files:ordered};
}
function validate(lock){if(!lock||lock.version!==1||lock.kind!=='REVIEWED_CLASSIC_WIN64_BUILD_INPUTS'||!lock.files||Array.isArray(lock.files)||Object.keys(lock).sort().join(',')!=='files,inputSha512,kind,sdkHeaderSha512,version')throw Error('WINDOWS_TEST_BUILD_LOCK_INVALID');for(const [k,v]of Object.entries(lock.files)){if(/[\x00-\x1f\x7f\\:]/.test(k)||k.split('/').some(p=>!p||p==='.'||p==='..')||!/^[a-f0-9]{128}$/.test(v))throw Error('WINDOWS_TEST_BUILD_LOCK_INVALID');}for(const role of TOOL_NAMES)if(!lock.files['toolchain/'+role+'/executable'])throw Error('WINDOWS_TEST_BUILD_TOOL_LOCK_REQUIRED');if(!lock.files["recipes/tools/build/peace.build-input-lock.js"]||!lock.files["recipes/tools/windows/Invoke-FinalWindowsTests.ps1"]||!lock.files["recipes/tools/windows/WindowsCommon.ps1"])throw Error('WINDOWS_TEST_BUILD_RECIPE_LOCK_REQUIRED');const ordered=Object.fromEntries(Object.keys(lock.files).sort().map(k=>[k,lock.files[k]]));if(sha(Buffer.from(JSON.stringify(ordered)))!==lock.inputSha512||sha(Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(ordered).filter(([k])=>k.startsWith('bds/include/windows/sdk/'))))))!==lock.sdkHeaderSha512)throw Error('WINDOWS_TEST_BUILD_LOCK_DIGEST_INVALID');return lock;}
function verify(expected,observed){validate(expected);validate(observed);if(expected.inputSha512!==observed.inputSha512||JSON.stringify(expected.files)!==JSON.stringify(observed.files))throw Error('WINDOWS_TEST_UNAPPROVED_BUILD_INPUTS');return{version:1,status:'PASS',inputSha512:observed.inputSha512,sdkHeaderSha512:observed.sdkHeaderSha512,files:Object.keys(observed.files).length};}
if(require.main===module){try{const [command,native,web,bds,lock,out]=process.argv.slice(2);if(!['observe','verify'].includes(command)||!native||!web||!bds||!lock)throw Error('WINDOWS_TEST_BUILD_LOCK_ARGUMENTS');const observed=collect(native,web,bds);if(command==='observe'){fs.writeFileSync(lock,JSON.stringify(observed,null,2)+'\n',{flag:'wx'});console.log('OBSERVED_ONLY_REQUIRES_INDEPENDENT_REVIEW');}else{const result=verify(json(lock),observed);if(out)fs.writeFileSync(out,JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));}}catch(e){console.error(/^WINDOWS_TEST_[A-Z_]+$/.test(e.message)?e.message:'WINDOWS_TEST_BUILD_LOCK_FAILED');process.exitCode=1;}}
module.exports={collect,validate,verify,discoverTools,TOOL_NAMES};
