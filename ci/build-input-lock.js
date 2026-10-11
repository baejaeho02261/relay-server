'use strict';
// A reviewed allowlist of real compiler, RTL, SDK/header and bridge bytes. Observation
// never approves itself. CI requires a separately supplied lock before building.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const strict=require('../services/strictJson');
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
function read(file,max=64*1024*1024){const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.size>max)throw Error('CI_BUILD_INPUT_INVALID');const b=fs.readFileSync(file),a=fs.lstatSync(file);if(b.length!==s.size||a.size!==s.size||a.mtimeMs!==s.mtimeMs||a.ctimeMs!==s.ctimeMs)throw Error('CI_BUILD_INPUT_CHANGED');return b;}
function json(file){return strict.Parse(read(file,32*1024*1024),{maxBytes:32*1024*1024,maxNodes:1000000});}
function collect(native,web,bds,node=process.execPath){
 const override=process.env.GAME_IMGUI_BCC64;if(override&&path.resolve(override).toLowerCase()!==path.resolve(bds,'bin','bcc64.exe').toLowerCase())throw Error('CI_UNAPPROVED_COMPILER_OVERRIDE');
 const files={};let count=0,total=0;
 function add(key,file){if(++count>100000)throw Error('CI_BUILD_INPUT_COUNT');const stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>512*1024*1024)throw Error('CI_BUILD_INPUT_INVALID');total+=stat.size;if(total>32*1024**3)throw Error('CI_BUILD_INPUT_TOTAL');const fd=fs.openSync(file,'r'),h=crypto.createHash('sha512'),buffer=Buffer.alloc(1024*1024);let size=0;try{const start=fs.fstatSync(fd);if(start.size!==stat.size)throw Error('CI_BUILD_INPUT_CHANGED');let n;while((n=fs.readSync(fd,buffer,0,buffer.length,null))>0){size+=n;if(size>stat.size)throw Error('CI_BUILD_INPUT_CHANGED');h.update(buffer.subarray(0,n));}const end=fs.fstatSync(fd);if(size!==stat.size||end.mtimeMs!==start.mtimeMs||end.ctimeMs!==start.ctimeMs||end.size!==start.size)throw Error('CI_BUILD_INPUT_CHANGED');files[key]=h.digest('hex');}finally{fs.closeSync(fd);}}
 function tree(prefix,dir){const s=fs.lstatSync(dir);if(!s.isDirectory()||s.isSymbolicLink())throw Error('CI_BUILD_INPUT_DIRECTORY');for(const e of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){if(e.isSymbolicLink()||!e.isFile()&&!e.isDirectory())throw Error('CI_BUILD_INPUT_LINK');if(e.isDirectory())tree(prefix+'/'+e.name,path.join(dir,e.name));else add(prefix+'/'+e.name,path.join(dir,e.name));}}
 tree('bds/bin',path.join(bds,'bin'));
 for(const name of ['dcc64.exe','bcc64.exe','brcc32.exe','rsvars.bat','CodeGear.Delphi.Targets'])if(!Object.keys(files).some(k=>k.toLowerCase()===('bds/bin/'+name).toLowerCase()))throw Error('CI_CLASSIC_RECIPE_REQUIRED');
 if(fs.existsSync(path.join(bds,'lib','clang')))tree('bds/lib/clang',path.join(bds,'lib','clang'));
 // These are the actual -isystem roots used by classic bcc64, not the unrelated
 // WindowsSDKVersion from an MSVC prompt. Pinning the whole search universe also
 // detects newly added headers that could shadow an existing #include.
 tree('bds/include',path.join(bds,'include'));
 tree('bds/lib/win64/release',path.join(bds,'lib','win64','release'));
 if(!files['bds/include/windows/sdk/d3d11.h'])throw Error('CI_CLASSIC_SDK_REQUIRED');
 tree('native/imgui/vendor',path.join(native,'imgui','vendor'));
 tree('native/imgui/bridge',path.join(native,'imgui','bridge'));
 for(const name of ['imgui/Build_ImGui_Win64.bat','Game.BuildIsolation.targets','Game.BuildSearchPaths.cs'])add('native/'+name,path.join(native,name));
 for(const name of ['package.json','package-lock.json'])add('web/'+name,path.join(web,name));
 add('runtime/node.exe',node);
 const ordered=Object.fromEntries(Object.keys(files).sort().map(k=>[k,files[k]]));
 const sdk=Object.fromEntries(Object.entries(ordered).filter(([k])=>k.startsWith('bds/include/windows/sdk/')));
 return{version:1,kind:'REVIEWED_CLASSIC_WIN64_BUILD_INPUTS',sdkHeaderSha512:sha(Buffer.from(JSON.stringify(sdk))),inputSha512:sha(Buffer.from(JSON.stringify(ordered))),files:ordered};
}
function validate(lock){if(!lock||lock.version!==1||lock.kind!=='REVIEWED_CLASSIC_WIN64_BUILD_INPUTS'||!lock.files||Array.isArray(lock.files)||Object.keys(lock).sort().join(',')!=='files,inputSha512,kind,sdkHeaderSha512,version')throw Error('CI_BUILD_LOCK_INVALID');for(const [k,v]of Object.entries(lock.files)){if(/[\x00-\x1f\x7f\\:]/.test(k)||k.split('/').some(p=>!p||p==='.'||p==='..')||!/^[a-f0-9]{128}$/.test(v))throw Error('CI_BUILD_LOCK_INVALID');}const ordered=Object.fromEntries(Object.keys(lock.files).sort().map(k=>[k,lock.files[k]]));if(sha(Buffer.from(JSON.stringify(ordered)))!==lock.inputSha512||sha(Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(ordered).filter(([k])=>k.startsWith('bds/include/windows/sdk/'))))))!==lock.sdkHeaderSha512)throw Error('CI_BUILD_LOCK_DIGEST_INVALID');return lock;}
function verify(expected,observed){validate(expected);validate(observed);if(expected.inputSha512!==observed.inputSha512||JSON.stringify(expected.files)!==JSON.stringify(observed.files))throw Error('CI_UNAPPROVED_BUILD_INPUTS');return{version:1,status:'PASS',inputSha512:observed.inputSha512,sdkHeaderSha512:observed.sdkHeaderSha512,files:Object.keys(observed.files).length};}
if(require.main===module){try{const [command,native,web,bds,lock,out]=process.argv.slice(2);if(!['observe','verify'].includes(command)||!native||!web||!bds||!lock)throw Error('CI_BUILD_LOCK_ARGUMENTS');const observed=collect(native,web,bds);if(command==='observe'){fs.writeFileSync(lock,JSON.stringify(observed,null,2)+'\n',{flag:'wx'});console.log('OBSERVED_ONLY_REQUIRES_INDEPENDENT_REVIEW');}else{const result=verify(json(lock),observed);if(out)fs.writeFileSync(out,JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));}}catch(e){console.error(/^CI_[A-Z_]+$/.test(e.message)?e.message:'CI_BUILD_LOCK_FAILED');process.exitCode=1;}}
module.exports={collect,validate,verify};
