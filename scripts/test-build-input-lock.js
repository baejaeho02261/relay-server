'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const lock=require('../ci/build-input-lock');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-build-lock-'));
try{
 const native=path.join(temp,'native'),web=path.join(temp,'web'),bds=path.join(temp,'bds'),node=path.join(temp,'node.exe');
 function file(name,value='sample'){const f=path.join(temp,name);fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,value);return f;}
 for(const f of ['bds/bin/dcc64.exe','bds/bin/bcc64.exe','bds/bin/brcc32.exe','bds/bin/rsvars.bat','bds/bin/CodeGear.Delphi.Targets','bds/bin/compiler-support.dll','bds/include/windows/sdk/d3d11.h','bds/include/dinkumware64/cstdint','bds/lib/win64/release/System.dcu','native/imgui/vendor/imgui.h','native/imgui/bridge/game_imgui_bridge.cpp','native/imgui/Build_ImGui_Win64.bat','native/Game.BuildIsolation.targets','native/Game.BuildSearchPaths.cs','web/package.json','web/package-lock.json','node.exe'])file(f);
 const previousOverride=process.env.GAME_IMGUI_BCC64;
 try{process.env.GAME_IMGUI_BCC64=file('foreign-bcc64.exe');assert.throws(()=>lock.collect(native,web,bds,node),/UNAPPROVED_COMPILER_OVERRIDE/);process.env.GAME_IMGUI_BCC64=path.join(bds,'bin','bcc64.exe');lock.collect(native,web,bds,node);}finally{if(previousOverride===undefined)delete process.env.GAME_IMGUI_BCC64;else process.env.GAME_IMGUI_BCC64=previousOverride;}
 const observed=lock.collect(native,web,bds,node);assert.equal(lock.verify(observed,lock.collect(native,web,bds,node)).status,'PASS');
 file('bds/include/windows/sdk/d3d11.h','tampered header');assert.throws(()=>lock.verify(observed,lock.collect(native,web,bds,node)),/UNAPPROVED/);file('bds/include/windows/sdk/d3d11.h');
 file('bds/include/shadow.h','new header search candidate');assert.throws(()=>lock.verify(observed,lock.collect(native,web,bds,node)),/UNAPPROVED/);fs.unlinkSync(path.join(bds,'include/shadow.h'));
 file('bds/bin/bcc64.exe','new compiler');assert.throws(()=>lock.verify(observed,lock.collect(native,web,bds,node)),/UNAPPROVED/);file('bds/bin/bcc64.exe');
 file('bds/bin/compiler-support.dll','altered loaded compiler DLL');assert.throws(()=>lock.verify(observed,lock.collect(native,web,bds,node)),/UNAPPROVED/);file('bds/bin/compiler-support.dll');
 file('bds/bin/CodeGear.Delphi.Targets','altered MSBuild recipe');assert.throws(()=>lock.verify(observed,lock.collect(native,web,bds,node)),/UNAPPROVED/);file('bds/bin/CodeGear.Delphi.Targets');
 const forged=structuredClone(observed);forged.files['bds/bin/bcc64.exe']='0'.repeat(128);assert.throws(()=>lock.validate(forged),/DIGEST_INVALID/);
 file('bds/lib/win64/release/System.dcu','altered runtime');assert.throws(()=>lock.verify(observed,lock.collect(native,web,bds,node)),/UNAPPROVED/);
 const observedPath=path.join(temp,'observed.json'),reviewedPath=path.join(temp,'reviewed.json'),approve=path.resolve(__dirname,'../ci/approve-build-inputs.js'),spawn=require('node:child_process').spawnSync;
 fs.writeFileSync(observedPath,JSON.stringify(observed));
 assert.notEqual(spawn(process.execPath,[approve,observedPath,'f'.repeat(128),reviewedPath]).status,0);assert.equal(fs.existsSync(reviewedPath),false);
 assert.equal(spawn(process.execPath,[approve,observedPath,observed.inputSha512,reviewedPath]).status,0);assert.equal(JSON.parse(fs.readFileSync(reviewedPath)).inputSha512,observed.inputSha512);
 assert.notEqual(spawn(process.execPath,[approve,observedPath,observed.inputSha512,reviewedPath]).status,0);
 const cfgDir=path.join(temp,'cfg');fs.mkdirSync(cfgDir);for(const role of ['A','B','O'])fs.writeFileSync(path.join(cfgDir,role+'.exe'),require('./completion-6-10-fixture').PE(role,undefined,true));
 const cfg=require('../ci/cfg-evidence').Inspect(cfgDir,observed.inputSha512);for(const role of ['A','B','O']){assert.equal(cfg.artifacts[role].metadataValid,true);assert.equal(cfg.artifacts[role].instrumentation,'METADATA_ONLY_UNVERIFIED');assert.equal(cfg.artifacts[role].strictProfileSupported,false);}
 console.log('PASS reviewed build lock: unchanged compiler/SDK, header mutation, added shadow header, compiler drift/foreign override, forged digest, RTL mutation, explicit approval digest/overwrite refusal, CFG metadata not instrumentation');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
