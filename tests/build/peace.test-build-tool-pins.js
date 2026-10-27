'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const lock=require("../../tools/build/peace.build-input-lock"),synthetic=require("../fixtures/build/peace.build-tool-fixture");
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'peace-build-tool-pins-'));
try{
 const native=path.join(temp,'native'),web=path.join(temp,'web'),bds=path.join(temp,'bds'),tools=synthetic.fixture(temp);
 const put=(name,bytes='fixture')=>{const file=path.join(temp,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,bytes);return file;};
 for(const name of ['bds/bin/dcc64.exe','bds/bin/bcc64.exe','bds/bin/brcc32.exe','bds/bin/rsvars.bat','bds/bin/CodeGear.Delphi.Targets','bds/include/windows/sdk/d3d11.h','bds/lib/win64/release/System.dcu','native/Cozy.ImGui/Cozy.Vendor/Cozy.Core/Cozy.imgui.h','native/Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp','native/Cozy.ImGui/Cozy.Build/Cozy.Build_ImGui_Win64.bat','native/Cozy.Build/Cozy.BuildIsolation.targets','native/Cozy.Build/Cozy.Tasks/Cozy.BuildSearchPaths.cs','web/package.json','web/package-lock.json'])put(name);
 synthetic.recipes(web);
 const observe=()=>lock.collect(native,web,bds,tools.node,tools),approved=observe();
 assert.equal(lock.verify(approved,observe()).status,'PASS');
 for(const role of lock.TOOL_NAMES){
  assert.ok(approved.files['toolchain/'+role+'/executable'],role+' missing pin');
  const before=fs.readFileSync(tools[role]);fs.appendFileSync(tools[role],'tampered');
  assert.throws(()=>lock.verify(approved,observe()),/WINDOWS_TEST_UNAPPROVED_BUILD_INPUTS/,role+' drift accepted');fs.writeFileSync(tools[role],before);
 }
 const dll=path.join(path.dirname(tools.msbuild),'support.dll'),beforeDll=fs.readFileSync(dll);fs.appendFileSync(dll,'tampered task assembly');assert.throws(()=>lock.verify(approved,observe()),/WINDOWS_TEST_UNAPPROVED_BUILD_INPUTS/);fs.writeFileSync(dll,beforeDll);
 const shadow=put('synthetic-tools/msbuild/new-tasks/shadow.dll','new task search candidate');assert.throws(()=>lock.verify(approved,observe()),/WINDOWS_TEST_UNAPPROVED_BUILD_INPUTS/);fs.unlinkSync(shadow);fs.rmdirSync(path.dirname(shadow));
 const recipe=path.join(web,'tools','windows','Invoke-FinalWindowsTests.ps1'),beforeRecipe=fs.readFileSync(recipe);fs.appendFileSync(recipe,'changed invocation');assert.throws(()=>lock.verify(approved,observe()),/WINDOWS_TEST_UNAPPROVED_BUILD_INPUTS/);fs.writeFileSync(recipe,beforeRecipe);
 const nested=put('native/Cozy.Projects/Cozy.Client/Cozy.Client.dproj','new nested project recipe');assert.throws(()=>lock.verify(approved,observe()),/WINDOWS_TEST_UNAPPROVED_BUILD_INPUTS/);fs.unlinkSync(nested);
 const cache=put('native/Cozy.Projects/Cozy.Client/Cozy.ClientResources.res','generated cache');assert.equal(lock.verify(approved,observe()).status,'PASS');fs.unlinkSync(cache);
 const output=put('native/Cozy.BuildOutputs/Cozy.ImGui/Cozy.game_imgui_bridge.o','generated object');assert.equal(lock.verify(approved,observe()).status,'PASS');fs.unlinkSync(output);
 const oldLock=structuredClone(approved);delete oldLock.files['toolchain/msbuild/executable'];assert.throws(()=>lock.validate(oldLock),/WINDOWS_TEST_BUILD_TOOL_LOCK_REQUIRED/);
 const missing={...tools};delete missing.python;assert.throws(()=>lock.collect(native,web,bds,tools.node,missing),/WINDOWS_TEST_BUILD_TOOLS_INVALID/);
 assert.throws(()=>lock.collect(native,web,bds,tools.npm,tools),/WINDOWS_TEST_BUILD_TOOL_NODE_MISMATCH/);
 const alias=path.join(path.dirname(tools.msbuild),'alias.dll');
 try{fs.symlinkSync(dll,alias);assert.throws(observe,/WINDOWS_TEST_BUILD_INPUT_LINK/);}catch(e){if(process.platform!=='win32'||e.code!=='EPERM')throw e;}finally{if(fs.existsSync(alias))fs.unlinkSync(alias);}
 const priorPath=process.env.PATH;try{process.env.PATH='';assert.throws(()=>lock.discoverTools(tools.node),/WINDOWS_TEST_BUILD_TOOL_REQUIRED/);}finally{process.env.PATH=priorPath;}
 console.log('PASS build tool pins: all 11 executables, loaded support/task bytes, added shadow task, recipe drift, missing-tool/old-lock refusal, node identity and symlink rejection; synthetic bytes, no Windows execution.');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
