'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const check=require('../tools/manual-release-check'),tools=require('../tools/release-tools'),provenance=require('../services/desktopReleaseProvenance');
const dependencySource=["module.exports=req","uire(","'./dependency'", ");\n"].join('');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'game-manual-inspection-')),home=path.join(root,'GameWeb/tools'),roles=['A','B','O'];
const hash=b=>crypto.createHash('sha512').update(b).digest('hex'),write=(file,value)=>fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n');
function pe(configuration='RELEASE'){
 const source=require('./crc-pe-fixture').crcPeFixture('GAME-AUTHORITY-V2 GAME-CONNECT-4'),bytes=Buffer.alloc(1536+4096);source.copy(bytes);const opt=0x80+24,table=opt+240,s=table+80,raw=1536,rva=0x3000;
 bytes.writeUInt16LE(3,0x80+6);bytes.writeUInt32LE(0x5000,opt+56);bytes.write('.extra',s);bytes.writeUInt32LE(4096,s+8);bytes.writeUInt32LE(rva,s+12);bytes.writeUInt32LE(4096,s+16);bytes.writeUInt32LE(raw,s+20);bytes.writeUInt32LE(0x40000040,s+36);
 if(configuration){bytes.writeUInt32LE(rva,opt+112);bytes.writeUInt32LE(256,opt+116);bytes.writeUInt32LE(rva+176,raw+12);bytes.writeUInt32LE(1,raw+16);bytes.writeUInt32LE(1,raw+20);bytes.writeUInt32LE(1,raw+24);bytes.writeUInt32LE(rva+80,raw+28);bytes.writeUInt32LE(rva+96,raw+32);bytes.writeUInt32LE(rva+112,raw+36);bytes.writeUInt32LE(0x1000,raw+80);bytes.writeUInt32LE(rva+128,raw+96);bytes.write('GAME_BUILD_'+configuration+'_V1\0',raw+128);bytes.write('game.exe\0',raw+176);}
 const manifest=fs.readFileSync(path.resolve(__dirname,'../../GameConnect_Win64/GameOverlay.manifest')),offset=raw+512,resourceRva=rva+512;
 bytes.writeUInt32LE(resourceRva,opt+128);bytes.writeUInt32LE(128+manifest.length,opt+132);
 for(const [base,id,target]of [[0,24,0x80000018],[24,1,0x80000030],[48,0,72]]){bytes.writeUInt16LE(1,offset+base+14);bytes.writeUInt32LE(id,offset+base+16);bytes.writeUInt32LE(target,offset+base+20);}
 bytes.writeUInt32LE(resourceRva+128,offset+72);bytes.writeUInt32LE(manifest.length,offset+76);manifest.copy(bytes,offset+128);return bytes;
}
let key,record,selected,policy,spec,canonical;
function approval(role,bytes,file){const sha512=hash(bytes),signature=crypto.sign(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,spec.releaseName,sha512].join('\n')),key.privateKey).toString('base64');write(file,{component:role,version:spec.releaseName,sha512,trustedKey:record,approval:{keyId:record.keyId,signature}});}
function inspect(options){return check.inspect(home,selected,options);}
function expect(code,options){const r=inspect(options);assert.equal(r.outcome,'FAIL',JSON.stringify(r));assert.equal(r.error.code,code,JSON.stringify(r));return r;}
try{
 fs.mkdirSync(home,{recursive:true});fs.mkdirSync(path.join(root,'GameWeb/maintenance'));fs.mkdirSync(path.join(root,'GameWeb/services'));fs.mkdirSync(path.join(root,'GameConnect_Win64'));
 const required=path.join(root,'GameWeb/services/required.js'),dependency=path.join(root,'GameWeb/services/dependency.js');fs.writeFileSync(required,dependencySource);fs.writeFileSync(dependency,'module.exports={};\n');canonical=path.join(root,'GameWeb/maintenance/source-manifest.json');
 const metadata={version:2,algorithm:'sha512',files:{'GameWeb/services/required.js':hash(fs.readFileSync(required)),'GameWeb/services/dependency.js':hash(fs.readFileSync(dependency))}};write(canonical,metadata);
 fs.copyFileSync(path.resolve(__dirname,'../../GameConnect_Win64/GameOverlay.manifest'),path.join(root,'GameConnect_Win64/GameOverlay.manifest'));
 key=crypto.generateKeyPairSync('ed25519');record={keyId:provenance.KeyId(key.publicKey),publicKey:key.publicKey.export({format:'pem',type:'spki'}).toString()};
 spec={version:1,releaseName:'1.0.0',securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,toolchain:{delphi:'test-only',cpp:'test-only',windowsSdk:'test-only',imgui:'test-only'}};
 policy={version:1,revision:2,requireReleaseSignature:true,requireCfg:false,trustedReleaseKeys:[record],revokedSha512:[],minVersionA:'1.0.0',minVersionB:'1.0.0',minVersionO:'1.0.0'};
 write(path.join(home,'spec.json'),spec);write(path.join(home,'deployment-policy.json'),policy);
 selected=roles.map(role=>{const exe=path.join(root,role+'_Release_한글 ! &.exe'),out=path.join(home,role+'.approval.json'),bytes=pe();fs.writeFileSync(exe,bytes);approval(role,bytes,out);return{exe,approval:out};});
 const before=selected.map(s=>fs.readFileSync(s.exe));
 assert.equal(inspect({preManifest:true}).outcome,'PASS');assert.equal(fs.existsSync(path.join(home,'release-manifest.json')),false);
 const missing=expect('MANUAL_INPUT_MISSING');assert.equal(missing.error.stage,'manifest');
 tools.makeManifest(home,selected.map(s=>s.exe));const complete=inspect();assert.equal(complete.outcome,'PASS',JSON.stringify(complete));assert.equal(complete.ciEvidence,false);assert.equal(complete.windowsExecuted,false);assert.equal(complete.serverPublicationApproved,false);assert.equal(complete.source.sourceHashesCompared,true);assert.equal(complete.source.baselineAuthenticity,'NOT_ATTESTED');assert.equal(complete.source.compiledSourceProvenance,'NOT_PROVEN_BY_MANUAL_INSPECTION');assert.equal(complete.buildInputs.status,'NOT_CHECKED');
 for(const [i,s]of selected.entries())assert.deepEqual(fs.readFileSync(s.exe),before[i]);
 const a=selected[0],saved=fs.readFileSync(a.approval);let json=JSON.parse(saved);json.component='B';write(a.approval,json);expect('MANUAL_APPROVAL_ROLE_VERSION_MISMATCH');fs.writeFileSync(a.approval,saved);
 json=JSON.parse(saved);json.version='2.0.0';write(a.approval,json);expect('MANUAL_APPROVAL_ROLE_VERSION_MISMATCH');fs.writeFileSync(a.approval,saved);
 json=JSON.parse(saved);json.approval.signature=Buffer.alloc(64).toString('base64');write(a.approval,json);expect('MANUAL_APPROVAL_SIGNATURE_INVALID');fs.writeFileSync(a.approval,saved);
 const changed=Buffer.from(before[0]);changed[600]^=1;fs.writeFileSync(a.exe,changed);expect('MANUAL_APPROVAL_HASH_MISMATCH');fs.writeFileSync(a.exe,before[0]);
 write(path.join(home,'deployment-policy.json'),{...policy,trustedReleaseKeys:[]});expect('MANUAL_POLICY_INVALID');write(path.join(home,'deployment-policy.json'),policy);
 write(path.join(home,'deployment-policy.json'),{...policy,revision:3});expect('MANUAL_MANIFEST_MISMATCH');write(path.join(home,'deployment-policy.json'),policy);
 for(const config of ['DEBUG',null]){const bytes=pe(config);fs.writeFileSync(a.exe,bytes);approval('A',bytes,a.approval);expect(config?'MANUAL_DEBUG_ARTIFACT':'MANUAL_BUILD_CONFIGURATION_UNVERIFIED');}fs.writeFileSync(a.exe,before[0]);fs.writeFileSync(a.approval,saved);
 fs.unlinkSync(required);expect('MANUAL_SOURCE_FILE_MISSING');fs.writeFileSync(required,dependencySource);
 write(canonical,{...metadata,files:{'GameWeb/services/required.js':metadata.files['GameWeb/services/required.js']}});fs.unlinkSync(dependency);expect('MANUAL_LOCAL_MODULE_MISSING');fs.writeFileSync(dependency,'module.exports={};\n');write(canonical,metadata);
 write(a.approval,{accidental:'-----BEGIN PRIVATE KEY-----'});expect('MANUAL_PRIVATE_KEY_NOT_ALLOWED');fs.writeFileSync(a.approval,saved);
 fs.writeFileSync(required,'module.exports = ;');expect('MANUAL_SOURCE_HASH_MISMATCH');
 write(canonical,{...metadata,files:{...metadata.files,'GameWeb/services/required.js':hash(fs.readFileSync(required))}});expect('MANUAL_JAVASCRIPT_SYNTAX');fs.writeFileSync(required,dependencySource);write(canonical,metadata);
 // No source baseline is rewritten on mismatch, including a same-length edit.
 const sourceRecordBefore=fs.readFileSync(canonical);fs.writeFileSync(dependency,'module.exports=[];\n');expect('MANUAL_SOURCE_HASH_MISMATCH');assert.deepEqual(fs.readFileSync(canonical),sourceRecordBefore);fs.writeFileSync(dependency,'module.exports={};\n');
 for(const invalid of ['../outside.js','GameWeb/services/x:stream','GameWeb/services/x.','GameWeb/services/NUL.js','GameWeb/services/a\\b.js','GameWeb/services/\u0000.js']){write(canonical,{...metadata,files:{[invalid]:'0'.repeat(128)}});expect('MANUAL_SOURCE_PATH_INVALID');}write(canonical,metadata);
 write(canonical,{...metadata,files:{...metadata.files,'gameweb/services/required.js':metadata.files['GameWeb/services/required.js']}});expect('MANUAL_SOURCE_PATH_DUPLICATE');write(canonical,metadata);
 write(canonical,{...metadata,files:{'GameWeb/services/required.js':'invalid'}});expect('MANUAL_SOURCE_METADATA_INVALID');
 fs.writeFileSync(canonical,'{"version":2,"algorithm":"sha512","files":{"GameWeb/services/required.js":"'+metadata.files['GameWeb/services/required.js']+'","GameWeb/services/required.js":"'+'0'.repeat(128)+'"}}');expect('MANUAL_SOURCE_METADATA_INVALID');write(canonical,metadata);
 const outside=path.join(root,'outside.js');fs.writeFileSync(outside,dependencySource);
 fs.unlinkSync(required);try{fs.symlinkSync(outside,required,'file');expect('MANUAL_SOURCE_LINK_NOT_ALLOWED');fs.unlinkSync(required);}catch(e){if(process.platform!=='win32'||e.code!=='EPERM')throw e;console.log('NOT_RUN: file symlink creation requires Windows privilege; directory junction and hardlink rejection are tested separately.');}finally{fs.writeFileSync(required,dependencySource);}
 const serviceDir=path.dirname(required),realDir=serviceDir+'-real';fs.renameSync(serviceDir,realDir);fs.symlinkSync(realDir,serviceDir,'junction');expect('MANUAL_SOURCE_LINK_NOT_ALLOWED');fs.unlinkSync(serviceDir);fs.renameSync(realDir,serviceDir);
 fs.unlinkSync(required);fs.linkSync(outside,required);expect('MANUAL_SOURCE_FILE_INVALID');fs.unlinkSync(required);fs.writeFileSync(required,dependencySource);fs.unlinkSync(outside);
 // Explicit size limits reject sparse oversized files before allocating them.
 fs.truncateSync(required,64*1024*1024+1);expect('MANUAL_SOURCE_SIZE_LIMIT');fs.writeFileSync(required,dependencySource);
 // The final source recheck catches a mutation after the initial hash pass.
 const originalVerify=crypto.verify;let changedDuringCheck=false;try{crypto.verify=(...args)=>{if(!changedDuringCheck){changedDuringCheck=true;fs.writeFileSync(dependency,'module.exports=[];\n');}return originalVerify(...args);};expect('MANUAL_INPUT_CHANGED');}finally{crypto.verify=originalVerify;fs.writeFileSync(dependency,'module.exports={};\n');}
 const growing=path.join(root,'growing.bin');fs.writeFileSync(growing,'small');const originalRead=fs.readSync;let grew=false,maxRequested=0;
 try{fs.readSync=(fd,buf,offset,length,pos)=>{maxRequested=Math.max(maxRequested,length);if(!grew){grew=true;fs.appendFileSync(growing,Buffer.alloc(4096));}return originalRead(fd,buf,offset,length,pos);};assert.throws(()=>check.read(growing,64*1024*1024),/MANUAL_INPUT_CHANGED/);assert.equal(maxRequested,6);}finally{fs.readSync=originalRead;fs.unlinkSync(growing);}
 // Optional build-input comparison measures current bytes, never trusts a
 // stored observed JSON and never generates a reviewed record for the user.
 const bds=path.join(root,'mock-bds'),native=path.join(root,'GameConnect_Win64');
 const put=(file,text='fixture')=>{fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,text);};
 for(const name of ['dcc64.exe','bcc64.exe','brcc32.exe','rsvars.bat','CodeGear.Delphi.Targets'])put(path.join(bds,'bin',name));
 put(path.join(bds,'include/windows/sdk/d3d11.h'));put(path.join(bds,'lib/win64/release/test.dcu'));put(path.join(native,'imgui/vendor/fixture.h'));put(path.join(native,'imgui/bridge/fixture.cpp'));
 for(const name of ['imgui/Build_ImGui_Win64.bat','Game.BuildIsolation.targets','Game.BuildSearchPaths.cs'])put(path.join(native,name));for(const name of ['package.json','package-lock.json'])put(path.join(root,'GameWeb',name),'{}');
 const lock=require('../ci/build-input-lock'),reviewed=path.join(home,'reviewed-build-inputs.json');write(reviewed,lock.collect(native,path.join(root,'GameWeb'),bds));const reviewedBefore=fs.readFileSync(reviewed);
 const compared=inspect({verifyBuildInputs:true,bds});assert.equal(compared.outcome,'PASS',JSON.stringify(compared));assert.equal(compared.buildInputs.status,'CURRENT_FILES_MATCH_REVIEWED_RECORD');assert.equal(compared.buildInputs.storedObservationUsed,false);assert.equal(compared.buildInputs.compiledInputCausality,'NOT_PROVEN');
 put(path.join(bds,'bin/dcc64.exe'),'changed');expect('MANUAL_BUILD_INPUTS_MISMATCH',{verifyBuildInputs:true,bds});assert.deepEqual(fs.readFileSync(reviewed),reviewedBefore);
 expect('MANUAL_BUILD_INPUT_BDS_REQUIRED',{verifyBuildInputs:true,bds:''});fs.unlinkSync(reviewed);
 assert.equal(inspect().outcome,'PASS');
 const child=require('node:child_process').spawnSync(process.execPath,['-e',"require(process.argv[1]).main(process.argv.slice(3),process.argv[2]).catch(()=>process.exitCode=1)",path.resolve(__dirname,'../tools/manual-release-check.js'),home,...selected.flatMap(s=>[s.exe,s.approval])],{encoding:'utf8',timeout:30000});assert.equal(child.status,0,child.stderr||child.stdout);
 const reports=fs.readdirSync(home).filter(x=>/^manual-release-check-.*\.json$/.test(x));assert.equal(reports.length,1);const report=JSON.parse(fs.readFileSync(path.join(home,reports[0])));assert.equal(report.kind,'MANUAL_RELEASE_FILE_INSPECTION');assert.equal(report.outcome,'PASS');assert.equal(report.ciEvidence,false);assert.equal(report.windowsExecuted,false);assert(!JSON.stringify(report).includes('PRIVATE KEY'));
 assert(!fs.existsSync(path.join(root,'GameWeb/data')));assert(!fs.existsSync(path.join(home,'ci-evidence.json')));assert(!fs.existsSync(path.join(home,'reviewed-build-inputs.json')));
 console.log('PASS: manual file inspection, real source SHA-512 comparison and final recheck, bounded reads/path/link rejection, optional current reviewed-input comparison, Ed25519 signatures, final-byte/manifest binding and Debug rejection; synthetic fixtures, no Windows execution.');
}finally{fs.rmSync(root,{recursive:true,force:true});}
