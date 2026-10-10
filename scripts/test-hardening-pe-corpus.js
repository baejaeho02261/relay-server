 'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),os=require('node:os'),cp=require('node:child_process');
const corpus=require('../contracts/pe-corpus-v1.json'),server=require('../services/desktopIntegrity'),cap=require('../services/peCapabilities'),pre=require('../services/pePreflight');
const root=path.join(__dirname,'../tools');
function block(file){return fs.readFileSync(path.join(root,file),'utf8').replace(/\r\n/g,'\n').split('// BEGIN STANDALONE PE PREFLIGHT\n')[1].split('// END STANDALONE PE PREFLIGHT')[0];}
const create=block('Create_Approval.bat'),check=block('Check_Approval.bat');assert.equal(create,check);
assert(fs.readFileSync(path.join(__dirname,'../services/pePreflight.js'),'utf8').includes(create),'Embedded/server preflight drift');
const standalone=vm.runInNewContext(create+'\nValidatePeImage',{Buffer});
const nativeAt=process.argv.indexOf('--native'),native=nativeAt>=0?process.argv[nativeAt+1]:null;
if(nativeAt>=0&&!native)throw Error('NATIVE_PROBE_REQUIRED');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'game-pe-corpus-'));let comparisons=0;
try{for(const row of corpus.cases){const bytes=Buffer.from(row.bytes,'base64');let actual,accepted=true;
 try{actual=server.CodeImage(bytes);}catch(_){accepted=false;}assert.equal(accepted,row.accepted,row.id+' server');
 for(const [name,validate] of [['BAT',standalone],['preflight',pre.ValidatePeImage]]){let good=true;try{validate(bytes,code=>{throw Error(code);});}catch(_){good=false;}assert.equal(good,row.accepted,row.id+' '+name);comparisons++;}
 if(accepted){assert.equal(actual.sha512,row.codeSha512,row.id);assert.equal(actual.crc64,row.codeCrc64,row.id);const file=server.Digests(bytes);assert.equal(file.sha512,row.fileSha512);assert.equal(file.crc64,row.fileCrc64);}
 if(native){const file=path.join(dir,row.id+'.pe');fs.writeFileSync(file,bytes);const result=cp.spawnSync(native,[file],{encoding:'utf8',timeout:35000});assert.equal(result.status,0,result.stderr||result.stdout);const value=JSON.parse(result.stdout.trim());assert.equal(value.accepted,row.accepted,row.id+' Delphi');if(row.accepted){for(const field of ['codeSha512','codeCrc64','fileSha512','fileCrc64'])assert.equal(value[field],row[field],row.id+' '+field);assert.equal(value.codeXxh3_128,actual.xxh3_128);assert.equal(value.codeBlake3,actual.blake3);}comparisons++;}
 }
 // The standalone capability report must not use the retired flags-only heuristic.
 const text=fs.readFileSync(path.join(root,'Create_Approval.bat'),'utf8');const cfg=text.split('// BEGIN STANDALONE CFG PREFLIGHT\n')[1].split('// END STANDALONE CFG PREFLIGHT')[0];
 const cfgBat=vm.runInNewContext(cfg+'\nPeCapabilities',{Buffer});for(const row of corpus.cases){const b=Buffer.from(row.bytes,'base64');assert.equal(JSON.stringify(cfgBat(b)),JSON.stringify(cap.PeCapabilities(b)));}
 const valid=corpus.cases.find(r=>r.accepted),images=['A','B','O'].map(role=>{const file=path.join(dir,role+'.exe');fs.writeFileSync(file,Buffer.from(valid.bytes,'base64'));return file;});
 const audit=require('../tools/audit-final-artifacts').Audit(images);for(const role of ['A','B','O']){assert.equal(audit.artifacts[role].sha512,valid.fileSha512);assert.equal(audit.artifacts[role].windowsRuntime,'NOT_RUN_BY_THIS_TOOL');}
 console.log(JSON.stringify({suite:'PE_CORPUS_V1',cases:corpus.cases.length,comparisons,nativeExecuted:!!native,status:'PASS'}));
}finally{fs.rmSync(dir,{recursive:true,force:true});}
