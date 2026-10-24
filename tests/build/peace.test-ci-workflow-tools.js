'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const workflow=require("../../tools/build/peace.ci-workflow"),provenance=require("../../tools/artifacts/peace.release-provenance"),p=require("../../services/artifacts/peace.desktop-release-provenance");
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ci-workflow-tools-')),root=path.join(dir,'source with spaces'),keys=path.join(dir,'private'),out=path.join(root,'Relay Server/tools/ci-runs/test');
const sha=b=>crypto.createHash('sha512').update(b).digest('hex'),write=(name,v)=>fs.writeFileSync(path.join(out,name),JSON.stringify(v,null,2)+'\n');
try{
 // The real runner supplies this allowlist to every subprocess. Python options
 // accepted by preflight must survive that boundary for npm/node-gyp rebuilds.
 const common=fs.readFileSync(path.join(MODULE_RESOURCE_ROOT,"../ci/pipeline/CiCommon.ps1"),'utf8');
 const envList=common.match(/foreach \(\$name in @\(([^\n]+)\)\)/);assert.ok(envList,'Explicit child-environment allowlist');
 const envNames=[...envList[1].matchAll(/'([^']+)'/g)].map(x=>x[1]);
 for(const name of ['NODE_GYP_FORCE_PYTHON','npm_config_python','PYTHON'])assert.ok(envNames.includes(name),'Preserve '+name);
 for(const name of ['GAME_RELEASE_APPROVAL_KEY_B64','GAME_CI_ATTESTATION_KEY_B64','NPM_TOKEN','NODE_OPTIONS'])assert.ok(!envNames.includes(name),'Do not inherit '+name);
 fs.mkdirSync(out,{recursive:true});fs.mkdirSync(keys);fs.mkdirSync(path.join(root,'Relay Server/maintenance'),{recursive:true});fs.mkdirSync(path.join(out,'logs'));
 assert.throws(()=>workflow.externalKeyPath(root,path.join(root,'secret.pem')),/OUTSIDE_SOURCE/);
 const ciFile=path.join(keys,'ci.pem'),releaseFile=path.join(keys,'release.pem');workflow.createKey(root,ciFile);workflow.createKey(root,releaseFile);assert.throws(()=>workflow.createKey(root,ciFile),e=>e.code==='EEXIST');
 const recordFile=path.join(dir,'ci-public-key.json');workflow.exportKey(root,ciFile,recordFile);assert.throws(()=>workflow.exportKey(root,ciFile,recordFile),e=>e.code==='EEXIST');const record=JSON.parse(fs.readFileSync(recordFile)),ci=crypto.createPrivateKey(fs.readFileSync(ciFile)),release=crypto.createPrivateKey(fs.readFileSync(releaseFile)),releasePub=crypto.createPublicKey(release);
 const sourceFile=path.join(root,'Relay Server/maintenance/source-manifest.json');
 const trackedSources={
  'Relay Server/example.js':'',
  "Relay Server/services/runtime/peace.desktop-deadline.js":'deadline source fixture',
  "Railway/Cozy.Source/Cozy.Integrity/Cozy.Measurement.pas":'measurement source fixture'
 };
 fs.writeFileSync(path.join(root,'Relay Server/example.js'),'');
 fs.writeFileSync(sourceFile,JSON.stringify({version:2,algorithm:'sha512',files:Object.fromEntries(Object.entries(trackedSources).map(([name,contents])=>[name,sha(contents)]))}));
 // One diagnosis must name both missing tracked files, including a missing
 // intermediate directory, before attempting to load policy dependencies.
 assert.throws(()=>workflow.verifySource(root),error=>{
  assert.match(error.message,/^CI_SOURCE_FILES_MISSING:/);
  assert.ok(error.message.includes("Relay Server/services/runtime/peace.desktop-deadline.js"));
  assert.ok(error.message.includes("Railway/Cozy.Source/Cozy.Integrity/Cozy.Measurement.pas"));
  assert.ok(!error.message.includes('Relay Server/example.js'),'Present files must not be reported missing');
  assert.ok(!error.message.includes('ENOENT'),'Show actionable relative source paths');
  return true;
 });
 assert.throws(()=>workflow.prerequisites(root,path.join(root,'Relay Server/tools')),error=>{
  assert.match(error.message,/^CI_SOURCE_FILES_MISSING:/);
  assert.ok(error.message.includes("Relay Server/services/runtime/peace.desktop-deadline.js"));
  assert.ok(error.message.includes("Railway/Cozy.Source/Cozy.Integrity/Cozy.Measurement.pas"));
  return true;
 });
 for(const [name,contents]of Object.entries(trackedSources)){const full=path.join(root,name);fs.mkdirSync(path.dirname(full),{recursive:true});fs.writeFileSync(full,contents);}
 assert.equal(workflow.verifySource(root),3);
 fs.writeFileSync(path.join(root,'Relay Server/example.js'),'tampered');assert.throws(()=>workflow.verifySource(root),/SOURCE_HASH_MISMATCH/);fs.writeFileSync(path.join(root,'Relay Server/example.js'),'');
 for(const moduleName of ['../../services/runtime/peace.desktop-deadline','..\\..\\services\\runtime\\peace.desktop-deadline']){
  const missingModule=Object.assign(new Error("Cannot find module '"+moduleName+"'\nRequire stack:\n- C:\\PRIVATE\\ci-private.pem"),{code:'MODULE_NOT_FOUND'});
  const diagnostic=workflow.formatError(missingModule);
  assert.equal(diagnostic,'CI_MODULE_NOT_FOUND: '+moduleName+'; restore the matching source package.');
  assert.ok(!diagnostic.includes('Require stack'));assert.ok(!diagnostic.includes('PRIVATE'));assert.ok(!diagnostic.includes('ci-private.pem'));
 }
 const unsafeModule=Object.assign(new Error("Cannot find module './peace.desktop-deadline\nPRIVATE_SECRET\x1b[31m'\nRequire stack:"),{code:'MODULE_NOT_FOUND'});
 const unsafeDiagnostic=workflow.formatError(unsafeModule);assert.match(unsafeDiagnostic,/MODULE_NOT_FOUND/);assert.ok(!unsafeDiagnostic.includes('PRIVATE_SECRET'));assert.ok(!/[\x00-\x1f\x7f]/.test(unsafeDiagnostic));
 const privateError=Object.assign(new Error('PRIVATE_SECRET -----BEGIN PRIVATE KEY-----'),{code:'ERR_INVALID_ARG_VALUE'});
 assert.ok(!workflow.formatError(privateError).includes('PRIVATE_SECRET'));
 fs.copyFileSync(sourceFile,path.join(out,'source-manifest.json'));
 const policy={version:1,trustedReleaseKeys:[{keyId:p.KeyId(releasePub),publicKey:releasePub.export({type:'spki',format:'pem'}).toString()}]};write('policy.json',policy);
 for(const r of ['A','B','O'])fs.writeFileSync(path.join(out,r+'.exe'),'fixture bytes '+r);
 const manifest={version:1,releaseName:'Windows CI 1.0.0',securityVersion:97,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,sourceManifestSha512:sha(fs.readFileSync(sourceFile)),policySha512:p.PolicyDigest(policy),toolchain:{delphi:'fixture',cpp:'fixture',windowsSdk:'fixture',imgui:'fixture'},artifacts:Object.fromEntries(['A','B','O'].map(r=>[r,sha(fs.readFileSync(path.join(out,r+'.exe')))]))};write('manifest.json',{manifestId:p.ManifestId(manifest),manifest});
 fs.writeFileSync(path.join(out,'logs/build.log'),'test fixture only\n');
 const emptyLog=path.join(out,'logs/empty.log');fs.writeFileSync(emptyLog,'');
 // Silent subprocesses legitimately produce an empty log. It is still bound
 // to the signed index; executable and other required inputs stay nonempty.
 assert.throws(()=>provenance.FileHash(emptyLog,1024),/PROVENANCE_INPUT_INVALID/);
 assert.equal(provenance.FileHash(emptyLog,1024,true),sha(''));
 const logIndex={version:1,files:[{name:'build.log',sha512:sha(fs.readFileSync(path.join(out,'logs/build.log')))},{name:'empty.log',sha512:sha('')}]};write('logs-index.json',logIndex);
 const report={version:1,aSha512:manifest.artifacts.A,bSha512:manifest.artifacts.B,oSha512:manifest.artifacts.O,sourceManifestSha512:manifest.sourceManifestSha512,nativeBuild:'PASS',apiProbe:'PASS',integration:'PASS',logsSha512:sha(fs.readFileSync(path.join(out,'logs-index.json')))};write('report.json',report);
 const evidence=provenance.Sign(path.join(out,'manifest.json'),path.join(out,'report.json'),ciFile,'test-fixture');write('ci-evidence.json',evidence);fs.writeFileSync(path.join(out,'ci-public-key.pem'),record.publicKey);write('runner-results.json',{windowsExecuted:true,signed:true,nativeBuild:'PASS',apiProbe:'PASS',integration:'PASS',runId:'test-fixture'});
 for(const r of ['A','B','O'])write(r+'.approval.json',{keyId:p.KeyId(releasePub),signature:crypto.sign(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',r,'1.0.0',manifest.artifacts[r]].join('\n')),release).toString('base64')});
 assert.equal(workflow.checkOutput(out,recordFile).serverTrustChecked,false);
 fs.writeFileSync(emptyLog,'changed');assert.throws(()=>workflow.checkOutput(out,recordFile),/LOG_HASH_MISMATCH/);fs.writeFileSync(emptyLog,'');
 fs.appendFileSync(path.join(out,'O.exe'),'changed');assert.throws(()=>workflow.checkOutput(out,recordFile),/FINAL_EXE_HASH_MISMATCH/);fs.writeFileSync(path.join(out,'O.exe'),'fixture bytes O');
 fs.appendFileSync(path.join(out,'logs/build.log'),'changed');assert.throws(()=>workflow.checkOutput(out,recordFile),/LOG_HASH_MISMATCH/);fs.writeFileSync(path.join(out,'logs/build.log'),'test fixture only\n');
 const other=crypto.generateKeyPairSync('ed25519').publicKey;fs.writeFileSync(recordFile,JSON.stringify({...record,keyId:p.KeyId(other),publicKey:other.export({type:'spki',format:'pem'}).toString()}));assert.throws(()=>workflow.checkOutput(out,recordFile),/SIGNER_RECORD/);fs.writeFileSync(recordFile,JSON.stringify(record));
 const failed={...evidence,statement:{...evidence.statement,integration:'NOT_RUN'}};failed.signature=crypto.sign(null,Buffer.from(p.Canonical(failed.statement)),ci).toString('base64');write('ci-evidence.json',failed);assert.throws(()=>workflow.checkOutput(out,recordFile),/REQUIRED_CHECK_NOT_PASS/);write('ci-evidence.json',evidence);
 write('report.json',{...report,aSha512:'f'.repeat(128)});assert.throws(()=>workflow.checkOutput(out,recordFile),/FINAL_EXE_HASH_MISMATCH/);write('report.json',report);
 write('runner-results.json',{windowsExecuted:true,signed:true,nativeBuild:'PASS',apiProbe:'PASS',integration:'PASS',cleanupFailed:true,runId:'test-fixture'});assert.throws(()=>workflow.checkOutput(out,recordFile),/RUNNER_NOT_SUCCESSFUL/);
 console.log('PASS: source/key boundaries, signature identity, exact EXEs, approval signatures, logs, reports and failed-stage rejection (fixtures only; no Windows execution).');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
