'use strict';
// Synthetic fixtures verify offline boundaries; they are not Windows results.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-offline-release-signing-'));
require('../fixtures/runtime/peace.private-test-directory').Prepare(root);
process.env.DATA_DIR='';process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';
const signer=require('../../tools/artifacts/peace.separated-signing'),p=require('../../services/artifacts/peace.desktop-release-provenance'),authority=require('../../services/security/peace.desktop-security-authority');
const hash=b=>crypto.createHash('sha512').update(b).digest('hex'),write=(f,v)=>fs.writeFileSync(f,JSON.stringify(v));let serial=0;
function Fixture(){
 const home=path.join(root,String(++serial)),input=path.join(home,'input'),out=path.join(home,'output');fs.mkdirSync(input,{recursive:true,mode:0o700});
 const pair=crypto.generateKeyPairSync('ed25519'),keyId=p.KeyId(pair.publicKey),publicKey=pair.publicKey.export({type:'spki',format:'pem'}).toString(),privateFile=path.join(home,'key.pem');fs.writeFileSync(privateFile,pair.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
 const policy={...authority.Defaults(),mode:'enforce',requireReadonlyApi:true,requireCompleteCrcLayers:true,requireReleaseSignature:true,trustedReleaseKeys:[{keyId,publicKey}]};
 const artifacts={};for(const role of ['A','B','O']){const bytes=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture').PE(role,'SYNTHETIC OFFLINE TEST');fs.writeFileSync(path.join(input,role+'.exe'),bytes);artifacts[role]={sha512:hash(bytes),size:bytes.length};}
 const source=Buffer.from('{"synthetic":true}'),spec={version:1,releaseName:'Synthetic offline test',securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,toolchain:{delphi:'NOT_ATTESTED',cpp:'NOT_ATTESTED',windowsSdk:'NOT_ATTESTED',imgui:'NOT_ATTESTED'}};
 fs.writeFileSync(path.join(input,'source-manifest.json'),source);write(path.join(input,'spec.json'),spec);write(path.join(input,'policy.json'),policy);
 const manifest={...spec,sourceManifestSha512:hash(source),policySha512:p.PolicyDigest(policy),artifacts:Object.fromEntries(Object.entries(artifacts).map(([k,v])=>[k,v.sha512]))};write(path.join(input,'manifest.json'),{manifestId:p.ManifestId(manifest),manifest});
 const result={version:1,kind:'FINAL_WINDOWS_EXECUTION_OBSERVATION',outcome:'PASS',finalExecutionOnly:true,buildProvenance:'NOT_ATTESTED',productionApproved:false,finalExecutionVerified:true,integrationAttempted:true,integration:'PASS',cleanup:'PASS',secretBoundary:'PASS',secretScanGuaranteesAbsenceOfSecrets:false,fixtureClaimObservationBarrierUsed:true,releaseVersion:'1.0.0',sourceManifestSha512:hash(source),reviewedPolicySha512:p.PolicyDigest(policy),artifacts,stages:Object.fromEntries(['snapshot','dependencies','prepare','client-secrets','integration','verify'].map(n=>[n,{outcome:'PASS',exitCode:0}]))};
 write(path.join(input,'final-windows-result.json'),result);const policyFile=path.join(home,'deploy-policy.json');write(policyFile,policy);
 return{home,input,out,policy,policyFile,keyId,publicKey,privateFile,result,seal(){return signer.Seal(input).sha512;},release(digest){return signer.Release(input,digest,out,privateFile,policyFile);}};
}
test('signs exact operator-reviewed bytes and preserves observation limitations',()=>{
 const f=Fixture(),report=fs.readFileSync(path.join(f.input,'final-windows-result.json')),digest=f.seal(),signed=f.release(digest),verified=signer.VerifyRelease(f.out,Buffer.from(f.publicKey));
 assert.equal(signed.kind,'RELEASE_APPROVED_TESTED_BUNDLE');assert.equal(verified.keyId,f.keyId);assert.equal(verified.buildProvenance,'NOT_ATTESTED');assert.equal(verified.windowsEvidence,'OPERATOR_REVIEWED_NOT_INDEPENDENT_ATTESTATION');assert.equal(verified.publicationPerformed,false);assert.deepEqual(fs.readFileSync(path.join(f.out,'final-windows-result.json')),report);
 for(const role of ['A','B','O'])assert.deepEqual(fs.readFileSync(path.join(f.out,role+'.exe')),fs.readFileSync(path.join(f.input,role+'.exe')));
 assert.equal(signer.VerifyIndex(f.out,signed.sha512,signed.kind).kind,signed.kind);
});
test('does not convert failure, incomplete execution, stale source or policy into approval',()=>{
 for(const alter of [r=>r.outcome='FAIL',r=>r.cleanup='FAIL',r=>r.finalExecutionVerified=false,r=>r.stages.verify.exitCode=1,r=>r.sourceManifestSha512='0'.repeat(128),r=>r.reviewedPolicySha512='1'.repeat(128),r=>r.artifacts.B.sha512='2'.repeat(128)]){
  const f=Fixture();alter(f.result);write(path.join(f.input,'final-windows-result.json'),f.result);const d=f.seal();assert.throws(()=>f.release(d),/SIGNING_(FINAL_WINDOWS_OBSERVATION_REQUIRED|REPORT_BINDING_INVALID|FINAL_FILE_MISMATCH)/);assert.equal(fs.existsSync(f.out),false);
 }
});
test('requires reported enrollment completion for protected final file tests',()=>{const f=Fixture();f.result.protectionEngine='COZY_SERVER_POLICY_V2';write(path.join(f.input,'final-windows-result.json'),f.result);assert.throws(()=>f.release(f.seal()),/SIGNING_FINAL_WINDOWS_APPROVAL_MISSING/);assert.equal(fs.existsSync(f.out),false);});
test('rejects report or file changes after digest review',()=>{
 const f=Fixture(),d=f.seal();fs.appendFileSync(path.join(f.input,'A.exe'),'changed');assert.throws(()=>f.release(d),/SIGNING_BUNDLE_CHANGED/);assert.equal(fs.existsSync(f.out),false);
 const g=Fixture(),e=g.seal();fs.appendFileSync(path.join(g.input,'final-windows-result.json'),' ');assert.throws(()=>g.release(e),/SIGNING_BUNDLE_CHANGED/);
});
test('does not accept arbitrary attachments, symlinks or private keys',()=>{
 const f=Fixture();fs.writeFileSync(path.join(f.input,'run.js'),'throw Error("must not execute")');assert.throws(()=>f.seal(),/SIGNING_BUNDLE_FILE_INVALID/);
 const g=Fixture(),exe=path.join(g.input,'A.exe');fs.renameSync(exe,path.join(g.home,'real.exe'));fs.symlinkSync(path.join(g.home,'real.exe'),exe);assert.throws(()=>g.seal(),/SIGNING_BUNDLE_FILE_INVALID/);
 const h=Fixture();fs.writeFileSync(path.join(h.input,'source-manifest.json'),'-----BEGIN PRIVATE KEY-----\n'+('a'.repeat(80))+'\n-----END PRIVATE KEY-----');assert.throws(()=>h.seal(),/SIGNING_SECRET_IN_OUTPUT/);
});
test('permits only trust-key changes and refuses key missing from deployment trust',()=>{
 const f=Fixture(),d=f.seal();write(f.policyFile,{...f.policy,requireReadonlyApi:false});assert.throws(()=>f.release(d),/SIGNING_TESTED_POLICY_CHANGED/);assert.equal(fs.existsSync(f.out),false);
 const g=Fixture(),e=g.seal(),pair=crypto.generateKeyPairSync('ed25519');write(g.policyFile,{...g.policy,trustedReleaseKeys:[{keyId:p.KeyId(pair.publicKey),publicKey:pair.publicKey.export({type:'spki',format:'pem'}).toString()}]});assert.throws(()=>g.release(e),/SIGNING_APPROVAL_KEY_NOT_TRUSTED/);
});
test('rejects modified signed report, approval, trust key and output attachment',()=>{
 for(const modify of [f=>fs.appendFileSync(path.join(f.out,'final-windows-result.json'),' '),f=>write(path.join(f.out,'A.approval.json'),{keyId:f.keyId,signature:Buffer.alloc(64).toString('base64')}),f=>fs.writeFileSync(path.join(f.out,'unexpected.txt'),'no')]){const f=Fixture();f.release(f.seal());modify(f);assert.throws(()=>signer.VerifyRelease(f.out,Buffer.from(f.publicKey)),/SIGNING_(ORIGINAL_EVIDENCE_CHANGED|FINAL_APPROVAL_INVALID|BUNDLE_FILE_INVALID)/);}
 const f=Fixture();f.release(f.seal());assert.throws(()=>signer.VerifyRelease(f.out,Buffer.from(crypto.generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'}))),/SIGNING_RELEASE_BINDING_SIGNATURE_INVALID/);
});
test('rejects changed manifest metadata even when artifact hashes match',()=>{const f=Fixture();f.release(f.seal());const target=path.join(f.out,'manifest.json'),r=JSON.parse(fs.readFileSync(target));r.manifest.securityVersion++;r.manifestId=p.ManifestId(r.manifest);write(target,r);assert.throws(()=>signer.VerifyRelease(f.out,Buffer.from(f.publicKey)),/SIGNING_RELEASE_BINDING_INVALID/);});
test('accepts the exact report kind emitted by the retained Windows runner',()=>{const script=fs.readFileSync(path.join(__dirname,'../../tools/windows/Invoke-FinalWindowsTests.ps1'),'utf8'),kind=/\$result=\[ordered\]@\{version=1;kind='([^']+)'/.exec(script);assert.ok(kind,'Windows runner result contract must be explicit');assert.equal(kind[1],signer.OBSERVATION_KIND);assert.match(script,/buildProvenance='NOT_ATTESTED'/);assert.match(script,/finalExecutionVerified=\$false/);});
test('cleanup never removes a replacement output directory after a rename race',()=>{
 const f=Fixture(),d=f.seal(),writeFile=fs.writeFileSync,renamed=path.join(f.home,'owned-output-renamed');let replaced=false;
 fs.writeFileSync=function(file,...args){if(!replaced&&typeof file==='string'&&file.startsWith(f.out+path.sep)){replaced=true;fs.renameSync(f.out,renamed);fs.mkdirSync(f.out,{mode:0o700});writeFile.call(fs,path.join(f.out,'unrelated.txt'),'preserve');throw Error('INJECTED_WRITE_FAILURE');}return writeFile.call(fs,file,...args);};
 try{assert.throws(()=>f.release(d),/SIGNING_OUTPUT_OWNERSHIP_CHANGED/);}finally{fs.writeFileSync=writeFile;}
 assert.equal(replaced,true);assert.equal(fs.readFileSync(path.join(f.out,'unrelated.txt'),'utf8'),'preserve');assert.equal(fs.existsSync(renamed),true);
});
test.after(()=>fs.rmSync(root,{recursive:true,force:true}));
