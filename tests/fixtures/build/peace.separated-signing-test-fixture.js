'use strict';
// Every execution claim in this fixture is SYNTHETIC, for parser/signing tests
// only. Its fake PE bytes are never executed and the directory is always deleted.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const split=require("../../../ci/evidence/peace.separated-signing"),artifacts=require("../../../ci/evidence/peace.ci-artifacts"),p=require("../../../services/artifacts/peace.desktop-release-provenance");
const hash=b=>crypto.createHash('sha512').update(b).digest('hex');
function Fixture(){const root=fs.mkdtempSync(path.join(os.tmpdir(),'SYNTHETIC-signing-validator-')),out=path.join(root,'unsigned'),priv=path.join(root,'private');fs.mkdirSync(out);fs.mkdirSync(priv);fs.mkdirSync(path.join(out,'logs'));
 try {
 const write=(n,v)=>fs.writeFileSync(path.join(out,n),JSON.stringify(v,null,2)+'\n');
 const key=(name)=>{const pair=crypto.generateKeyPairSync('ed25519'),file=path.join(root,name+'.pem'),publicFile=path.join(root,name+'.public.pem');fs.writeFileSync(file,pair.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});fs.writeFileSync(publicFile,pair.publicKey.export({type:'spki',format:'pem'}));return {file,publicFile,keyId:p.KeyId(pair.publicKey),publicKey:pair.publicKey.export({type:'spki',format:'pem'}).toString()};};
 const releaseKey=key('release'),ciKey=key('ci'),policy={...require("../../../services/security/peace.desktop-security-authority").Defaults(),requireReleaseSignature:true,trustedReleaseKeys:[{keyId:releaseKey.keyId,publicKey:releaseKey.publicKey}]},policyFile=path.join(root,'deployment-policy.json');fs.writeFileSync(policyFile,JSON.stringify(policy));
 const digests={};for(const role of ['A','B','O']){const b=Buffer.from('SYNTHETIC, NON-EXECUTABLE VALIDATOR BYTES '+role);fs.writeFileSync(path.join(out,role+'.exe'),b);digests[role]=hash(b);}
 write('source-manifest.json',{version:2,algorithm:'sha512',files:{synthetic:'0'.repeat(128)}});write('toolchain.json',{delphi:'SYNTHETIC_NOT_EXECUTED',cpp:'SYNTHETIC_NOT_EXECUTED',windowsSdk:'SYNTHETIC_NOT_EXECUTED',imgui:'SYNTHETIC_NOT_EXECUTED'});
 write('build-inputs.json',{version:1,status:'PASS',files:1,inputSha512:'a'.repeat(128),sdkHeaderSha512:'b'.repeat(128)});fs.copyFileSync(path.join(out,'build-inputs.json'),path.join(out,'build-inputs-after.json'));fs.copyFileSync(path.join(out,'build-inputs.json'),path.join(out,'build-inputs-before-dependencies.json'));
 write('final-artifact-audit.json',{version:1,kind:'FINAL_FILE_INSPECTION_NOT_RUNTIME_ATTESTATION',artifacts:Object.fromEntries(['A','B','O'].map(role=>[role,{sha512:digests[role],...(role==='O'?{overlayManifest:{status:'EXACT_SOURCE_BYTES_MATCH'}}:{})}]))});
 split.Fixture(out,priv,'1.0.0',1,policyFile);const testedPolicy=JSON.parse(fs.readFileSync(path.join(out,'policy.json')));
 const names=['build-inputs-before-dependencies','self-test','snapshot','dependencies','build-inputs','build','build-inputs-after','normalize','approve','native-probes','native-hash-compare','overlay-contracts','compatibility-probes','device-identity','sdk-probe','abi-compare','integration','security-authority','report'];
 const result={version:1,runId:'SYNTHETIC-validator-only',releaseVersion:'1.0.0',securityVersion:1,windowsExecuted:true,productionKeysPresent:false,signed:false,nativeBuild:'PASS',apiProbe:'PASS',integration:'PASS',stages:Object.fromEntries(names.map(n=>[n,{outcome:'PASS',exitCode:0}]))};write('runner-results.json',result);
 for(const n of names)fs.writeFileSync(path.join(out,'logs',n+'.log'),'SYNTHETIC VALIDATOR INPUT; NOT REAL WINDOWS OUTPUT\n');
 write('integration-result.json',{version:1,outcome:'PASS',...Object.fromEntries(['ready','licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed'].map(k=>[k,true]))});
 write('security-authority-result.json',require("../security/peace.security-authority-test-fixture").Result(digests,hash(fs.readFileSync(path.join(out,'source-manifest.json'))),testedPolicy));
 artifacts.Report(out,path.join(out,'runner-results.json'));
 return {root,out,priv,write,key,releaseKey,ciKey,policyFile,policy,digests,dispose(){fs.rmSync(root,{recursive:true,force:true});}};
 }catch(error){fs.rmSync(root,{recursive:true,force:true});throw error;}
}
module.exports={Fixture};
