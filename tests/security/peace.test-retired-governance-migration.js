'use strict';
// Exercises authenticated authority persistence and independent license storage.
// All executable bytes and keys are isolated synthetic fixtures.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'../..');
if(process.argv[2]){
 const mode=process.argv[2],dir=process.env.DATA_DIR,expectedFile=path.join(path.dirname(dir),'expected.json');
 require('../../core/peace.utilities').EnsureDirs();
 const store=require('../../services/bootstrap/peace.desktop-bootstrap-store'),ops=require('../../services/security/peace.desktop-security-operations'),prov=require('../../services/artifacts/peace.desktop-release-provenance'),auth=require('../../services/security/peace.desktop-security-authority'),licenses=require('../../services/licensing/peace.desktop-licenses'),keys=require('../../services/security/peace.desktop-key-purposes');
 if(mode==='seed'){
  const f=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),boot=f.Publish();boot.Publish('O','80.0.0',f.PE('O'));
  licenses.Create({requestId:crypto.randomUUID(),label:'Preserved license'},'TEST');
  boot.IssueLauncher({requestId:crypto.randomUUID(),label:'Preserved issuance'},'TEST');
  const pair=store.Load(),manifest={version:1,releaseName:'migration fixture',securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:1,sourceManifestSha512:'1'.repeat(128),policySha512:prov.PolicyDigest(auth.Policy()),toolchain:{delphi:'synthetic',cpp:'synthetic',windowsSdk:'synthetic',imgui:'synthetic'},artifacts:Object.fromEntries(['A','B','O'].map(k=>[k,pair.artifacts[pair.active[k]].sha512]))};
  ops.RecordReleaseManifest({expectedRevision:ops.Revision(),manifest},'TEST');
  const release=crypto.generateKeyPairSync('ed25519').publicKey,pem=release.export({type:'spki',format:'pem'}).toString();auth.SetPolicy({expectedRevision:auth.Policy().revision,trustedReleaseKeys:[{keyId:prov.KeyId(release),publicKey:pem}]},'TEST');
  const profile=require('../../services/security/peace.desktop-mitigation-profiles'),legacyKey=crypto.generateKeyPairSync('ed25519'),legacyPem=legacyKey.publicKey.export({type:'spki',format:'pem'}).toString(),legacyId=prov.KeyId(legacyKey.publicKey),at=Date.now(),manifestId=prov.ManifestId(manifest);
  const statement={version:1,manifestId,component:'B',artifactSha512:manifest.artifacts.B,buildInputSha512:'2'.repeat(128),environment:{architecture:'x64',windowsBuild:26100,gpuIdentitySha512:'none'},settings:{dynamicCode:'observe',strictHandles:true,imageLoadMask:3,requireCfg:false},testedAt:at-100,expiresAt:at+600000,windowsExecuted:true,integration:'PASS',policyReadback:'PASS',cfgInstrumentation:'NOT_REQUESTED',logsSha512:'3'.repeat(128),testScope:'NATIVE_LINKED_RELEASE_UNITS_AND_BASE_WORKFLOW'},id=profile.Id({statement}),compatibility={version:1,profileIds:[id]},envelope={keyId:legacyId,statement,compatibility,signature:crypto.sign(null,Buffer.from(profile.Canonical(statement)),legacyKey.privateKey).toString('base64')},evidence={version:2,purpose:'GAME-CI-ATTESTATION-V1',manifestId,runId:'SYNTHETIC_MIGRATION',issuedAt:at-50,nativeBuild:'PASS',apiProbe:'PASS',integration:'PASS',logsSha512:statement.logsSha512,buildInputSha512:statement.buildInputSha512,compatibilitySha512:profile.CompatibilityHash(compatibility)};
  const manual=require('../../services/runtime/peace.desktop-manual-verification'),report={version:1,kind:'MANUAL_VERIFICATION',runId:'preserved-operator-report',startedAt:'2026-01-01T00:00:00.000Z',finishedAt:'2026-01-01T00:01:00.000Z',platform:'win32',architecture:'x64',sourceManifestSha512:manifest.sourceManifestSha512,sourceManifestUnchanged:true,artifacts:Object.fromEntries(['A','B','O'].map(k=>[k,{sha512:manifest.artifacts[k],unchanged:true}])),stages:manual.STAGES.map(id=>({id,outcome:'NOT_RUN'})),nativeBuild:'NOT_RUN',hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false},reportId=crypto.createHash('sha512').update(JSON.stringify(report)).digest('hex');
  store.Atomic(db=>{Object.assign(db.securityOperations.releaseGovernance,{requireManifest:true,minimumSecurityVersion:1,requireCiEvidence:true,ciKeys:{[legacyId]:{keyId:legacyId,publicKey:legacyPem,purpose:'GAME-CI-ATTESTATION-V1',state:'ACTIVE',notBefore:at-10000,notAfter:at+3600000,changedAt:at-1000,changedBy:'SYNTHETIC'}},ciEvidence:{[manifestId]:{recordedAt:at-10,recordedBy:'SYNTHETIC',evidenceType:'CI_SIGNED_VERIFIED',envelope:{keyId:legacyId,statement:evidence,signature:crypto.sign(null,Buffer.from('GAME-CI-ATTESTATION-V1\n'+prov.Stable(evidence)),legacyKey.privateKey).toString('base64')}}}});db.mitigationProfiles={version:1,entries:{[id]:{envelope,enabled:true,registeredAt:at}}};db.manualVerifications={[reportId]:{report,manifestId,recordedAt:at,actorHash:'1'.repeat(64)}};});
  const registry=JSON.parse(fs.readFileSync(keys.FILE));registry.entries['f'.repeat(128)]={purpose:'CI_ATTESTATION',firstSeenAt:Date.now()};registry.revision++;fs.writeFileSync(keys.FILE,JSON.stringify(registry)+'\n');
  fs.writeFileSync(expectedFile,JSON.stringify({authority:store.Load(),license:licenses.DB(),registry}));
 }else if(mode==='contend'){
  require('../../services/storage/peace.desktop-single-writer').Acquire(dir,{haEnabled:false});const file=path.join(dir,'desktop-bootstrap/authority.json'),before=fs.readFileSync(file);
  const denied=spawnSync(process.execPath,[__filename,'load'],{cwd:root,env:process.env,encoding:'utf8',timeout:30000});assert.notEqual(denied.status,0);assert.match(denied.stderr,/DESKTOP_DATA_DIR_ALREADY_IN_USE/);assert.deepEqual(fs.readFileSync(file),before);
 }else{
  const expected=JSON.parse(fs.readFileSync(expectedFile)),loaded=store.Load();
  for(const k of ['requireCiEvidence','ciKeys','ciEvidence'])delete expected.authority.securityOperations.releaseGovernance[k];
  expected.authority.revision++;expected.authority.securityOperations.revision++;
  const comparison=structuredClone(loaded),profile=require('../../services/security/peace.desktop-mitigation-profiles'),id=Object.keys(loaded.mitigationProfiles.entries)[0],envelope=loaded.mitigationProfiles.entries[id].envelope;
  assert.equal(profile.Verify(envelope,loaded).artifactSha512,envelope.statement.artifactSha512);assert.equal(loaded.mitigationProfiles.profileTrust[id].notAfter,envelope.statement.expiresAt);delete comparison.mitigationProfiles.profileTrust;
  assert.deepEqual(comparison,expected.authority,'only retired governance, bounded profile receipt and revisions may change');
  const manual=require('../../services/runtime/peace.desktop-manual-verification');assert.doesNotThrow(()=>manual.Validate(loaded.manualVerifications));assert.equal(Object.hasOwn(manual.ValidateReport(Object.values(loaded.manualVerifications)[0].report),'ciEvidenceCreated'),false);
  assert.deepEqual(licenses.DB(),expected.license,'license identities and consumption preserved');
  const registry=JSON.parse(fs.readFileSync(keys.FILE));delete expected.registry.entries['f'.repeat(128)];expected.registry.revision++;
  assert.deepEqual(registry,expected.registry,'all remaining key reservations preserved');
  assert.equal(ops.RecordCiEvidence,undefined);assert.equal(ops.SetCiSigner,undefined);
  assert.throws(()=>ops.SetProductionGovernance({expectedRevision:ops.Revision(),requireCiEvidence:false},'TEST'),/SECURITY_OPERATIONS_INVALID/);
  const before=JSON.stringify(store.Load());ops.List();assert.equal(JSON.stringify(store.Load()),before);
 }
 process.stdout.write('MIGRATION_OK\n');
}else{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-retired-governance-')),dir=path.join(temp,'data');fs.mkdirSync(dir);
 try{
  const env={...process.env,DATA_DIR:dir,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'};
  for(const mode of ['seed','contend','load','load']){const run=spawnSync(process.execPath,[__filename,mode],{cwd:root,env,encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});assert.equal(run.status,0,run.stderr);assert.match(run.stdout,/MIGRATION_OK/);}
  const guards=require('../../services/authentication/peace.desktop-admin-guard');for(const action of ['ci-signers','ci-evidence'])assert.equal(guards.IsMutation('/api/desktop/bootstrap/security-operations/'+action),false);
  const code=fs.readFileSync(path.join(root,'web/routes/security/peace.desktop-security-routes.js'),'utf8');assert.doesNotMatch(code,/SetCiSigner|RecordCiEvidence|ci-signers|ci-evidence/);
  console.log('Retired governance migration: PASS; artifacts, active pointers, licenses, issuance, release keys and manifests preserved; second startup idempotent.');
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
