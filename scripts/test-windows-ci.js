'use strict';
// Portable regression only: synthetic PE bytes and synthetic subprocess outcomes.
// PASS here is not evidence that Windows/Delphi/ImGui binaries compiled or ran.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-windows-ci-portable-')),fixture=path.join(temp,'fixture');fs.mkdirSync(fixture);fs.writeFileSync(path.join(fixture,'ci-owned-marker'),'GAME_WINDOWS_CI_V1');
process.env.DATA_DIR=path.join(fixture,'server-data');process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require('../core/utils').EnsureDirs();require('../storage/database').LoadDatabase();require('../services/desktopMachinePolicy').Load();require('../services/desktopLicenses').ReconcileOperations();
const ci=require('../ci/ci-artifacts'),svc=require('../ci/fixture-services'),authority=require('../services/desktopSecurityAuthority'),ops=require('../services/desktopSecurityOperations'),store=require('../services/desktopBootstrapStore'),p=require('../services/desktopReleaseProvenance'),provenance=require('../tools/release-provenance'),{PE}=require('./desktop-bootstrap-fixture');
const hash=x=>crypto.createHash('sha512').update(x).digest('hex');let count=0;
function test(name,fn){fn();count++;console.log('PASS '+name);}
function json(file,value){fs.writeFileSync(file,JSON.stringify(value));return file;}
function key(name){const k=crypto.generateKeyPairSync('ed25519');fs.writeFileSync(path.join(temp,name),k.privateKey.export({type:'pkcs8',format:'pem'}));return{file:path.join(temp,name),publicKey:k.publicKey.export({type:'spki',format:'pem'}).toString(),keyId:p.KeyId(k.publicKey)};}
const release=key('release.pem'),signer=key('ci.pem');
function output(name){const out=path.join(temp,name);fs.mkdirSync(out);for(const file of ['build-inputs.json','build-inputs-after.json'])json(path.join(out,file),{version:1,status:'PASS',inputSha512:hash('SYNTHETIC BUILD INPUTS - NOT WINDOWS EVIDENCE'),sdkHeaderSha512:hash('SYNTHETIC SDK'),files:1});for(const role of ['A','B','O'])fs.writeFileSync(path.join(out,role+'.exe'),require('./completion-6-10-fixture').PE(role));json(path.join(out,'final-artifact-audit.json'),require('../tools/audit-final-artifacts').Audit(['A','B','O'].map(role=>path.join(out,role+'.exe'))));fs.mkdirSync(path.join(out,'logs'));fs.writeFileSync(path.join(out,'logs','build.log'),'SYNTHETIC TEST LOG - no Windows execution\n');json(path.join(out,'toolchain.json'),{delphi:'SYNTHETIC',cpp:'SYNTHETIC',windowsSdk:'SYNTHETIC',imgui:'SYNTHETIC'});json(path.join(out,'source-manifest.json'),{version:2,algorithm:'sha512',files:{}});return out;}
function prepare(out,policy){return ci.Prepare(out,release.file,'99.1',1,path.join(out,'toolchain.json'),path.join(out,'source-manifest.json'),policy);}
function stages(){return Object.fromEntries(['build-inputs','build','build-inputs-after','normalize','approve','native-probes','native-hash-compare','overlay-contracts','compatibility-probes','device-identity','sdk-probe','abi-compare','integration'].map(k=>[k,{outcome:'PASS',exitCode:0}]));}
function syntheticCompatibility(){
 // Generated only under the disposable test directory. These are mutation-test
 // inputs, never evidence of a Windows, hardware or production execution.
 return {version:1,kind:'ACTUAL_WINDOWS_LINKED_RELEASE_UNIT_MATRIX',windowsExecuted:true,
  rows:['AB','O'].flatMap(kind=>['observe','prohibit'].map(mode=>({kind,mode,status:'PASS',
   environment:{architecture:'x64',windowsBuild:26100,gpuIdentitySha512:kind==='O'?hash('SYNTHETIC GPU'):'none'},
   settings:{dynamicCode:mode,strictHandles:true,imageLoadMask:3,requireCfg:false},testedAt:Date.now()})))};
}
try{
 test('source snapshot copies only hash-verified manifest files',()=>{const root=path.join(temp,'source');fs.mkdirSync(path.join(root,'GameWeb','maintenance'),{recursive:true});fs.writeFileSync(path.join(root,'source.pas'),'unit Synthetic;');fs.writeFileSync(path.join(root,'not-allowlisted.key'),'DO NOT COPY');json(path.join(root,'GameWeb/maintenance/source-manifest.json'),{version:2,algorithm:'sha512',files:{'source.pas':hash('unit Synthetic;')}});ci.Snapshot(root,path.join(temp,'snapshot'));assert.equal(fs.readFileSync(path.join(temp,'snapshot','source.pas'),'utf8'),'unit Synthetic;');assert.equal(fs.existsSync(path.join(temp,'snapshot','not-allowlisted.key')),false);});
 test('source snapshot rejects tampered files and existing destination',()=>{const root=path.join(temp,'source');fs.writeFileSync(path.join(root,'source.pas'),'tampered');assert.throws(()=>ci.Snapshot(root,path.join(temp,'bad-snapshot')),/CI_SOURCE_HASH_MISMATCH/);assert.throws(()=>ci.Snapshot(root,path.join(temp,'snapshot')),/CI_SNAPSHOT_EXISTS/);});
 test('generated A B O resource outputs cannot change or enter the source snapshot',()=>{
  const root=path.join(temp,'source-generated-resources'),names=['GameLauncher','GameConnect','GameOverlay'];
  fs.mkdirSync(path.join(root,'GameWeb','maintenance'),{recursive:true});fs.mkdirSync(path.join(root,'GameConnect_Win64'));
  const inputs={},files={};
  for(const name of names)for(const ext of ['rc','manifest','ico','dproj']){
   const relative='GameConnect_Win64/'+name+'.'+ext,bytes=Buffer.from('SYNTHETIC TRACKED RESOURCE INPUT '+relative);
   inputs[relative]=bytes;files[relative]=hash(bytes);fs.writeFileSync(path.join(root,relative),bytes);
  }
  const manifestFile=json(path.join(root,'GameWeb/maintenance/source-manifest.json'),{version:2,algorithm:'sha512',files});
  const manifestBytes=fs.readFileSync(manifestFile),manifestDigest=hash(manifestBytes);let first;
  for(const state of ['present','modified','missing']){
   for(const name of names){
    const resource=path.join(root,'GameConnect_Win64',name+'Resources.res');
    if(state==='missing')fs.rmSync(resource);else fs.writeFileSync(resource,'SYNTHETIC GENERATED '+state+' '+name);
   }
   const destination=path.join(temp,'snapshot-generated-resources-'+state),result=ci.Snapshot(root,destination);
   assert.equal(result.sourceManifestSha512,manifestDigest);assert.equal(result.files,Object.keys(inputs).length);
   if(first)assert.deepEqual(result,first);else first=result;
   assert.deepEqual(fs.readFileSync(path.join(destination,'GameWeb/maintenance/source-manifest.json')),manifestBytes);
   for(const [relative,bytes]of Object.entries(inputs))assert.deepEqual(fs.readFileSync(path.join(destination,relative)),bytes);
   for(const name of names)assert.equal(fs.existsSync(path.join(destination,'GameConnect_Win64',name+'Resources.res')),false);
  }
  // The exclusion belongs to the source manifest; tracked resource inputs still
  // use the same strict byte verification as every other allowlisted source.
  fs.appendFileSync(path.join(root,'GameConnect_Win64','GameOverlay.rc'),'TAMPERED');
  assert.throws(()=>ci.Snapshot(root,path.join(temp,'snapshot-generated-resources-tampered-input')),/CI_SOURCE_HASH_MISMATCH/);
 });
 test('snapshot rejects duplicate fields and malformed UTF-8 before publishing any directory',()=>{
  const root=path.join(temp,'source-strict');fs.mkdirSync(path.join(root,'GameWeb','maintenance'),{recursive:true});
  const file=path.join(root,'GameWeb/maintenance/source-manifest.json');
  fs.writeFileSync(path.join(root,'a.pas'),'a');const digest=hash('a');
  const cases=[Buffer.from('{"version":2,"version":2,"algorithm":"sha512","files":{"a.pas":"'+digest+'"}}'),
   Buffer.from('{"version":2,"algorithm":"sha512","files":{"a.pas":"'+digest+'","a.pas":"'+digest+'"}}'),
   Buffer.concat([Buffer.from('{"version":2,"algorithm":"sha512","comment":"'),Buffer.from([0xc3,0x28]),Buffer.from('","files":{"a.pas":"'+digest+'"}}')]),
   Buffer.from('{"version":2,"algorithm":"sha512","files":[]}'),Buffer.from('{"version":2,"algorithm":"sha512","files":{}}')];
  cases.forEach((bytes,i)=>{const destination=path.join(temp,'strict-snapshot-'+i);fs.writeFileSync(file,bytes);assert.throws(()=>ci.Snapshot(root,destination));assert.equal(fs.existsSync(destination),false);});
 });
 test('source snapshot rejects traversal, absolute paths, aliases and symlinks',()=>{for(const name of ['../x','/x','a//b','a/./b','a\\b','C:/x'])assert.throws(()=>ci.Contained(temp,name),/CI_SOURCE_PATH_INVALID/);const root=path.join(temp,'source');fs.symlinkSync(path.join(root,'source.pas'),path.join(root,'linked.pas'));json(path.join(root,'GameWeb/maintenance/source-manifest.json'),{version:2,algorithm:'sha512',files:{'linked.pas':hash('tampered')}});assert.throws(()=>ci.Snapshot(root,path.join(temp,'link-snapshot')),/CI_SOURCE_SYMLINK/);});
 test('snapshot binds original manifest bytes even if source manifest changes during copy',()=>{const root=path.join(temp,'source-race'),destination=path.join(temp,'snapshot-race');fs.mkdirSync(path.join(root,'GameWeb','maintenance'),{recursive:true});fs.writeFileSync(path.join(root,'a.pas'),'a');const file=json(path.join(root,'GameWeb/maintenance/source-manifest.json'),{version:2,algorithm:'sha512',files:{'a.pas':hash('a')}}),original=fs.readFileSync(file),write=fs.writeFileSync;let injected=false;fs.writeFileSync=function(target,...args){if(target===path.join(destination,'a.pas')){injected=true;write(file,JSON.stringify({version:2,algorithm:'sha512',files:{'different.pas':'0'.repeat(128)}}));}return write.call(fs,target,...args);};let result;try{result=ci.Snapshot(root,destination);}finally{fs.writeFileSync=write;}assert.ok(injected);assert.equal(result.sourceManifestSha512,hash(original));assert.deepEqual(fs.readFileSync(path.join(destination,'GameWeb/maintenance/source-manifest.json')),original);});
 test('stage outcomes require every real exit code zero; missing never passes',()=>{assert.equal(ci.Outcome({a:{outcome:'PASS',exitCode:0}},['a']),'PASS');assert.equal(ci.Outcome({a:{outcome:'PASS',exitCode:1}},['a']),'NOT_RUN');assert.equal(ci.Outcome({},['a']),'NOT_RUN');assert.equal(ci.Outcome({a:{outcome:'FAIL',exitCode:1}},['a','b']),'FAIL');});
 const policy={...authority.Defaults(),revision:42,mode:'enforce',requireReleaseSignature:true,trustedReleaseKeys:[{keyId:release.keyId,publicKey:release.publicKey}]};const reviewed=json(path.join(temp,'reviewed.json'),policy),out=output('valid');
 test('reviewed policy preserves exact production revision and digest',()=>{prepare(out,reviewed);assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'policy.json'))),policy);assert.equal(provenance.LoadManifest(path.join(out,'manifest.json')).manifest.policySha512,p.PolicyDigest(policy));});
 test('final A B O approval signatures bind role, version and final bytes',()=>{for(const role of ['A','B','O']){const approval=JSON.parse(fs.readFileSync(path.join(out,role+'.approval.json'))),canonical=['GAME-RELEASE-APPROVAL-V2',role,'99.1',hash(fs.readFileSync(path.join(out,role+'.exe')))].join('\n');assert.equal(approval.keyId,release.keyId);assert.ok(crypto.verify(null,Buffer.from(canonical),release.publicKey,Buffer.from(approval.signature,'base64')));assert.equal(crypto.verify(null,Buffer.from(canonical+'tamper'),release.publicKey,Buffer.from(approval.signature,'base64')),false);}});
 test('reviewed policy rejects weaker enforcement',()=>{const bad=output('weak');assert.throws(()=>prepare(bad,json(path.join(temp,'weak.json'),{...policy,mode:'observe'})),/CI_POLICY_REQUIRED_PROTECTIONS/);});
 test('reviewed policy rejects mismatching approval key',()=>{const bad=output('wrong-key');assert.throws(()=>prepare(bad,json(path.join(temp,'wrong-key.json'),{...policy,trustedReleaseKeys:[{keyId:signer.keyId,publicKey:signer.publicKey}]})),/CI_POLICY_APPROVAL_KEY_MISMATCH/);});
 test('actual production fixture APIs plan bind register and activate synthetic cohort',()=>{const selected=svc.Provision(fixture,out,'99.1');assert.equal(authority.Policy().revision,42);assert.equal(require('../services/desktopKeyPurposes').Summary().counts.RELEASE_APPROVAL,1);assert.ok(ops.State().releaseGovernance.releaseKeyIds.includes(release.keyId));const manifest=provenance.LoadManifest(path.join(out,'manifest.json'));assert.equal(ops.State().releaseGovernance.requireManifest,true);assert.equal(ops.State().releaseGovernance.manifests[manifest.manifestId].registration,'REGISTERED');for(const role of ['A','B','O']){assert.equal(store.Load().active[role],selected[role].id);assert.equal(selected[role].deploymentManifestId,manifest.manifestId);}assert.equal(ops.PreviewPair({aId:selected.A.id,bId:selected.B.id,oId:selected.O.id}).eligible,true);});
 test('fixture cannot reseed policy or reuse existing runtime directory',()=>assert.throws(()=>svc.Provision(fixture,out,'99.1'),/CI_FIXTURE_MUST_BE_EMPTY/));
 test('fixture refuses unrelated DATA_DIR even with owner marker',()=>{const prior=process.env.DATA_DIR;process.env.DATA_DIR=temp;try{assert.throws(()=>svc.Provision(fixture,out,'99.1'),/CI_PRIVATE_DATA_DIR_REQUIRED/);}finally{process.env.DATA_DIR=prior;}});
 test('fixture status reports no fabricated native activity or credentials',()=>{const status=svc.Status();assert.equal(status.flowCount,0);assert.equal(status.overlayAuthorized,false);assert.equal(status.licenseUsed,false);assert.equal(/token|key|machine|device/i.test(JSON.stringify(status)),false);});
 test('logs index hashes actual bytes including empty logs, excludes self-referential signing logs',()=>{fs.writeFileSync(path.join(out,'logs','empty.log'),'');fs.writeFileSync(path.join(out,'logs','sign.log'),'future');const index=ci.LogIndex(path.join(out,'logs'));assert.equal(index.files.find(x=>x.name==='empty.log').sha512,hash(''));assert.equal(index.files.some(x=>x.name==='sign.log'),false);const before=index.files.find(x=>x.name==='build.log').sha512;fs.appendFileSync(path.join(out,'logs','build.log'),'changed');assert.notEqual(ci.LogIndex(path.join(out,'logs')).files.find(x=>x.name==='build.log').sha512,before);});
 test('report hashes saved log index bytes and records actual selected outcomes',()=>{const result=stages();result.integration={outcome:'FAIL',exitCode:9};const r=ci.Report(out,json(path.join(out,'runner-results.json'),{stages:result}));assert.equal(r.nativeBuild,'PASS');assert.equal(r.apiProbe,'PASS');assert.equal(r.integration,'FAIL');assert.equal(r.logsSha512,hash(fs.readFileSync(path.join(out,'logs-index.json'))));});
 test('signed CI evidence preserves FAIL and verifies exact manifest, not hardware attestation',()=>{ci.Sign(out,signer.file,'SYNTHETIC-PORTABLE-TEST');const result=provenance.Verify(path.join(out,'manifest.json'),path.join(out,'ci-evidence.json'),path.join(out,'ci-public-key.pem'));assert.equal(result.signatureVerified,true);assert.equal(result.integration,'FAIL');assert.equal(result.hardwareAttested,false);});
 test('approval key cannot sign CI evidence',()=>assert.throws(()=>ci.Sign(out,release.file,'SYNTHETIC'),/CI_KEY_PURPOSE_CONFLICT/));
 test('artifact mutation after approval and tests refuses report',()=>{const changed=output('changed');prepare(changed,reviewed);fs.appendFileSync(path.join(changed,'O.exe'),'tamper');assert.throws(()=>ci.Report(changed,json(path.join(changed,'results.json'),{stages:stages()})),/CI_ARTIFACT_CHANGED_AFTER_TEST/);});
 test('missing probe and integration stages remain NOT_RUN in report',()=>{const pending=output('pending');prepare(pending,reviewed);const r=ci.Report(pending,json(path.join(pending,'results.json'),{stages:{build:{outcome:'PASS',exitCode:0},normalize:{outcome:'PASS',exitCode:0},approve:{outcome:'PASS',exitCode:0}}}));assert.equal(r.apiProbe,'NOT_RUN');assert.equal(r.integration,'NOT_RUN');});
 test('script source contracts: explicit handle allowlist, suspended before Job assignment, memory/process bounds',()=>{const text=fs.readFileSync(path.join(__dirname,'../ci/WindowsJob.cs'),'utf8');assert.ok(text.indexOf('AssignProcessToJobObject(result.job,pi.process)')<text.indexOf('ResumeThread(pi.thread)'));assert.match(text,/0x20002/);assert.match(text,/0x80404/);assert.match(text,/activeLimit=64/);assert.match(text,/8UL\*1024\*1024\*1024/);assert.match(text,/GetConsoleMode\(input/);assert.doesNotMatch(text,/String\.IsNullOrWhiteSpace\(screen/);});
 test('workflow source contract: dispatch only, least token authority, no fork secret jobs',()=>{const text=fs.readFileSync(path.join(__dirname,'../../.github/workflows/windows-ci.yml'),'utf8');assert.match(text,/workflow_dispatch:/);assert.doesNotMatch(text,/pull_request(?:_target)?:/);assert.match(text,/contents: read/);assert.match(text,/repository\.fork == false/);assert.match(text,/persist-credentials: false/);assert.match(text,/environment: windows-release-ci/);assert.equal((text.match(/uses: actions\/[^@\s]+@[a-f0-9]{40}/g)||[]).length,2);});
 test('v2 producer signs build-input and exact compatibility membership with the same logs',()=>{
  const target=output('compatibility-v2');prepare(target,reviewed);
  json(path.join(target,'compatibility-observations.json'),syntheticCompatibility());
  const report=ci.Report(target,json(path.join(target,'results.json'),{stages:stages()}));
  assert.equal(report.version,2);assert.equal(report.apiProbe,'PASS');
  const profiles=require('../services/desktopMitigationProfiles');
  ci.Sign(target,signer.file,'SYNTHETIC-V2-NOT-HARDWARE');
  const evidence=JSON.parse(fs.readFileSync(path.join(target,'ci-evidence.json')));
  assert.equal(provenance.Verify(path.join(target,'manifest.json'),path.join(target,'ci-evidence.json'),path.join(target,'ci-public-key.pem')).signatureVerified,true);
  const files=fs.readdirSync(target).filter(name=>/^mitigation-/.test(name));assert.equal(files.length,6);
  for(const file of files){
   const e=profiles.Envelope(JSON.parse(fs.readFileSync(path.join(target,file))));
   assert.equal(profiles.CompatibilityHash(e.compatibility),evidence.statement.compatibilitySha512);
   assert(e.compatibility.profileIds.includes(profiles.Id(e)));
   assert.equal(e.statement.buildInputSha512,evidence.statement.buildInputSha512);
   assert.equal(e.statement.logsSha512,evidence.statement.logsSha512);
   assert(crypto.verify(null,Buffer.from(profiles.Canonical(e.statement)),signer.publicKey,Buffer.from(e.signature,'base64')));
  }
 });
 test('changed compatibility attachment refuses signing before publishing evidence',()=>{
  const target=output('compatibility-tamper');prepare(target,reviewed);
  json(path.join(target,'compatibility-observations.json'),syntheticCompatibility());
  ci.Report(target,json(path.join(target,'results.json'),{stages:stages()}));
  const file=path.join(target,'compatibility-statements.json'),attachment=JSON.parse(fs.readFileSync(file));
  attachment.statements[0].logsSha512='f'.repeat(128);json(file,attachment);
  assert.throws(()=>ci.Sign(target,signer.file,'SYNTHETIC-TAMPER'),/CI_COMPATIBILITY_BINDING_INVALID/);
  assert.equal(fs.existsSync(path.join(target,'ci-evidence.json')),false);
  assert.equal(fs.readdirSync(target).some(name=>/^mitigation-/.test(name)),false);
 });
 test('unrun compatibility stage produces no usable profile membership',()=>{
  const target=output('compatibility-unrun');prepare(target,reviewed);
  json(path.join(target,'compatibility-observations.json'),syntheticCompatibility());
  const outcomes=stages();delete outcomes['compatibility-probes'];
  const report=ci.Report(target,json(path.join(target,'results.json'),{stages:outcomes}));
  assert.equal(report.apiProbe,'NOT_RUN');
  const attachment=JSON.parse(fs.readFileSync(path.join(target,'compatibility-statements.json')));
  assert.deepEqual(attachment.compatibility.profileIds,[]);assert.deepEqual(attachment.statements,[]);
 });
 test('full profile scope requires each policy workflow result and all cleanup gates',()=>{
  const target=output('full-profile-scopes');prepare(target,reviewed);
  json(path.join(target,'compatibility-observations.json'),syntheticCompatibility());
  const outcomes=stages(),flags=['ready','licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed'];
  for(const mode of ['observe','prohibit']){
   outcomes['profile-integration-'+mode]={outcome:'PASS',exitCode:0};
   json(path.join(target,'integration-profile-'+mode+'-result.json'),{version:1,outcome:'PASS',mitigationMode:mode,profiledAuthorityStages:['A','B','O'],...Object.fromEntries(flags.map(k=>[k,true]))});
  }
  ci.Report(target,json(path.join(target,'results.json'),{stages:outcomes}));
  const attached=JSON.parse(fs.readFileSync(path.join(target,'compatibility-statements.json')));
  assert.equal(attached.statements.length,6);
  assert(attached.statements.every(s=>s.testScope==='FULL_ABO_WORKFLOW_UNDER_PROFILE'));
  ci.Sign(target,signer.file,'SYNTHETIC-FULL-SCOPE-NOT-WINDOWS');
  assert.equal(provenance.Verify(path.join(target,'manifest.json'),path.join(target,'ci-evidence.json'),path.join(target,'ci-public-key.pem')).signatureVerified,true);
 });
 test('full profile scope rejects missing roles, mode substitution and each incomplete gate',()=>{
  const target=output('invalid-full-profile'),mode='prohibit',file=path.join(target,'integration-profile-'+mode+'-result.json');
  const outcomes={['profile-integration-'+mode]:{outcome:'PASS',exitCode:0}};
  const flags=['ready','licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed'];
  const valid={version:1,outcome:'PASS',mitigationMode:mode,profiledAuthorityStages:['A','B','O'],...Object.fromEntries(flags.map(k=>[k,true]))};
  for(const change of [{version:2},{outcome:'FAIL'},{mitigationMode:'observe'},{profiledAuthorityStages:['A','B']},{profiledAuthorityStages:['A','B','B']},...flags.map(k=>({[k]:false}))]){
   json(file,{...valid,...change});assert.throws(()=>ci.FullProfileWorkflow(target,outcomes,mode),/CI_PROFILE_WORKFLOW_RESULT_INVALID/);
  }
  fs.rmSync(file);assert.throws(()=>ci.FullProfileWorkflow(target,outcomes,mode));
 });
 test('unrun workflow remains limited and known-failed mode gets no usable profile',()=>{
  const target=output('limited-profile-scopes');prepare(target,reviewed);
  json(path.join(target,'compatibility-observations.json'),syntheticCompatibility());
  const outcomes=stages();outcomes['profile-integration-prohibit']={outcome:'FAIL',exitCode:1};
  assert.equal(ci.FullProfileWorkflow(target,outcomes,'observe'),false);
  assert.equal(ci.FullProfileWorkflow(target,outcomes,'prohibit'),false);
  ci.Report(target,json(path.join(target,'results.json'),{stages:outcomes}));
  const attached=JSON.parse(fs.readFileSync(path.join(target,'compatibility-statements.json')));
  assert.equal(attached.statements.length,3);
  assert(attached.statements.every(s=>s.testScope==='NATIVE_LINKED_RELEASE_UNITS_AND_BASE_WORKFLOW'));
  assert(attached.statements.every(s=>s.settings.dynamicCode==='observe'));
 });
 console.log('Windows CI portable regression: '+count+' PASS; Windows build/probe/desktop execution NOT RUN.');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
