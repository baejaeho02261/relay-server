'use strict';
// Portable protocol regression: synthetic mutation inputs, never Windows evidence.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-profile-fixture-')),run=path.join(temp,'fixture'),out=path.join(temp,'output');fs.mkdirSync(run);fs.mkdirSync(out);fs.writeFileSync(path.join(run,'test-owned-marker'),'GAME_WINDOWS_TEST_V1');
process.env.DATA_DIR=path.join(run,'server-data');process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29132';
require("../../../core/peace.utilities.js").EnsureDirs();require("../../../storage/snapshots/peace.database.js").LoadDatabase();require("../../../services/devices/peace.desktop-machine-policy").Load();require("../../../services/licensing/peace.desktop-licenses").ReconcileOperations();
const trial=require("../../../tools/fixtures/peace.profile-fixture"),profiles=require("../../../services/security/peace.desktop-mitigation-profiles"),store=require("../../../services/bootstrap/peace.desktop-bootstrap-store");
const hash=x=>crypto.createHash('sha512').update(x).digest('hex'),json=(name,x)=>fs.writeFileSync(path.join(out,name),JSON.stringify(x)),now=Date.now();let count=0;function test(name,fn){fn();count++;console.log('PASS '+name);}
function CurrentSyntheticTemplates(){
 // Keep fixture issuer generation exclusively in this portable mutation test.
 // Actual Windows/operator provisioning never substitutes this trust anchor.
 const signing=require('../../../services/bootstrap/peace.issued-a-signing'),issuer=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
 process.env[signing.ENV]=Buffer.from(issuer.privateKey.export({type:'pkcs8',format:'pem'})).toString('base64');
 const protection=require('../../../services/artifacts/peace.server-policy-protection'),evidence=require('../../../services/artifacts/peace.desktop-packing-evidence'),bootstrap=require('../../../services/bootstrap/peace.desktop-bootstrap');
 const outputs={},records=[],jobId=crypto.randomBytes(16).toString('hex'),createdAt=Date.now();
 for(const role of ['A','B','O']){
  const raw=require('../protocol/peace.completion-6-10-fixture').PE(role),anchor=role==='A'?Buffer.alloc(512):Buffer.alloc(0);
  if(role==='A')signing.AnchorBytes(issuer.publicKey).copy(anchor);
  const slot=protection.CreateUnsealedSlot(),bytes=Buffer.concat([raw,anchor,slot]),pe=bytes.readUInt32LE(60),opt=pe+24,table=opt+bytes.readUInt16LE(pe+20),last=table+(bytes.readUInt16LE(pe+6)-1)*40;
  const size=bytes.readUInt32LE(last+16)+anchor.length+slot.length;bytes.writeUInt32LE(size,last+8);bytes.writeUInt32LE(size,last+16);bytes.writeUInt32LE(Math.ceil((bytes.readUInt32LE(last+12)+size)/4096)*4096,opt+56);
  const source=bootstrap.Publish(role,'99.1',bytes,undefined,{activate:false}),output=protection.BindTemplate(bytes,role);outputs[role]=output;
  records.push({version:1,purpose:evidence.DOMAIN,jobId,component:role,sourceArtifactId:source.id,inputSha512:output.inputSha512,outputSha512:output.sha512,size:output.bytes.length,toolSha512:output.toolSha512,profileSha512:output.profileSha512,createdAt,actorHash:hash('SYNTHETIC_PROFILE_TEST')});
  fs.writeFileSync(path.join(out,role+'.exe'),output.bytes);
 }
 store.Atomic(db=>{evidence.RecordJob(db,records);require('../../../services/security/peace.server-policy-registry').RecordJob(db,records,outputs);});
}
function ProvisionSyntheticCurrent(policy){
 const authority=require('../../../services/security/peace.desktop-security-authority'),ops=require('../../../services/security/peace.desktop-security-operations'),{version,revision,...fields}=policy;
 authority.SetPolicy({...fields,expectedRevision:0},'SYNTHETIC_PROFILE_TEST');
 const manifest=JSON.parse(fs.readFileSync(path.join(out,'manifest.json'),'utf8'));
 ops.PlanReleaseManifest({expectedRevision:ops.Revision(),...manifest},'SYNTHETIC_PROFILE_TEST');ops.SetReleaseGovernance({expectedRevision:ops.Revision(),requireManifest:true},'SYNTHETIC_PROFILE_TEST');
 const selected={};for(const role of ['A','B','O'])selected[role]=ops.Stage(role,'99.1',fs.readFileSync(path.join(out,role+'.exe')),JSON.parse(fs.readFileSync(path.join(out,role+'.approval.json'),'utf8')),'SYNTHETIC_PROFILE_TEST',manifest.manifestId);
 ops.RecordReleaseManifest({expectedRevision:ops.Revision(),...manifest},'SYNTHETIC_PROFILE_TEST');ops.ActivatePair({expectedRevision:ops.Revision(),expectedPolicyRevision:authority.Policy().revision,aId:selected.A.id,bId:selected.B.id,oId:selected.O.id},'SYNTHETIC_PROFILE_TEST');
 return selected;
}
try{
 const pair=crypto.generateKeyPairSync('ed25519'),key=path.join(run,'release.pem');fs.writeFileSync(key,pair.privateKey.export({type:'pkcs8',format:'pem'}));
 CurrentSyntheticTemplates();
 json('final-artifact-audit.json',require("../../../tools/artifacts/peace.audit-final-artifacts").Audit(['A','B','O'].map(k=>path.join(out,k+'.exe'))));
 for(const name of ['build-inputs.json','build-inputs-after.json'])json(name,{version:1,status:'PASS',files:1,inputSha512:hash('SYNTHETIC NOT WINDOWS'),sdkHeaderSha512:hash('SYNTHETIC SDK')});
 json('toolchain.json',{delphi:'SYNTHETIC',cpp:'SYNTHETIC',windowsSdk:'SYNTHETIC',imgui:'SYNTHETIC'});json('source-manifest.json',{version:2,algorithm:'sha512',files:{}});
 const p=require("../../../services/artifacts/peace.desktop-release-provenance"),provenance=require("../../../tools/artifacts/peace.release-provenance"),keyId=p.KeyId(pair.publicKey),publicKey=pair.publicKey.export({type:'spki',format:'pem'}).toString();
 const policy=require("../../../services/security/peace.desktop-security-authority").ValidatePolicy({version:1,revision:1,mode:'enforce',enforceLegacy:false,freshnessMs:45000,challengeMs:15000,requireReadonlyApi:true,requireCompleteCrcLayers:true,dynamicCode:'observe',requireCfg:false,minVersionA:'0',minVersionB:'0',minVersionO:'0',requireReleaseSignature:true,trustedReleaseKeys:[{keyId,publicKey}],revokedSha512:[],revokedLegacySha256:[]});
 json('policy.json',policy);
 for(const role of ['A','B','O']){const sha=hash(fs.readFileSync(path.join(out,role+'.exe')));json(role+'.approval.json',{keyId,signature:crypto.sign(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,'99.1',sha].join('\n')),pair.privateKey).toString('base64')});}
 json('spec.json',{version:1,releaseName:'Synthetic local test',securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,toolchain:JSON.parse(fs.readFileSync(path.join(out,'toolchain.json')))});
 json('manifest.json',provenance.MakeManifest(path.join(out,'spec.json'),...['A','B','O'].map(r=>path.join(out,r+'.exe')),path.join(out,'source-manifest.json'),path.join(out,'policy.json')));
 fs.mkdirSync(path.join(out,'logs'));for(const name of ['compatibility-probes','integration'])fs.writeFileSync(path.join(out,'logs',name+'.log'),'SYNTHETIC PORTABLE MUTATION TEST - NOT WINDOWS\n');
 const stages=Object.fromEntries(['build-inputs','build','build-inputs-after','normalize','approve','native-probes','native-hash-compare','overlay-contracts','compatibility-probes','device-identity','sdk-probe','abi-compare','integration'].map(k=>[k,{outcome:'PASS',exitCode:0}]));
 const matrix={version:1,kind:'ACTUAL_WINDOWS_LINKED_RELEASE_UNIT_MATRIX',windowsExecuted:true,rows:['AB','O'].flatMap(kind=>['observe','prohibit'].map(mode=>({kind,mode,status:'PASS',testedAt:now,environment:{architecture:'x64',windowsBuild:26100,gpuIdentitySha512:kind==='O'?hash('SYNTHETIC GPU'):'none'},settings:{dynamicCode:mode,strictHandles:true,imageLoadMask:3,requireCfg:false}})))};
 json('runner-results.json',{stages});json('compatibility-observations.json',matrix);
 test('candidate fixture grants retain narrower proof and exact A B O final hashes',()=>{const c=trial.Candidates(out,'prohibit');assert.deepEqual(c.statements.map(s=>s.component),['A','B','O']);assert(c.statements.every(s=>s.testScope==='NATIVE_LINKED_RELEASE_UNITS_AND_BASE_WORKFLOW'));});
 test('unrun baseline never becomes a profile prerequisite',()=>{json('runner-results.json',{stages:{...stages,integration:{outcome:'NOT_RUN',exitCode:null}}});assert.throws(()=>trial.Candidates(out,'prohibit'),/PREREQUISITE_NOT_PASS/);json('runner-results.json',{stages});});
 test('unsupported renderer never becomes a candidate PASS',()=>{const x=structuredClone(matrix);x.rows.find(r=>r.kind==='O'&&r.mode==='prohibit').status='UNSUPPORTED';json('compatibility-observations.json',x);assert.throws(()=>trial.Candidates(out,'prohibit'),/PROFILE_UNSUPPORTED/);json('compatibility-observations.json',matrix);});
 const selected=ProvisionSyntheticCurrent(policy);let state;
 test('fresh fixture registers real signatures and all profiles via production APIs',()=>{state=trial.Register(run,out,'prohibit',key);assert.deepEqual(Object.keys(state.ids),['A','B','O']);for(const role of ['A','B','O']){const env=matrix.rows.find(r=>r.kind===(role==='O'?'O':'AB')).environment;assert.equal(profiles.Select(selected[role],env,{dynamicCode:'observe',requireCfg:false}).id,state.ids[role]);}});
 test('profile uses the existing trusted release signer and exports no key',()=>{const db=store.Load();assert.equal(db.securityAuthorityPolicy.trustedReleaseKeys.length,1);assert.equal(db.securityAuthorityPolicy.trustedReleaseKeys[0].keyId,keyId);assert.equal(fs.readdirSync(out).some(n=>/private|profile.*pem/.test(n)),false);});
 test('profile signer must remain inside the owned fixture',()=>{assert.throws(()=>trial.Register(run,out,'prohibit',path.join(temp,'outside.pem')),/PROFILE_PRIVATE_KEY_REQUIRED/);const link=path.join(run,'linked.pem');fs.symlinkSync(key,link);try{assert.throws(()=>trial.Register(run,out,'prohibit',link),/PROFILE_PRIVATE_KEY_REQUIRED/);}finally{fs.unlinkSync(link);}});
 test('untrusted private keys cannot become profile signers',()=>{const other=path.join(run,'untrusted.pem'),foreign=crypto.generateKeyPairSync('ed25519');fs.writeFileSync(other,foreign.privateKey.export({type:'pkcs8',format:'pem'}));try{assert.throws(()=>trial.Register(run,out,'prohibit',other),/PROFILE_SIGNING_KEY_UNTRUSTED/);}finally{fs.unlinkSync(other);}});
 test('profile registration fabricates no native observation',()=>{const status=trial.Status(state);assert.equal(status.enabled,true);assert.deepEqual(status.authorityStages,[]);});
 test('unrelated DATA_DIR refused',()=>{const prior=process.env.DATA_DIR;process.env.DATA_DIR=temp;try{assert.throws(()=>trial.Register(run,out,'prohibit',key),/PRIVATE_PROFILE_FIXTURE_REQUIRED/);}finally{process.env.DATA_DIR=prior;}});
 test('profile expiry after challenge rejects signed submit, receipt recovery and decision use',()=>{
  const f=require("../bootstrap/peace.desktop-bootstrap-fixture"),boot=require("../../../services/bootstrap/peace.desktop-bootstrap"),auth=require("../../../services/security/peace.desktop-security-authority"),device=f.Device(),started=f.Begin(device,{handoffVersion:3}),row=boot.Initialize().flows[started.begin.flowId];
  const context={action:'challenge',stage:'A',sessionId:started.begin.flowId,sessionToken:started.begin.downloadTicket,machineId:device.machineId,intent:'finish',binding:auth.Binding(started.begin.flowId,started.begin.release.sha512)};
  const environment=matrix.rows.find(r=>r.kind==='AB').environment,deadline=Math.min(...Object.values(store.Load().mitigationProfiles.entries).map(r=>r.envelope.statement.expiresAt)),real=Date.now;let time=deadline-1000;Date.now=()=>time;
  try{
   function request(c,requestContext=context){const b=boot.AuthenticateIntegrityReport(requestContext).integrityArtifact,d={version:2,profileId:state.ids.A,requestedMode:'prohibit',setAttempted:false,setSucceeded:false,setError:0,strictSetAttempted:false,strictSetSucceeded:false,strictSetError:0,imageSetAttempted:false,imageSetSucceeded:false,imageSetError:0};for(const n of ['dynamic','cfg','strictHandle','imageLoad']){d[n+'Queried']=true;d[n+'Flags']=0;d[n+'Error']=0;}d.dynamicFlags=1;d.strictHandleFlags=3;d.imageLoadFlags=3;const payload=JSON.stringify({version:1,hashVersion:3,measurement:'MEASURED',fileSha512:b.sha512,fileCrc64:b.crc64,codeSha512:b.codeSha512,codeCrc64:b.codeCrc64,codeXxh3_128:b.codeXxh3_128,codeBlake3:b.codeBlake3,crcLayers:b.crcLayers,apiSealed:true,apiSlots:60,cfg:'DISABLED',dynamicCode:'PROHIBITED',mitigationDiagnostics:d});return{...requestContext,action:'submit',challengeId:c.challengeId,payload,signature:f.Sign(device,auth.Canonical(requestContext,c,payload))};}
   const first=auth.Execute({...context,mitigationProfileVersion:1,mitigationEnvironment:environment}),response=request(first);assert.equal(auth.Execute(response).status,'PASS');auth.RequireFresh(row,'A','finish',context.binding);
   const pendingContext={...context,binding:auth.Binding('audit-profile-expiry',started.begin.release.sha512)},pending=auth.Execute({...pendingContext,mitigationProfileVersion:1,mitigationEnvironment:environment}),signed=request(pending,pendingContext);
   // Keep this independent request from superseding the in-flight audit race.
   const laterContext={...context,binding:auth.Binding('later-profile-expiry',started.begin.release.sha512)},later=auth.Execute({...laterContext,mitigationProfileVersion:1,mitigationEnvironment:environment}),expiredSubmit=request(later,laterContext);
   const audit=require("../../../storage/audit/peace.audit.js"),log=audit.LogEvent;let delayed=false;
   audit.LogEvent=(kind,message)=>{const result=log(kind,message);if(kind==='DESKTOP_SECURITY_AUTHORITY'&&JSON.parse(message).kind==='OBSERVATION'){delayed=true;time=deadline+1;}return result;};
   try{assert.throws(()=>auth.Execute(signed),/SECURITY_MITIGATION_EVIDENCE_UNTRUSTED/);assert.equal(delayed,true);}finally{audit.LogEvent=log;}
   time=deadline+1;
   assert.throws(()=>auth.Execute(signed),/SECURITY_CHALLENGE_INVALID/);assert.throws(()=>auth.Execute(expiredSubmit),/SECURITY_MITIGATION_EVIDENCE_UNTRUSTED/);
   for(const action of [()=>auth.Execute(response),()=>auth.RequireFresh(row,'A','finish',context.binding),()=>auth.RenewalIdentity(row,'A','finish',context.binding)])assert.throws(action,/SECURITY_MITIGATION_EVIDENCE_UNTRUSTED/);
  }finally{Date.now=real;}
 });
 console.log(`Profile fixture: ${count} PASS; actual Windows profile workflow NOT RUN`);
}finally{fs.rmSync(temp,{recursive:true,force:true});}
