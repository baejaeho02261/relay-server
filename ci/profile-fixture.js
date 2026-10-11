'use strict';
// Isolated Windows test server only. A fresh, in-memory signer grants test
// profiles from already completed actual probe/baseline observations. Its key
// and evidence never leave the private fixture or become release CI evidence.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const p=require('../services/desktopReleaseProvenance'),profiles=require('../services/desktopMitigationProfiles');
const hash=x=>crypto.createHash('sha512').update(x).digest('hex');
function Read(file){return require('../services/strictJson').Parse(require('../services/boundedArtifactRead').Read(file,8*1024*1024),{maxBytes:8*1024*1024});}
function Candidates(out,mode){
 if(!['observe','prohibit'].includes(mode))throw Error('CI_PROFILE_MODE_INVALID');
 const result=Read(path.join(out,'runner-results.json')),ci=require('./ci-artifacts');
 const names=['build-inputs','build','build-inputs-after','normalize','approve','native-probes','native-hash-compare','overlay-contracts','compatibility-probes','device-identity','sdk-probe','abi-compare','integration'];
 if(ci.Outcome(result.stages,names)!=='PASS')throw Error('CI_PROFILE_PREREQUISITE_NOT_PASS');
 const input=Read(path.join(out,'build-inputs-after.json')),matrix=Read(path.join(out,'compatibility-observations.json')),manifest=require('../tools/release-provenance').LoadManifest(path.join(out,'manifest.json'));
 if(input.version!==1||input.status!=='PASS'||! /^[a-f0-9]{128}$/.test(input.inputSha512||'')||matrix.version!==1||matrix.windowsExecuted!==true||matrix.kind!=='ACTUAL_WINDOWS_LINKED_RELEASE_UNIT_MATRIX'||!Array.isArray(matrix.rows))throw Error('CI_PROFILE_INPUT_INVALID');
 const rows=matrix.rows.filter(r=>r.mode===mode);
 if(rows.length!==2||new Set(rows.map(r=>r.kind)).size!==2||rows.some(r=>!['AB','O'].includes(r.kind)||r.status!=='PASS'||r.settings?.dynamicCode!==mode||r.settings?.strictHandles!==true||r.settings?.imageLoadMask!==3||r.settings?.requireCfg!==false))throw Error('CI_PROFILE_UNSUPPORTED');
 const logs=['compatibility-probes','integration'].map(n=>({name:n+'.log',sha512:hash(fs.readFileSync(path.join(out,'logs',n+'.log')))})),logsSha512=hash(p.Stable(logs)),now=Date.now();
 const statements=[];
 for(const row of rows)for(const component of row.kind==='AB'?['A','B']:['O'])statements.push(profiles.Statement({version:1,manifestId:manifest.manifestId,component,artifactSha512:manifest.manifest.artifacts[component],buildInputSha512:input.inputSha512,environment:row.environment,settings:row.settings,testedAt:row.testedAt,expiresAt:now+600000,windowsExecuted:true,integration:'PASS',policyReadback:'PASS',cfgInstrumentation:'NOT_REQUESTED',logsSha512,testScope:'NATIVE_LINKED_RELEASE_UNITS_AND_BASE_WORKFLOW'}));
 if(statements.some(s=>s.testedAt>now))throw Error('CI_PROFILE_INPUT_INVALID');
 return {statements,manifestId:manifest.manifestId,logsSha512,buildInputSha512:input.inputSha512};
}
function Register(run,out,mode){
 const root=fs.realpathSync(run),data=path.join(root,'server-data'),store=require('../services/desktopBootstrapStore'),ops=require('../services/desktopSecurityOperations');
 if(!fs.existsSync(path.join(root,'ci-owned-marker'))||path.resolve(process.env.DATA_DIR||'')!==data||require('../config/config').DATA_DIR!==data||Object.keys(store.Load().flows).length)throw Error('CI_PRIVATE_PROFILE_FIXTURE_REQUIRED');
 const candidate=Candidates(out,mode),now=Date.now(),actor='ISOLATED_PROFILE_WORKFLOW_CI';
 if(require('../services/desktopSecurityAuthority').Policy().dynamicCode==='prohibit'&&mode!=='prohibit')throw Error('CI_PROFILE_BASE_POLICY_STRONGER');
 const pair=crypto.generateKeyPairSync('ed25519'),publicKey=pair.publicKey.export({type:'spki',format:'pem'}).toString(),keyId=p.KeyId(pair.publicKey);
 ops.SetCiSigner({expectedRevision:ops.Revision(),keyId,state:'ACTIVE',publicKey,notBefore:Math.min(...candidate.statements.map(s=>s.testedAt))-1,notAfter:now+600000},actor);
 const compatibility={version:1,profileIds:candidate.statements.map(statement=>profiles.Id({statement})).sort()};
 const statement={version:2,purpose:p.CI_DOMAIN,manifestId:candidate.manifestId,runId:'ISOLATED_FIXTURE_'+crypto.randomUUID(),issuedAt:now,nativeBuild:'PASS',apiProbe:'PASS',integration:'PASS',logsSha512:candidate.logsSha512,buildInputSha512:candidate.buildInputSha512,compatibilitySha512:profiles.CompatibilityHash(compatibility)};
 const envelope={keyId,statement,signature:crypto.sign(null,Buffer.from(p.Canonical(statement)),pair.privateKey).toString('base64')};
 ops.RecordCiEvidence({expectedRevision:ops.Revision(),envelope},actor);
 const ids={};for(const statement of candidate.statements){const envelope={keyId,statement,compatibility,signature:crypto.sign(null,Buffer.from(profiles.Canonical(statement)),pair.privateKey).toString('base64')};const result=profiles.Register({requestId:crypto.randomUUID(),envelope,enabled:true,expectedOperationsRevision:ops.Revision()},actor);ids[statement.component]=result.profileId;}
 return {mode,ids,seen:new Set()};
}
function Status(state){if(!state)return undefined;const view=require('../services/desktopSecurityAuthority').List();for(const e of view.events)if(e.kind==='OBSERVATION'&&e.reason==='BASELINE_MATCH'&&Object.hasOwn(state.ids,e.stage))state.seen.add(e.stage);const current=view.mitigationProfiles.profiles;const enabled=Object.entries(state.ids).every(([component,id])=>current.some(r=>r.id===id&&r.component===component&&r.enabled&&r.usable));return{mode:state.mode,enabled,authorityStages:[...state.seen].sort()};}
module.exports={Candidates,Register,Status};
