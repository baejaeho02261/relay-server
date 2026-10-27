'use strict';
// Isolated Windows test server only. An explicitly supplied fixture release key
// signs profiles from completed probe/baseline observations. It is never logged
// or exported and cannot authorize production without separate operator review.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const p=require("../../services/artifacts/peace.desktop-release-provenance"),profiles=require("../../services/security/peace.desktop-mitigation-profiles");
const hash=x=>crypto.createHash('sha512').update(x).digest('hex');
function Read(file){return require("../../services/protocol/peace.strict-json").Parse(require("../../services/artifacts/peace.bounded-artifact-read").Read(file,8*1024*1024),{maxBytes:8*1024*1024});}
function Candidates(out,mode){
 if(!['observe','prohibit'].includes(mode))throw Error('WINDOWS_TEST_PROFILE_MODE_INVALID');
 const result=Read(path.join(out,'runner-results.json')); 
 const names=['compatibility-probes','integration'];
 if(names.some(n=>result.stages?.[n]?.outcome!=='PASS'||result.stages[n].exitCode!==0))throw Error('WINDOWS_TEST_PROFILE_PREREQUISITE_NOT_PASS');
 const input=Read(path.join(out,'build-inputs-after.json')),matrix=Read(path.join(out,'compatibility-observations.json')),manifest=require("../../tools/artifacts/peace.release-provenance").LoadManifest(path.join(out,'manifest.json'));
 if(input.version!==1||input.status!=='PASS'||! /^[a-f0-9]{128}$/.test(input.inputSha512||'')||matrix.version!==1||matrix.windowsExecuted!==true||matrix.kind!=='ACTUAL_WINDOWS_LINKED_RELEASE_UNIT_MATRIX'||!Array.isArray(matrix.rows))throw Error('WINDOWS_TEST_PROFILE_INPUT_INVALID');
 const rows=matrix.rows.filter(r=>r.mode===mode);
 if(rows.length!==2||new Set(rows.map(r=>r.kind)).size!==2||rows.some(r=>!['AB','O'].includes(r.kind)||r.status!=='PASS'||r.settings?.dynamicCode!==mode||r.settings?.strictHandles!==true||r.settings?.imageLoadMask!==3||r.settings?.requireCfg!==false))throw Error('WINDOWS_TEST_PROFILE_UNSUPPORTED');
 const logs=['compatibility-probes','integration'].map(n=>({name:n+'.log',sha512:hash(fs.readFileSync(path.join(out,'logs',n+'.log')))})),logsSha512=hash(p.Stable(logs)),now=Date.now();
 const statements=[];
 for(const row of rows)for(const component of row.kind==='AB'?['A','B']:['O'])statements.push(profiles.Statement({version:1,manifestId:manifest.manifestId,component,artifactSha512:manifest.manifest.artifacts[component],buildInputSha512:input.inputSha512,environment:row.environment,settings:row.settings,testedAt:row.testedAt,expiresAt:now+600000,windowsExecuted:true,integration:'PASS',policyReadback:'PASS',cfgInstrumentation:'NOT_REQUESTED',logsSha512,testScope:'NATIVE_LINKED_RELEASE_UNITS_AND_BASE_WORKFLOW'}));
 if(statements.some(s=>s.testedAt>now))throw Error('WINDOWS_TEST_PROFILE_INPUT_INVALID');
 return {statements,manifestId:manifest.manifestId,logsSha512,buildInputSha512:input.inputSha512};
}
function Register(run,out,mode,keyFile){
 const root=fs.realpathSync(run),data=path.join(root,'server-data'),store=require("../../services/bootstrap/peace.desktop-bootstrap-store"),ops=require("../../services/security/peace.desktop-security-operations");
 if(!fs.existsSync(path.join(root,'test-owned-marker'))||path.resolve(process.env.DATA_DIR||'')!==data||require("../../config/peace.runtime-configuration").DATA_DIR!==data||Object.keys(store.Load().flows).length)throw Error('WINDOWS_TEST_PRIVATE_PROFILE_FIXTURE_REQUIRED');
 const candidate=Candidates(out,mode),now=Date.now(),actor='ISOLATED_PROFILE_WORKFLOW_TEST';
 if(require("../../services/security/peace.desktop-security-authority").Policy().dynamicCode==='prohibit'&&mode!=='prohibit')throw Error('WINDOWS_TEST_PROFILE_BASE_POLICY_STRONGER');
 // A profile is signed with an existing trusted release key in this isolated
 // fixture. No signer registry or fabricated execution statement is created.
 const parent=path.dirname(root),parents=[root];
 if(fs.existsSync(path.join(parent,'test-owned-marker'))&&fs.readFileSync(path.join(parent,'test-owned-marker'),'utf8')==='GAME_WINDOWS_TEST_V1')parents.push(parent);
 if(typeof keyFile!=='string'||!path.isAbsolute(keyFile)||!parents.some(base=>path.resolve(keyFile).startsWith(base+path.sep)))throw Error('WINDOWS_TEST_PROFILE_PRIVATE_KEY_REQUIRED');
 const resolved=path.resolve(keyFile);let cursor=path.dirname(resolved);
 while(true){const stat=fs.lstatSync(cursor);if(stat.isSymbolicLink()||!stat.isDirectory())throw Error('WINDOWS_TEST_PROFILE_PRIVATE_KEY_REQUIRED');const next=path.dirname(cursor);if(next===cursor)break;cursor=next;}
 const keyStat=fs.lstatSync(resolved);if(!keyStat.isFile()||keyStat.isSymbolicLink()||keyStat.nlink!==1)throw Error('WINDOWS_TEST_PROFILE_PRIVATE_KEY_REQUIRED');
 const keyBytes=require("../../services/artifacts/peace.bounded-artifact-read").Read(keyFile,16384);let privateKey;
 try{privateKey=crypto.createPrivateKey(keyBytes);}finally{keyBytes.fill(0);}
 if(privateKey.asymmetricKeyType!=='ed25519')throw Error('WINDOWS_TEST_PROFILE_SIGNING_KEY_INVALID');
 const publicKey=crypto.createPublicKey(privateKey),keyId=p.KeyId(publicKey),policy=require("../../services/security/peace.desktop-security-authority").Policy();
 if(!policy.trustedReleaseKeys.some(k=>k.keyId===keyId))throw Error('WINDOWS_TEST_PROFILE_SIGNING_KEY_UNTRUSTED');
 const compatibility={version:1,profileIds:candidate.statements.map(statement=>profiles.Id({statement})).sort()};
 const ids={};for(const statement of candidate.statements){const envelope={keyId,statement,compatibility,signature:crypto.sign(null,Buffer.from(profiles.Canonical(statement)),privateKey).toString('base64')};const result=profiles.Register({requestId:crypto.randomUUID(),envelope,enabled:true,expectedOperationsRevision:ops.Revision()},actor);ids[statement.component]=result.profileId;}
 return {mode,ids,seen:new Set()};
}
function Status(state){if(!state)return undefined;const view=require("../../services/security/peace.desktop-security-authority").List();for(const e of view.events)if(e.kind==='OBSERVATION'&&e.reason==='BASELINE_MATCH'&&Object.hasOwn(state.ids,e.stage))state.seen.add(e.stage);const current=view.mitigationProfiles.profiles;const enabled=Object.entries(state.ids).every(([component,id])=>current.some(r=>r.id===id&&r.component===component&&r.enabled&&r.usable));return{mode:state.mode,enabled,authorityStages:[...state.seen].sort()};}
module.exports={Candidates,Register,Status};
