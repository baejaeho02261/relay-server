'use strict';
// CI-only immutable source snapshot / approvals / automatic report assembly.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const provenance=require('../tools/release-provenance'),p=require('../services/desktopReleaseProvenance');
const hash=b=>crypto.createHash('sha512').update(b).digest('hex');
function ReadBytes(file,max){const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.size>max)throw Error('CI_INPUT_FILE_INVALID');const fd=fs.openSync(file,'r');try{const before=fs.fstatSync(fd);if(!before.isFile()||before.size>max)throw Error('CI_INPUT_FILE_INVALID');const bytes=Buffer.alloc(before.size+1);let total=0,n;while(total<bytes.length&&(n=fs.readSync(fd,bytes,total,bytes.length-total,null))>0)total+=n;const after=fs.fstatSync(fd);if(total!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw Error('CI_INPUT_FILE_CHANGED');return bytes.subarray(0,total);}finally{fs.closeSync(fd);}}
function ReadJson(file,max=8*1024*1024){const bytes=ReadBytes(file,max);return require('../services/strictJson').Parse(bytes.subarray(bytes.length>=3&&bytes[0]===239&&bytes[1]===187&&bytes[2]===191?3:0),{maxBytes:max,maxNodes:4000000});}
function NewJson(file,value){fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});}
function Contained(root,name){if(typeof name!=='string'||!name||name.includes('\\')||name.includes(':')||path.isAbsolute(name)||name.split('/').some(x=>!x||x==='.'||x==='..'))throw Error('CI_SOURCE_PATH_INVALID');const file=path.resolve(root,name);if(!file.startsWith(path.resolve(root)+path.sep))throw Error('CI_SOURCE_PATH_INVALID');return file;}
function Snapshot(root,destination){if(fs.existsSync(destination))throw Error('CI_SNAPSHOT_EXISTS');const manifestFile=path.join(root,'GameWeb/maintenance/source-manifest.json'),manifestBytes=ReadBytes(manifestFile,8*1024*1024),m=require('../services/strictJson').Parse(manifestBytes.subarray(manifestBytes.length>=3&&manifestBytes[0]===239&&manifestBytes[1]===187&&manifestBytes[2]===191?3:0),{maxBytes:8*1024*1024,maxNodes:4000000});if(!m||m.version!==2||m.algorithm!=='sha512'||!m.files||typeof m.files!=='object'||Array.isArray(m.files)||Object.keys(m.files).length===0||Object.keys(m.files).length>10000)throw Error('CI_SOURCE_MANIFEST_INVALID');
 let total=0;for(const name of Object.keys(m.files)){total+=fs.lstatSync(Contained(root,name)).size;if(total>256*1024*1024)throw Error('CI_SOURCE_TOTAL_LIMIT');}
 fs.mkdirSync(destination,{recursive:false,mode:0o700});
 for(const [name,expected]of Object.entries(m.files)){const src=Contained(root,name);let cursor=path.resolve(root);for(const part of name.split('/')){cursor=path.join(cursor,part);if(fs.lstatSync(cursor).isSymbolicLink())throw Error('CI_SOURCE_SYMLINK');}const stat=fs.statSync(src);if(!stat.isFile()||stat.size>64*1024*1024||!/^[a-f0-9]{128}$/.test(expected))throw Error('CI_SOURCE_FILE_INVALID');const bytes=ReadBytes(src,64*1024*1024);if(hash(bytes)!==expected)throw Error('CI_SOURCE_HASH_MISMATCH');const target=Contained(destination,name);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,bytes,{flag:'wx',mode:0o600});}
 const target=path.join(destination,'GameWeb/maintenance/source-manifest.json');fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,manifestBytes,{flag:'wx',mode:0o600});return{files:Object.keys(m.files).length,sourceManifestSha512:hash(manifestBytes)};
}
function PrivateKey(file){const bytes=ReadBytes(file,16384);try{const key=crypto.createPrivateKey(bytes);if(key.asymmetricKeyType!=='ed25519')throw Error('CI_ED25519_KEY_REQUIRED');return key;}finally{bytes.fill(0);}}
function Prepare(out,keyFile,version,securityVersion,toolchainFile,sourceManifest,policyFile){if(!/^\d+(?:\.\d+){0,3}$/.test(version))throw Error('CI_VERSION_INVALID');const key=PrivateKey(keyFile),pub=crypto.createPublicKey(key),keyId=p.KeyId(pub),publicKey=pub.export({type:'spki',format:'pem'}).toString();
 const auditFile=path.join(out,'final-artifact-audit.json');if(!fs.existsSync(auditFile))throw Error('CI_FINAL_AUDIT_REQUIRED');const audit=ReadJson(auditFile);if(audit.version!==1||audit.kind!=='FINAL_FILE_INSPECTION_NOT_RUNTIME_ATTESTATION'||audit.artifacts?.O?.overlayManifest?.status!=='EXACT_SOURCE_BYTES_MATCH')throw Error('CI_FINAL_AUDIT_INVALID');
 const before=ReadJson(path.join(out,'build-inputs.json')),after=ReadJson(path.join(out,'build-inputs-after.json'));if([before,after].some(x=>x.version!==1||x.status!=='PASS'||!Number.isSafeInteger(x.files)||x.files<1||!(/^[a-f0-9]{128}$/.test(x.inputSha512||''))||!(/^[a-f0-9]{128}$/.test(x.sdkHeaderSha512||'')))||before.inputSha512!==after.inputSha512||before.sdkHeaderSha512!==after.sdkHeaderSha512)throw Error('CI_REVIEWED_BUILD_INPUT_LOCK_REQUIRED');
 const artifacts={};for(const role of ['A','B','O']){const digest=provenance.FileHash(path.join(out,role+'.exe'),64*1024*1024);if(audit&&(audit.version!==1||audit.artifacts?.[role]?.sha512!==digest))throw Error('CI_FINAL_AUDIT_HASH_MISMATCH');artifacts[role]=digest;const canonical=['GAME-RELEASE-APPROVAL-V2',role,version,digest].join('\n');NewJson(path.join(out,role+'.approval.json'),{keyId,signature:crypto.sign(null,Buffer.from(canonical),key).toString('base64')});}
 // Immutable CI fixture policy; exact same complete policy is applied by the
 // isolated production services and committed into the deployment manifest.
 let policy={version:1,revision:1,mode:'enforce',enforceLegacy:false,freshnessMs:45000,challengeMs:15000,requireReadonlyApi:true,requireCompleteCrcLayers:true,dynamicCode:'observe',requireCfg:false,minVersionA:'0',minVersionB:'0',minVersionO:'0',requireReleaseSignature:true,trustedReleaseKeys:[{keyId,publicKey}],revokedSha512:[],revokedLegacySha256:[]};
 if(policyFile)policy=ReadJson(policyFile,65536);
 policy=require('../services/desktopSecurityAuthority').ValidatePolicy(policy);
 if(policy.requireCfg)throw Error('CI_CFG_INSTRUMENTATION_NOT_VERIFIED_BY_CLASSIC_PIPELINE');
 if(policy.mode!=='enforce'||!policy.requireReadonlyApi||!policy.requireCompleteCrcLayers||!policy.requireReleaseSignature)throw Error('CI_POLICY_REQUIRED_PROTECTIONS');
 if(!policy.trustedReleaseKeys.some(k=>k.keyId===keyId&&p.KeyId(crypto.createPublicKey(k.publicKey))===keyId))throw Error('CI_POLICY_APPROVAL_KEY_MISMATCH');
 NewJson(path.join(out,'policy.json'),policy);
 const toolchain=ReadJson(toolchainFile),spec={version:1,releaseName:'Windows CI '+version,securityVersion:Number(securityVersion),protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,toolchain};
 NewJson(path.join(out,'spec.json'),spec);const manifest=provenance.MakeManifest(path.join(out,'spec.json'),path.join(out,'A.exe'),path.join(out,'B.exe'),path.join(out,'O.exe'),sourceManifest,path.join(out,'policy.json'));provenance.Write(path.join(out,'manifest.json'),manifest);
 return{manifestId:manifest.manifestId,releaseKeyId:keyId};
}
function Outcome(stages,names){if(names.some(n=>stages[n]?.outcome==='FAIL'))return'FAIL';return names.every(n=>stages[n]?.outcome==='PASS'&&stages[n].exitCode===0)?'PASS':'NOT_RUN';}
function LogIndex(directory){const files=fs.readdirSync(directory).filter(n=>/^[a-z0-9-]+\.log$/.test(n)&&!['report.log','sign.log'].includes(n)).sort();if(!files.length)throw Error('CI_LOGS_MISSING');return{version:1,files:files.map(name=>{const file=path.join(directory,name),s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.size>64*1024*1024)throw Error('CI_LOG_INVALID');return{name,sha512:hash(fs.readFileSync(file))};})};}
function FullProfileWorkflow(out,stages,mode){
 if(Outcome(stages,['profile-integration-'+mode])!=='PASS')return false;
 const result=ReadJson(path.join(out,'integration-profile-'+mode+'-result.json'));
 if(result.version!==1||result.outcome!=='PASS'||result.mitigationMode!==mode||!Array.isArray(result.profiledAuthorityStages)||result.profiledAuthorityStages.slice().sort().join(',')!=='A,B,O'||['ready','licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed'].some(k=>result[k]!==true))throw Error('CI_PROFILE_WORKFLOW_RESULT_INVALID');
 return true;
}
function Report(out,resultsFile){const result=ReadJson(resultsFile),m=provenance.LoadManifest(path.join(out,'manifest.json')),index=LogIndex(path.join(out,'logs'));NewJson(path.join(out,'logs-index.json'),index);
 const report={version:1,...Object.fromEntries(['A','B','O'].map(k=>[k.toLowerCase()+'Sha512',m.manifest.artifacts[k]])),sourceManifestSha512:m.manifest.sourceManifestSha512,nativeBuild:Outcome(result.stages,['build-inputs','build','build-inputs-after','normalize','approve']),apiProbe:Outcome(result.stages,['native-probes','native-hash-compare','overlay-contracts','compatibility-probes','device-identity','sdk-probe','abi-compare']),integration:Outcome(result.stages,['integration']),logsSha512:provenance.FileHash(path.join(out,'logs-index.json'),8*1024*1024)};
 for(const k of ['A','B','O'])if(provenance.FileHash(path.join(out,k+'.exe'),64*1024*1024)!==m.manifest.artifacts[k])throw Error('CI_ARTIFACT_CHANGED_AFTER_TEST');
 if(fs.existsSync(path.join(out,'compatibility-observations.json'))){
  const matrix=ReadJson(path.join(out,'compatibility-observations.json')),profile=require('../services/desktopMitigationProfiles'),input=ReadJson(path.join(out,'build-inputs-after.json'));
  if(matrix.version!==1||matrix.kind!=='ACTUAL_WINDOWS_LINKED_RELEASE_UNIT_MATRIX'||matrix.windowsExecuted!==true||!Array.isArray(matrix.rows)||matrix.rows.length!==4||new Set(matrix.rows.map(r=>r.kind+':'+r.mode)).size!==4||matrix.rows.some(r=>!['AB:observe','AB:prohibit','O:observe','O:prohibit'].includes(r.kind+':'+r.mode))||input.status!=='PASS')throw Error('CI_COMPATIBILITY_MATRIX_INVALID');
  const statements=[];
  if(report.integration==='PASS'&&Outcome(result.stages,['compatibility-probes'])==='PASS')for(const row of matrix.rows){
   const workflow=result.stages['profile-integration-'+row.mode];if(workflow?.outcome==='FAIL'||workflow?.exitCode!==undefined&&workflow?.exitCode!==null&&workflow.exitCode!==0)continue;
   if(row.status==='UNSUPPORTED')continue;if(row.status!=='PASS'||!['AB','O'].includes(row.kind)||row.settings?.dynamicCode!==row.mode||row.settings?.strictHandles!==true||row.settings?.imageLoadMask!==3||row.settings?.requireCfg!==false||row.testedAt>Date.now())throw Error('CI_COMPATIBILITY_MATRIX_INVALID');
   for(const component of row.kind==='AB'?['A','B']:['O'])statements.push(profile.Statement({version:1,manifestId:m.manifestId,component,artifactSha512:m.manifest.artifacts[component],buildInputSha512:input.inputSha512,environment:row.environment,settings:row.settings,testedAt:row.testedAt,expiresAt:row.testedAt+7*86400000,windowsExecuted:true,integration:'PASS',policyReadback:'PASS',cfgInstrumentation:'NOT_REQUESTED',logsSha512:report.logsSha512,testScope:FullProfileWorkflow(out,result.stages,row.mode)?'FULL_ABO_WORKFLOW_UNDER_PROFILE':'NATIVE_LINKED_RELEASE_UNITS_AND_BASE_WORKFLOW'}));
  }
  const compatibility={version:1,profileIds:statements.map(statement=>profile.Id({statement})).sort()};
  report.version=2;report.buildInputSha512=input.inputSha512;report.compatibilitySha512=profile.CompatibilityHash(compatibility);
  NewJson(path.join(out,'compatibility-statements.json'),{version:1,compatibility,statements});
 }
 NewJson(path.join(out,'report.json'),report);return report;
}
function Sign(out,keyFile,runId){
 const key=PrivateKey(keyFile),pub=crypto.createPublicKey(key),keyId=p.KeyId(pub),policy=ReadJson(path.join(out,'policy.json'));
 if(policy.trustedReleaseKeys.some(k=>k.keyId===keyId))throw Error('CI_KEY_PURPOSE_CONFLICT');
 // Validate every attachment and destination before producing any signed file.
 // An invalid optional attachment must not leave an otherwise publishable CI envelope.
 const report=ReadJson(path.join(out,'report.json')),manifest=provenance.LoadManifest(path.join(out,'manifest.json')),pending=[];
 if(report.version===2){
  const attached=ReadJson(path.join(out,'compatibility-statements.json')),profile=require('../services/desktopMitigationProfiles');
  if(!attached||Object.keys(attached).sort().join(',')!=='compatibility,statements,version'||attached.version!==1||!Array.isArray(attached.statements)||attached.statements.length>64||profile.CompatibilityHash(attached.compatibility)!==report.compatibilitySha512)throw Error('CI_COMPATIBILITY_BINDING_INVALID');
  const ids=[],targets=new Set(),now=Date.now();
  for(const statement of attached.statements){
   profile.Statement(statement);const id=profile.Id({statement}),target='mitigation-'+statement.component+'-'+statement.settings.dynamicCode+'.json';
   if(statement.buildInputSha512!==report.buildInputSha512||statement.logsSha512!==report.logsSha512||statement.manifestId!==manifest.manifestId||statement.artifactSha512!==manifest.manifest.artifacts[statement.component]||statement.testedAt>now||statement.expiresAt<=now||targets.has(target))throw Error('CI_COMPATIBILITY_BINDING_INVALID');
   ids.push(id);targets.add(target);pending.push({target,statement,compatibility:attached.compatibility});
  }
  if(new Set(ids).size!==ids.length||ids.sort().join(',')!==attached.compatibility.profileIds.slice().sort().join(','))throw Error('CI_COMPATIBILITY_BINDING_INVALID');
  if(pending.length&&['nativeBuild','apiProbe','integration'].some(k=>report[k]!=='PASS'))throw Error('CI_COMPATIBILITY_BINDING_INVALID');
 }
 const targets=['ci-evidence.json','ci-public-key.pem',...pending.map(x=>x.target)];
 if(targets.some(name=>fs.existsSync(path.join(out,name))))throw Error('CI_OUTPUT_ALREADY_EXISTS');
 const envelope=provenance.Sign(path.join(out,'manifest.json'),path.join(out,'report.json'),keyFile,runId);
 // Recheck the immutable inputs consumed by the signing helper before publishing.
 if(p.Stable(report)!==p.Stable(ReadJson(path.join(out,'report.json')))||p.Stable(manifest)!==p.Stable(provenance.LoadManifest(path.join(out,'manifest.json'))))throw Error('CI_INPUT_FILE_CHANGED');
 const profiles=pending.map(x=>({target:x.target,envelope:require('../services/desktopMitigationProfiles').Envelope({keyId,statement:x.statement,compatibility:x.compatibility,signature:crypto.sign(null,Buffer.from(require('../services/desktopMitigationProfiles').Canonical(x.statement)),key).toString('base64')})}));
 provenance.Write(path.join(out,'ci-evidence.json'),envelope);
 fs.writeFileSync(path.join(out,'ci-public-key.pem'),pub.export({type:'spki',format:'pem'}),{flag:'wx',mode:0o600});
 for(const item of profiles)NewJson(path.join(out,item.target),item.envelope);
 provenance.Verify(path.join(out,'manifest.json'),path.join(out,'ci-evidence.json'),path.join(out,'ci-public-key.pem'));
 return{keyId,signed:true};}

if(require.main===module){try{const [command,...args]=process.argv.slice(2);let result;if(command==='snapshot'&&args.length===2)result=Snapshot(...args);else if(command==='prepare'&&[6,7].includes(args.length))result=Prepare(...args);else if(command==='report'&&args.length===2)result=Report(...args);else if(command==='sign'&&args.length===3)result=Sign(...args);else throw Error('CI_ARGUMENT_INVALID');console.log(JSON.stringify(result));}catch(error){console.error(/^CI_[A-Z0-9_]+$/.test(error.message)?error.message:'CI_ARTIFACT_OPERATION_FAILED');process.exitCode=1;}}
module.exports={Snapshot,Contained,Prepare,Outcome,LogIndex,FullProfileWorkflow,Report,Sign};
