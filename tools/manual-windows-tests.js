'use strict';
// Execution-only diagnostics. No compiler, production store, operator key,
// publication approval or CI attestation is used by this tool.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const ROOT=path.resolve(__dirname,'../..'),WEB=path.join(ROOT,'GameWeb');
const hash=b=>crypto.createHash('sha512').update(b).digest('hex');
const read=(file,max=64*1024*1024)=>require('../services/boundedArtifactRead').Read(file,max);
const json=file=>JSON.parse(read(file,8*1024*1024).toString('utf8').replace(/^\uFEFF/,''));
const write=(file,value)=>fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
const PROBES=['StartupProbe','NativeAbiProbe','PeCorpusProbe','IntegrityHashProbe','CrcProbe','CrcPeProbe','HashProbe','HashContracts','Blake3ParallelProbe','HandoffKdfProbe','HandoffCryptoProbe','HandoffPipeProbe','HandoffProcessProbe','DeterministicStateProbe','HardeningContractsProbe','MeasurementLifetimeProbe','ModuleGenerationFixture','ThreadInventoryProbe','DeviceSignalsProbe','NativeApiContractsProbe','DeviceKeyContractProbe','OverlayFirstFrameProbe','OverlayPrivacyProbe','OverlayShutdownProbe','OverlayGpuFaultProbe','ProcessMitigationProfileProbe','NativeAbiSdkProbe'];
function Config(c){
 if(!c||c.version!==1||Object.keys(c).some(k=>!['version','probeDirectory','probes','artifacts','faultArtifacts','verificationContext','releaseVersion','runIntegration','collectHardwareSignals'].includes(k)))throw Error('MANUAL_INPUT_INVALID');
 if(typeof c.probeDirectory!=='string'||!path.isAbsolute(c.probeDirectory))throw Error('MANUAL_PROBE_DIRECTORY_ABSOLUTE_REQUIRED');
 for(const [key,value] of Object.entries(c.probes||{}))if(!PROBES.includes(key)||typeof value!=='string'||!path.isAbsolute(value))throw Error('MANUAL_PROBE_PATH_INVALID');
 for(const [key,value] of Object.entries(c.artifacts||{}))if(!['A','B','O'].includes(key)||typeof value!=='string'||!path.isAbsolute(value))throw Error('MANUAL_ARTIFACT_PATH_INVALID');
 if(c.faultArtifacts!==undefined){if(!c.faultArtifacts||Object.keys(c.faultArtifacts).sort().join(',')!=='A,B,O'||Object.values(c.faultArtifacts).some(value=>typeof value!=='string'||!path.isAbsolute(value)))throw Error('MANUAL_FAULT_ARTIFACT_PATH_INVALID');}
 if(c.verificationContext!==undefined&&(typeof c.verificationContext!=='string'||!path.isAbsolute(c.verificationContext)))throw Error('MANUAL_VERIFICATION_CONTEXT_PATH_INVALID');
 if(c.collectHardwareSignals!==undefined&&typeof c.collectHardwareSignals!=='boolean')throw Error('MANUAL_INPUT_INVALID');
 if(typeof c.runIntegration!=='boolean'||typeof c.releaseVersion!=='string'||!/^\d{1,9}(?:\.\d{1,9}){0,3}$/.test(c.releaseVersion))throw Error('MANUAL_INPUT_INVALID');
 return c;
}
function Pe64(bytes){if(bytes.length<256||bytes.readUInt16LE(0)!==0x5a4d)throw Error('MANUAL_PE_INVALID');const pe=bytes.readUInt32LE(0x3c);if(pe>bytes.length-26||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664||bytes.readUInt16LE(pe+24)!==0x20b)throw Error('MANUAL_WIN64_PE_REQUIRED');}
function Snapshot(source,destination){const bytes=read(source);Pe64(bytes);fs.writeFileSync(destination,bytes,{flag:'wx',mode:0o600});return {source:path.resolve(source),executedCopy:destination,beforeSha512:hash(bytes),bytes:bytes.length};}
function FinishHash(row){try{const source=hash(read(row.source)),copy=hash(read(row.executedCopy));return {...row,afterSha512:source,executedCopyAfterSha512:copy,unchanged:source===row.beforeSha512&&copy===row.beforeSha512};}catch(e){return {...row,unchanged:false,error:/^[A-Z0-9_]+$/.test(e.message)?e.message:'MANUAL_INPUT_CHANGED'};}}
function Prepare(inputFile,run,privateRoot,node,pwsh,opensslAvailable){
 const c=Config(json(inputFile));for(const dir of [run,privateRoot])if(!fs.existsSync(path.join(dir,'ci-owned-marker')))throw Error('MANUAL_OWNED_DIRECTORY_REQUIRED');
 const bin=path.join(run,'bin');fs.mkdirSync(bin);const copies={},inputs={},stages=[];
 for(const name of PROBES){const extension=name==='ModuleGenerationFixture'?'.dll':'.exe',source=c.probes?.[name]||path.join(c.probeDirectory,name+extension);if(!fs.existsSync(source))continue;inputs[name]=Snapshot(source,path.join(bin,name+extension));copies[name]=inputs[name].executedCopy;}
 const add=(id,needs,exe,args,validator,timeoutSeconds=120)=>{const missing=needs.filter(n=>!copies[n]);stages.push({id,needs,exe,args,validator,timeoutSeconds,...(missing.length?{skip:'PREBUILT_PROBE_MISSING: '+missing.join(',')}:{})});};
 const native=(id,name,validator='pass')=>add(id,[name],copies[name]||'',[],validator);
 add('probe-build-output-contracts',[],node,[path.join(WEB,'scripts/test-probe-build-output.js')],'pass');
 native('startup','StartupProbe');native('abi-layout','NativeAbiProbe','abi');
 native('hash-contracts','HashContracts');native('handoff-kdf','HandoffKdfProbe');add('blake3-parallel',['Blake3ParallelProbe'],node,[path.join(WEB,'scripts/verify-blake3-parallel.js'),copies.Blake3ParallelProbe||''],'pass',240);native('handoff-crypto','HandoffCryptoProbe');native('handoff-pipe','HandoffPipeProbe');native('handoff-process','HandoffProcessProbe');
 native('memory-lifetime','MeasurementLifetimeProbe');native('thread-inventory','ThreadInventoryProbe');add('device-signals',['DeviceSignalsProbe'],copies.DeviceSignalsProbe||'',c.collectHardwareSignals===true?['--collect-hardware']:[],'pass');add('module-generation',['MeasurementLifetimeProbe','ModuleGenerationFixture'],copies.MeasurementLifetimeProbe||'',['--loader-fixture',copies.ModuleGenerationFixture||''],'pass');native('native-api','NativeApiContractsProbe');native('device-key-construction','DeviceKeyContractProbe');native('hardening-contracts','HardeningContractsProbe');native('deterministic-state-core','DeterministicStateProbe','state');
 add('pe-corpus',['PeCorpusProbe'],node,[path.join(WEB,'scripts/test-hardening-pe-corpus.js'),'--native',copies.PeCorpusProbe||''],'pe-reference',180);
 add('independent-pe',['PeCorpusProbe'],node,[path.join(WEB,'scripts/test-independent-contracts-14.js'),'--native-pe',copies.PeCorpusProbe||''],'independent-pe-reference',180);
 add('independent-crc',['CrcProbe'],node,[path.join(WEB,'scripts/test-independent-contracts-14.js'),'--native-crc',copies.CrcProbe||''],'independent-crc-reference',180);
 add('hash-reference',['IntegrityHashProbe','CrcProbe','CrcPeProbe','HashProbe','PeCorpusProbe'],node,[path.join(WEB,'scripts/compare-native-hashes.js'),'--hash-probe',copies.IntegrityHashProbe||'','--crc-probe',copies.CrcProbe||'','--mode-probe',copies.HashProbe||'','--pe-probe',copies.PeCorpusProbe||''],'hash-reference',900);
 add('deterministic-state',['DeterministicStateProbe'],node,[path.join(WEB,'scripts/test-independent-contracts-14.js'),'--native',copies.DeterministicStateProbe||''],'state-reference',180);
 add('abi-sdk-compare',['NativeAbiProbe','NativeAbiSdkProbe'],node,[path.join(ROOT,'GameConnect_Win64/tests/compare-native-abi.js'),copies.NativeAbiProbe||'',copies.NativeAbiSdkProbe||''],'abi-reference');
 native('overlay-first-frame','OverlayFirstFrameProbe');native('overlay-privacy','OverlayPrivacyProbe');native('overlay-shutdown','OverlayShutdownProbe');native('overlay-gpu-faults','OverlayGpuFaultProbe');native('mitigation-readback','ProcessMitigationProfileProbe');
 // Final-image CRC reads are useful even when isolated A/B/O execution is off.
 const finals=path.join(privateRoot,'finals');let finalPreparationError;
 if(Object.keys(c.artifacts||{}).length){
  fs.mkdirSync(finals);
  try{for(const role of ['A','B','O'])if(c.artifacts?.[role])inputs[role]=Snapshot(c.artifacts[role],path.join(finals,role+'.exe'));}
  catch(e){finalPreparationError=/^[A-Z0-9_]+$/.test(e.message)?e.message:'FINAL_INPUT_INVALID';}
 }
 const finalRoles=['A','B','O'].filter(role=>inputs[role]);
 add('independent-crc-pe',['CrcPeProbe'],node,[path.join(WEB,'scripts/compare-native-crc-pe.js'),'--probe',copies.CrcPeProbe||'',...finalRoles.flatMap(role=>['--'+role.toLowerCase(),inputs[role].executedCopy])],'crc-pe-reference',900);
 Object.assign(stages.at(-1),{requireFinalArtifacts:true,finalArtifactSha512:Object.fromEntries(finalRoles.map(role=>[role,inputs[role].beforeSha512]))});
 if(finalPreparationError)Object.assign(stages.at(-1),{skip:'FINAL_CRC_PREPARATION_FAILED',preparationError:finalPreparationError});
 const integration={id:'abo-integration',needs:[],exe:pwsh,args:[],validator:'integration',timeoutSeconds:300};
 if(!c.runIntegration)integration.skip='OPERATOR_DID_NOT_SELECT_ISOLATED_ABO_EXECUTION';
 else if(!['A','B','O'].every(k=>c.artifacts?.[k]))integration.skip='FINAL_A_B_O_PATHS_REQUIRED';
 else if(!opensslAvailable)integration.skip='OPENSSL_REQUIRED_ONLY_FOR_ISOLATED_TLS_FIXTURE';
 else{
  const out=finals;
  try{if(finalPreparationError)throw Error(finalPreparationError);
   PrepareIntegration(out,c.releaseVersion);
   integration.args=['-NoLogo','-NoProfile','-NonInteractive','-File',path.join(WEB,'ci/Integration-Control.ps1'),'-WorkRoot',ROOT,'-Output',out,'-PrivateRoot',privateRoot,'-Version',c.releaseVersion];integration.resultFile=path.join(out,'integration-result.json');
  }catch(e){integration.skip='INTEGRATION_PREPARATION_FAILED';integration.preparationError=/^[A-Z0-9_]+$/.test(e.message)?e.message:'FINAL_INPUT_INVALID';}
 }
 stages.push(integration);
 const sourceManifestSha512=hash(read(path.join(WEB,'maintenance/source-manifest.json'),8*1024*1024));
 const overlayLeaseExpiry={id:'overlay-lease-expiry',selected:!!c.faultArtifacts,scope:'DEDICATED_PRODUCT_TESTBUILD',exe:pwsh,args:[],timeoutSeconds:600,resultFile:path.join(run,'overlay-lease-expiry.json')};
 if(!c.faultArtifacts)overlayLeaseExpiry.skip='DEDICATED_PRODUCT_TESTBUILD_NOT_SELECTED';
 else if(!opensslAvailable)overlayLeaseExpiry.skip='OPENSSL_REQUIRED_ONLY_FOR_ISOLATED_TLS_FIXTURE';
 else{
  const faultDir=path.join(privateRoot,'fault-finals');fs.mkdirSync(faultDir);
  const faultArtifacts={};for(const role of ['A','B','O']){inputs['fault'+role]=Snapshot(c.faultArtifacts[role],path.join(faultDir,role+'.exe'));faultArtifacts[role]=inputs['fault'+role].executedCopy;}
  const input=path.join(privateRoot,'overlay-lease-inputs.json');write(input,{version:1,releaseVersion:c.releaseVersion,faultArtifacts,scenarios:['overlay-lease-expiry']});
  overlayLeaseExpiry.args=['-NoLogo','-NoProfile','-NonInteractive','-File',path.join(WEB,'tools/product-fault-tests.ps1'),'-InputFile',input,'-ResultFile',overlayLeaseExpiry.resultFile];
 }
 let verificationBinding;
 if(c.verificationContext){verificationBinding=require('./verification-report').Binding(json(c.verificationContext));if(verificationBinding.sourceManifestSha512!==sourceManifestSha512)throw Error('MANUAL_VERIFICATION_SOURCE_MISMATCH');for(const role of ['A','B','O'])if(inputs[role]?.beforeSha512!==verificationBinding.artifacts[role])throw Error('MANUAL_VERIFICATION_ARTIFACT_MISMATCH');}
 const plan={version:1,kind:'MANUAL_EXECUTION',sourceManifestSha512,root:ROOT,run,privateRoot,inputs,stages,overlayLeaseExpiry,...(verificationBinding?{verificationBinding}:{}),releaseVersion:c.releaseVersion,environment:{node:process.version,nodeArchitecture:process.arch,nodePlatform:process.platform}};write(path.join(run,'plan.json'),plan);return plan;
}
function PrepareIntegration(out,version){
 // Fresh keys live only in this function. Trust is confined to a brand-new
 // localhost fixture. Production policy, credentials and data are never read.
 const files=['A','B','O'].map(r=>path.join(out,r+'.exe'));require('./audit-final-artifacts').Audit(files);
 const authority=require('../services/desktopSecurityAuthority'),provenance=require('../services/desktopReleaseProvenance'),delegation=require('../services/desktopHandoffDelegation');
 const buffers=files.map(file=>read(file)),handoff=buffers.map(bytes=>delegation.ArtifactVersion(bytes));if(new Set(handoff).size!==1)throw Error('BOOTSTRAP_HANDOFF_VERSION_MISMATCH');
 if(buffers.some(bytes=>require('../services/peBuildConfiguration').HasProductFaultMarker(bytes)))throw Error('SECURITY_TEST_BUILD_NOT_PUBLISHABLE');
 const configurations=buffers.map(bytes=>require('../services/peBuildConfiguration').ReadBuildConfiguration(bytes).configuration);if(configurations.some(x=>x!=='RELEASE'))throw Error('MANUAL_ABO_RELEASE_BUILD_REQUIRED');
 const pair=crypto.generateKeyPairSync('ed25519'),keyId=provenance.KeyId(pair.publicKey),publicKey=pair.publicKey.export({type:'spki',format:'pem'}).toString();
 const policy=authority.ValidatePolicy({...authority.Defaults(),requireReleaseSignature:true,trustedReleaseKeys:[{keyId,publicKey}],revision:1});
 const artifacts={};for(const [i,role] of ['A','B','O'].entries()){artifacts[role]=hash(buffers[i]);write(path.join(out,role+'.approval.json'),{keyId,signature:crypto.sign(null,Buffer.from(authority.ReleaseCanonical(role,version,artifacts[role])),pair.privateKey).toString('base64')});}
 const manifest=provenance.ValidateManifest({version:1,releaseName:version,securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:handoff[0],sourceManifestSha512:hash(read(path.join(WEB,'maintenance/source-manifest.json'),8*1024*1024)),policySha512:provenance.PolicyDigest(policy),toolchain:{delphi:'IDE_PREBUILT_NOT_OBSERVED',cpp:'NOT_OBSERVED',windowsSdk:'NOT_OBSERVED',imgui:'NOT_OBSERVED'},artifacts});
 write(path.join(out,'policy.json'),policy);write(path.join(out,'manifest.json'),{manifest,manifestId:provenance.ManifestId(manifest)});
}
function Evaluate(stage,exitCode,log,integrationResult){
 if(exitCode!==0)return {outcome:'FAIL',reason:'EXECUTABLE_NONZERO_EXIT'};
 if(/^\s*(?:FAIL(?:ED)?\b|ERROR(?:\b|:))/m.test(log))return {outcome:'FAIL',reason:'PROBE_REPORTED_FAILURE'};
 const objects=log.split(/\r?\n/).map(line=>{try{return JSON.parse(line);}catch{return null;}}).filter(Boolean);
 if(stage.validator==='abi'){require('../../GameConnect_Win64/tests/compare-native-abi').Parse(log);return {outcome:'PASS',scope:'DELPHI_SELF_LAYOUT_ONLY'};}
 if(stage.validator==='state'&&!objects.some(x=>x.status==='PASS'&&JSON.stringify(x.observedTransitionMasks)==='[18,20,24,16,32,0]'&&x.stateChecks===36&&x.scheduleChecks===512&&x.gpuExecuted===false))return {outcome:'FAIL',reason:'NATIVE_STATE_CONTRACT_MISMATCH'};
 if(stage.validator==='hash-reference'){
  if(!objects.some(x=>x.status==='PASS'&&x.actualNativeExecuted===true&&x.scope==='WINDOWS_PASCAL_WITH_EXPORTS'&&x.exportComparison==='PASS'&&x.hashCases>0&&x.crcCases>0&&x.exportCases>=4))return {outcome:'FAIL',reason:'NATIVE_HASH_RESULT_MISSING'};
  // The optional full PE-role comparison has its own mandatory V2 stage. Its
  // absence in this primitive/hash/export command must not double-count a skip.
  return {outcome:'PASS',scope:'NATIVE_HASH_CRC_PRIMITIVES_AND_EXPORTS',fullPeRoleComparison:'SEPARATE_INDEPENDENT_CRC_PE_STAGE'};
 }
 if(stage.validator==='crc-pe-reference'){
  const crc=require('../scripts/compare-native-crc-pe');
  const result=objects.find(x=>x.status==='PASS'&&x.cases>=46&&x.nativeExecutions>=x.cases+2&&x.selectedRangeComparison==='PASS'&&x.nativeMappedImageComparison==='PASS'&&x.nativeDiskComparison==='PASS'&&JSON.stringify(x.independentRoles)===JSON.stringify(crc.ROLES));
  if(!result)return {outcome:'FAIL',reason:'NATIVE_FULL_PE_CRC_COMPARISON_MISSING'};
  // Old persisted plans/receipts retain their original scoped interpretation.
  if(stage.requireFinalArtifacts){
   const selected=Object.keys(stage.finalArtifactSha512||{});
   if(result.inputsUnchanged!==true||result.inputs?.probe?.unchanged!==true)return {outcome:'FAIL',reason:'NATIVE_CRC_INPUT_BINDING_MISSING'};
   for(const role of selected){const row=result.finalArtifacts?.[role],input=result.inputs?.[role];
    if(!row||row.selectionRole!==role||row.nativeDiskComparison!=='PASS'||crc.ROLES.some(k=>row.coverage?.[k]!=='measured')||input?.beforeSha512!==stage.finalArtifactSha512[role]||input.unchanged!==true)return {outcome:'FAIL',reason:'NATIVE_FINAL_CRC_COMPARISON_MISSING'};
   }
   if(selected.length!==3)return {outcome:'PARTIAL',reason:'FINAL_A_B_O_CRC_PATHS_REQUIRED',finalArtifactComparison:result.finalArtifactComparison};
   if(result.finalArtifactComparison!=='PASS')return {outcome:'FAIL',reason:'NATIVE_FINAL_CRC_COMPARISON_MISSING'};
   return {outcome:'PASS',scope:'NATIVE_CORPUS_SELF_IMAGE_AND_SELECTED_FINAL_A_B_O',finalArtifactComparison:'PASS'};
  }
  return {outcome:'PASS',scope:'NATIVE_CORPUS_AND_PROBE_SELF_IMAGE'};
 }
 if(stage.validator==='independent-crc-reference'&&!objects.some(x=>x.status==='PASS'&&x.nativeCrcPrimitiveOutcome==='PASS'&&x.nativeCrcPrimitiveCompared===true&&x.nativeCrcConstantsCompared===true))return {outcome:'FAIL',reason:'NATIVE_INDEPENDENT_CRC_RESULT_MISSING'};
 if(stage.validator==='independent-pe-reference'&&!objects.some(x=>x.status==='PASS'&&x.nativePeOutcome==='PASS'&&x.nativePeCrcCompared===true))return {outcome:'FAIL',reason:'NATIVE_INDEPENDENT_PE_RESULT_MISSING'};
 if(stage.validator==='pe-reference'&&!objects.some(x=>x.status==='PASS'&&x.nativeExecuted===true&&x.suite==='PE_CORPUS_V1'))return {outcome:'FAIL',reason:'NATIVE_PE_RESULT_MISSING'};
 if(stage.validator==='state-reference'&&!objects.some(x=>x.status==='PASS'&&x.nativeExecuted===true))return {outcome:'FAIL',reason:'NATIVE_STATE_RESULT_MISSING'};
 if(stage.validator==='abi-reference'&&!objects.some(x=>x.match===true&&x.nativeExecuted===true&&x.fieldCount===require('../../GameConnect_Win64/tests/native-abi-fields-v1.json').fields.length))return {outcome:'FAIL',reason:'ABI_COMPARISON_RESULT_MISSING'};
 if(stage.validator==='integration'){
  const fields=['ready','licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed'];
  if(integrationResult?.outcome!=='PASS'||fields.some(k=>integrationResult[k]!==true))return {outcome:'FAIL',reason:integrationResult?.error||'ABO_RESULT_INCOMPLETE',integration:integrationResult||null};
  return {outcome:'PASS',integration:integrationResult,scope:'ISOLATED_LOCALHOST_TEST_SERVER_ONLY'};
 }
 if(stage.validator==='pass'&&!/\bPASS\b/.test(log))return {outcome:'FAIL',reason:'EXPECTED_PROBE_RESULT_MISSING'};
 if(/\bSKIP\b|\bNOT_RUN\b|\bPARTIAL\b/.test(log))return {outcome:'PARTIAL',reason:'PROBE_REPORTED_UNEXECUTED_CASE'};
 return {outcome:'PASS'};
}
function EvaluateLeaseResult(report,expectedArtifacts,sourceManifestSha512){
 const fail=reason=>({outcome:'FAIL',reason,scope:'DEDICATED_PRODUCT_TESTBUILD'});
 if(!report||report.version!==1||report.kind!=='PRODUCT_FAULT_EXECUTION'||typeof report.runId!=='string'||!report.runId||report.environment?.platform!=='win32'||report.environment?.architecture!=='x64'||report.sourceManifestSha512!==sourceManifestSha512||report.sourceManifestUnchanged!==true||report.inputsUnchanged!==true||!Array.isArray(report.cases)||report.cases.length!==1||report.cases[0].id!=='overlay-lease-expiry')return fail('LEASE_RESULT_BINDING_INVALID');
 for(const role of ['A','B','O'])if(!expectedArtifacts?.[role]||report.inputs?.faultArtifacts?.[role]?.sha512!==expectedArtifacts[role]||report.inputs.faultArtifacts[role].unchanged!==true)return fail('LEASE_TESTBUILD_HASH_MISMATCH');
 const row=report.cases[0];if(row.outcome==='NOT_RUN'&&!row.evidence)return {outcome:'NOT_RUN',reason:row.reason||'NATIVE_EXECUTION_NOT_OBSERVED',scope:'DEDICATED_PRODUCT_TESTBUILD'};
 if(row.evidence?.runId!==report.runId)return fail('LEASE_RESULT_RUN_MISMATCH');
 const actual=require('./product-fault-tests').Evaluate(row.id,row.evidence);
 if(actual.outcome!==row.outcome||report.outcome==='FAIL')return fail('LEASE_RESULT_REVALIDATION_FAILED');
 return {...actual,nativeExecuted:row.evidence?.nativeExecuted===true,evidenceSha512:hash(Buffer.from(JSON.stringify(report)))};
}
function Finalize(run,resultFile,publicResultFile=resultFile){
 const plan=json(path.join(run,'plan.json')),executed=json(path.join(run,'execution.json')),stages=[];
 for(const stage of plan.stages){const actual=executed.stages.find(x=>x.id===stage.id);if(stage.skip){stages.push({id:stage.id,outcome:stage.preparationError?'FAIL':'NOT_RUN',reason:stage.skip,...(stage.preparationError?{detail:stage.preparationError}:{})});continue;}
  if(!actual||actual.outcome==='NOT_RUN'){stages.push({id:stage.id,outcome:'NOT_RUN',reason:actual?.reason||'EXECUTION_NOT_REACHED'});continue;}
  let details;try{const log=read(path.join(run,'logs',stage.id+'.log'),64*1024*1024).toString('utf8');details=actual.error?{outcome:'FAIL',reason:actual.error}:Evaluate(stage,actual.exitCode,log,stage.resultFile&&fs.existsSync(stage.resultFile)?json(stage.resultFile):null);}catch(e){details={outcome:'FAIL',reason:/^[A-Z0-9_]+$/.test(e.message)?e.message:'MANUAL_RESULT_INVALID'};}
  stages.push({id:stage.id,exitCode:actual.exitCode,elapsedMs:actual.elapsedMs,...details});
 }
 const inputs=Object.fromEntries(Object.entries(plan.inputs).map(([k,row])=>{const {source,executedCopy,...publicRow}=FinishHash(row);return [k,publicRow];}));
 const environment={...executed.environment,...plan.environment};delete environment.nodePath;
 const unchanged=Object.values(inputs).every(x=>x.unchanged);const result={version:1,kind:'MANUAL_EXECUTION',runId:path.basename(run),startedAt:executed.startedAt,finishedAt:new Date().toISOString(),environment,nativeBuild:'NOT_RUN',buildProvenance:'IDE_PREBUILT_INPUTS_NOT_ATTESTED',ciEvidenceCreated:false,hardwareAttested:false,publicationApproval:false,inputs,inputsUnchanged:unchanged,stages,physicalChecks:[{id:'physical-dpi-multi-monitor',outcome:'MANUAL_REQUIRED'},{id:'real-gpu-driver-loss-and-recovery',outcome:'MANUAL_REQUIRED'},{id:'rdp-disconnect-reconnect',outcome:'MANUAL_REQUIRED'},{id:'tpm-manufacturer-attestation',outcome:'NOT_RUN'}],outcome:!unchanged||stages.some(x=>x.outcome==='FAIL')?'FAIL':stages.some(x=>x.outcome!=='PASS')?'INCOMPLETE':'PASS',scope:'Only listed executed checks; not CI, build, hardware or publication attestation.'};
 // Export only bounded public diagnostics; local paths, logs and keys stay local.
 result.sourceManifestSha512=plan.sourceManifestSha512||null;
 try{result.sourceManifestUnchanged=!!plan.sourceManifestSha512&&hash(read(path.join(WEB,'maintenance/source-manifest.json'),8*1024*1024))===plan.sourceManifestSha512;}catch(_){result.sourceManifestUnchanged=false;}
 if(plan.sourceManifestSha512&&!result.sourceManifestUnchanged)result.outcome='FAIL';
 if(plan.overlayLeaseExpiry){
  const selected=plan.overlayLeaseExpiry.selected,actual=executed.overlayLeaseExpiry,expected=Object.fromEntries(['A','B','O'].map(role=>[role,inputs['fault'+role]?.beforeSha512]));
  let lease,leaseEvidenceBytes;
  if(plan.overlayLeaseExpiry.skip)lease={outcome:'NOT_RUN',reason:plan.overlayLeaseExpiry.skip};
  else if(!actual||actual.outcome==='NOT_RUN')lease={outcome:'NOT_RUN',reason:'EXECUTION_NOT_REACHED'};
  else try{const bytes=read(plan.overlayLeaseExpiry.resultFile,8*1024*1024),report=JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/,''));lease=EvaluateLeaseResult(report,expected,plan.sourceManifestSha512);lease.evidenceSha512=hash(bytes);if(lease.nativeExecuted===true)leaseEvidenceBytes=bytes;if(actual.error||![0,2].includes(actual.exitCode))lease={...lease,outcome:'FAIL',reason:actual.error||'LEASE_RUNNER_FAILED'};}catch(_){lease={outcome:'FAIL',reason:'LEASE_RESULT_MISSING_OR_INVALID'};}
  if(selected&&['A','B','O'].some(role=>inputs['fault'+role]&&!inputs['fault'+role].unchanged))lease={...lease,outcome:'FAIL',reason:'LEASE_TESTBUILD_CHANGED'};
  result.overlayLeaseExpiry={id:'overlay-lease-expiry',selected,scope:'DEDICATED_PRODUCT_TESTBUILD',subjectArtifacts:expected,...lease};
  if(leaseEvidenceBytes){result.leaseEvidenceFile=path.join(path.dirname(publicResultFile),path.basename(publicResultFile,'.json')+'-lease-evidence.json');fs.writeFileSync(path.join(path.dirname(resultFile),path.basename(resultFile,'.json')+'-lease-evidence.json'),leaseEvidenceBytes,{flag:'wx',mode:0o600});}
  if(selected&&lease.outcome==='FAIL')result.outcome='FAIL';else if(selected&&lease.outcome!=='PASS'&&result.outcome==='PASS')result.outcome='INCOMPLETE';
  if(selected&&(lease.nativeExecuted===true||lease.outcome==='NOT_RUN')&&plan.verificationBinding&&Object.values(expected).every(Boolean)&&result.environment.nodePlatform==='win32'&&result.environment.nodeArchitecture==='x64'){
   const binding=plan.verificationBinding,notRun=lease.outcome==='NOT_RUN';
   const report=require('../services/desktopManualVerification').ValidateReport({version:3,kind:'MANUAL_VERIFICATION',runId:result.runId+'-lease',startedAt:new Date(result.startedAt).toISOString(),finishedAt:result.finishedAt,platform:'win32',architecture:'x64',manifestId:binding.manifestId,sourceManifestSha512:plan.sourceManifestSha512,sourceManifestUnchanged:result.sourceManifestUnchanged,artifacts:Object.fromEntries(['A','B','O'].map(role=>[role,{sha512:inputs[role].beforeSha512,unchanged:inputs[role].unchanged}])),policy:binding.policy,domains:[{id:'9',checks:[{id:'overlay-lease-expiry',outcome:lease.outcome,scope:'DEDICATED_PRODUCT_TESTBUILD',execution:notRun?'NOT_EXECUTED':'WINDOWS_EXECUTED',evidenceSha512:notRun?null:lease.evidenceSha512,reasonCode:lease.reason||'',subjectArtifacts:expected}]}],nativeBuild:'NOT_RUN',hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false});
   result.leaseVerificationFile=path.join(path.dirname(publicResultFile),path.basename(publicResultFile,'.json')+'-lease-verification.json');write(path.join(path.dirname(resultFile),path.basename(resultFile,'.json')+'-lease-verification.json'),report);
  }
 }
 if(result.environment.nodePlatform==='win32'&&result.environment.nodeArchitecture==='x64'&&plan.sourceManifestSha512&&['A','B','O'].every(role=>inputs[role])){
  const report=require('../services/desktopManualVerification').ValidateReport({version:2,kind:'MANUAL_VERIFICATION',runId:result.runId,startedAt:new Date(result.startedAt).toISOString(),finishedAt:result.finishedAt,platform:'win32',architecture:'x64',sourceManifestSha512:plan.sourceManifestSha512,sourceManifestUnchanged:result.sourceManifestUnchanged,artifacts:Object.fromEntries(['A','B','O'].map(role=>[role,{sha512:inputs[role].beforeSha512,unchanged:inputs[role].unchanged}])),stages:stages.map(({id,outcome})=>({id,outcome})),nativeBuild:'NOT_RUN',hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false});
  result.publicVerificationFile=path.join(path.dirname(publicResultFile),path.basename(publicResultFile,'.json')+'-verification.json');write(path.join(path.dirname(resultFile),path.basename(resultFile,'.json')+'-verification.json'),report);
 }
 write(resultFile,result);return result;
}
if(require.main===module){try{let value;const [action,...args]=process.argv.slice(2);if(action==='prepare'&&args.length===6)value=Prepare(...args.slice(0,5),args[5]==='true');else if(action==='finalize'&&[2,3].includes(args.length))value=Finalize(...args);else throw Error('MANUAL_ARGUMENTS_INVALID');console.log(JSON.stringify(action==='prepare'?{stages:value.stages.length}: {outcome:value.outcome,resultFile:args[1],ciEvidenceCreated:false}));if(action==='finalize'&&value.outcome==='FAIL')process.exitCode=1;}catch(e){console.error(/^[A-Z0-9_]+$/.test(e.message)?e.message:'MANUAL_TOOL_FAILED');process.exitCode=1;}}
module.exports={Config,Pe64,Snapshot,FinishHash,Evaluate,EvaluateLeaseResult,Finalize,Prepare,PROBES};
