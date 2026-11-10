'use strict';
// Every NHW observation is adjudicated here without changing sensor admission.
// Client context is signed evidence, not a peer grant or hardware observation.
const crypto=require('node:crypto');
const PHASES=Object.freeze(['UNKNOWN','A_BOOTSTRAP','A_ATTESTED','A_ISSUANCE','A_HANDOFF_TO_B','A_SHUTDOWN','B_BOOTSTRAP','B_ATTESTED','B_RUNTIME','B_HANDOFF_TO_O','B_SHUTDOWN','O_BOOTSTRAP','O_ATTESTED','O_RUNTIME','O_SHUTDOWN']);
const CAPABILITIES=Object.freeze(['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS','TOKEN_STATE','SELF_MEMORY','MODULE_STATE','IPC','ETW_STATE','KERNEL_STATE','UNKNOWN']);
const COVERAGE=Object.freeze(['UNKNOWN','COMPLETE','TRANSIENT_GAP','PERSISTENT_GAP']);
const DISPOSITIONS=Object.freeze(['INTERNAL_EVIDENCE','EXPECTED_FIRST_PARTY','COVERAGE_WARNING','COVERAGE_DEGRADED','CORROBORATED_ANOMALY','DETECTION','OBSERVATION_UNRESOLVED']);
const CONTEXT_FIELDS=['actorClass','actorRole','actorIdentity','targetRole','targetIdentity','phase','capability','accessMask','tokenDelta','coverage','peerId','grantId','baseline','contextMixed'];
const plain=x=>!!x&&Object.getPrototypeOf(x)===Object.prototype;
const alias=x=>typeof x==='string'&&(x===''||/^[a-f0-9]{64}$/.test(x));
const reference=x=>typeof x==='string'&&(x===''||/^[a-f0-9]{48}$/.test(x));
const exactMutation=new Set(['dkWriteIntegrity','dkPECodeIntegrity','dkImageCOWIntegrity','dkImportRedirect','dkTLSCallbackIntegrity','dkTLSPointer','dkFLSCallback','dkHeapIntegrity','dkExceptionCallback','dkEvidenceIntegrity','dkControlFlow','dkFileAttestation','dkUnwindStructural']);
const structuralInvariant=new Set(['dkIAT','dkFunctionPointer','dkCallback','dkFunctionTable','dkExceptionRange','dkUnwind','dkPEHeader','dkSectionMapping','dkRelocation','dkTLSDirectory','dkLoadConfig','dkDirectoryBounds','dkExportTable','dkExportForwarder','dkAPISet','dkExportTarget','dkResolution','dkDelayImport']);
const sensorCorrelated=new Set(['dkETWImageFusion','dkInjectionEvidence','dkSectionBacking','dkThreadStackOrigin','dkLoaderCrossView','dkSnapshotETW','dkObserverMismatch','dkRiskConfidence','dkCausalSequence','dkCodeProvenance','dkSectionCorrelation','dkIndirectTarget','dkThreadTimeline','dkIncidentReconstruction','dkAPCStyleEvidence','dkExecutableLifecycle']);
const confirmedKernel=new Set(['dkVulnerableDriver','dkKernelMappingEvidence','dkDriverSignerAttestation']);
const TOKEN_KINDS=new Set(['dkTokenObject','dkTokenRights','dkTokenChange','dkThreadToken']);
const ACCESS_KINDS=new Set(['dkProcess','dkThread','dkOwnership','dkEscalation','dkReappearance','dkCrossAccess','dkAccessBurst','dkHandleChurn','dkHandleInherit','dkHandleSharingEvidence','dkTemporalHandleGraph',...TOKEN_KINDS]);
const categoryCapabilities=Object.freeze({
 PROCESS_HANDLE:['PROCESS_ACCESS','THREAD_ACCESS'],PROCESS_LIFECYCLE:['PROCESS_ACCESS','THREAD_ACCESS'],TOKEN_SECURITY:['TOKEN_ACCESS','TOKEN_STATE'],IPC_JOB:['IPC'],FILE_IDENTITY:['MODULE_STATE'],REGISTRY:[],SCHEDULING_MITIGATION:['THREAD_ACCESS','PROCESS_ACCESS'],NAMESPACE:['IPC'],ETW_LIFECYCLE:['ETW_STATE'],THREAD_ORIGIN:['THREAD_ACCESS'],STACK:['THREAD_ACCESS','SELF_MEMORY'],MEMORY_ALLOCATION:['SELF_MEMORY'],MEMORY_MAPPING:['SELF_MEMORY','MODULE_STATE'],MEMORY_PROTECTION:['SELF_MEMORY'],MEMORY_READ:['PROCESS_ACCESS','SELF_MEMORY'],MEMORY_WRITE:['PROCESS_ACCESS','SELF_MEMORY'],WAIT_CHAIN:['THREAD_ACCESS','IPC'],CAPTURE:[],NETWORK_FILTER:[],NETWORK_PATH:[],SELF_POINTER:['MODULE_STATE'],HEAP_TLS:['SELF_MEMORY'],EXCEPTION_UNWIND:['MODULE_STATE'],ASYNC:['IPC'],PE_IMAGE:['MODULE_STATE'],PE_EXPORT:['MODULE_STATE'],EXECUTION_CORRELATION:['PROCESS_ACCESS','MODULE_STATE'],EVIDENCE_CORRELATION:['ETW_STATE','MODULE_STATE'],KERNEL_TRUST:['KERNEL_STATE']
});
function Fail(){throw Object.assign(Error('SECURITY_DETECTION_CONTEXT_INVALID'),{desktopError:true,status:400});}
function ParseContext(value){
 if(!plain(value)||Object.keys(value).length!==CONTEXT_FIELDS.length||CONTEXT_FIELDS.some(k=>!Object.hasOwn(value,k)))Fail();
 if(!['SELF','TRUSTED_A','TRUSTED_B','TRUSTED_O','EXTERNAL','UNKNOWN'].includes(value.actorClass)||!['A','B','O','?'].includes(value.actorRole)||!['A','B','O','?'].includes(value.targetRole)||!alias(value.actorIdentity)||!alias(value.targetIdentity)||!PHASES.includes(value.phase)||!CAPABILITIES.includes(value.capability)||!Number.isInteger(value.accessMask)||value.accessMask<0||value.accessMask>0xffffffff||!Number.isInteger(value.tokenDelta)||value.tokenDelta<0||value.tokenDelta>511||!COVERAGE.includes(value.coverage)||!reference(value.peerId)||!reference(value.grantId)||typeof value.baseline!=='boolean'||typeof value.contextMixed!=='boolean')Fail();
 if(value.capability!=='TOKEN_STATE'&&value.tokenDelta!==0)Fail();
 if(!['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS'].includes(value.capability)&&value.accessMask!==0)Fail();
 return value;
}
function ContextKey(value){
 if(!value)return '';
 return crypto.createHash('sha256').update(JSON.stringify(['actorClass','actorRole','actorIdentity','targetRole','targetIdentity','phase','capability','peerId','grantId','baseline','contextMixed'].map(k=>value[k]))).digest('hex');
}
function UnknownContext(stage='?'){
 return {actorClass:'UNKNOWN',actorRole:'?',actorIdentity:'',targetRole:stage,targetIdentity:'',phase:'UNKNOWN',capability:'UNKNOWN',accessMask:0,tokenDelta:0,coverage:'UNKNOWN',peerId:'',grantId:'',baseline:false,contextMixed:false,capabilityDecision:'OBSERVE',serverBound:false,firstPartyAttested:false,sameSession:null,bindingScope:'UNVERIFIED_CLIENT_OBSERVATION'};
}
function PolicyClass(row){
 if(!Object.hasOwn(categoryCapabilities,row.category))throw Error('NHW_POLICY_CATEGORY_UNCLASSIFIED:'+row.id);
 if(row.standaloneOutput===false)return 'INTERNAL_TELEMETRY';
 if(row.signalClass==='UNKNOWN')return 'COVERAGE_HEALTH';
 if(exactMutation.has(row.id))return 'EXACT_INTEGRITY_MUTATION';
 if(structuralInvariant.has(row.id))return 'CONFIRMED_STRUCTURAL_INVARIANT';
 if(sensorCorrelated.has(row.id))return 'SENSOR_VALIDATED_CORRELATION';
 if(confirmedKernel.has(row.id))return 'CONFIRMED_KERNEL_EVIDENCE';
 if(row.category==='KERNEL_TRUST')return 'CONFIRMED_KERNEL_CONDITION';
 if(TOKEN_KINDS.has(row.id))return 'TOKEN_TRANSITION_OR_CAPABILITY';
 if(ACCESS_KINDS.has(row.id))return 'PROCESS_THREAD_CAPABILITY';
 return 'CONTEXT_AND_INDEPENDENT_CORROBORATION';
}
function Resolve(row,stage,record){
 const fallback=UnknownContext(stage),wire=record.context;
 if(!wire)return fallback;
 ParseContext(wire);
 const resolved=require('./peace.nhw-peer-context').ResolveContext(row,stage,wire);
 // Keep requested values for diagnosis, but actor trust/role/phase must be
 // resolved by the server registry. A class name in a payload grants nothing.
 const merged={...fallback,...wire,...resolved};
 return Object.fromEntries([...CONTEXT_FIELDS,'capabilityDecision','serverBound','firstPartyAttested','sameSession','bindingScope'].map(k=>[k,(['actorRole','targetRole'].includes(k)&&merged[k]==='UNKNOWN')?'?':merged[k]]));
}
function Fresh(record,tick){const age=BigInt('0x'+tick)-BigInt('0x'+record.lastTick);return age>=0n&&age<=90000n;}
function ForbiddenCapability(record,context=UnknownContext()){
 const c=context;if(!c||!ACCESS_KINDS.has(record.id))return false;
 // Object-specific rights: process/thread/token bits have different meanings.
 if(c.capability==='PROCESS_ACCESS')return (c.accessMask&0x2a)!==0; // CREATE_THREAD | VM_OPERATION | VM_WRITE
 if(c.capability==='THREAD_ACCESS')return (c.accessMask&0x10)!==0; // SET_CONTEXT
 if(c.capability==='TOKEN_ACCESS')return (c.accessMask&0x1e7)!==0; // mutation, not QUERY / QUERY_SOURCE
 return false;
}
function TokenMutation(record,context=UnknownContext()){return TOKEN_KINDS.has(record.id)&&context.capability==='TOKEN_STATE'&&(context.tokenDelta&255)!==0;}
function ExpectedCompatible(entry,r,context){
 if(context.capabilityDecision!=='EXPECTED'||context.firstPartyAttested!==true||context.serverBound!==true||context.sameSession!==true||context.contextMixed||r.correlation||r.localOnly!==true)return false;
 if(!categoryCapabilities[entry.category]?.includes(context.capability))return false;
 // Observation of a permissible operation does not explain a changed code
 // byte, injected execution, signer regression, or another semantic finding.
 // Expected classification is limited to explicitly attributed benign access
 // and initial state, never a role-wide or startup-wide exemption.
 // The server-resolved capability matrix has already decided what was permitted.
 if(ACCESS_KINDS.has(entry.id)&&['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS'].includes(context.capability))return true;
 return TOKEN_KINDS.has(entry.id)&&context.capability==='TOKEN_STATE'&&context.baseline&&context.tokenDelta===0;
}
function Evaluate(entry,r,{tick,context=UnknownContext(),corroborated=false,prior=null,now=Date.now(),version=4}={}){
 const base={context,disposition:'OBSERVATION_UNRESOLVED',decisionReason:'ADDITIONAL_CONTEXT_OR_CORROBORATION_REQUIRED',sessionStopPolicy:'CONTEXT_AND_CORROBORATION',coverageState:'UNKNOWN',stop:false};
 if(!Fresh(r,tick))return {...base,decisionReason:'STALE_OBSERVATION_RECORDED'};
 const cls=PolicyClass(entry);
 if(cls==='INTERNAL_TELEMETRY')return {...base,disposition:'INTERNAL_EVIDENCE',decisionReason:'INTERNAL_TELEMETRY_ONLY',sessionStopPolicy:'OBSERVE_ONLY'};
 if(cls==='COVERAGE_HEALTH'){
  // Replays are rejected before this code. Only newer sensor ticks received
  // within a bounded gap extend a server-timed coverage episode.
  const newer=prior&&BigInt('0x'+r.lastTick)>BigInt('0x'+prior.lastTick);
  const continuous=newer&&prior.coverageEpisode&&now>=prior.coverageEpisode.lastAt&&now-prior.coverageEpisode.lastAt<=60000;
  const episode=continuous?{startedAt:prior.coverageEpisode.startedAt,lastAt:now,observations:Math.min(65535,prior.coverageEpisode.observations+1)}:{startedAt:now,lastAt:now,observations:1};
  const degraded=episode.observations>=3&&now-episode.startedAt>=30000;
  return {...base,disposition:degraded?'COVERAGE_DEGRADED':'COVERAGE_WARNING',decisionReason:degraded?'PERSISTENT_COVERAGE_GAP_REVALIDATION_REQUIRED':'TRANSIENT_COVERAGE_GAP_RECOVERY_REQUIRED',sessionStopPolicy:'RECOVER_AND_REVALIDATE',coverageState:degraded?'SESSION_DEGRADED':'RECOVERY_PENDING',coverageEpisode:episode};
 }
 // An access mask is a capability, not proof that a write, token change or
 // injection happened. Resolve actor identity before applying role policy.
 // Version 3 carried no distinction between sensor findings and context-only
 // observations, so a single legacy access report must not revoke a session.
 const nativeFinding=r.signal==='DETECTED'||(r.signal===undefined&&r.context===undefined); // v2 only reported sensor flags
 const expected=ExpectedCompatible(entry,r,context);
 if(expected)return {...base,disposition:'EXPECTED_FIRST_PARTY',decisionReason:'SERVER_BOUND_ROLE_CAPABILITY_ALLOWED',sessionStopPolicy:'OBSERVE_ONLY'};
 // V5 exclusively applies the native *post-filter* output contract. A
 // server-bound, expected A/B/O scheduling operation is still an observation,
 // never a reason to terminate its own session.
 const expectedScheduling=version>=5&&entry.category==='SCHEDULING_MITIGATION'&&
   context.serverBound===true&&context.firstPartyAttested===true&&
   context.sameSession===true&&context.capabilityDecision==='EXPECTED'&&
   !context.contextMixed&&r.localOnly===true&&r.correlation===false&&
   ['PROCESS_ACCESS','THREAD_ACCESS'].includes(context.capability);
 if(expectedScheduling)return {...base,disposition:'EXPECTED_FIRST_PARTY',decisionReason:'SERVER_BOUND_SCHEDULING_CAPABILITY_ALLOWED',sessionStopPolicy:'OBSERVE_ONLY'};
 const verifiedPeer=context.serverBound===true&&context.firstPartyAttested===true&&
   context.sameSession===true&&!context.contextMixed;
 const forbiddenRole=verifiedPeer&&context.capabilityDecision==='FORBIDDEN'&&
   ['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS'].includes(context.capability)&&
   categoryCapabilities[entry.category]?.includes(context.capability);
 // A confirmed, server-resolved cross-process permission violation is distinct
 // from an untrusted report containing a large bitmask or an own-process handle.
 if(forbiddenRole&&nativeFinding&&!context.baseline&&r.confidence>=30)
  return {...base,disposition:'DETECTION',decisionReason:'FIRST_PARTY_CAPABILITY_MATRIX_VIOLATION',sessionStopPolicy:'STOP_ON_CAPABILITY_VIOLATION',stop:true};
 // A single token delta may be a legitimate startup privilege adjustment.
 // Preserve it as evidence, and act only when independent corroboration exists.
 if(TokenMutation(r,context)&&nativeFinding&&corroborated)
  return {...base,disposition:'CORROBORATED_ANOMALY',decisionReason:'CORROBORATED_TOKEN_SECURITY_TRANSITION',sessionStopPolicy:'STOP_ON_CORROBORATED_ANOMALY',stop:true};
 // A server-identified SELF token initialization during the actual measured
 // baseline can produce a delta without proving hostile intervention. Keep
 // that specific isolated observation, never an unbound SELF claim, as
 // evidence; independent correlation or a post-baseline delta is actionable.
 // Baseline, binding and session are all mandatory; no role-wide bypass.
 const isolatedStartupToken=version>=5&&TOKEN_KINDS.has(entry.id)&&
   context.capability==='TOKEN_STATE'&&context.tokenDelta>0&&
   context.tokenDelta<256&&context.baseline===true&&
   context.actorClass==='SELF'&&context.firstPartyAttested===true&&
   context.serverBound===true&&context.sameSession===true&&
   !context.contextMixed&&r.localOnly===true&&r.correlation===false&&
   !corroborated;
 if(isolatedStartupToken)return {...base,disposition:'EXPECTED_FIRST_PARTY',
   decisionReason:'SERVER_BOUND_STARTUP_TOKEN_OBSERVATION',sessionStopPolicy:'OBSERVE_ONLY'};
 if(r.signal==='OBSERVED')return {...base,disposition:'INTERNAL_EVIDENCE',decisionReason:'CONTEXT_ONLY_OBSERVATION',sessionStopPolicy:'OBSERVE_ONLY'};
 // V1-V4 preserve their existing correlation/typed-evidence rules. Beginning
 // with V5, DETECTED means the v109 native sensor emitted this standalone
 // output AFTER baseline/cooldown suppression. Only this explicit finding is
 // eligible here; context-only observations and coverage health never revoke.
 // The authenticated report is not a hardware attestation. A compromised
 // client can still lie; server-side ownership and exact-cohort checks remain.
 if(version>=5&&r.signal==='DETECTED'&&entry.standaloneOutput===true&&
    cls!=='COVERAGE_HEALTH'&&cls!=='INTERNAL_TELEMETRY')
  return {...base,disposition:'DETECTION',decisionReason:'V5_NATIVE_SENSOR_OUTPUT',sessionStopPolicy:'STOP_ON_NATIVE_DETECTED_OUTPUT',stop:true};
 // These specific sensor families contain internal baseline/confirmation.
 // For legacy clients without the new source discriminator, require an
 // independent correlation rather than assuming every record was a finding.
 if(nativeFinding&&(cls==='EXACT_INTEGRITY_MUTATION'||cls==='CONFIRMED_STRUCTURAL_INVARIANT'||
    cls==='SENSOR_VALIDATED_CORRELATION'||cls==='CONFIRMED_KERNEL_EVIDENCE'||
    cls==='CONFIRMED_KERNEL_CONDITION'))
  return {...base,disposition:'DETECTION',decisionReason:cls,sessionStopPolicy:'STOP_ON_TYPED_SECURITY_EVIDENCE',stop:true};
 if(corroborated)return {...base,disposition:'CORROBORATED_ANOMALY',decisionReason:'INDEPENDENT_EVIDENCE_CORROBORATION',sessionStopPolicy:'STOP_ON_CORROBORATED_ANOMALY',stop:true};
 return base;
}
module.exports={ParseContext,ContextKey,UnknownContext,PolicyClass,Resolve,Evaluate,Fresh,ForbiddenCapability,TokenMutation,PHASES,CAPABILITIES,COVERAGE,DISPOSITIONS,CONTEXT_FIELDS};
