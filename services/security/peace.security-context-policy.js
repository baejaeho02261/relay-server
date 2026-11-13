'use strict';
// Every NHW observation is adjudicated here without changing sensor admission.
// Client context is signed evidence, not a peer grant or hardware observation.
const crypto=require('node:crypto');
const PHASES=Object.freeze(['UNKNOWN','A_BOOTSTRAP','A_ATTESTED','A_ISSUANCE','A_HANDOFF_TO_B','A_SHUTDOWN','B_BOOTSTRAP','B_ATTESTED','B_RUNTIME','B_HANDOFF_TO_O','B_SHUTDOWN','O_BOOTSTRAP','O_ATTESTED','O_RUNTIME','O_SHUTDOWN']);
const PRIMARY_TOKEN_POSTURE='PRIMARY_TOKEN_POSTURE';
const PRIMARY_TOKEN_PHASES=Object.freeze({A:Object.freeze(['A_ATTESTED','A_ISSUANCE']),B:Object.freeze(['B_RUNTIME']),O:Object.freeze(['O_RUNTIME'])});
const CAPABILITIES=Object.freeze(['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS','TOKEN_STATE',PRIMARY_TOKEN_POSTURE,'SELF_MEMORY','MODULE_STATE','IPC','ETW_STATE','KERNEL_STATE','UNKNOWN']);
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
function ParseContext(value,version=5){
 if(!plain(value)||Object.keys(value).length!==CONTEXT_FIELDS.length||CONTEXT_FIELDS.some(k=>!Object.hasOwn(value,k)))Fail();
 if(!['SELF','TRUSTED_A','TRUSTED_B','TRUSTED_O','EXTERNAL','UNKNOWN'].includes(value.actorClass)||!['A','B','O','?'].includes(value.actorRole)||!['A','B','O','?'].includes(value.targetRole)||!alias(value.actorIdentity)||!alias(value.targetIdentity)||!PHASES.includes(value.phase)||!CAPABILITIES.includes(value.capability)||!Number.isInteger(value.accessMask)||value.accessMask<0||value.accessMask>0xffffffff||!Number.isInteger(value.tokenDelta)||value.tokenDelta<0||value.tokenDelta>511||!COVERAGE.includes(value.coverage)||!reference(value.peerId)||!reference(value.grantId)||typeof value.baseline!=='boolean'||typeof value.contextMixed!=='boolean')Fail();
 if(value.capability===PRIMARY_TOKEN_POSTURE){
  if(version!==5||value.actorClass!=='UNKNOWN'||value.actorRole!=='?'||value.actorIdentity!==''||
     !value.targetIdentity||!value.peerId||value.grantId!==''||value.baseline||value.contextMixed||
     value.coverage!=='COMPLETE'||!PrimaryTokenPhase(value.targetRole,value.phase)||
     value.tokenDelta===0||(value.tokenDelta&~0x64)!==0)Fail();
 }else if(value.capability!=='TOKEN_STATE'&&value.tokenDelta!==0)Fail();
 if(!['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS'].includes(value.capability)&&value.accessMask!==0)Fail();
 return value;
}
function PrimaryTokenPhase(role,phase){return Object.hasOwn(PRIMARY_TOKEN_PHASES,role)&&PRIMARY_TOKEN_PHASES[role].includes(phase);}
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
function ForbiddenCapability(record){
 const c=record.context;if(!c||!ACCESS_KINDS.has(record.id))return false;
 // Object-specific rights: process/thread/token bits have different meanings.
 if(c.capability==='PROCESS_ACCESS')return (c.accessMask&0x2a)!==0; // CREATE_THREAD | VM_OPERATION | VM_WRITE
 if(c.capability==='THREAD_ACCESS')return (c.accessMask&0x10)!==0; // SET_CONTEXT
 if(c.capability==='TOKEN_ACCESS')return (c.accessMask&0x1e7)!==0; // mutation, not QUERY / QUERY_SOURCE
 return false;
}
function TokenMutation(record){
 const c=record.context;
 // v3 cannot distinguish enabling an existing privilege from obtaining one.
 // Only a measured integrity raise or containment removal is conclusive here.
 return TOKEN_KINDS.has(record.id)&&c?.capability==='TOKEN_STATE'&&
  !c.baseline&&!c.contextMixed&&(c.tokenDelta&0x64)!==0;
}
function ExpectedCompatible(entry,r,context,version){
 if(context.capabilityDecision!=='EXPECTED'||context.firstPartyAttested!==true||context.serverBound!==true||context.sameSession!==true||context.contextMixed||r.correlation||r.localOnly!==true)return false;
 if(!categoryCapabilities[entry.category]?.includes(context.capability))return false;
 // Observation of a permissible operation does not explain a changed code
 // byte, injected execution, signer regression, or another semantic finding.
 // Expected classification is limited to explicitly attributed benign access
 // and initial state, never a role-wide or startup-wide exemption.
 if(ACCESS_KINDS.has(entry.id)&&['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS'].includes(context.capability))return true;
 if(version===5&&entry.category==='SCHEDULING_MITIGATION'&&['PROCESS_ACCESS','THREAD_ACCESS'].includes(context.capability))return true;
 return TOKEN_KINDS.has(entry.id)&&context.capability==='TOKEN_STATE'&&context.baseline&&context.tokenDelta===0;
}

function IsForbiddenBoundPeer(entry,context){
 return context.serverBound===true&&context.firstPartyAttested===true&&
  context.sameSession===true&&!context.contextMixed&&context.actorClass!=='SELF'&&
  context.capabilityDecision==='FORBIDDEN'&&
  ['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS'].includes(context.capability)&&
  categoryCapabilities[entry.category]?.includes(context.capability);
}

function EvaluateNativeFinding(entry,r,base,cls,corroborated,channel){
 const {context}=base;
 if(r.signal==='OBSERVED')return {...base,disposition:'INTERNAL_EVIDENCE',decisionReason:'CONTEXT_ONLY_OBSERVATION',sessionStopPolicy:'OBSERVE_ONLY'};
 if(r.signal!=='DETECTED')return base;

 if(context.capability===PRIMARY_TOKEN_POSTURE){
  // A stable loss of the sealed primary-token posture does not identify an
  // actor or create a second acquisition root. The proof applies only to the
  // exact enrolled reporting process and its server-accepted live phase.
  if(channel==='integrity'&&entry.id==='dkTokenChange'&&r.source==='Cozy.NHW.Engine'&&
     r.localOnly===true&&!r.correlation&&r.families===32&&context.serverBound===true&&
     context.firstPartyAttested===true&&context.sameSession===true&&context.capabilityDecision==='FORBIDDEN')
   return {...base,disposition:'DETECTION',decisionReason:'VERIFIED_PRIMARY_TOKEN_CONTAINMENT_LOSS',sessionStopPolicy:'STOP_ON_VERIFIED_NATIVE_INVARIANT',stop:true};
  return {...base,decisionReason:'PRIMARY_TOKEN_POSTURE_BINDING_UNVERIFIED',sessionStopPolicy:'REQUIRE_CAUSAL_OR_INDEPENDENT_EVIDENCE'};
 }

 // The kernel decision is a separate server-verified quorum. Its aggregate
 // family is never counted as an independent user-mode root.
 const roots=r.families&127;
 const evidence=entry.category==='KERNEL_TRUST'?(r.families&128)!==0:(roots&(roots-1))!==0;
 const confirmed=corroborated&&r.correlation===true&&r.localOnly===false&&r.confidence>=50&&evidence;
 if(confirmed){
  const tokenState=TOKEN_KINDS.has(entry.id)&&context.capability==='TOKEN_STATE'&&context.tokenDelta!==0;
  return {...base,disposition:'CORROBORATED_ANOMALY',decisionReason:tokenState?'CORROBORATED_TOKEN_SECURITY_TRANSITION':'INDEPENDENT_EVIDENCE_CORROBORATION',sessionStopPolicy:'STOP_ON_CORROBORATED_ANOMALY',stop:true};
 }
 if(IsForbiddenBoundPeer(entry,context)&&['TRUSTED_A','TRUSTED_B','TRUSTED_O'].includes(context.actorClass)&&!context.baseline&&r.confidence>=30)
  return {...base,disposition:'DETECTION',decisionReason:'FIRST_PARTY_CAPABILITY_MATRIX_VIOLATION',sessionStopPolicy:'STOP_ON_CAPABILITY_VIOLATION',stop:true};

 // These producers already validate stable integrity invariants or assemble
 // a bounded causal sequence from external access, thread origin and impact.
 const stable=cls==='EXACT_INTEGRITY_MUTATION'||cls==='CONFIRMED_STRUCTURAL_INVARIANT';
 if(stable||entry.id==='dkInjectionEvidence')
  return {...base,disposition:'DETECTION',decisionReason:stable?'STABLE_INTEGRITY_INVARIANT':'NATIVE_MULTI_SIGNAL_PROOF',sessionStopPolicy:'STOP_ON_VERIFIED_NATIVE_INVARIANT',stop:true};

 const reason=TOKEN_KINDS.has(entry.id)&&context.capability==='TOKEN_STATE'?'TOKEN_STATE_REQUIRES_CORROBORATION':
  entry.id==='dkThreadSpawn'?'THREAD_BURST_ORIGIN_NOT_VERIFIED':
  entry.id==='dkNoAccess'?'MEMORY_PROTECTION_CAUSE_UNVERIFIED':
  'ADDITIONAL_CONTEXT_OR_CORROBORATION_REQUIRED';
 return {...base,decisionReason:reason,sessionStopPolicy:'REQUIRE_CAUSAL_OR_INDEPENDENT_EVIDENCE'};
}

function Evaluate(entry,r,{tick,context=UnknownContext(),corroborated=false,prior=null,now=Date.now(),version=3,channel}={}){
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
 if(ExpectedCompatible(entry,r,context,version))return {...base,disposition:'EXPECTED_FIRST_PARTY',decisionReason:'SERVER_BOUND_ROLE_CAPABILITY_ALLOWED',sessionStopPolicy:'OBSERVE_ONLY'};
 if(version===5)return EvaluateNativeFinding(entry,r,base,cls,corroborated,channel);
 // The kernel path reports both raw samples and receipt-qualified findings.
 // A kernel kind only contributes when the server's kernel quorum selected it.
 if(entry.category==='KERNEL_TRUST'){
  if(corroborated)return {...base,disposition:'CORROBORATED_ANOMALY',decisionReason:'INDEPENDENT_EVIDENCE_CORROBORATION',sessionStopPolicy:'STOP_ON_CORROBORATED_ANOMALY',stop:true};
  return base;
 }
 const knownPeer=context.serverBound===true&&context.firstPartyAttested===true&&
  context.sameSession===true&&!context.contextMixed;
 if(IsForbiddenBoundPeer(entry,context))
  return {...base,disposition:'DETECTION',decisionReason:'FIRST_PARTY_CAPABILITY_MATRIX_VIOLATION',sessionStopPolicy:'STOP_ON_CAPABILITY_VIOLATION',stop:true};
 // The native collector supplies an alias only for a measured holder identity.
 // Startup inventory and ambiguous identity do not prove an external violation.
 if(!knownPeer&&r.context?.actorClass==='EXTERNAL'&&context.actorClass==='EXTERNAL'&&
    context.actorIdentity&&!context.baseline&&!context.contextMixed&&ForbiddenCapability(r))
  return {...base,context:{...context,capabilityDecision:'FORBIDDEN'},disposition:'DETECTION',decisionReason:'FORBIDDEN_CAPABILITY_OBSERVED',sessionStopPolicy:'STOP_ON_CAPABILITY_VIOLATION',stop:true};
 if(TokenMutation(r))return {...base,context:{...context,capabilityDecision:'FORBIDDEN'},disposition:'DETECTION',decisionReason:'TOKEN_SECURITY_TRANSITION',sessionStopPolicy:'STOP_ON_TOKEN_SECURITY_TRANSITION',stop:true};
 // The existing native integrity and compound detectors retain their own checks.
 if(cls==='EXACT_INTEGRITY_MUTATION'||cls==='CONFIRMED_STRUCTURAL_INVARIANT'||cls==='SENSOR_VALIDATED_CORRELATION')return {...base,disposition:'DETECTION',decisionReason:cls,sessionStopPolicy:'STOP_ON_TYPED_SECURITY_EVIDENCE',stop:true};
 if(corroborated)return {...base,disposition:'CORROBORATED_ANOMALY',decisionReason:'INDEPENDENT_EVIDENCE_CORROBORATION',sessionStopPolicy:'STOP_ON_CORROBORATED_ANOMALY',stop:true};
 return base;
}
module.exports={PRIMARY_TOKEN_POSTURE,PrimaryTokenPhase,ParseContext,ContextKey,UnknownContext,PolicyClass,Resolve,Evaluate,Fresh,ForbiddenCapability,TokenMutation,PHASES,CAPABILITIES,COVERAGE,DISPOSITIONS,CONTEXT_FIELDS};
