'use strict';
// Authenticated, minimized server-side observation history. This is not a
// client trust grant. No raw PID/path/account/machine identity is accepted.
const crypto=require('node:crypto');
const store=require('../bootstrap/peace.desktop-bootstrap-store');
const MAX_FLOWS=512,MAX_EVENTS=2048,MAX_RECORDS=16384,ZERO='0000000000000000';
const plain=x=>!!x&&Object.getPrototypeOf(x)===Object.prototype;
const hex64=x=>typeof x==='string'&&/^[a-f0-9]{16}$/.test(x);
const id24=x=>typeof x==='string'&&/^[A-F0-9]{24}$/.test(x);
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const catalog=()=>require('./peace.security-detection-catalog');
const bitCount=n=>{let c=0;for(;n;n&=n-1)c++;return c;};
const STRONG=new Set(['dkInjectionEvidence','dkRemoteThread','dkPrivateThread','dkWriteIntegrity','dkImportRedirect','dkTLSCallbackIntegrity','dkImageCOWIntegrity','dkPECodeIntegrity']);
const KERNEL_ALLOWED=new Set(['dkBootTrust','dkVBSHVCI','dkBootAttestationContinuity','dkHypervisorVBSCrossView','dkKernelDMAIOMMUTrust','dkDriverIdentity','dkDriverCrossView','dkSystemViewDisagreement','dkKernelTrustDowngrade','dkCodeIntegrityEventCorrelation']);
const KERNEL_EXCLUDED=new Set(['dkKernelTelemetryGap','dkVulnerableDriver','dkKernelMappingEvidence','dkDriverTimelineKernel','dkDriverSignerAttestation','dkDriverLoadProvenance','dkDriverServiceTimeline','dkCodeIntegrityPolicy']);
function Fail(code='SECURITY_DETECTION_INVALID',status=400){throw Object.assign(Error(code),{desktopError:true,status});}
function Fields(x,names){if(!plain(x)||Object.keys(x).length!==names.length||names.some(k=>!Object.hasOwn(x,k)))Fail();}
function Entry(id){const c=catalog();return c.Get(id);}
function SourceAllowed(entry,source){return entry&&typeof source==='string'&&((entry.sourceUnits||[]).includes(source)||entry.id.startsWith('dk')&&source==='Cozy.NHW.Engine');}
const AVAILABILITY_SOURCES=new Set(['Cozy.NHW.Handles','Cozy.NHW.Guard']);
function AvailabilityOnly(r){return r.id==='dkObservationUncertain'&&AVAILABILITY_SOURCES.has(r.source);}
function ParseRecords(rows,tick){
 if(!Array.isArray(rows)||rows.length>32||!hex64(tick)||tick===ZERO)Fail();
 const seen=new Set();
 for(const r of rows){
  Fields(r,['id','source','firstTick','lastTick','count','families','confidence','correlation','attestationSequence','localOnly']);
  const e=Entry(r.id);if(!e||!e.id.startsWith('dk')||!SourceAllowed(e,r.source))Fail();
  if(!hex64(r.firstTick)||r.firstTick===ZERO||!hex64(r.lastTick)||!hex64(r.attestationSequence)||BigInt('0x'+r.firstTick)>BigInt('0x'+r.lastTick)||BigInt('0x'+r.lastTick)>BigInt('0x'+tick))Fail();
  if(!Number.isInteger(r.count)||r.count<1||r.count>65535||!Number.isInteger(r.families)||r.families<0||r.families>255||!Number.isInteger(r.confidence)||r.confidence<0||r.confidence>100||typeof r.correlation!=='boolean'||typeof r.localOnly!=='boolean'||r.localOnly===r.correlation)Fail();
  if(AvailabilityOnly(r)&&(r.families!==0||r.confidence!==0||r.correlation||!r.localOnly))Fail();
  const key=r.id+':'+r.source;if(seen.has(key))Fail();seen.add(key);
 }
 return rows;
}
function KernelPolicy(rows){
 // Same conservative semantic policy as the native CorrelationPolicy after
 // AuthorityKinds excludes unverified CI provenance/telemetry-only signals.
 // These semantic families are NOT independent acquisition roots.
 const kinds=new Set(rows.filter(r=>(r.families&128)&&r.correlation&&!r.localOnly&&r.confidence>=50&&!KERNEL_EXCLUDED.has(r.id)).map(r=>r.id));
 const any=names=>names.some(k=>kinds.has(k));let familyMask=0,score=0,strong=0;
 if(any(['dkBootTrust','dkVBSHVCI','dkBootAttestationContinuity','dkHypervisorVBSCrossView','dkKernelDMAIOMMUTrust'])){familyMask|=1;score+=2;}
 if(any(['dkDriverIdentity','dkDriverCrossView','dkSystemViewDisagreement'])){familyMask|=4;score+=2;}
 if(any(['dkKernelTrustDowngrade','dkCodeIntegrityEventCorrelation']))familyMask|=8;
 for(const id of ['dkKernelTrustDowngrade','dkCodeIntegrityEventCorrelation'])if(kinds.has(id)){score+=4;strong++;}
 const families=bitCount(familyMask);return {eligible:strong>=1&&families>=2&&score>=6||families>=3&&score>=8,score,families};
}
function UserModeVote(rows,tick){
 return rows.some(r=>BigInt('0x'+tick)-BigInt('0x'+r.lastTick)<=90000n&&STRONG.has(r.id)&&r.correlation&&!r.localOnly&&r.confidence>=50&&bitCount(r.families&127)>=2);
}
function CorrelatedVote(rows,tick){
 const fresh=rows.filter(r=>BigInt('0x'+tick)-BigInt('0x'+r.lastTick)<=90000n);
 const strong=fresh.some(r=>STRONG.has(r.id)&&r.correlation&&!r.localOnly&&r.confidence>=50&&bitCount(r.families&127)>=2);
 return strong||KernelPolicy(fresh).eligible;
}
function QualifiedIds(rows,tick){
 const fresh=rows.filter(r=>BigInt('0x'+tick)-BigInt('0x'+r.lastTick)<=90000n);
 const kernel=KernelPolicy(fresh).eligible;
 return fresh.filter(r=>r.correlation&&!r.localOnly&&r.confidence>=50&&(STRONG.has(r.id)&&bitCount(r.families&127)>=2||kernel&&(r.families&128)&&KERNEL_ALLOWED.has(r.id))).map(r=>r.id);
}
function StopRecords(rows,tick){
 // Reporting an FP1 state is distinct from corroborating an attack. The
 // operator's policy closes this exact session for every actual printed
 // detection, including coverage warnings. It does not alter sensor thresholds,
 // manufacture confidence, or stop for the seven internal evidence states.
 return rows.filter(r=>!AvailabilityOnly(r)&&Entry(r.id)?.standaloneOutput===true&&BigInt('0x'+tick)-BigInt('0x'+r.lastTick)>=0n&&BigInt('0x'+tick)-BigInt('0x'+r.lastTick)<=90000n);
}
function StopDecision(stage,channel,value){
 const selected=StopRecords(value.detections,value.tick);if(!selected.length)return null;
 const diagnostic=selected.every(r=>Entry(r.id).signalClass==='UNKNOWN');
 return {reason:((diagnostic?'NHW_COVERAGE_STOP:':'NHW_DETECTED:')+stage+':'+channel+':'+value.sequence+':'+[...new Set(selected.map(r=>r.id))].join(',')).slice(0,300),keys:selected.map(r=>r.id+':'+r.source)};
}
function BatchDigest(value){return sha(JSON.stringify({version:value.version,sequence:value.sequence,digest:value.digest,confirmed:value.confirmed,trust:value.trust,detections:value.detections}));}
function RecoverBatch(row,stage,channel,value){
 const previous=row.nhwResponseOrders?.[stage+':'+channel];
 // A renewed nonce must still carry a freshly verified signature for the same
 // role/epoch/channel. Only the exact already accepted batch may recover its
 // acknowledgment; a new sequence with recycled evidence remains a replay.
 return value.version===2&&previous?.sequence===value.sequence&&previous.batchDigest===BatchDigest(value)&&BigInt('0x'+value.tick)>=BigInt('0x'+previous.tick)?previous:null;
}
function State(db){return db.securityDetections||(db.securityDetections={version:1,flows:{}});}
function Binding(db,row,stage){
 if(!row||!['A','B','O'].includes(stage)||!Number.isSafeInteger(row.createdAt)||row.createdAt<1)Fail();
 const flow=stage==='O'?db.flows[row.parentFlowId]:db.flows[row.id];
 const live=stage==='O'?db.overlays[row.id]:flow;
 if(!flow||!live||live.createdAt!==row.createdAt)Fail('SECURITY_DETECTION_CONTEXT_INVALID',403);
 return {flow,live,flowId:flow.id,sessionId:stage==='A'?flow.id:live.sessionId,epoch:String(live.createdAt)};
}
function Key(binding,stage,path,id,source){return sha([binding.flowId,stage,binding.sessionId,binding.epoch,path,id,source].join('\n'));}
function Trim(state){
 while(Object.keys(state.flows).length>MAX_FLOWS){const f=Object.values(state.flows).sort((a,b)=>a.updatedAt-b.updatedAt)[0];delete state.flows[f.flowId];}
 for(const flow of Object.values(state.flows))if(flow.events.length>MAX_EVENTS)flow.events.splice(0,flow.events.length-MAX_EVENTS);
 let count=Object.values(state.flows).reduce((sum,f)=>sum+f.events.length,0);
 if(count>MAX_RECORDS){const all=Object.values(state.flows).flatMap(f=>f.events.map(e=>({flow:f,event:e}))).sort((a,b)=>a.event.lastAt-b.event.lastAt);for(const item of all){if(count--<=MAX_RECORDS)break;const at=item.flow.events.indexOf(item.event);if(at>=0)item.flow.events.splice(at,1);}}
}
function Append(db,binding,stage,path,r,provenance,invalidated=false){
 const entry=Entry(r.id);if(!entry)Fail();
 const s=State(db),at=Date.now(),key=Key(binding,stage,path,r.id,r.source);
 const flow=s.flows[binding.flowId]||(s.flows[binding.flowId]={flowId:binding.flowId,updatedAt:at,events:[]});
 let e=flow.events.find(x=>x.id===key);
 if(e&&(BigInt('0x'+r.lastTick)<BigInt('0x'+e.lastTick)||e.firstTick===r.firstTick&&r.count<e.producerCount||e.firstTick!==r.firstTick&&BigInt('0x'+r.firstTick)<=BigInt('0x'+e.lastTick)))Fail('SECURITY_DETECTION_COUNTER_REPLAY',409);
 const previous=e&&e.firstTick===r.firstTick?e.producerCount:0;
 // A producer's first tick identifies its bounded RAM counter generation.
 // Repeated cumulative counts update metadata without inflating confirmation.
 const delta=Math.max(0,r.count-previous);
 const attestation=binding.live.nhwAttestations?.[stage]?.find(x=>x.sequence===r.attestationSequence);
 if(!e){e={id:key,flowId:binding.flowId,sessionId:binding.sessionId,role:stage,epoch:binding.epoch,detectionId:r.id,category:entry.category||'SECURITY',sensor:r.source,responsePath:path,firstAt:at,lastAt:at,count:0,confirmationCount:0,firstTick:r.firstTick,lastTick:r.lastTick,producerCount:0,evidenceFamilies:0,confidence:0,correlation:false,localOnly:true,attestationSequence:ZERO,invalidated:false,provenance};flow.events.push(e);}
 e.lastAt=at;e.count=Math.min(0x7fffffff,e.count+delta);e.confirmationCount=Math.min(0x7fffffff,e.confirmationCount+(r.correlation?delta:0));e.producerCount=r.count;e.firstTick=r.firstTick;e.lastTick=r.lastTick;e.evidenceFamilies|=r.families;e.confidence=Math.max(e.confidence,r.confidence);e.correlation||=r.correlation;e.localOnly=!e.correlation;e.attestationSequence=r.attestationSequence;e.invalidated||=invalidated;e.provenance=provenance;if(attestation){e.attestationStatus=attestation.status;e.hardwareAttested=attestation.hardwareAttested;}flow.updatedAt=at;
 return e.id;
}
function CheckOrder(row,stage,channel,value){
 const prior=row.nhwResponseOrders?.[stage+':'+channel];
 if(value.version===2&&value.detections.length&&prior?.evidenceDigest===sha(JSON.stringify(value.detections)))Fail('SECURITY_EVIDENCE_REPLAY',409);
 if(prior&&(BigInt('0x'+value.sequence)<=BigInt('0x'+prior.sequence)||BigInt('0x'+value.tick)<BigInt('0x'+prior.tick)))Fail('SECURITY_OBSERVATION_REPLAY',409);
}
function CheckCounters(row,stage,channel,records){
 if(channel!=='integrity'&&(records||[]).some(AvailabilityOnly))Fail();
 const db=store.Load(),b=Binding(db,row,stage),events=db.securityDetections?.flows[b.flowId]?.events||[];
 for(const r of records||[]){const e=events.find(e=>e.id===Key(b,stage,channel,r.id,r.source));if(e&&(BigInt('0x'+r.lastTick)<BigInt('0x'+e.lastTick)||e.firstTick===r.firstTick&&r.count<e.producerCount||e.firstTick!==r.firstTick&&BigInt('0x'+r.firstTick)<=BigInt('0x'+e.lastTick)))Fail('SECURITY_DETECTION_COUNTER_REPLAY',409);}
}
function TerminalAllowed(row,stage){
 const db=store.Load(),b=Binding(db,row,stage),g=b.flow.nhwTerminalReport;
 if(!g||g.serverEpoch!==require('../recovery/peace.desktop-recovery').Epoch(db)||require('../runtime/peace.desktop-deadline').persistent.expired('nhw.terminal:'+b.flowId,g.startedAt,g.expiresAt))return false;
 const origin=g.originRole==='O'?Object.values(db.overlays||{}).find(o=>o.parentFlowId===b.flowId&&o.sessionId===g.originSessionId):b.flow;
 return !!origin&&origin.status==='REVOKED'&&String(origin.createdAt)===g.originEpoch&&sha(origin.reason||'')===g.reasonDigest&&['REVOKED','CLOSED'].includes(b.live.status);
}
function ValidateTerminal(value){
 if(value===undefined)return;const names=['version','startedAt','expiresAt','serverEpoch','originRole','originSessionId','originEpoch','reasonDigest'];
 if(!plain(value)||Object.keys(value).length!==names.length||names.some(k=>!Object.hasOwn(value,k))||value.version!==1||!Number.isSafeInteger(value.startedAt)||value.startedAt<1||value.expiresAt!==value.startedAt+30000||!Number.isSafeInteger(value.serverEpoch)||value.serverEpoch<0||!['A','B','O'].includes(value.originRole)||!id24(value.originSessionId)||typeof value.originEpoch!=='string'||!/^[1-9][0-9]{0,15}$/.test(value.originEpoch)||BigInt(value.originEpoch)>BigInt(Number.MAX_SAFE_INTEGER)||!/^[a-f0-9]{64}$/.test(value.reasonDigest))Fail('SECURITY_DETECTION_STORAGE_INVALID',503);
}
function InvalidationReason(reason){return typeof reason==='string'&&/^(NHW_CORRELATED|NHW_DETECTED|NHW_COVERAGE_STOP):/.test(reason);}
function ApplyInvalidation(db,row,stage,contributors,reason){
 const b=Binding(db,row,stage);if(b.live.status!=='REVOKED'||b.live.reason!==reason)Fail('SECURITY_DETECTION_CONTEXT_INVALID',409);
  if(!b.flow.nhwTerminalReport){const at=b.live.revokedAt;if(!Number.isSafeInteger(at)||at<1)Fail();b.flow.nhwTerminalReport={version:1,startedAt:at,expiresAt:at+30000,serverEpoch:require('../recovery/peace.desktop-recovery').Epoch(db),originRole:stage,originSessionId:b.sessionId,originEpoch:b.epoch,reasonDigest:sha(reason)};}
  for(const e of db.securityDetections?.flows[b.flowId]?.events||[])if(e.role===stage&&e.sessionId===b.sessionId&&contributors.some(v=>v.channel===e.responsePath&&(v.keys?v.keys.includes(e.detectionId+':'+e.sensor):e.correlation&&!e.localOnly&&v.ids.includes(e.detectionId))))e.invalidated=true;
}
function CommitInvalidation(row,stage,contributors,reason){
 if(!InvalidationReason(reason))Fail();
 // Current v2 decisions are annotated inside the Revoke transaction through
 // ObserveTransitions. Keep this idempotent entry point for legacy callers.
 const db=store.Load(),b=Binding(db,row,stage);
 if(b.live.status==='REVOKED'&&b.live.reason===reason&&b.flow.nhwTerminalReport)return;
 return store.Atomic(db=>ApplyInvalidation(db,row,stage,contributors,reason));
}
function RecordPath(row,stage,channel,value,decision=null){
 return store.Atomic(db=>{const b=Binding(db,row,stage);CheckOrder(b.live,stage,channel,value);
  (b.live.nhwResponseOrders||(b.live.nhwResponseOrders={}))[stage+':'+channel]={sequence:value.sequence,tick:value.tick,...(value.version===2?{batchDigest:BatchDigest(value)}:{}),...(value.version===2&&value.detections.length?{evidenceDigest:sha(JSON.stringify(value.detections))}:{}),...(decision?{stopDecision:decision}:{})};
  // Observation persistence cannot assert that a later authority write succeeded.
  // Revoke's durable transition commits causality in the same transaction.
  const ids=(value.detections||[]).map(r=>Append(db,b,stage,channel,r,'AUTHENTICATED_CLIENT_REPORT',false));
  if(db.securityDetections)Trim(db.securityDetections);return ids;
 });
}
function CrcFindings(comparison){
 if(comparison===undefined)return undefined;
 const registry=require('../cryptography/peace.crc-layers').registry;
 if(!plain(comparison)||!Array.isArray(comparison.signals))Fail();
 const findings=[];
 for(const signal of comparison.signals){
  if(!plain(signal)||!Object.hasOwn(registry,signal.role)||!['MATCH','PARTIAL','UNAVAILABLE','MISMATCH','FAILED'].includes(signal.status))Fail();
  if(!['MISMATCH','FAILED'].includes(signal.status))continue;
  const r={role:signal.role,status:signal.status};
  if(signal.status==='FAILED'){if(!['FILE_CHANGED','READ_ERROR','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED'].includes(signal.reason))Fail();r.reason=signal.reason;}
  if(findings.some(e=>e.role===r.role))Fail();findings.push(r);
 }
 return findings;
}
function RecordServer({row,stage,id,source,confidence=100,correlation=true,evidenceFamilies,invalidated=false,attestationSequence=ZERO,crcComparison}){
 const entry=Entry(id);if(!entry||entry.id.startsWith('dk')||!SourceAllowed(entry,source))Fail();
 if(!Number.isInteger(confidence)||confidence<0||confidence>100||typeof correlation!=='boolean'||typeof invalidated!=='boolean'||!hex64(attestationSequence))Fail();
 if(crcComparison!==undefined&&id!=='CRC_ROLE_MISMATCH')Fail();
 const crcFindings=CrcFindings(crcComparison);
 return store.Atomic(db=>{const b=Binding(db,row,stage),tick=BigInt(Date.now()).toString(16).padStart(16,'0'),key=Key(b,stage,'server',id,source),prior=db.securityDetections?.flows[b.flowId]?.events.find(e=>e.id===key);
  const r={id,source,firstTick:prior?.firstTick||tick,lastTick:tick,count:Math.min(65535,(prior?.producerCount||0)+1),families:0,confidence,correlation,localOnly:!correlation,attestationSequence};
  const result=Append(db,b,stage,'server',r,'SERVER_COMPARISON',invalidated&&b.live.status==='REVOKED');
  if(crcFindings!==undefined){const event=db.securityDetections.flows[b.flowId].events.find(e=>e.id===result),findings=new Map((event.crcFindings||[]).map(r=>[r.role,r]));for(const r of crcFindings)if(findings.get(r.role)?.status!=='MISMATCH')findings.set(r.role,r);event.crcFindings=[...findings.values()];}
  Trim(db.securityDetections);return result;
 });
}
function RecordAttestation({row,stage,sequence,status,hardwareAttested=false}){
 if(!hex64(sequence)||sequence===ZERO||!['VERIFIED_BINDING','REJECTED','TPM_QUOTE_ONLY','UNKNOWN'].includes(status)||typeof hardwareAttested!=='boolean'||hardwareAttested&&status!=='TPM_QUOTE_ONLY')Fail();
 return store.Atomic(db=>{const b=Binding(db,row,stage),all=b.live.nhwAttestations||(b.live.nhwAttestations={}),items=all[stage]||(all[stage]=[]);
  const prior=items.find(x=>x.sequence===sequence);if(prior){if(prior.status!==status||prior.hardwareAttested!==hardwareAttested)Fail('SECURITY_ATTESTATION_REPLAY',409);return prior;}
  const value={sequence,status,hardwareAttested,at:Date.now()};items.push(value);
  for(const e of db.securityDetections?.flows[b.flowId]?.events||[])if(e.role===stage&&e.sessionId===b.sessionId&&e.epoch===b.epoch&&e.attestationSequence===sequence){e.attestationStatus=status;e.hardwareAttested=hardwareAttested;}if(items.length>16)items.splice(0,items.length-16);return value;
 });
}
function ValidateAttestations(value){
 if(value===undefined)return;if(!plain(value)||Object.keys(value).some(k=>!['A','B','O'].includes(k)))Fail('SECURITY_DETECTION_STORAGE_INVALID',503);
 for(const items of Object.values(value)){if(!Array.isArray(items)||items.length>16)Fail('SECURITY_DETECTION_STORAGE_INVALID',503);const seen=new Set();for(const e of items){if(!plain(e)||Object.keys(e).sort().join(',')!=='at,hardwareAttested,sequence,status'||!hex64(e.sequence)||e.sequence===ZERO||seen.has(e.sequence)||!['VERIFIED_BINDING','REJECTED','TPM_QUOTE_ONLY','UNKNOWN'].includes(e.status)||typeof e.hardwareAttested!=='boolean'||e.hardwareAttested&&e.status!=='TPM_QUOTE_ONLY'||!Number.isSafeInteger(e.at)||e.at<1)Fail('SECURITY_DETECTION_STORAGE_INVALID',503);seen.add(e.sequence);}}
}
function Public(db,e,index){
 const flow=db.flows[e.flowId],overlay=e.role==='O'?index.bySession.get(e.sessionId):null;
 const active=e.role==='O'?overlay:flow,invalidated=e.invalidated,sessionInvalidated=active?.status==='REVOKED';
 const handoffStatus=flow?.closedByOverlay?'TRANSFERRED':overlay?.status||flow?.status||'UNKNOWN';
 const attestation=active?.nhwAttestations?.[e.role]?.find(x=>x.sequence===e.attestationSequence);
 const names=['HANDLE_SNAPSHOT','THREAD_SNAPSHOT','ETW','SELF_MEMORY','MODULE_FILE','OBJECT_STATE','OBSERVER','KERNEL_AGGREGATE'];
 const entry=Entry(e.detectionId),availability=AvailabilityOnly({id:e.detectionId,source:e.sensor});
 const algorithms=(e.crcFindings||[]).filter(r=>r.status==='MISMATCH').map(r=>require('../cryptography/peace.crc-layers').registry[r.role].name);
 const displayName=algorithms.length===1?algorithms[0]+' Detect':entry.displayName;
 const crcUnavailable=e.detectionId==='CRC_ROLE_MISMATCH'&&e.confidence===0&&!e.correlation;
 const metadata={displayName,origin:entry.origin,algorithms,signalClass:crcUnavailable?'UNKNOWN':entry.signalClass,
  conditionLabel:availability?(e.sensor==='Cozy.NHW.Handles'?'Native handle inventory unavailable':'Security worker unavailable'):entry.conditionLabel,
  observationClass:availability?'SENSOR_AVAILABILITY':crcUnavailable?'UNAVAILABLE_OR_INCOMPLETE':entry.observationClass,sessionStopPolicy:availability?'OBSERVE_ONLY':entry.sessionStopPolicy,
  decisionReason:invalidated?(e.detectionId.startsWith('dk')?entry.signalClass==='UNKNOWN'?'COVERAGE_POLICY_STOP':'DETECTION_POLICY_STOP':'SERVER_SESSION_REJECTION'):'RECORDED_WITHOUT_INVALIDATION'};
 return {...e,...metadata,recordId:e.id,stage:e.role,evidenceFamilyMask:e.evidenceFamilies,evidenceFamilies:names.filter((name,index)=>e.evidenceFamilies&(1<<index)),semanticFamilies:Entry(e.detectionId)?.evidenceFamilies||[],semanticEvidenceFamilies:Entry(e.detectionId)?.evidenceFamilies||[],invalidated,sessionInvalidated,sessionCurrentlyInvalidated:sessionInvalidated,evidenceLevel:e.provenance==='SERVER_COMPARISON'?'SERVER_COMPARISON':e.correlation?'CLIENT_CORROBORATED':'CLIENT_LOCAL_OBSERVATION',attestation:{sequence:e.attestationSequence,status:attestation?.status||e.attestationStatus||(e.attestationSequence===ZERO?'NOT_BOUND':'CLIENT_SEQUENCE_REPORTED'),hardwareAttested:attestation?.hardwareAttested===true||e.hardwareAttested===true,bootHealthVerified:false},handoffStatus,handoff:{A:flow?.claimedAt?'HANDED_OFF':flow?.status||'UNKNOWN',B:flow?.claimedAt?flow.status:'NOT_STARTED',O:overlay?.status||index.byFlow.get(flow?.id)?.status||'NOT_STARTED'}};
}
function MemberIndex(){const db=store.Load(),index={bySession:new Map(),byFlow:new Map()};for(const row of Object.values(db.overlays||{})){index.bySession.set(row.sessionId,row);const old=index.byFlow.get(row.parentFlowId);if(!old||row.createdAt>old.createdAt)index.byFlow.set(row.parentFlowId,row);}return Object.values(db.securityDetections?.flows||{}).flatMap(f=>f.events.map(e=>Public(db,e,index))).sort((a,b)=>b.lastAt-a.lastAt);}
function MemberRecords(ids){if(!Array.isArray(ids)||ids.length>MAX_RECORDS||ids.some(id=>typeof id!=='string'||!/^[a-f0-9]{64}$/.test(id)))Fail();const selected=new Set(ids);return MemberIndex().filter(e=>selected.has(e.id));}
function ForFlow(flowId){if(!id24(flowId))Fail();return MemberIndex().filter(e=>e.flowId===flowId);}
function ValidateOrder(value){
 if(value===undefined)return;const invalid=()=>Fail('SECURITY_DETECTION_STORAGE_INVALID',503);
 if(!plain(value)||Object.keys(value).length>9)invalid();
 for(const [key,v]of Object.entries(value)){
  if(!/^[ABO]:(trust|driver|integrity)$/.test(key)||!plain(v)||Object.keys(v).some(k=>!['sequence','tick','evidenceDigest','batchDigest','stopDecision'].includes(k))||v.evidenceDigest!==undefined&&!/^[a-f0-9]{64}$/.test(v.evidenceDigest)||v.batchDigest!==undefined&&!/^[a-f0-9]{64}$/.test(v.batchDigest)||!hex64(v.sequence)||v.sequence===ZERO||!hex64(v.tick)||v.tick===ZERO)invalid();
  if(v.stopDecision!==undefined){
   const d=v.stopDecision;
   if(!v.batchDigest||!v.evidenceDigest||!plain(d)||Object.keys(d).sort().join(',')!=='keys,reason'||!InvalidationReason(d.reason)||d.reason.length>300||/[\x00-\x1f\x7f]/.test(d.reason)||!Array.isArray(d.keys)||!d.keys.length||d.keys.length>32||new Set(d.keys).size!==d.keys.length)invalid();
   for(const item of d.keys){if(typeof item!=='string')invalid();const [id,source,...rest]=item.split(':');if(rest.length||!SourceAllowed(Entry(id),source)||Entry(id)?.standaloneOutput!==true||AvailabilityOnly({id,source}))invalid();}
  }
 }
}
function ObserveTransitions(before,db){
 if(!db.securityDetections)return;
 // The accepted decision is durable before enforcement; causality and the
 // bounded terminal diagnostic grant commit atomically with the actual revoke.
 // A failed Revoke write leaves both unasserted and can be retried safely.
 for(const table of ['flows','overlays'])for(const [id,row]of Object.entries(db[table]||{})){
  if(row.status!=='REVOKED'||before[table]?.[id]?.status==='REVOKED'||!InvalidationReason(row.reason))continue;
  for(const [key,order]of Object.entries(row.nhwResponseOrders||{}))if(order.stopDecision?.reason===row.reason){
   const [stage,channel]=key.split(':');if((table==='overlays')!==(stage==='O'))continue;
   ApplyInvalidation(db,row,stage,[{channel,keys:order.stopDecision.keys}],row.reason);break;
  }
 }
 for(const [id,f]of Object.entries(db.securityDetections.flows)){if(!db.flows[id]){delete db.securityDetections.flows[id];continue;}f.events=f.events.filter(e=>e.role!=='O'||Object.values(db.overlays||{}).some(o=>o.parentFlowId===id&&o.sessionId===e.sessionId));}
}
function Validate(s,db){
 const invalid=()=>Fail('SECURITY_DETECTION_STORAGE_INVALID',503);
 if(!plain(s)||Object.keys(s).sort().join(',')!=='flows,version'||s.version!==1||!plain(s.flows)||Object.keys(s.flows).length>MAX_FLOWS)invalid();let total=0;
 for(const [id,f]of Object.entries(s.flows)){
  if(!id24(id)||!db.flows[id]||!plain(f)||Object.keys(f).sort().join(',')!=='events,flowId,updatedAt'||f.flowId!==id||!Number.isSafeInteger(f.updatedAt)||f.updatedAt<1||!Array.isArray(f.events)||f.events.length>MAX_EVENTS)invalid();total+=f.events.length;
  const seen=new Set();for(const e of f.events){
   const required=['id','flowId','sessionId','role','epoch','detectionId','category','sensor','responsePath','firstAt','lastAt','count','confirmationCount','firstTick','lastTick','producerCount','evidenceFamilies','confidence','correlation','localOnly','attestationSequence','invalidated','provenance'];
   if(!plain(e)||required.some(k=>!Object.hasOwn(e,k))||Object.keys(e).some(k=>!required.includes(k)&&!['attestationStatus','hardwareAttested','crcFindings'].includes(k))||(e.attestationStatus===undefined)!==(e.hardwareAttested===undefined))invalid();
   const entry=Entry(e.detectionId),live=e.role==='O'?Object.values(db.overlays||{}).find(o=>o.sessionId===e.sessionId&&o.parentFlowId===id):db.flows[id];
   if(!plain(e)||!entry||e.category!==(entry.category||'SECURITY')||!SourceAllowed(entry,e.sensor)||!live||!['A','B','O'].includes(e.role)||!['trust','driver','integrity','server'].includes(e.responsePath)||e.flowId!==id||!id24(e.sessionId)||e.sessionId!==(e.role==='A'?id:live.sessionId)||e.epoch!==String(live.createdAt)||e.id!==Key({flowId:id,sessionId:e.sessionId,epoch:e.epoch},e.role,e.responsePath,e.detectionId,e.sensor)||seen.has(e.id))invalid();seen.add(e.id);
   if(e.crcFindings!==undefined){if(e.detectionId!=='CRC_ROLE_MISMATCH'||!Array.isArray(e.crcFindings)||e.crcFindings.length>9)invalid();try{if(JSON.stringify(CrcFindings({signals:e.crcFindings}))!==JSON.stringify(e.crcFindings))invalid();}catch(_){invalid();}}
   if(AvailabilityOnly({id:e.detectionId,source:e.sensor})&&(e.responsePath!=='integrity'||e.evidenceFamilies!==0||e.confidence!==0||e.correlation||!e.localOnly||e.invalidated))invalid();
   if(e.attestationStatus!==undefined&&(!['VERIFIED_BINDING','REJECTED','TPM_QUOTE_ONLY','UNKNOWN'].includes(e.attestationStatus)||typeof e.hardwareAttested!=='boolean'||e.hardwareAttested&&e.attestationStatus!=='TPM_QUOTE_ONLY'))invalid();
   if(!Number.isSafeInteger(e.firstAt)||e.firstAt<1||!Number.isSafeInteger(e.lastAt)||e.lastAt<e.firstAt||!hex64(e.firstTick)||!hex64(e.lastTick)||!hex64(e.attestationSequence)||!Number.isInteger(e.count)||e.count<0||e.count>0x7fffffff||!Number.isInteger(e.confirmationCount)||e.confirmationCount<0||e.confirmationCount>e.count||!Number.isInteger(e.producerCount)||e.producerCount<1||e.producerCount>65535||!Number.isInteger(e.evidenceFamilies)||e.evidenceFamilies<0||e.evidenceFamilies>255||!Number.isInteger(e.confidence)||e.confidence<0||e.confidence>100||typeof e.correlation!=='boolean'||typeof e.localOnly!=='boolean'||e.localOnly===e.correlation||typeof e.invalidated!=='boolean'||!['AUTHENTICATED_CLIENT_REPORT','SERVER_COMPARISON'].includes(e.provenance))invalid();
  }
 }
 if(total>MAX_RECORDS)invalid();return s;
}
module.exports={ParseRecords,CorrelatedVote,UserModeVote,QualifiedIds,KernelPolicy,StopRecords,StopDecision,RecoverBatch,CheckOrder,CheckCounters,CommitInvalidation,TerminalAllowed,ValidateTerminal,RecordPath,RecordServer,RecordAttestation,ValidateAttestations,MemberIndex,MemberRecords,ForFlow,Validate,ObserveTransitions,ValidateOrder,MAX_FLOWS,MAX_EVENTS,MAX_RECORDS};
