'use strict';
// Read-only attribution. A shared PC, client display name or raw process
// identity never joins security evidence to an administrator's member record.
const store=require('../bootstrap/peace.desktop-bootstrap-store');
const PUBLIC_FIELDS=['id','recordId','flowId','detectionId','displayName','origin','conditionLabel','signalClass','observationClass','sessionStopPolicy','decisionReason','category','sensor','sourceUnit','responsePath','firstAt','lastAt','firstTick','lastTick','count','confirmationCount','sessionId','epoch','role','stage','confidence','correlation','localOnly','attestationSequence','attestationStatus','sessionInvalidated','invalidated','evidenceLevel','provenance','handoffStatus','disposition','coverageState'];
// Context is a deliberately small public projection. Raw PID, image path,
// token/logon identity and signed enrollment material are never UI fields.
const CONTEXT_TEXT_FIELDS=['actorClass','actorRole','targetRole','phase','capability','coverage','capabilityDecision','bindingScope'];
const CONTEXT_HASH_FIELDS=['actorIdentity','targetIdentity','peerId','grantId'];
function PublicContext(context){
 if(!context||typeof context!=='object'||Array.isArray(context))return null;
 const value={};
 for(const key of CONTEXT_TEXT_FIELDS)if(typeof context[key]==='string'&&context[key].length<=96)value[key]=context[key];
 for(const key of CONTEXT_HASH_FIELDS)if(typeof context[key]==='string'&&(key.endsWith('Identity')?/^[a-f0-9]{64}$/i:/^[a-f0-9]{48}$/i).test(context[key]))value[key]=context[key];
 for(const [key,max] of [['accessMask',0xffffffff],['tokenDelta',511]])if(Number.isInteger(context[key])&&context[key]>=0&&context[key]<=max)value[key]=context[key];
 for(const key of ['baseline','contextMixed','firstPartyAttested','sameSession','serverBound'])if(typeof context[key]==='boolean')value[key]=context[key];
 return value;
}
function Public(row){
 const value=Object.fromEntries(PUBLIC_FIELDS.filter(key=>Object.hasOwn(row,key)&&(typeof row[key]==='string'||typeof row[key]==='boolean'||Number.isFinite(row[key]))).map(key=>[key,row[key]]));
 value.algorithms=Array.isArray(row.algorithms)?row.algorithms.filter(v=>typeof v==='string'&&v.length<=80).slice(0,16):[];
 value.evidenceFamilies=Array.isArray(row.evidenceFamilies)?row.evidenceFamilies.filter(v=>typeof v==='string'||Number.isSafeInteger(v)).slice(0,32):[];
 const context=PublicContext(row.context);if(context)value.context=context;
 if(row.attestation)value.attestation=Object.fromEntries(['sequence','status'].filter(key=>Object.hasOwn(row.attestation,key)).map(key=>[key,row.attestation[key]]));
 if(row.handoff)value.handoff=Object.fromEntries(['A','B','O'].filter(role=>typeof row.handoff[role]==='string').map(role=>[role,row.handoff[role]]));
 return value;
}
function Index(db=store.Load()){
 const sessions=new Map();
 function bind(role,sessionId,flowId,epoch){
  if(!sessionId)return;const key=role+':'+sessionId,value={flowId,epoch:String(epoch)},previous=sessions.get(key);
  sessions.set(key,previous===undefined||previous&&previous.flowId===flowId&&previous.epoch===value.epoch?value:null);
 }
 for(const row of Object.values(db.flows||{})){bind('A',row.id,row.id,row.createdAt);bind('B',row.sessionId,row.id,row.createdAt);}
 for(const row of Object.values(db.overlays||{}))bind('O',row.sessionId,row.parentFlowId,row.createdAt);
 return require('../security/peace.security-detections').MemberIndex().map(row=>{
  const byFlow=db.flows?.[row.flowId]?row.flowId:'',session=sessions.get(row.role+':'+row.sessionId);
  // Contradictory or retired/missing identity stays unassigned, not silently
  // attached by the remaining identifier. Preserve the evidence itself.
  const rootFlowId=byFlow&&session?.flowId===byFlow&&session.epoch===row.epoch?byFlow:'';
  return {...Public(row),rootFlowId,at:row.lastAt};
 });
}
function ForFlows(flowIds,{db=store.Load(),rows,limit=100}={}){
 if(!Array.isArray(flowIds)||!Number.isSafeInteger(limit)||limit<1||limit>100)throw Error('DETECTION_VIEW_INPUT_INVALID');
 const allowed=new Set(flowIds.filter(id=>db.flows?.[id]));
 const items=(rows||Index(db)).filter(row=>allowed.has(row.rootFlowId)).sort((a,b)=>b.lastAt-a.lastAt||a.id.localeCompare(b.id));
 return {items:items.slice(0,limit),totalCount:items.length,limit,truncated:items.length>limit,scope:'SESSION_BOUND_AGGREGATED_EVIDENCE',hardwareAttested:false};
}
module.exports={Index,ForFlows};
