'use strict';
// Registered application-owned binding cells only. No raw process addresses,
// memory traversal, cross-report replay claim, or hardware attestation.
const crypto=require('node:crypto');
const lifecycle=require('./peace.pointer-graph-lifecycle');
const crc=require('../cryptography/peace.crc-layers');
const SCOPE='REGISTERED_APP_OBJECTS';
const PROFILES=Object.freeze({A:'BOOTSTRAP_CLIENT_V1',B:'LICENSE_API_V1',O:'OVERLAY_CLIENT_V1'});
const REASONS=Object.freeze(['STABLE','RUNTIME_GRAPH_CHANGED','RUNTIME_OBJECT_RETIRED','RUNTIME_BINDING_INVALID','RUNTIME_GRAPH_REQUIRED','CANCELLED','DEADLINE_EXCEEDED','MEASUREMENT_FAILED']);
const FIELDS=Object.freeze(['version','scope','profile','status','reason','stable','before','after','changes','sha512','crc64']);
const plain=v=>!!v&&Object.getPrototypeOf(v)===Object.prototype;
function requireValue(ok){if(!ok)throw Error('OWN_RUNTIME_GRAPH_INVALID');}
function snapshotBytes(snapshot){
 requireValue(plain(snapshot)&&Array.isArray(snapshot.nodes)&&snapshot.nodes.length===6&&Array.isArray(snapshot.edges)&&snapshot.edges.length===5);
 // This fixed reviewed profile is stricter than the generic lifecycle helper.
 // Borrowed Security/Image/Code are represented by client-owned binding cells;
 // their pointees and pointer values are never serialized as owned resources.
 const result=lifecycle.bytes(snapshot);
 requireValue(snapshot.rootId===1&&snapshot.rootGeneration===1);
 const nodes=[...snapshot.nodes].sort((a,b)=>a.id-b.id);
 nodes.forEach((n,i)=>requireValue(n.id===i+1&&n.kind===i+1&&n.alive===true&&
   n.span===(i===0?40:8)&&n.ownerId===(i===0?0:1)&&n.ownerGeneration===(i===0?0:1)&&
   (i!==0||n.generation===1)));
 const edges=[...snapshot.edges].sort((a,b)=>a.offset-b.offset);
 edges.forEach((e,i)=>requireValue(e.sourceId===1&&e.sourceGeneration===1&&e.targetId===i+2&&
   e.targetGeneration===nodes[i+1].generation&&e.offset===i*8&&e.width===8));
 requireValue(result.liveNodes===6&&result.ownerDepth===1);
 return result.bytes;
}
function Validate(value){
 try{
  requireValue(plain(value)&&Object.keys(value).length===FIELDS.length&&FIELDS.every(k=>Object.hasOwn(value,k)));
  requireValue(value.version===1&&value.scope===SCOPE&&(Object.values(PROFILES).includes(value.profile)||value.profile==='UNAVAILABLE')&&REASONS.includes(value.reason));
  requireValue(Array.isArray(value.changes)&&value.changes.length===0);
  if(value.status==='FAILED')return value.reason!=='STABLE'&&value.stable===false&&value.before===null&&value.after===null&&value.sha512===''&&value.crc64==='';
  requireValue(value.status==='MEASURED'&&Object.values(PROFILES).includes(value.profile)&&value.reason==='STABLE'&&value.stable===true);
  requireValue(typeof value.sha512==='string'&&/^[a-f0-9]{128}$/.test(value.sha512)&&typeof value.crc64==='string'&&/^[A-F0-9]{16}$/.test(value.crc64));
  const before=snapshotBytes(value.before),after=snapshotBytes(value.after);
  return before.equals(after)&&crypto.createHash('sha512').update(before).digest('hex')===value.sha512&&crc.crcHex('ecma182',before)===value.crc64;
 }catch(_){return false;}
}
function Compare(value,component){
 const profile=PROFILES[component];
 if(!profile)return {matched:false,reason:'RUNTIME_GRAPH_BUILD_COMPONENT_REQUIRED'};
 if(!Validate(value)||value.status!=='MEASURED')return {matched:false,reason:'RUNTIME_GRAPH_INCOMPLETE'};
 if(value.profile!==profile)return {matched:false,reason:'RUNTIME_GRAPH_PROFILE_MISMATCH'};
 return {matched:true,reason:'RUNTIME_GRAPH_MATCH',scope:SCOPE,profile,attested:false};
}
module.exports=Object.freeze({SCOPE,PROFILES,REASONS,FIELDS,Validate,Compare});
