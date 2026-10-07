'use strict';
// Compatibility boundary for APK modules absent from this desktop distribution.
// Archive data is preserved. No missing workflow is simulated or authorized.
const state = require('../core/state');
function Reject() { const error=Error('APK_FEATURE_RETIRED'); error.desktopError=true; error.status=410; throw error; }
const archived = {
 requestRecovery:['offlineQueuePolicy','clientOfflineQueueEnabled','offlineQueue','deadLetters'],
 qrApproval:['qrAuthRequests'],
 buildGate:['pendingBuildGrants','buildSessions','clientBuildBindings','accessGroupGuids','buildSessionPolicy'],
 userDashboard:[], clientInstallation:['clientInstallations'], supportCenter:['supportThreads','supportSettings']
};
function Import(name,data) {
 for(const key of archived[name]||[]) {
  const current=state[key],value=data[key];
  if(current instanceof Map){current.clear();if(value&&typeof value==='object'&&!Array.isArray(value))for(const [k,v] of Object.entries(value))current.set(k,structuredClone(v));}
  else if(current instanceof Set){current.clear();if(Array.isArray(value))for(const v of value)current.add(structuredClone(v));}
  else if(value&&typeof value==='object')state[key]=structuredClone(value);
 }
}
const cache=new Map();
function Service(name) {
 if(cache.has(name))return cache.get(name);
 const archive={
  Summary:()=>({retired:true,active:0}),
  ImportPersisted:data=>Import(name,data),
  // Retired records are intentionally not backfilled or replayed.
  Backfill:()=>{}, RebuildQueueRuntime:()=>{},
  NormalizePolicy:value=>value&&typeof value==='object'?structuredClone(value):{},
  NormalizeAccessType:value=>typeof value==='string'?value.slice(0,32):'',
  Expired:license=>license?.entryPass!==true&&(!Number.isFinite(license?.expiresAt)||license.expiresAt<=Date.now()),
  IsEntry:license=>license?.entryPass===true
 };
 // Unknown/operational entry points consistently fail closed, including Ready.
 const result=new Proxy(Object.freeze(archive),{get:(target,key)=>Object.hasOwn(target,key)?target[key]:Reject});
 cache.set(name,result); return result;
}
module.exports={Service,Reject};
