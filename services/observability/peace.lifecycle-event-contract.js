"use strict";
// The same specification generates the native enum tables. Diagnostics remain
// authenticated client claims, never execution authority or OS attestation.
const spec = require("../../contracts/runtime/peace.lifecycle-events-v1.json");
const pairs = Object.freeze(Object.fromEntries(spec.events.map(e=>[e.name,Object.freeze([...e.statuses])])));
// Closed application stages only. The existing exitCode wire field carries
// these for STARTUP_FAILURE; it is not an observed process exit in that event.
// V1 is an additive event/optional-number extension: old stored reports and
// signatures stay valid. Deploy this receiver before the new native cohort.
const startupStages = new Map(spec.startupStages.map(stage=>[stage.code,stage]));
function startupStage(code,role){const stage=startupStages.get(code);return stage?.roles.includes(role)?{code:stage.code,label:stage.label}:null;}
// B's 312xx/313xx/314xx codes annotate an actually observed child exit only.
// They never become an A startup stage or establish a successful B claim.
const childStartupStages = new Map(spec.childStartupStages.map(stage=>[stage.code,stage]));
function childStartupStage(code){const stage=childStartupStages.get(code);return stage?{code:stage.code,label:stage.label}:null;}
const plain = x=>!!x&&Object.getPrototypeOf(x)===Object.prototype;
function roleAllowed(reporter,target){return spec.roles.includes(reporter)&&spec.roles.includes(target)&&(reporter===target||spec.parentRole[reporter]===target||spec.failedChildRole[reporter]===target);}
function combinationAllowed(reporter,target,event,status){
 if(!roleAllowed(reporter,target)||!Object.hasOwn(pairs,event)||!pairs[event].includes(status))return false;
 const def=spec.events.find(x=>x.name===event);
 if(reporter!==target&&def.scope!=='self-or-parent')return false;
 if(reporter===target&&def.selfForbidden?.includes(status))return false;
 if(def.scope==='A-self'&&(reporter!=='A'||target!=='A'))return false;
 return true;
}
function validate(events,reporter,target,{ordered=true}={}){
 if(!Array.isArray(events)||events.length<1||events.length>spec.maxEvents)return false;
 const seen=new Set();let parentExitObserved=false;
 for(const e of events){
  if(!plain(e)||!combinationAllowed(reporter,target,e.event,e.status))return false;
  if(e.event==='STARTUP_FAILURE'&&!startupStage(e.exitCode,reporter))return false;
  if(ordered){
   if(seen.has(e.event))return false;
   if(reporter!==target){
    if(e.event==='PROCESS_EXIT'&&seen.has('FILE_CLEANUP'))return false;
    if(e.event==='FILE_CLEANUP'&&e.status==='REMOVED'&&!parentExitObserved)return false;
   }else if(e.event==='SHUTDOWN_BEGIN'&&seen.has('FILE_CLEANUP'))return false;
  }
  seen.add(e.event);
  if(e.event==='PROCESS_EXIT')parentExitObserved=e.status==='OBSERVED';
 }
 return true;
}
module.exports=Object.freeze({spec,pairs,roleAllowed,combinationAllowed,startupStage,childStartupStage,validate});
