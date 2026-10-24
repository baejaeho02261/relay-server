'use strict';
// Process-local bounded diagnostics only. Nothing here writes or renews a lease.
const phases=Object.freeze(['CLAIMED','IMAGE_BOUND','GPU_BEGIN','GPU_READY','OWN_BEGIN','OWN_READY','MODULES_BEGIN','MODULES_READY','AUTHORITY_BEGIN','AUTHORIZED','VISIBLE','FAILED']);
const entries=new Map(),TTL=180000,MAX=2048;
function Fail(code){const e=Error(code);e.desktopError=true;e.status=400;throw e;}
function Parse(b){
 if(!b||Object.getPrototypeOf(b)!==Object.prototype||Object.keys(b).some(k=>!['action','sessionId','sessionToken','sequence','phase','elapsedMs','signature'].includes(k))||typeof b.sessionId!=='string'||!/^[A-F0-9]{24}$/.test(b.sessionId)||typeof b.sessionToken!=='string'||!b.sessionToken||b.sessionToken.length>512||typeof b.signature!=='string'||!b.signature||b.signature.length>1024||!Number.isInteger(b.sequence)||b.sequence<1||b.sequence>32||!phases.includes(b.phase)||!Number.isInteger(b.elapsedMs)||b.elapsedMs<0||b.elapsedMs>180000)Fail('OVERLAY_PROGRESS_INVALID');
 return b;
}
function Canonical(b){Parse(b);return ['GAME-OVERLAY-PROGRESS-V1',b.sessionId,b.sequence,b.phase,b.elapsedMs].join('\n');}
function Record(row,b){
 Parse(b);const now=Date.now();for(const [k,v]of entries)if(now>=v.until)entries.delete(k);
 const old=entries.get(row.sessionId);
 if(old){if(b.sequence===old.sequence&&b.phase===old.phase&&b.elapsedMs===old.elapsedMs)return {recorded:true};if(b.sequence<=old.sequence||old.phase==='FAILED'||old.phase==='VISIBLE'||b.elapsedMs<old.elapsedMs||phases.indexOf(b.phase)<=phases.indexOf(old.phase))Fail('OVERLAY_PROGRESS_REPLAY');}
 else if(entries.size>=MAX)Fail('OVERLAY_PROGRESS_CAPACITY');
 const item={phase:b.phase,sequence:b.sequence,elapsedMs:b.elapsedMs,receivedAt:now,until:old?.until||now+TTL,source:'SIGNED_CLIENT_REPORT',attested:false};
 entries.set(row.sessionId,item);
 try{require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_OVERLAY_PROGRESS',JSON.stringify({overlayId:row.id,sessionId:row.sessionId,parentSessionId:row.parentSessionId,licenseId:row.licenseId,...item}));}catch(_){}
 return {recorded:true};
}
function View(id){const e=entries.get(id);return e&&Date.now()<e.until?{...e}:{phase:'NOT_REPORTED',source:'NO_OBSERVATION',attested:false};}
module.exports={Parse,Canonical,Record,View,phases};
