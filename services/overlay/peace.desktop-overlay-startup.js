'use strict';
// Process-local bounded diagnostics only. Nothing here writes or renews a lease.
const phases=Object.freeze(['CLAIMED','IMAGE_BOUND','GPU_BEGIN','GPU_READY','OWN_BEGIN','OWN_READY','MODULES_BEGIN','MODULES_READY','AUTHORITY_BEGIN','AUTHORIZED','VISIBLE','FAILED']);
const failureStages=Object.freeze(['BINDING','FONT_READ','FONT_DATA','CREATE','RESIZE','GPU_IDENTITY','FLOATING_POINT','UNKNOWN']);
// Closed native FACILITY_ITF codes describe only the bridge's own CPU gate.
// Legacy E_OUTOFMEMORY and arbitrary driver codes remain unclassified: neither
// is evidence of a particular GPU allocation or system-wide memory shortage.
const admissionFailures=Object.freeze({
 '-2147171839':'CPU 컨텍스트 할당 실패',
 '-2147171838':'CPU 고정 메모리 예약 실패',
 '-2147171837':'폰트 복사 메모리 할당 실패',
 '-2147171836':'프레임·업로드용 여유 메모리 확보 실패'
});
const entries=new Map(),TTL=180000,MAX=2048;
function Fail(code){const e=Error(code);e.desktopError=true;e.status=400;throw e;}
function ValidFailure(value){
 return !!value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).length===3&&
  ['version','stage','code'].every(key=>Object.hasOwn(value,key))&&value.version===1&&failureStages.includes(value.stage)&&
  Number.isInteger(value.code)&&value.code>=-2147483648&&value.code<=2147483647;
}
function CopyFailure(value){return {version:1,stage:value.stage,code:value.code};}
function SameFailure(a,b){return a===undefined?b===undefined:b!==undefined&&a.version===b.version&&a.stage===b.stage&&a.code===b.code;}
function Parse(b){
 if(!b||Object.getPrototypeOf(b)!==Object.prototype||Object.keys(b).some(k=>!['action','sessionId','sessionToken','sequence','phase','elapsedMs','signature','failure'].includes(k))||typeof b.sessionId!=='string'||!/^[A-F0-9]{24}$/.test(b.sessionId)||typeof b.sessionToken!=='string'||!b.sessionToken||b.sessionToken.length>512||typeof b.signature!=='string'||!b.signature||b.signature.length>1024||!Number.isInteger(b.sequence)||b.sequence<1||b.sequence>32||!phases.includes(b.phase)||!Number.isInteger(b.elapsedMs)||b.elapsedMs<0||b.elapsedMs>180000)Fail('OVERLAY_PROGRESS_INVALID');
 if(Object.hasOwn(b,'failure')&&(b.phase!=='FAILED'||!ValidFailure(b.failure)))Fail('OVERLAY_PROGRESS_INVALID');
 return b;
}
function Canonical(b){
 Parse(b);
 if(Object.hasOwn(b,'failure'))return ['GAME-OVERLAY-PROGRESS-V2',b.sessionId,b.sequence,b.phase,b.elapsedMs,1,b.failure.stage,b.failure.code].join('\n');
 return ['GAME-OVERLAY-PROGRESS-V1',b.sessionId,b.sequence,b.phase,b.elapsedMs].join('\n');
}
function Record(row,b){
 Parse(b);const now=Date.now();for(const [k,v]of entries)if(now>=v.until)entries.delete(k);
 // Anchor retention to the server's fixed Claim timestamp. Cache eviction or
 // a restart must not let an old signed progress request buy another TTL.
 const until=row.claimedAt+TTL;
 if(!Number.isSafeInteger(row.claimedAt)||!Number.isSafeInteger(until)||now<row.claimedAt||now>=until)Fail('OVERLAY_PROGRESS_EXPIRED');
 const old=entries.get(row.sessionId);
 if(old){if(b.sequence===old.sequence&&b.phase===old.phase&&b.elapsedMs===old.elapsedMs&&SameFailure(b.failure,old.failure))return {recorded:true};if(b.sequence<=old.sequence||old.phase==='FAILED'||old.phase==='VISIBLE'||b.elapsedMs<old.elapsedMs||phases.indexOf(b.phase)<=phases.indexOf(old.phase))Fail('OVERLAY_PROGRESS_REPLAY');}
 else if(entries.size>=MAX)Fail('OVERLAY_PROGRESS_CAPACITY');
 const item={phase:b.phase,sequence:b.sequence,elapsedMs:b.elapsedMs,receivedAt:now,until:old?.until||until,source:'SIGNED_CLIENT_REPORT',attested:false,...(b.failure?{failure:CopyFailure(b.failure)}:{})};
 entries.set(row.sessionId,item);
 try{require("../../storage/audit/peace.audit.js").LogEvent('DESKTOP_OVERLAY_PROGRESS',JSON.stringify({overlayId:row.id,sessionId:row.sessionId,parentSessionId:row.parentSessionId,licenseId:row.licenseId,...item}));}catch(_){}
 return {recorded:true};
}
function View(id){const e=entries.get(id);return e&&Date.now()<e.until?{...e,...(e.failure?{failure:CopyFailure(e.failure)}:{})}:{phase:'NOT_REPORTED',source:'NO_OBSERVATION',attested:false};}
function FailureLabel(value){
 if(!ValidFailure(value))return '';
 const label=value.stage+' · '+(value.code===0?'원인 코드 없음':'0x'+(value.code>>>0).toString(16).toUpperCase().padStart(8,'0'));
 const detail=value.stage==='CREATE'&&Object.hasOwn(admissionFailures,String(value.code))?admissionFailures[String(value.code)]:'';
 return label+(detail?' · '+detail:'');
}
module.exports={Parse,Canonical,Record,View,phases,FailureLabel};
