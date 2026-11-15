'use strict';
// Administrator-scheduled certificate window. The offer travels ONLY inside a
// response authenticated by the current pinned TLS + per-request AES-GCM keys.
// No CA discovery, TOFU, client-supplied certificate or private-key delivery.
const path=require('node:path'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
// Once this process observes retirement, a backward wall-clock correction
// cannot reopen the old certificate. No client timestamp sets this clock.
const clockTick=performance.now();let clockWall=Date.now(),clockLast=clockWall;
function TimeNow(){
 const elapsed=Math.floor(performance.now()-clockTick),wall=Date.now();
 if(!Number.isSafeInteger(wall)||elapsed<0||!Number.isSafeInteger(elapsed))Fail('TLS_PIN_CLOCK_INVALID',503);
 const at=Math.max(wall,clockWall+elapsed,clockLast);
 if(!Number.isSafeInteger(at))Fail('TLS_PIN_CLOCK_INVALID',503);
 clockWall=at-elapsed;clockLast=at;return at;
}
const MAX_OVERLAP=86400000,MAX_LEAD=7*86400000,MAX_HISTORY=64;
const FIELDS=['version','generation','host','port','serverKeyId','tlsServerName','currentPin','nextPin','issuedAt','notBefore','oldNotAfter'];
const HEX=/^[a-f0-9]{64}$/,ID=/^[a-f0-9]{48}$/;
function Fail(code,status=409){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Plain(x){return !!x&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function ValidatePlan(p){
 if(!Plain(p)||Object.keys(p).length!==FIELDS.length||FIELDS.some(k=>!Object.hasOwn(p,k))||p.version!==1||!Number.isSafeInteger(p.generation)||p.generation<1||p.generation>MAX_HISTORY||
  ![p.currentPin,p.nextPin,p.serverKeyId].every(x=>typeof x==='string'&&HEX.test(x))||p.currentPin===p.nextPin||
  ![p.host,p.tlsServerName].every(x=>typeof x==='string'&&x.length<=253&&/^[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$/.test(x))||
  !Number.isInteger(p.port)||p.port<1||p.port>65535||
  !['issuedAt','notBefore','oldNotAfter'].every(k=>Number.isSafeInteger(p[k])&&p[k]>0&&p[k]<=8640000000000000)||
  p.notBefore<p.issuedAt||p.notBefore-p.issuedAt>MAX_LEAD||p.oldNotAfter-p.notBefore<60000||p.oldNotAfter-p.notBefore>MAX_OVERLAP)
  Fail('TLS_PIN_PLAN_INVALID',400);
 return p;
}
function Validate(row){
 if(!Plain(row)||Object.keys(row).sort().join(',')!=='generation,plan,retiredPins,stagedGeneration,version'||row.version!==1||!ID.test(row.stagedGeneration||''))Fail('TLS_PIN_STORE_INVALID');
 ValidatePlan(row.plan);
 if(row.generation!==row.plan.generation||!Array.isArray(row.retiredPins)||row.retiredPins.length!==row.generation-1||row.retiredPins.length>=MAX_HISTORY||new Set(row.retiredPins).size!==row.retiredPins.length||row.retiredPins.some(x=>!HEX.test(x)||x===row.plan.currentPin||x===row.plan.nextPin))Fail('TLS_PIN_STORE_INVALID');
 return row;
}
function Candidate(generation,serverName){
 if(!ID.test(generation||''))Fail('TLS_PIN_STAGED_GENERATION_INVALID',400);
 const tls=require('./peace.connect-tls');tls.Directory(tls.DIR);const dir=path.join(tls.DIR,generation);tls.Directory(dir);
 const cert=tls.Read(path.join(dir,'certificate.pem'),32768),key=tls.Read(path.join(dir,'private-key.pem'),16384);
 try{tls.AssertPurpose(cert);return {...tls.Validate(cert,key,serverName),generation};}finally{key.fill(0);}
}
function CheckBinding(plan,profile){if(['host','port','serverKeyId','tlsServerName'].some(k=>plan[k]!==profile[k]))Fail('TLS_PIN_ENDPOINT_CHANGED');}
function Accepts(plan,pin,now){ValidatePlan(plan);if(!Number.isSafeInteger(now))return false;return pin===plan.currentPin&&now<plan.oldNotAfter||pin===plan.nextPin&&now>=plan.notBefore;}
function Schedule(body,actor){
 if(!Plain(body)||Object.keys(body).sort().join(',')!=='expectedGeneration,notBefore,oldNotAfter,stagedGeneration'||!Number.isSafeInteger(body.expectedGeneration)||body.expectedGeneration<0)Fail('TLS_PIN_INPUT_INVALID',400);
 const tls=require('./peace.connect-tls'),profile=require('./peace.connect-transport-key').Profile(),current=tls.Load(),next=Candidate(body.stagedGeneration,profile.tlsServerName),at=TimeNow();
 const plan=ValidatePlan({version:1,generation:body.expectedGeneration+1,host:profile.host,port:profile.port,serverKeyId:profile.serverKeyId,tlsServerName:profile.tlsServerName,currentPin:current.fingerprint,nextPin:next.fingerprint,issuedAt:at,notBefore:body.notBefore,oldNotAfter:body.oldNotAfter});
 if(plan.notBefore<at+60000||current.expiresAt<plan.oldNotAfter||next.validFrom>plan.notBefore||next.expiresAt<=plan.oldNotAfter)Fail('TLS_PIN_CERTIFICATE_WINDOW_INVALID');
 return require("../storage/peace.desktop-operation-audit").Run('TLS_PIN_TRANSITION',actor,{fingerprint:next.fingerprint},db=>{
  const old=db.tlsPinTransition;if(old)Validate(old);
  if((old?.generation||0)!==body.expectedGeneration)Fail('TLS_PIN_GENERATION_CONFLICT');
  if(old&&(at<old.plan.oldNotAfter||current.fingerprint!==old.plan.nextPin))Fail('TLS_PIN_TRANSITION_NOT_FINISHED');
  const retired=old?[...old.retiredPins,old.plan.currentPin]:[];
  if(retired.includes(next.fingerprint)||retired.includes(current.fingerprint))Fail('TLS_PIN_ROLLBACK_FORBIDDEN');
  const artifacts=['A','B','O'].map(c=>db.artifacts[db.active[c]]);
  if(artifacts.some(a=>a?.tlsPinVersion!==1))Fail('TLS_PIN_ACTIVE_BUILD_UPGRADE_REQUIRED');
  // An announced generation is immutable. A bad scheduled certificate requires
  // new trusted launcher provisioning, not silently cancelling the client rule.
  db.tlsPinTransition=Validate({version:1,generation:plan.generation,plan,stagedGeneration:body.stagedGeneration,retiredPins:retired});
  return {generation:plan.generation,plan,serverCertificateAutomaticallyChanged:false};
 });
}
function Offer(){
 const row=require("../bootstrap/peace.desktop-bootstrap-store").Load().tlsPinTransition;if(!row)return null;Validate(row);
 const profile=require('./peace.connect-transport-key').Profile();CheckBinding(row.plan,profile);
 if(!Accepts(row.plan,profile.tlsCertificateSha256,TimeNow()))Fail('TLS_PIN_SERVER_CERTIFICATE_OUTSIDE_WINDOW',503);
 return structuredClone(row.plan);
}
function Status(){const row=require("../bootstrap/peace.desktop-bootstrap-store").Load().tlsPinTransition;if(!row)return {enabled:false,generation:0};Validate(row);return {enabled:true,generation:row.generation,plan:structuredClone(row.plan),stagedGeneration:row.stagedGeneration,retiredPinCount:row.retiredPins.length,maxOverlapMs:MAX_OVERLAP,clientTrustPersistence:'MEMORY_AND_AUTHENTICATED_HANDOFF_ONLY',serverCertificateAutomaticallyChanged:false};}
module.exports={MAX_OVERLAP,MAX_LEAD,MAX_HISTORY,FIELDS,ValidatePlan,Validate,Candidate,CheckBinding,Accepts,Schedule,Offer,Status};
