'use strict';
// Bounded rule engine fed only by server outcome events. No raw request body,
// password, assertion, token, path or client-supplied "success" is persisted.
const crypto=require('node:crypto');
const CODE=/^[A-Z][A-Z0-9_]{1,79}$/;
const RULES=Object.freeze({AUTH_FAILURE:{count:8,windowMs:60000,severity:'HIGH'},INTEGRITY_FAILURE:{count:3,windowMs:120000,severity:'HIGH'},RESOURCE_REJECTED:{count:8,windowMs:60000,severity:'MEDIUM'},WORKER_TIMEOUT:{count:3,windowMs:120000,severity:'HIGH'},AUDIT_FAILURE:{count:1,windowMs:60000,severity:'CRITICAL'},TRUST_CHANGED:{count:1,windowMs:60000,severity:'HIGH'},EXPOSURE_BLOCKED:{count:1,windowMs:60000,severity:'HIGH'},PARSER_TEST_FAILED:{count:1,windowMs:60000,severity:'HIGH'},SNAPSHOT_STALE:{count:3,windowMs:120000,severity:'MEDIUM'}});
function Subject(s){return crypto.createHash('sha512').update(String(s||'SERVER')).digest('hex').slice(0,48);}
class Detector {
 constructor({clock=()=>Date.now(),emit=()=>{},maxAlerts=200,maxBuckets=512}={}){this.clock=clock;this.emit=emit;this.maxAlerts=maxAlerts;this.maxBuckets=maxBuckets;this.buckets=new Map();this.alerts=new Map();this.dropped=0;this.lastAt=0;this.emitting=false;}
 record(kind,fields={}){
  const rule=RULES[kind];if(!rule)return null;const now=this.clock();this.lastAt=now;const subject=Subject(fields.subject),reason=CODE.test(fields.reason||'')?fields.reason:kind,key=kind+':'+subject;
  for(const [k,b]of this.buckets)if(now-b.lastAt>Math.max(rule.windowMs,300000))this.buckets.delete(k);
  let b=this.buckets.get(key);if(!b){if(this.buckets.size>=this.maxBuckets){this.dropped++;return null;}b={firstAt:now,lastAt:now,count:0};this.buckets.set(key,b);}
  if(now-b.firstAt>rule.windowMs){b.firstAt=now;b.count=0;}b.lastAt=now;b.count=Math.min(1000000,b.count+1);if(b.count<rule.count)return null;
  const old=[...this.alerts.values()].find(a=>a.key===key&&a.status!=='RESOLVED'&&now-a.lastAt<300000);
  if(old){old.lastAt=now;old.count=Math.min(1000000,old.count+1);return this.publicAlert(old);}
  if(this.alerts.size>=this.maxAlerts){const resolved=[...this.alerts.values()].find(a=>a.status==='RESOLVED');if(resolved)this.alerts.delete(resolved.id);else{this.dropped++;return null;}}
  const a={id:crypto.randomBytes(12).toString('hex'),key,kind,reason,subject,severity:rule.severity,status:'OPEN',firstAt:now,lastAt:now,count:b.count,threshold:rule.count,windowMs:rule.windowMs,auditRecorded:false};this.alerts.set(a.id,a);
  // Audit failure is deliberately memory-only. Calling the failed writer again
  // here could append after a rollback and violate the original failed ACK.
  if(kind!=='AUDIT_FAILURE'&&!this.emitting){this.emitting=true;try{this.emit('SECURITY_DETECTION_ALERT',{...this.publicAlert(a),auditRecorded:true});a.auditRecorded=true;}catch(_){this.dropped++;}finally{this.emitting=false;}}
  return this.publicAlert(a);
 }
 publicAlert(a){const {key,...out}=a;return {...out};}
 validateResponse(body){if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).sort().join(',')!=='action,alertId,reason'||!['ACKNOWLEDGE','RESOLVE','HOLD_BACKGROUND','RELEASE_BACKGROUND'].includes(body.action)||typeof body.alertId!=='string'||!CODE.test(body.reason||''))throw Error('SECURITY_RESPONSE_INVALID');const a=this.alerts.get(body.alertId);if(!a)throw Error('SECURITY_ALERT_NOT_FOUND');
  return a;}
 respond(body){const a=this.validateResponse(body);
  if(body.action==='ACKNOWLEDGE')a.status='ACKNOWLEDGED';if(body.action==='RESOLVE')a.status='RESOLVED';a.respondedAt=this.clock();a.response=body.action;return this.publicAlert(a);}
 capture(event){if(!event||typeof event.type!=='string'||event.type.startsWith('SECURITY_DETECTION_')||event.type==='SECURITY_RESPONSE')return;
  let d={};if(typeof event.detail==='string'&&Buffer.byteLength(event.detail)<=65536){try{d=JSON.parse(event.detail);}catch(_){d={};}}if(!d||Array.isArray(d)||typeof d!=='object')d={};const subject=d.sessionId||d.actorHash||d.subject||d.flowId||'SERVER',reason=d.reason||event.type;
  if(event.type==='AUDIT_WRITE_FAILED')return this.record('AUDIT_FAILURE',{subject:'AUDIT',reason:'AUDIT_WRITE_FAILED'});
  if(['WEB_LOGIN_FAILED','ADMIN_LOGIN_FAILED','WEB_REAUTH_FAILED','PASSKEY_AUTH_FAILED'].includes(event.type))return this.record('AUTH_FAILURE',{subject,reason:'AUTHENTICATION_FAILED'});
  if(event.type==='DESKTOP_INTEGRITY_REJECTED'||event.type==='DESKTOP_SECURITY_AUTHORITY'&&['INVALIDATED','HOLD'].includes(d.kind))return this.record('INTEGRITY_FAILURE',{subject,reason});
  if(event.type==='DESKTOP_OVERLAY_LEASE_BOUND'&&d.bound==='MODULE_SNAPSHOT'&&Number.isFinite(d.expiresAt)&&Number.isFinite(d.serverTime)&&d.expiresAt-d.serverTime<10000)return this.record('SNAPSHOT_STALE',{subject,reason:'MODULE_SNAPSHOT_BOUND'});
  if(event.type==='ARTIFACT_EXPOSURE_BLOCKED')return this.record('EXPOSURE_BLOCKED',{subject:d.sha512,reason:'ARTIFACT_EXPOSURE_BLOCKED'});
  if(event.type==='DESKTOP_SECURITY_OPERATIONS'&&/SIGNER|RECOVERY|COHORT_REVOKE|CONTROLS_CHANGED|BUILD_CONTRACT_CHANGED|RELEASE_GOVERNANCE|PAIR_ACTIVATED/.test(d.kind||''))return this.record('TRUST_CHANGED',{subject,reason:'TRUST_CONFIGURATION_CHANGED'});
  if(event.type==='DESKTOP_SERVER_OPERATION'&&d.phase==='COMMITTED'&&/SIGNER|RECOVERY|COHORT_REVOKE|DEVICE_KEY_REVOKE|SECURITY_POLICY|RELEASE_GOVERNANCE/.test(d.kind||''))return this.record('TRUST_CHANGED',{subject,reason:'TRUST_CONFIGURATION_CHANGED'});
 }
 status(){return {version:1,mode:'ALERT_ONLY_NO_AUTOMATIC_DEVICE_BAN',scope:'THIS_PROCESS_RECENT_AUDIT_REPLAY',countersDurable:false,alerts:[...this.alerts.values()].sort((a,b)=>b.lastAt-a.lastAt).map(a=>this.publicAlert(a)),dropped:this.dropped,lastEventAt:this.lastAt,rules:RULES};}
}
const detector=new Detector({emit:(type,body)=>{const r=require("../../storage/audit/peace.audit.js").LogEvent(type,JSON.stringify(body),{durable:true});if(!r?.ok)throw Error('AUDIT_WRITE_FAILED');}});
let bootstrapped=false;
function Start(){if(bootstrapped)return;bootstrapped=true;const events=require("../../core/peace.runtime-state").events;for(const e of events.slice(-2000)){if(e.type==='SECURITY_DETECTION_ALERT')try{const a=JSON.parse(e.detail);if(/^[a-f0-9]{24}$/.test(a.id)&&RULES[a.kind]&&/^[a-f0-9]{48}$/.test(a.subject)&&CODE.test(a.reason)&&Number.isSafeInteger(a.lastAt)){const safe={id:a.id,kind:a.kind,subject:a.subject,severity:RULES[a.kind].severity,reason:a.reason,status:'OPEN',firstAt:a.firstAt,lastAt:a.lastAt,count:a.count,threshold:RULES[a.kind].count,windowMs:RULES[a.kind].windowMs,auditRecorded:true,key:a.kind+':'+a.subject};detector.alerts.set(a.id,safe);if(detector.alerts.size>200)detector.alerts.delete(detector.alerts.keys().next().value);}}catch(_){}else if(e.type==='SECURITY_RESPONSE')try{const x=JSON.parse(e.detail),a=detector.alerts.get(x.alertId);if(a&&['ACKNOWLEDGE','RESOLVE'].includes(x.action))a.status=x.action==='RESOLVE'?'RESOLVED':'ACKNOWLEDGED';}catch(_){} }
}
function Respond(body,actor){
 detector.validateResponse(body);
 // Do not hold jobs or change incident status if the authenticated audit append
 // failed. A crash after the append is visible as a recorded intent; the brief
 // resource hold is explicitly volatile and is not silently restored on boot.
 const result=require("../../storage/audit/peace.audit.js").LogEvent('SECURITY_RESPONSE',JSON.stringify({alertId:body.alertId,action:body.action,reason:body.reason,actorHash:Subject(actor),scope:'BACKGROUND_NEW_JOBS_ONLY',holdMs:body.action==='HOLD_BACKGROUND'?300000:0}),{durable:true});
 if(!result?.ok){const e=Error('SECURITY_RESPONSE_AUDIT_FAILED');e.desktopError=true;e.status=503;throw e;}
 if(body.action==='HOLD_BACKGROUND')require("../runtime/peace.server-resource-budget").Hold(body.reason,300000);
 if(body.action==='RELEASE_BACKGROUND')require("../runtime/peace.server-resource-budget").ReleaseHold();
 return detector.respond(body);
}
module.exports={Detector,RULES,Start,Record:(...a)=>detector.record(...a),Capture:e=>detector.capture(e),Status:()=>detector.status(),Respond};
