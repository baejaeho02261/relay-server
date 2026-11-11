'use strict';
// Exhaustive source-neutral adjudication for all 204 NHW and 122 Cozy
// catalog rows. This tests reporting semantics, not 326 live Windows attacks.
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const catalog=require('../../services/security/peace.security-detection-catalog');
const {Semantics}=require('../../services/security/peace.security-event-semantics');
const all=[...catalog.NHW,...catalog.COZY];
const base={invalidated:false,sessionInvalidated:false,provenance:'AUTHENTICATED_CLIENT_REPORT',
 confidence:30,correlation:false,disposition:'OBSERVATION_UNRESOLVED'};

test('all NHW and Cozy kinds use one classification and never confuse a related revoked session with the cause',()=>{
 assert.equal(catalog.NHW.length,204);assert.equal(catalog.COZY.length,122);
 const seen=new Set();
 for(const entry of all){
  assert.ok(!seen.has(entry.id),entry.id);seen.add(entry.id);
  const unresolved=Semantics(entry,{...base,sessionInvalidated:true});
  assert.equal(unresolved.causedAuthorityChange,false,entry.id);
  assert.equal(unresolved.authorityAction,'EVIDENCE_ONLY',entry.id);
  assert.equal(unresolved.sessionCurrentlyRevoked,true,entry.id);
  assert.equal(unresolved.securityFinding,false,entry.id);
  assert.ok(unresolved.kind&&typeof unresolved.kind==='string',entry.id);
  const output=Semantics(entry,{...base,disposition:'DETECTION',invalidated:true});
  if(entry.signalClass==='UNKNOWN'){
   assert.equal(output.securityFinding,false,entry.id+' unavailable not attack');
   assert.notEqual(output.authorityAction,'DETECTION_REVOKE');
  }else if(entry.origin==='COZY'&&entry.signalClass==='POLICY_REJECTION'){
   assert.equal(output.securityFinding,false,entry.id+' policy rejection not attack');
   assert.equal(output.authorityAction,'POLICY_DENIAL');
  }else{
   assert.equal(output.securityFinding,true,entry.id+' detected finding');
   assert.equal(output.authorityAction,'DETECTION_REVOKE',entry.id);
  }
 }
 assert.equal(seen.size,326);
});

test('four real 2026-11-12 A incomplete snapshots share one denial, not four attack detections',()=>{
 const ids=['MEASUREMENT_PLAN_INCOMPLETE','MEASUREMENT_GENERATION_INCOMPLETE',
  'MEASUREMENT_EXPORT_INCOMPLETE','INCOMPLETE_SNAPSHOT'];
 for(const [i,id] of ids.entries()){
  const e=catalog.Get(id);assert.ok(e&&e.signalClass==='UNKNOWN');
  const out=Semantics(e,{...base,disposition:'OBSERVATION_UNRESOLVED',
   provenance:'SERVER_COMPARISON',confidence:0,invalidated:i===0,sessionInvalidated:true});
  assert.equal(out.kind,'MEASUREMENT_UNAVAILABLE');
  assert.equal(out.securityFinding,false);
  assert.equal(out.authorityAction,i===0?'MEASUREMENT_DENIAL':'EVIDENCE_ONLY');
  assert.equal(out.sessionCurrentlyRevoked,true);
 }
});

test('existing signed secondary records retain their historical invalidated bit without claiming four separate causative stops',()=>{
 const entry=catalog.Get('MEASUREMENT_EXPORT_INCOMPLETE');
 const legacy=Semantics(entry,{...base,invalidated:true,causalInvalidation:false,
  sessionInvalidated:true,provenance:'SERVER_COMPARISON',confidence:0});
 assert.equal(legacy.authorityAction,'EVIDENCE_ONLY');
 assert.equal(legacy.causedAuthorityChange,false);
 assert.equal(legacy.sessionCurrentlyRevoked,true);
 const primary=Semantics(catalog.Get('MEASUREMENT_PLAN_INCOMPLETE'),
  {...base,invalidated:true,causalInvalidation:true,provenance:'SERVER_COMPARISON',confidence:0});
 assert.equal(primary.authorityAction,'MEASUREMENT_DENIAL');
});

test('native NHW confirmed thread manipulation and independent tamper still revoke; observation never does',()=>{
 for(const id of ['dkThread','dkTokenObject','dkPECodeIntegrity','dkInjectionEvidence','dkWriteIntegrity']){
  const entry=catalog.Get(id);
  assert.equal(Semantics(entry,{...base,disposition:'DETECTION',invalidated:true}).authorityAction,'DETECTION_REVOKE');
  const seen=Semantics(entry,{...base,disposition:'INTERNAL_EVIDENCE',invalidated:false,sessionInvalidated:true});
  assert.equal(seen.authorityAction,'EVIDENCE_ONLY');
 }
});

test('all outcomes render consistent safety language without treating missing measurement as an attack',()=>{
 const source=fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-members.js'),'utf8');
 const context=vm.createContext({content:{addEventListener:()=>{}},desktopDate:()=>String(0),esc:v=>String(v??'').replace(/[&<>"']/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]))});
 vm.runInContext(source,context);
 const sample=(id,status,invalidated)=>{
  const e=catalog.Get(id),disposition=status,verified=Semantics(e,{...base,disposition,invalidated,sessionInvalidated:true});
  return {id,detectionId:id,displayName:e.displayName,origin:e.origin,signalClass:e.signalClass,role:'A',responsePath:'server',firstAt:1,lastAt:1,firstTick:'0000000000000001',lastTick:'0000000000000001',count:1,confirmationCount:0,confidence:0,correlation:false,evidenceFamilies:[],invalidated,sessionInvalidated:true,disposition,context:{},...verified};
 };
 const rows=[sample('MEASUREMENT_PLAN_INCOMPLETE','OBSERVATION_UNRESOLVED',true),sample('MEASUREMENT_EXPORT_INCOMPLETE','OBSERVATION_UNRESOLVED',false),sample('dkPECodeIntegrity','DETECTION',true),sample('dkThread','INTERNAL_EVIDENCE',false)];
 const html=context.desktopSecurityDetectionsMarkup(rows);
 assert.match(html,/측정 불완전/);assert.match(html,/필수 측정 미완료 · 서버 실행 승인 거부/);
 assert.match(html,/이 기록으로 인한 무효화 기록 없음/);assert.match(html,/현재 서버 권한/);
 assert.match(html,/보안 감지 · 서버 세션 무효화/);
 assert.doesNotMatch(html,/판정 보류 · 관측 보고|감지 · 서버 정책 적용/);
 for(const entry of all){const v=context.desktopDetectionDisposition(sample(entry.id,'OBSERVATION_UNRESOLVED',false));
  assert.ok(v.label&&v.tone&&v.code,entry.id);}
});

test('native first-party retry requires a tracked loader change, full discard, and strict exhausted-failure behavior',t=>{
 const native=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Integrity/Cozy.ModuleInventory.pas');
 const a=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas');
 const b=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Platform/Cozy.Api.pas');
 const o=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas');
 if(![native,a,b,o].every(fs.existsSync)){t.skip('native Delphi source shipped separately from relay-only Docker');return;}
 const n=fs.readFileSync(native,'utf8');const x=fs.readFileSync(a,'utf8');
 assert.match(n,/moduleGenerationStable_925125cf, False/);
 assert.match(n,/TRACKED_CHANGED_6fbd302a/);
 assert.match(n,/TransientPaths = Total - Measured/);
 assert.match(n,/PhaseValue = 1/);
 assert.match(x,/ModuleInventoryGenerationRetryable\(Snapshot\)/);
 assert.match(x,/GenerationRetries >= 2/);
 assert.match(x,/FreeAndNil\(Snapshot\)/);
 assert.match(fs.readFileSync(b,'utf8'),/ModuleInventoryGenerationRetryable\(FModuleSnapshot\)/);
 assert.match(fs.readFileSync(o,'utf8'),/ModuleInventoryGenerationRetryable\(Snapshot\)/);
});

test('server rejection chain preserves first incomplete cause and records dependent diagnostics without false revokes',()=>{
 const source=fs.readFileSync(path.resolve(__dirname,'../../services/integrity/peace.desktop-integrity-reports.js'),'utf8');
 assert.match(source,/RecordFinding\(row,stage,reason,reject&&reason===unique\[0\]\)/);
 assert.match(source,/if\(reject\)RevokeSnapshot\(row,'INTEGRITY_'\+unique\[0\]\)/);
 assert.match(source,/RequireSnapshot\(row,stage\)/);
 const detectionSource=fs.readFileSync(path.resolve(__dirname,'../../services/security/peace.security-detections.js'),'utf8');
 assert.match(detectionSource,/DENY_INCOMPLETE_MEASUREMENT/);
 assert.match(detectionSource,/Semantics\(/);
 assert.match(detectionSource,/active.reason!=='INTEGRITY_'\+e.detectionId/);
});
