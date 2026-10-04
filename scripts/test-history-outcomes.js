'use strict';
// Real Detail service and a temporary JSON store; injected event fixtures.
// This does not run a Windows executable or modify an operating server.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'game-history-outcomes-'));
Object.assign(process.env,{DATA_DIR:dir,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../core/utils').EnsureDirs();
const state=require('../core/state'),licenses=require('../services/desktopLicenses'),workspace=require('../services/desktopWorkspace'),boot=require('../services/desktopBootstrap');
let count=0;
function test(name,fn){fn();count++;console.log('PASS '+name);}
try {
  const license=licenses.Create({label:'Timeline fixture',requestId:crypto.randomUUID()},'TEST').license;
  function detail(type,data){
    state.events.length=0;
    state.events.push({time:Date.now(),type,detail:JSON.stringify({licenseId:license.id,...data})});
    return workspace.Detail(license.id);
  }
  const positive={kind:'OBSERVATION',reason:'BASELINE_MATCH'};
  function row(type,data){return detail(type,data).timeline.find(r=>r.type===type);}
  test('A known successful observation has a normal label and no error guidance',()=>{const r=row('DESKTOP_SECURITY_AUTHORITY',positive);assert.equal(r.label,'서버 보안 검사 정상');assert.equal(r.reason,'BASELINE_MATCH');assert.equal(r.problem,null);});
  test('Explicit PASS is accepted for the same known success event',()=>{assert.equal(row('DESKTOP_SECURITY_AUTHORITY',{...positive,status:'PASS'}).problem,null);});
  test('An explicit non-PASS status is not hidden by a matching reason',()=>{assert.ok(row('DESKTOP_SECURITY_AUTHORITY',{...positive,status:'MISMATCH'}).problem);});
  test('Image digest mismatch retains failure guidance',()=>{const r=row('DESKTOP_SECURITY_AUTHORITY',{kind:'OBSERVATION',reason:'IMAGE_DIGEST_MISMATCH'});assert.equal(r.problem.code,'IMAGE_DIGEST_MISMATCH');assert.notEqual(r.label,'서버 보안 검사 정상');});
  test('Unknown observation reasons retain diagnostic guidance',()=>{assert.equal(row('DESKTOP_SECURITY_AUTHORITY',{kind:'OBSERVATION',reason:'UNKNOWN_RESULT'}).problem.code,'UNKNOWN_RESULT');});
  test('A request failure cannot become success by copying BASELINE_MATCH',()=>{const r=row('DESKTOP_RUNTIME_REQUEST_FAILED',positive);assert.equal(r.label,'서버에서 요청 거절');assert.ok(r.problem);});
  test('Different authority event kinds retain existing handling',()=>{assert.ok(row('DESKTOP_SECURITY_AUTHORITY',{kind:'POLICY_CHANGED',reason:'BASELINE_MATCH'}).problem);});
  test('An event without a reason has no invented problem',()=>{assert.equal(row('DESKTOP_BOOTSTRAP_CLOSED',{}).problem,null);});
  test('Malformed event JSON is ignored without losing the issuance record',()=>{state.events.length=0;state.events.push({time:Date.now(),type:'DESKTOP_SECURITY_AUTHORITY',detail:'{broken'});const d=workspace.Detail(license.id);assert.equal(d.timeline.length,1);assert.equal(d.timeline[0].type,'LICENSE_ISSUED');});
  test('The timeline read does not rewrite the stored events or authority state',()=>{detail('DESKTOP_SECURITY_AUTHORITY',positive);const beforeEvents=JSON.stringify(state.events),beforeBoot=JSON.stringify(boot.Initialize());workspace.Detail(license.id);assert.equal(JSON.stringify(state.events),beforeEvents);assert.equal(JSON.stringify(boot.Initialize()),beforeBoot);});
  test('Four successful observations remain four separate successful records',()=>{state.events.length=0;for(let i=0;i<4;i++)state.events.push({time:Date.now()+i,type:'DESKTOP_SECURITY_AUTHORITY',detail:JSON.stringify({licenseId:license.id,...positive})});const rows=workspace.Detail(license.id).timeline.filter(x=>x.type==='DESKTOP_SECURITY_AUTHORITY');assert.equal(rows.length,4);assert.ok(rows.every(x=>x.problem===null));});
  test('Unknown sensitive fields in an event are not returned in the timeline',()=>{const d=detail('DESKTOP_SECURITY_AUTHORITY',{...positive,sessionToken:'NEVER_REFLECT_TOKEN',payload:'NEVER_REFLECT_PAYLOAD'});assert.ok(!JSON.stringify(d).includes('NEVER_REFLECT'));});
  console.log(`History outcome display: ${count} service tests passed. Injected event fixtures; not live server validation.`);
} catch(error){console.error(error);process.exitCode=1;}
finally {workspace.Stop();fs.rmSync(dir,{recursive:true,force:true});}
