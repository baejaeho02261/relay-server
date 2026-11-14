'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Real durable aggregate service -> admin controller. Synthetic timings are
// UI fixtures, never Windows/product or operational performance evidence.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom');
const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'game-performance-ui-'));
Object.assign(process.env,{DATA_DIR:temporary,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-PERFORMANCE-UI'});
const metrics=require("../../services/observability/peace.desktop-performance-metrics");
const source=fs.readFileSync(path.join(MODULE_RESOURCE_ROOT,"../public/scripts/desktop/peace.admin-desktop-server-state.js"),'utf8');
let wall=Date.parse('2026-10-16T02:30:00Z'),tick=0;
const factory={directory:path.join(temporary,'aggregate'),wall:()=>wall,tick:()=>tick,timer:false,acquire:()=>{}};
let store=metrics.Create(factory);
store.QueueState('authentication',1,2,1,2);
wall+=5000;tick+=5000;
assert(store.RecordRenewal('B',100,true));assert(store.RecordRenewal('O',211,false));
assert(store.RecordShutdown('O',{version:1,joinElapsedMs:42,joinBudgetMissed:false,durationTruncated:false}));
assert(store.RecordLifecycle('A','PROCESS_EXIT','OBSERVED',15));
assert(store.RecordLifecycle('B','FILE_CLEANUP','SCHEDULED',3));
assert(store.RecordLifecycle('B','FILE_CLEANUP','FAILED',undefined));
store.QueueState('authentication',0,0,1,2);
wall+=1000;tick+=1000;
assert(store.Flush());store.Close();wall+=61000;tick+=61000;store=metrics.Create(factory);
const expected=store.Snapshot({resolution:'hour',limit:24});
assert.equal(expected.summary.renewal.ALL.count,2);assert.equal(expected.summary.queues.authentication.saturatedMs,5000);
assert(expected.gaps.some(g=>g.code==='RESTART_UNOBSERVED'));
async function waitFor(test){for(let i=0;i<200;i++){if(test())return;await new Promise(resolve=>setTimeout(resolve,5));}throw Error('PERFORMANCE_UI_TIMEOUT');}
function create(overrides={}){
 const dom=new JSDOM('<!doctype html><body></body>',{url:'https://admin.test/',runScripts:'outside-only'}),w=dom.window,calls=[];let close;
 w.session={csrf:'SESSION_ONE'};w.roleIsAdmin=()=>true;
 w.esc=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 w.openModal=options=>{w.document.body.innerHTML=options.html;return new Promise(resolve=>{close=resolve;});};
 w.api=async(url,options)=>{calls.push({url,options});const custom=overrides.api?.(url,options);if(custom!==undefined)return custom;
  if(url.includes('/performance')){const query=new URL(url,'https://admin.test').searchParams;return store.Snapshot({resolution:query.get('resolution'),limit:Number(query.get('limit'))});}
  if(url.includes('/lifecycle'))return {version:1,items:[]};
  if(url.endsWith('/device-identity'))return {revision:0,mode:'COMPATIBLE',items:[]};
  if(url.endsWith('/devices'))return {revision:0,items:[]};
  if(url.endsWith('/quarantine'))return {items:[]};
  return {epoch:1,licenseRevision:1,witness:{status:'CONFIGURED'},auditPending:0,journal:{},capabilities:{features:[],manualVerification:{}}};
 };
 vm.runInContext(source,dom.getInternalVMContext());
 return {dom,w,calls,start:()=>w.showDesktopServerState(),close:()=>close?.(false)};
}
function select(w,value){const target=w.document.querySelector('#server-performance-window');target.value=value;target.dispatchEvent(new w.Event('change',{bubbles:true}));}
(async()=>{try{
 let x=create(),done=x.start(),w=x.w;
 try{
  await waitFor(()=>w.document.querySelector('#server-performance-renewal'));
  const panel=w.document.querySelector('#server-performance-panel');
  assert(panel.textContent.includes('100 ms'));assert(panel.textContent.includes('211 ms'));assert(panel.textContent.includes('83.33%'));
  assert(panel.textContent.includes('RESTART_UNOBSERVED'));assert(panel.textContent.includes('상한값'));assert(panel.textContent.includes('OS 프로세스 종료까지의 전체 시간이 아닙니다'));
  assert(panel.textContent.includes('TLS 연결·왕복 통신 시간은 포함하지 않습니다'));
  assert.equal(panel.querySelectorAll('#server-performance-renewal tbody tr').length,2);
  assert.equal(panel.querySelectorAll('#server-performance-shutdown tbody tr').length,4);
  assert.equal(panel.querySelectorAll('#server-performance-lifecycle tbody tr').length,8);
  assert(panel.querySelector('#server-performance-lifecycle').textContent.includes('정리 예약 1개'));
  assert(panel.querySelector('#server-performance-lifecycle').textContent.includes('실패 1개'));
  assert(panel.querySelector('#server-performance-lifecycle').textContent.includes('시간 미측정 1'));
  assert(panel.querySelectorAll('meter[aria-label]').length>0);
  assert.equal(panel.querySelectorAll('#server-performance-series tbody tr').length,1);
  assert(panel.textContent.includes('표본 없음'));assert(panel.textContent.includes('UTC'));
  w.document.querySelector('#server-device-new').value='KEEP_UNSENT_FORM';
  select(w,'day:365');await waitFor(()=>w.document.querySelector('#server-performance-series'));
  assert.equal(w.document.querySelector('#server-performance-window').value,'day:365');
  assert(x.calls.some(call=>call.url.endsWith('/performance?resolution=day&limit=365')));
  assert.equal(w.document.querySelector('#server-device-new').value,'KEEP_UNSENT_FORM');
  assert(!x.calls.some(call=>call.options?.method==='POST'));
  x.close();await done;
 }finally{x.close();x.dom.window.close();}
 // No samples is visibly distinct from zero latency or good health.
 const empty=metrics.Create({...factory,directory:path.join(temporary,'empty')});
 x=create({api:url=>url.includes('/performance')?empty.Snapshot():undefined});done=x.start();w=x.w;
 try{await waitFor(()=>w.document.querySelector('#server-performance-renewal'));assert(w.document.querySelector('#server-performance-panel').textContent.includes('선택 기간에 보존된 관측 기록이 없습니다'));assert(w.document.querySelector('.server-performance-cards').textContent.includes('표본 없음'));x.close();await done;}finally{empty.Close();x.dom.window.close();}
 // Real persistence write failure produces degraded display without fabricated success.
 const failing=metrics.Create({...factory,directory:path.join(temporary,'failing'),write:()=>{throw Error('SYNTHETIC_WRITE_FAILURE');}});failing.RecordRenewal('B',9,true);assert.equal(failing.Flush(),false);
 x=create({api:url=>url.includes('/performance')?failing.Snapshot():undefined});done=x.start();w=x.w;
 try{await waitFor(()=>w.document.querySelector('[data-state="DEGRADED"]'));assert(w.document.querySelector('#server-performance-panel').textContent.includes('PERFORMANCE_PERSISTENCE_UNAVAILABLE'));assert(w.document.querySelector('#server-performance-panel').textContent.includes('손실 구간 상한을 확인할 수 없습니다'));x.close();await done;}finally{failing.Close();x.dom.window.close();}
 // Escaped labels and error states cannot inject markup; malformed old API cannot look normal.
 const hostile=structuredClone(expected);hostile.status='DEGRADED';hostile.persistence.errorCode='<img src=x onerror=alert(1)>';hostile.gaps.push({code:'<svg onload=alert(1)>',from:wall,to:wall});hostile.summary.queues['<img src=x>']={observedMs:0,saturatedMs:0,saturationEpisodes:0,rejected:0,maxQueued:0};hostile.limitations.push('<script>alert(1)</script>');
 x=create({api:url=>url.includes('/performance')?hostile:undefined});done=x.start();w=x.w;
 try{await waitFor(()=>w.document.querySelector('#server-performance-renewal'));assert.equal(w.document.querySelectorAll('#server-performance-panel img,#server-performance-panel svg,#server-performance-panel script').length,0);assert(w.document.querySelector('#server-performance-panel').textContent.includes('<img src=x'));x.close();await done;}finally{x.dom.window.close();}
 for(const response of [()=>({version:0,series:[]}),()=>Promise.reject(Error('METRICS_UNAVAILABLE'))]){
  x=create({api:url=>url.includes('/performance')?response():undefined});done=x.start();w=x.w;
  try{await waitFor(()=>w.document.querySelector('#server-performance-panel [role="alert"]'));assert.equal(w.document.querySelector('#server-performance-renewal'),null);assert(w.document.querySelector('#server-performance-panel').textContent.includes('정상 또는 지연 0으로 표시하지 않습니다'));x.close();await done;}finally{x.dom.window.close();}
 }
 // Out-of-order period requests cannot repaint a more recent period or any other form.
 const pending=[];x=create({api:url=>url.includes('/performance')?new Promise(resolve=>pending.push({url,resolve})):undefined});done=x.start();w=x.w;
 try{await waitFor(()=>pending.length===1);select(w,'day:90');await waitFor(()=>pending.length===2);pending[1].resolve(store.Snapshot({resolution:'day',limit:90}));await waitFor(()=>w.document.querySelector('#server-performance-series'));pending[0].resolve(hostile);await new Promise(resolve=>setTimeout(resolve,15));assert.equal(w.document.querySelector('#server-performance-window').value,'day:90');assert.equal(w.document.querySelector('#server-performance-panel [data-state="DEGRADED"]'),null);x.close();await done;}finally{x.dom.window.close();}
 // Closing the modal or changing administrator sessions invalidates late reads.
 for(const changeSession of [false,true]){
  let release;x=create({api:url=>url.includes('/performance')?new Promise(resolve=>{release=resolve;}):undefined});done=x.start();w=x.w;
  try{await waitFor(()=>release);if(changeSession)w.session={csrf:'SESSION_TWO'};else{x.close();await done;}release(expected);await new Promise(resolve=>setTimeout(resolve,15));assert.equal(w.document.querySelector('#server-performance-renewal'),null);x.close();await done;}finally{x.dom.window.close();}
 }
 x=create();try{x.w.roleIsAdmin=()=>false;await assert.rejects(x.start(),/관리자/);assert.equal(x.calls.length,0);}finally{x.dom.window.close();}
 console.log('PERFORMANCE DASHBOARD UI PASS: durable real service reload, percentile bounds, queue observed-time ratios, join/parent/file duration scopes, restart gaps, histogram accessibility, bounded periods, empty/degraded/error/XSS/stale/session guards. Synthetic UI fixtures only.');
}finally{store.Close();fs.rmSync(temporary,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
