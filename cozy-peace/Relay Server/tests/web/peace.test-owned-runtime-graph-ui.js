'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom');
const dom=new JSDOM('<main id="content"></main>',{runScripts:'outside-only'}),w=dom.window;
vm.runInContext(`function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));} function fmtTime(x){return String(x);}`,dom.getInternalVMContext());
new vm.Script(fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-licenses.js'),'utf8')).runInContext(dom.getInternalVMContext());
const view=w.document.getElementById('content');
const bundle={version:3,coverage:'FULL',fileStatus:'MEASURED',codeStatus:'MEASURED',crcStatus:'MEASURED',imageStable:true,startedTick:10,finishedTick:20};
const graph={version:1,scope:'REGISTERED_APP_OBJECTS',profile:'LICENSE_API_V1',status:'MEASURED',stable:true,reason:'STABLE',after:{revision:'7',nodes:Array(6).fill({}),edges:Array(5).fill({})}};
function render(value){view.innerHTML=w.desktopOwnMeasurementMarkup(value);return view.textContent;}
try{
 assert.match(render({...bundle,ownedGraph:graph}),/B 라이선스 세션 · 객체 6개 · 연결 5개 · 세대 7/);
 assert.match(view.textContent,/클라이언트 측정/);assert.match(view.textContent,/서버가 직접 관측한 실행 증거가 아닙니다/);
 assert.match(render({...bundle,coverage:'PARTIAL',ownedGraph:{...graph,status:'FAILED',stable:false,reason:'RUNTIME_OBJECT_RETIRED',after:null}}),/미완료 보고/);
 assert.match(view.textContent,/등록 객체 수명 종료/);assert.match(view.textContent,/부분 측정/);
 assert.match(render({...bundle,ownedGraph:{...graph,version:99}}),/규격 미확인/);
 assert.doesNotMatch(view.textContent,/연결 일치 보고/);
 render({...bundle,version:2});assert.equal(view.querySelector('.desktop-owned-runtime'),null);
 render({...bundle,ownedGraph:{...graph,profile:'<img src=x onerror=alert(1)>',reason:'constructor',after:{revision:'<svg onload=alert(1)>',nodes:Array(33),edges:[]}}});
 assert.equal(view.querySelector('img,svg,script'),null);assert.match(view.textContent,/역할 미확인/);assert.match(view.textContent,/사유 미확인/);assert.match(view.textContent,/객체 —개/);
 const rejected={id:'REPORT',stage:'A',check:'OWN_CODE',status:'REJECTED',reason:'RUNTIME_GRAPH_REQUIRED',ownMeasurement:{...bundle,ownedGraph:graph}};
 view.innerHTML=w.desktopIntegrityRecordsMarkup([rejected],{});
 assert.match(view.querySelector('summary').textContent,/거부/);assert.match(view.textContent,/RUNTIME_GRAPH_REQUIRED/);
 assert.ok(view.querySelector('.desktop-integrity-rejected'));
 const pointer=require('../../services/integrity/peace.pointer-graph-contract'),observed=pointer.Expected(218),expected=pointer.Expected(222);
 const historical={...rejected,reason:'POINTER_GRAPH_MISMATCH',ownMeasurement:{...bundle,pointerGraph:observed,ownedGraph:{...graph,profile:'BOOTSTRAP_CLIENT_V1',after:{...graph.after,revision:'2'}}}};
 view.innerHTML=w.desktopIntegrityRecordsMarkup([historical],{});
 const api=view.querySelector('.desktop-api-pointer-graph');assert.ok(api);assert.match(api.textContent,/SEALED_API_ARENA/);assert.match(api.textContent,/218/);assert.match(api.textContent,/당시 서버 기준이 저장되지 않은 기록/);assert.match(view.querySelector('.desktop-owned-runtime').textContent,/객체 6개 · 연결 5개 · 세대 2/);
 assert.match(view.querySelector('.desktop-extended-hashes').textContent,/비교 단계 미도달 · 당시 값 저장 안 됨/);assert.doesNotMatch(view.querySelector('.desktop-extended-hashes').textContent,/미측정/);
 const current={...historical,hashComparisonStatus:'NOT_REACHED',pointerGraphVerified:false,ownedGraphValidated:false,pointerGraphComparison:{version:1,scope:'SEALED_API_ARENA',expected:pointer.Summary(expected),observed:pointer.Summary(observed)},observedXxh3_128:'a'.repeat(32),observedBlake3:'b'.repeat(64),expectedXxh3_128:'a'.repeat(32),expectedBlake3:'b'.repeat(64)};
 view.innerHTML=w.desktopIntegrityRecordsMarkup([current],{});assert.match(view.querySelector('.desktop-api-pointer-graph').textContent,/222/);assert.match(view.querySelector('.desktop-api-pointer-graph').textContent,/218/);assert.doesNotMatch(view.querySelector('.desktop-api-pointer-graph').textContent,/比較完了|기준 비교 완료/);assert.match(view.querySelectorAll('.desktop-extended-hashes')[1].textContent,/비교 단계 미도달 · 값만 보관/);assert.doesNotMatch(view.querySelectorAll('.desktop-extended-hashes')[1].textContent,/서버 확장 해시 기준 일치/);
 const hostile={...historical,pointerGraphComparison:{version:1,scope:'SEALED_API_ARENA',expected:{...pointer.Summary(expected),slots:'<img src=x onerror=alert(1)>',sha512:'x'.repeat(100000)},observed:{...pointer.Summary(observed),nodes:Infinity}},ownMeasurement:{...bundle,pointerGraph:{...observed,slots:1025,crc64:'<svg onload=x>'},ownedGraph:graph}};
 view.innerHTML=w.desktopIntegrityRecordsMarkup([hostile],{});assert.equal(view.querySelector('img,svg,script'),null);assert.match(view.querySelector('.desktop-api-pointer-graph').textContent,/당시 서버 기준이 저장되지 않은 기록/);assert.doesNotMatch(view.querySelector('.desktop-api-pointer-graph').textContent,/Infinity|100000/);
 view.innerHTML=w.desktopIntegrityMarkup({items:[historical]},{items:[]},null);
 assert.equal(view.querySelector('.desktop-integrity-record'),null,'the global policy workspace must not render member execution records');
 assert.doesNotMatch(view.textContent,/POINTER_GRAPH_MISMATCH|REPORT/);
 assert.ok(view.querySelector('#desktop-integrity-panel'));
 console.log('OWNED RUNTIME UI PASS: reported scope, failed lifetime, unknown format, legacy absence, safe fields, independent rejection and member-only record placement preserved');
}finally{dom.window.close();}
