'use strict';
// Actual controller exercised against isolated DOM and bounded API fixtures.
// These checks cover display provenance and interaction, not real Windows execution.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom');
const source=fs.readFileSync(path.join(__dirname,'../public/admin-desktop-server-state.js'),'utf8');
const hash=c=>c.repeat(128),manifest=hash('a'),otherManifest=hash('b'),currentId=hash('c'),oldId=hash('d');
const artifacts={A:hash('1'),B:hash('2'),O:hash('3')};
const when='2026-10-15T10:00:00.000Z';
function domain(id,outcome='NOT_RECORDED',policyStatus='NOT_RECORDED'){
 return {id:String(id),outcome,policyStatus,missingChecks:outcome==='NOT_RECORDED'?['probe-'+id]:[],checks:[{id:'probe-'+id,outcome,scope:'PRODUCT_WINDOWS',execution:'WINDOWS_X64',recordedAt:Date.parse(when),policyStatus,reasonCode:id===8?'<img src=x onerror=alert(1)>':null,evidenceSha512:outcome==='NOT_RECORDED'?null:hash('e')}]};
}
function status(){
 const domains=Array.from({length:14},(_,n)=>domain(n+1,n===0?'NOT_RUN':n===1?'FAIL':n===7?'PARTIAL':'PASS_REPORTED',n===0?'CURRENT':n===1?'STALE':'UNBOUND'));
 const reports=[{id:currentId,runId:'CURRENT',manifestId:manifest,recordedAt:Date.parse(when),finishedAt:when,outcome:'INCOMPLETE',policyStatus:'CURRENT',artifacts,domains},
 {id:oldId,runId:'HISTORIC <svg onload=alert(1)>',manifestId:manifest,recordedAt:Date.parse(when)-1000,finishedAt:when,outcome:'PASS_REPORTED',policyStatus:'STALE',artifacts,domains:domains.map(row=>({...row,outcome:'PASS_REPORTED',policyStatus:'STALE'}))}];
 return {epoch:2,licenseRevision:7,witness:{status:'CONFIGURED'},auditPending:0,journal:{},capabilities:{features:Array.from({length:14},(_,n)=>({id:String(n+1),name:n===0?'인증 <img src=x>':'분야 '+(n+1),implementation:n===0?'PARTIAL':'IMPLEMENTED',configured:{enabled:false},limitations:['SOURCE_TEST_NOT_WINDOWS']})),manualVerification:{recordCount:2,domains,history:reports,builds:[
 {buildKey:'current-build',manifestId:manifest,sourceManifestSha512:hash('f'),artifacts,active:true,latestRecordedAt:Date.parse(when),recordCount:2,domains,history:[currentId,oldId]},
 {buildKey:'other-build',manifestId:otherManifest,sourceManifestSha512:hash('f'),artifacts:{A:hash('4'),B:hash('5'),O:hash('6')},active:false,recordCount:0,domains:Array.from({length:14},(_,n)=>domain(n+1)),history:[]}
 ]}}};
}
const flows={version:1,items:[{flowId:'A'.repeat(24),createdAt:Date.parse(when),roles:{A:{status:'CLOSED',authorityEnded:true,processExit:'CLIENT_REPORTED',fileCleanup:'OBSERVED'},B:{status:'CLOSED',authorityEnded:true,processExit:'NOT_REPORTED',fileCleanup:'FAILED'},O:{status:'ACTIVE',authorityEnded:false,processExit:'NOT_REPORTED',fileCleanup:'NOT_REPORTED'}},events:[{id:'EVENT',role:'B',at:Date.parse(when),event:'FILE_CLEANUP <img src=x>',source:'CLIENT_REPORTED',status:'FAILED',pid:123,exitCode:0,win32Error:5,reporterRole:'O'}],bResidual:{code:'B_EXIT_NOT_REPORTED',summary:'B 종료 보고 없음 <img src=x>',confirmed:false}}]};
async function waitFor(test){for(let i=0;i<200;i++){if(test())return;await new Promise(resolve=>setTimeout(resolve,5));}throw Error('UI_COMPLETION_TIMEOUT');}
function create(overrides={}){
 const dom=new JSDOM('<!doctype html><body></body>',{url:'https://admin.test/',runScripts:'outside-only'}),w=dom.window,calls=[];let close,download=null;
 w.session={csrf:'SESSION_ONE'};w.roleIsAdmin=()=>true;
 w.esc=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 w.openModal=options=>{w.document.body.innerHTML=options.html;return new Promise(resolve=>{close=resolve;});};
 w.URL.createObjectURL=blob=>{download={blob};return 'blob:test';};w.URL.revokeObjectURL=()=>{};
 w.HTMLAnchorElement.prototype.click=function(){download.filename=this.download;};
 w.api=async(url,options)=>{calls.push({url,options});const custom=overrides.api?.(url,options);if(custom!==undefined)return custom;
  if(options?.method==='POST')return {record:{id:currentId,manifestId:manifest}};
  if(url.includes('/lifecycle'))return structuredClone(flows);
  if(url.includes('/verification-context'))return {manifestId:manifest,artifacts};
  if(url.endsWith('/device-identity'))return {revision:0,mode:'COMPATIBLE',items:[]};
  if(url.endsWith('/devices'))return {revision:0,items:[]};
  if(url.endsWith('/quarantine'))return {items:[]};
  return status();
 };
 vm.runInContext(source,dom.getInternalVMContext());
 return {dom,w,calls,start:()=>w.showDesktopServerState(),close:()=>close?.(false),download:()=>download};
}
const change=(w,id,value)=>{const el=w.document.getElementById(id);el.value=value;el.dispatchEvent(new w.Event('change',{bubbles:true}));};
const click=(w,action)=>w.document.querySelector(`[data-server-state-action="${action}"]`).click();
(async()=>{
 let x=create(),done=x.start(),w=x.w;
 try{
  await waitFor(()=>w.document.querySelector('#server-lifecycle-roles'));
  assert.equal(w.document.querySelectorAll('#server-capabilities-table>tbody>tr').length,14);
  assert.equal(w.document.querySelector('#server-verification-build').value,'current-build');
  assert(w.document.querySelector('#server-capabilities-panel').textContent.includes(artifacts.O));
  assert(w.document.querySelector('#server-capabilities-panel').textContent.includes('미실행'));
  assert(w.document.querySelector('#server-capabilities-panel').textContent.includes('정책 변경됨'));
  assert.equal(w.document.querySelectorAll('#desktop-server-state-root img,#desktop-server-state-root svg').length,0);
  assert(w.document.querySelector('#server-capabilities-panel').textContent.includes('<img src=x>'));
  assert(w.document.querySelector('#server-capabilities-panel').textContent.includes('부분 결과'));
  assert(w.document.querySelector('#server-capabilities-panel').textContent.includes('부분 구현'));
  w.document.querySelector('#server-device-new').value='draft-preserved';
  change(w,'server-verification-history',oldId);
  assert(w.document.querySelector('.server-state-report-meta').textContent.includes('HISTORIC <svg'));
  assert.equal(w.document.querySelector('#server-device-new').value,'draft-preserved');
  change(w,'server-verification-build','other-build');
  assert.equal(w.document.querySelector('#server-verification-history').options.length,1);
  assert(w.document.querySelector('#server-capabilities-panel').textContent.includes('기록 없음'));
  assert.equal(w.document.querySelector('#server-device-new').value,'draft-preserved');
  change(w,'server-verification-build','current-build');
  click(w,'verification-context');await waitFor(()=>x.download()?.filename);
  assert.equal(x.download().filename,'verification-context-'+manifest.slice(0,16)+'.json');
  assert(x.calls.some(call=>call.url.endsWith('/verification-context?manifestId='+manifest)));
  assert(w.document.querySelector('#server-lifecycle-panel').textContent.includes('B_EXIT_NOT_REPORTED'));
  assert(w.document.querySelector('#server-lifecycle-panel').textContent.includes('잔류 또는 정상 정리를 단정하지 않습니다'));
  assert(w.document.querySelector('#server-lifecycle-events').textContent.includes('Windows 오류 5'));
  assert(w.document.querySelector('#server-lifecycle-roles [data-outcome="FAILED"]'));
  assert.equal(w.document.querySelector('#server-lifecycle-panel img'),null);
  // Size rejection must never reach mutation API.
  const input=w.document.querySelector('#server-manual-verification');Object.defineProperty(input,'files',{configurable:true,value:[{size:65537,text:async()=>'{}'}]});
  click(w,'manual-verification');await waitFor(()=>w.document.querySelector('#server-state-status').dataset.state==='error');
  assert(!x.calls.some(call=>call.options?.method==='POST'));
  Object.defineProperty(input,'files',{configurable:true,value:[{size:64,text:async()=>'{}'}]});
  click(w,'manual-verification');await waitFor(()=>w.document.querySelector('#server-state-status').textContent.includes('시험 기록을 등록했습니다'));
  assert.equal(w.document.querySelector('#server-verification-history').value,currentId);
  assert.equal(x.calls.filter(call=>call.options?.method==='POST').length,1);
  x.close();await done;assert.equal(w.document.querySelector('#desktop-server-state-root').childNodes.length,0);
 }finally{x.close();x.dom.window.close();}
 // Delayed lifecycle response must not repaint a closed modal.
 let release;x=create({api:url=>url.includes('/lifecycle')?new Promise(resolve=>{release=resolve;}):undefined});done=x.start();w=x.w;
 try{await waitFor(()=>release);x.close();await done;release(flows);await new Promise(resolve=>setTimeout(resolve,15));assert.equal(w.document.querySelector('#desktop-server-state-root').childNodes.length,0);}finally{x.dom.window.close();}
 // A changed administrator session must prevent a delayed context download.
 let contextResolve;x=create({api:url=>url.includes('/verification-context')?new Promise(resolve=>{contextResolve=resolve;}):undefined});done=x.start();w=x.w;
 try{await waitFor(()=>w.document.querySelector('#server-lifecycle-roles'));click(w,'verification-context');await waitFor(()=>contextResolve);w.session={csrf:'SESSION_TWO'};contextResolve({manifestId:manifest});await new Promise(resolve=>setTimeout(resolve,15));assert.equal(x.download(),null);x.close();await done;}finally{x.dom.window.close();}
 // A failed trace request must explicitly show unknown/error, never prior success.
 x=create({api:url=>url.includes('/lifecycle')?Promise.reject(Error('TRACE_UNAVAILABLE')):undefined});done=x.start();w=x.w;
 try{await waitFor(()=>w.document.querySelector('#server-lifecycle-panel')?.textContent.includes('TRACE_UNAVAILABLE'));assert.equal(w.document.querySelector('#server-lifecycle-roles'),null);x.close();await done;}finally{x.dom.window.close();}
 // Display authorization is required before any read call.
 x=create();try{x.w.roleIsAdmin=()=>false;await assert.rejects(x.start(),/관리자/);assert.equal(x.calls.length,0);}finally{x.dom.window.close();}
 console.log('SERVER STATE DASHBOARD UI PASS: 14 domains, exact build/history isolation, scope and policy status, escaped evidence and trace, operator import, context download, preserved forms, authorization and late-response guards.');
})().catch(error=>{console.error(error);process.exitCode=1;});
