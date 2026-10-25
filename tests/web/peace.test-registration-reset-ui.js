'use strict';
// Executes the shipped reset UI against a scripted DOM/network. It does not
// claim browser E2E, Windows execution or production reset verification.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const all=fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-workflow.js'),'utf8');
const source=all.slice(all.indexOf('let desktopPendingRegistrationReset=null;'),all.indexOf('async function showDesktopReleaseSafety(){'));
const base='/api/desktop/bootstrap/security-operations/registration-reset',id='11'.repeat(32),otherId='22'.repeat(32),scope='ABO_LICENSES_ISSUANCE_OPERATIONS_V1';
const turn=()=>new Promise(resolve=>setImmediate(resolve));
function State(operation=null){return {ok:true,scope,confirmation:'전체 초기화',epoch:4,counts:{artifacts:3,activeArtifacts:3,licenses:7,issuedLaunchers:2,flows:1,overlays:0,issueReceipts:2,packingEvidence:3,releaseManifests:1},relatedCounts:{machine:{bindings:2},integrity:{baselines:3},workspace:{jobs:4}},operation};}
function Fixture({postError,postResult,fetchRows=[],holdFetch=false,loseSessionDuringPost=false}={}){
 const elements={},requests=[],reads=[],timers=new Map(),selected=new Set(['license']),roots=[];let nextTimer=0,currentRoot,close,options,finished,invalidations=0;
 const state=State();
 const ctx={URL,Uint8Array,AbortController,console,session:{csrf:'owner'},roleIsAdmin:()=>true,desktopWorkflowOwner:()=>ctx.session?.csrf,
  desktopSelectedLicenses:selected,desktopPendingIssue:{old:true},desktopPendingRevoke:{old:true},desktopPendingLauncher:{old:true},desktopInvalidatePanels(){invalidations++;},
  crypto:{getRandomValues(bytes){bytes.fill(0x11);return bytes;}},
  esc:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),
  document:{getElementById:()=>currentRoot},
  setTimeout(fn,delay){const n=++nextTimer;timers.set(n,{fn,delay});if(delay===2000)setImmediate(()=>{if(timers.delete(n))fn();});return n;},clearTimeout(n){timers.delete(n);},
  openModal(value){options=value;currentRoot={isConnected:true,querySelector(selector){return elements[selector.slice(1)];},replaceChildren(){this.empty=true;}};roots.push(currentRoot);
   for(const match of value.html.matchAll(/id="([^"]+)"/g))elements[match[1]]={value:'',disabled:false,hidden:false,textContent:'',innerHTML:'',dataset:{}};
   return new Promise(resolve=>{const root=currentRoot;close=()=>{root.isConnected=false;resolve(null);};});},
  api:async(url,opt)=>{requests.push({url,opt:opt?structuredClone(opt):undefined});if(opt?.method==='POST'){if(loseSessionDuringPost){ctx.showLogin();throw new TypeError('restart while receiving response');}if(postError)throw postError;return postResult||{ok:true,operation:{id,status:'QUEUED'},restartRequired:true};}return structuredClone(state);},
  fetch:async(url,opt)=>{reads.push({url,opt});if(holdFetch)return new Promise((resolve,reject)=>opt.signal.addEventListener('abort',()=>reject(Error('ABORTED')),{once:true}));const row=fetchRows.shift()||{status:401};if(row.error)throw row.error;const status=row.status||200;return {status,ok:status===200,json:async()=>row.value||State()};},
  showLogin(){ctx.session=null;close();}
 };
 vm.createContext(ctx);vm.runInContext(source+'\nglobalThis.run=showDesktopRegistrationReset;globalThis.pending=()=>desktopPendingRegistrationReset;',ctx);
 return {ctx,elements,requests,reads,state,timers,selected,roots,get options(){return options;},get invalidations(){return invalidations;},
  async start(){finished=ctx.run();await turn();},
  async submit(text='전체 초기화'){elements['desktop-reset-confirmation'].value=text;elements['desktop-reset-confirmation'].oninput();await elements['desktop-reset-submit'].onclick();},
  async close(){close();await finished;await turn();},
  status(){return elements['desktop-reset-status'].textContent;},
  async reopen(){ctx.session={csrf:'new-owner'};finished=ctx.run();await turn();},
  pending(){return ctx.pending();}
 };
}
test('main toolbar and server operations both expose the reset entry point',()=>{
 for(const file of ['peace.admin-desktop-licenses.js','peace.admin-desktop-security.js']){
  const text=fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop',file),'utf8');assert(text.includes('registration-reset'));assert(text.includes('등록 데이터 전체 초기화'));
 }
});
test('dialog explains counts, irreversible scope and preserved authentication/security',async()=>{
 const f=Fixture();await f.start();try{
  assert(f.options.html.includes('되돌릴 수 없습니다'));assert(f.options.html.includes('서버 키·관리자 로그인 수단·보안 정책'));
  assert(f.options.html.includes('PC에 저장된 EXE 파일은 바뀌지 않습니다'));
  const counts=f.elements['desktop-reset-counts'].innerHTML;assert(counts.includes('라이선스'));assert(counts.includes('7건'));assert(counts.includes('4건'));
  assert.equal(f.elements['desktop-reset-submit'].disabled,true);assert(!/localStorage|sessionStorage|indexedDB/.test(source));
 }finally{await f.close();}
});
test('exact Korean confirmation is required and POST binds scope epoch and random nonce',async()=>{
 const f=Fixture({fetchRows:[{value:State({id,status:'COMPLETE',completedAt:123})}]});await f.start();try{
  for(const wrong of ['', '전체초기화','전체 초기화 ','전체 삭제']){await f.submit(wrong);assert.equal(f.requests.filter(x=>x.opt).length,0);}
  await f.submit();const posts=f.requests.filter(x=>x.opt);assert.equal(posts.length,1);assert.equal(posts[0].url,base);
  assert.deepEqual(posts[0].opt.body,{requestId:id,scope,confirmation:'전체 초기화',expectedEpoch:4});assert.equal(f.elements['desktop-reset-status'].dataset.state,'success');
  assert.equal(f.invalidations,1);assert.equal(f.selected.size,0);assert.equal(f.ctx.desktopPendingIssue,null);assert.equal(f.pending(),null);
 }finally{await f.close();}
});
test('queued receipt followed by session expiry is pending, never success',async()=>{
 const f=Fixture({fetchRows:[{value:State({id,status:'QUEUED',completedAt:0})},{status:401}]});await f.start();try{
  await f.submit();assert(!f.status().includes('초기화가 완료되었습니다'));assert(f.status().includes('다시 로그인'));
  assert.equal(f.elements['desktop-reset-login'].hidden,false);assert.equal(f.pending().id,id);assert.equal(f.requests.filter(x=>x.opt).length,1);
  assert(f.reads.every(x=>x.url===base+'?requestId='+id));assert(f.reads.every(x=>x.opt.credentials==='same-origin'&&x.opt.cache==='no-store'));
 }finally{await f.close();}
});
test('ambiguous POST response is read by the same nonce and never resubmitted',async()=>{
 const f=Fixture({postError:new TypeError('connection lost'),fetchRows:[{value:State({id,status:'COMPLETE',completedAt:123})}]});await f.start();try{
  await f.submit();assert.equal(f.requests.filter(x=>x.opt).length,1);assert.equal(f.reads.length,1);assert.equal(f.elements['desktop-reset-status'].dataset.state,'success');
 }finally{await f.close();}
});
test('different operation COMPLETE and missing completion timestamp cannot report success',async()=>{
 for(const op of [{id:otherId,status:'COMPLETE',completedAt:123},{id,status:'COMPLETE',completedAt:0}]){
  const f=Fixture({fetchRows:[{value:State(op)},{status:401}]});await f.start();try{await f.submit();assert.notEqual(f.elements['desktop-reset-status'].dataset.state,'success');assert.equal(f.pending().id,id);}finally{await f.close();}
 }
});
test('pending nonce survives re-login in RAM and only exact persisted COMPLETE confirms reset',async()=>{
 const f=Fixture({fetchRows:[{status:401}]});await f.start();await f.submit();assert.equal(f.pending().id,id);await f.close();
 f.state.operation={id,status:'COMPLETE',completedAt:123};f.state.counts={};f.state.epoch=5;
 // Initial GET discovers the same receipt; observation still reads that nonce.
 f.ctx.fetch=async(url,opt)=>{f.reads.push({url,opt});return {status:200,ok:true,json:async()=>structuredClone(f.state)};};
 await f.reopen();try{await turn();assert(f.requests.at(-1).url.endsWith('?requestId='+id));assert.equal(f.elements['desktop-reset-status'].dataset.state,'success');assert.equal(f.pending(),null);assert.equal(f.requests.filter(x=>x.opt).length,1);}finally{await f.close();}
});
test('session loss before POST response retains the nonce even after its modal closes',async()=>{
 const f=Fixture({loseSessionDuringPost:true});await f.start();await f.submit();assert.equal(f.ctx.session,null);assert.equal(f.pending().id,id);assert.equal(f.requests.filter(x=>x.opt).length,1);assert.equal(f.reads.length,0);await f.close();
});
test('cancelled administrator reauthentication does not queue a nonce or send a second POST',async()=>{
 const f=Fixture({postError:Error('재인증을 취소했습니다. 작업은 적용되지 않았습니다.')});await f.start();try{
  await f.submit();assert.equal(f.pending(),null);assert.equal(f.reads.length,0);assert.equal(f.requests.filter(x=>x.opt).length,1);assert.equal(f.elements['desktop-reset-submit'].disabled,false);
 }finally{await f.close();}
});
test('stale epoch displays actionable Korean guidance without reusing approval',async()=>{
 const error=Error('conflict');error.status=409;error.code='REGISTRATION_RESET_EPOCH_CONFLICT';const f=Fixture({postError:error});await f.start();try{await f.submit();assert(f.status().includes('창을 닫고 다시 열어'));assert.equal(f.pending(),null);assert.equal(f.reads.length,0);}finally{await f.close();}
});
test('closing during status fetch aborts request and clears timeout resources',async()=>{
 const f=Fixture({holdFetch:true});await f.start();const action=f.submit();await turn();assert.equal(f.reads.length,1);const signal=f.reads[0].opt.signal;await f.close();await action;assert(signal.aborted);assert.equal(f.timers.size,0);
});
