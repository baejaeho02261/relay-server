'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM,VirtualConsole}=require('jsdom');
const root=path.resolve(__dirname,'../..'),errors=[],requests=[],now=Date.now();
const vc=new VirtualConsole();vc.on('jsdomError',error=>errors.push(error.message));
const dom=new JSDOM('<!doctype html><main><div id="content"></div></main><div id="modal"><div id="modal-body"></div><button id="modal-confirm"></button></div>',{url:'https://fixture.invalid',runScripts:'outside-only',pretendToBeVisual:true,virtualConsole:vc});
const w=dom.window;w.eval=code=>vm.runInContext(code,dom.getInternalVMContext());
const clone=value=>JSON.parse(JSON.stringify(value));
const memberId='A'.repeat(24),otherId='B'.repeat(24),targetId='C'.repeat(24);
let revision=3,failWrite=false,dialog=null,mutationCount=0;
const members=[{id:memberId,displayName:'<img src=x onerror=bad()>',note:'고객 메모 <script>bad()</script>',status:'ACTIVE',createdAt:now,updatedAt:now,counts:{licenses:25,launchers:1,flows:1,devices:1,integrity:1,incidents:1}},{id:otherId,displayName:'두 번째 회원',note:'',status:'ACTIVE',createdAt:now,updatedAt:now,counts:{licenses:0,launchers:0,flows:0,devices:0,integrity:0,incidents:0}}];
const receipts=new Map();
function category(items,totalCount=items.length,page=1){return {items,totalCount,page,pageSize:20};}
function detail(id,categoryName,page){
 const assignment={assignmentKind:'LICENSE',assignmentTargetId:targetId,assignedMemberId:id==='unassigned'?'':memberId,memberId:id==='unassigned'?'':memberId,memberDisplayName:id==='unassigned'?'':members[0].displayName,assignmentOrigin:id==='unassigned'?'UNASSIGNED':'DIRECT'};
 const categories={licenses:category([{id:targetId,label:page===2?'두 번째 페이지':'라이선스 <svg onload=bad()>',status:'USED',consumed:true,issuedAt:now,...assignment}],25,page),launchers:category([{id:'D'.repeat(24),label:'A 발급',status:'ISSUED',issuedAt:now,assignmentKind:'LAUNCHER',assignmentTargetId:'D'.repeat(24),assignedMemberId:'',memberId,assignmentOrigin:'LINKED'}]),flows:category([{id:'F'.repeat(24),status:'EXPIRED',createdAt:now,lifecycle:{roles:{A:{role:'A',status:'HANDED_OFF',authorityEnded:true,processExit:'CLIENT_REPORTED',fileCleanup:'REMOVED'},B:{role:'B',status:'EXPIRED',authorityEnded:true,processExit:'NOT_REPORTED',fileCleanup:'NOT_REPORTED'}},events:[{at:now,role:'B',event:'LEASE_EXPIRED',status:'EXPIRED',source:'SERVER_CONFIRMED'},{at:now,role:'B',event:'FILE_CLEANUP',status:'FAILED',source:'CLIENT_REPORTED',pid:12345,exitCode:31028,win32Error:5,elapsedMs:732}],bResidual:{code:'B_EXIT_NOT_REPORTED',summary:'종료 관측 보고가 없습니다.'}},assignmentKind:'FLOW',assignmentTargetId:'F'.repeat(24),assignedMemberId:'',memberId,assignmentOrigin:'LINKED'}]),devices:category([{id:'e'.repeat(64),status:'ACTIVE',blocked:true,blockSource:'SINGLE_USE',assurance:'APP_KEY_POSSESSION',firstSeenAt:now,assignmentKind:'DEVICE',assignmentTargetId:'e'.repeat(64),assignedMemberId:memberId,assignmentOrigin:'DIRECT'}]),integrity:category([{id:'report1',at:now,stage:'B',check:'OWN_CODE',status:'REJECTED',reason:'CODE_HASH_MISMATCH',expectedSha512:'ab'.repeat(64),observedSha512:'cd'.repeat(64),expectedCrc64:'123456789ABCDEF0',observedCrc64:'1111111111111111',assignmentKind:'FLOW',assignmentTargetId:'F'.repeat(24),assignedMemberId:'',memberId,assignmentOrigin:'LINKED'}]),incidents:category([{id:'incident1',at:now,kind:'INTEGRITY_REJECTION',source:'SERVER_INTEGRITY',stage:'B',status:'REJECTED',reason:'CODE_HASH_MISMATCH',flowId:'F'.repeat(24),assignmentKind:'FLOW',assignmentTargetId:'F'.repeat(24),assignedMemberId:'',memberId,assignmentOrigin:'LINKED'}])};
 return {version:1,revision,member:id==='unassigned'?null:members.find(row=>row.id===id),categories:categoryName==='all'?categories:{[categoryName]:categories[categoryName]}};
}
w.content=w.document.getElementById('content');w.modalEl=w.document.getElementById('modal');w.modalBody=w.document.getElementById('modal-body');w.modalConfirm=w.document.getElementById('modal-confirm');
w.session={csrf:'OWNER1'};w.currentView='desktop-licenses';w.roleIsAdmin=()=>true;w.esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));w.fmtTime=value=>new Date(value).toISOString();w.toast=()=>{};w.showDesktopFirstDeviceApproval=async()=>{};w.showDesktopUnifiedDetail=async()=>{};
w.api=async(url,options={})=>{
 const body=options.body&&clone(options.body),method=options.method||'GET';requests.push({url,method,body});const u=new URL(url,'https://fixture.invalid');
 if(method==='GET'){
  if(u.pathname==='/api/desktop/members'){
   const q=u.searchParams.get('q')||'',status=u.searchParams.get('status')||'ACTIVE',filtered=members.filter(row=>(status==='ALL'||row.status===status)&&(!q||row.displayName.includes(q)||row.id.includes(q)));
   return clone({version:1,revision,items:filtered,totalCount:filtered.length,page:Number(u.searchParams.get('page')||1),pageSize:Number(u.searchParams.get('pageSize')||20),unassigned:{counts:{licenses:1,launchers:0,flows:0,devices:0,integrity:0,incidents:0}}});
  }
  const id=u.pathname.split('/').at(-1);return clone(detail(id,u.searchParams.get('category')||'all',Number(u.searchParams.get('page')||1)));
 }
 if(receipts.has(body.requestId)){assert.deepEqual(receipts.get(body.requestId).body,body);return clone(receipts.get(body.requestId).response);}
 if(body.expectedRevision!==revision){const error=Error('MEMBER_REVISION_CONFLICT');error.code='MEMBER_REVISION_CONFLICT';error.status=409;throw error;}revision++;mutationCount++;
 if(u.pathname==='/api/desktop/members'){members.push({id:'E'.repeat(24),displayName:body.displayName,note:body.note,status:'ACTIVE',counts:{},createdAt:now,updatedAt:now});}
 const response={revision};receipts.set(body.requestId,{body,response});
 if(failWrite){failWrite=false;const error=Error('응답 유실');error.status=503;throw error;}
 return clone(response);
};
w.openModal=options=>{
 w.modalBody.innerHTML=(options.html||'')+(options.fields||[]).map(field=>field.type==='select'?`<select data-modal-field="${field.name}">${field.options.map(option=>`<option value="${w.esc(option.value)}" ${option.value===field.value?'selected':''}>${w.esc(option.label)}</option>`).join('')}</select>`:`<input data-modal-field="${field.name}" value="${w.esc(field.value||'')}">`).join('');
 return new Promise(resolve=>{dialog={options,resolve(value){dialog=null;w.modalBody.replaceChildren();resolve(value);}};});
};
for(const file of ['peace.admin-desktop-licenses.js','peace.admin-desktop-members.js'])w.eval(fs.readFileSync(path.join(root,'public/scripts/desktop',file),'utf8'));
assert.equal(w.eval("desktopLicenseTab"),'members');w.eval("desktopMemberResetOwner(session.csrf);");
w.renderCurrent=async()=>{
 w.eval('desktopMemberResetOwner(session.csrf);desktopMemberRequestPanels(session.csrf);');
 const next=w.document.createElement('template');next.innerHTML=w.desktopMembersMarkup();
 const previous=w.content.firstElementChild;if(previous)w.desktopPatchNode(previous,next.content.firstElementChild,true);else w.content.append(next.content.firstElementChild);
 w.eval('desktopMemberRenderedQuery=desktopMemberQuery;desktopMemberRenderedStatus=desktopMemberStatus;');
};
w.content.addEventListener('click',event=>{w.handleDesktopLicenseAction(event).catch(error=>errors.push(error.message));});
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(test,label){for(let i=0;i<150;i++){if(test())return;await delay(15);}throw Error('Timed out: '+label);}
const query=selector=>w.document.querySelector(selector),click=selector=>{const node=query(selector);assert.ok(node,selector);node.click();};
async function idle(){await until(()=>w.eval('!desktopLicenseActionPending'),'action idle');}
(async()=>{try{
 await w.renderCurrent();await until(()=>query('[data-desktop-member-id="'+memberId+'"]'),'member list');
 assert.match(w.content.textContent,/미배정 기록/);assert.match(w.content.textContent,/<img src=x onerror=bad\(\)>/);assert.equal(query('#content img,#content script,#content svg'),null);
 // Retired support controls cannot return through ordinary member refreshes.
 assert.equal(query('[data-member-captures],[data-capture-action],[data-desktop-key="member-captures-unassigned"]'),null);
 assert.doesNotMatch(w.content.textContent,/지원 화면|사용자 동의 자료|최초 기기 승인 1회 사용/);
 click('[data-member-action="create"]');await until(()=>dialog?.options.title==='회원 등록','member registration');dialog.resolve(null);await idle();
 assert.equal(requests.some(row=>row.url.includes('/captures')),false,'member management does not request removed support routes');

 const disclosure=query('[data-desktop-member-id="'+memberId+'"]');disclosure.open=true;
 await until(()=>disclosure.textContent.includes('CODE_HASH_MISMATCH'),'member details');
 assert.match(disclosure.textContent,/CRC64/);assert.match(disclosure.textContent,/123456789ABCDEF0/);assert.match(disclosure.textContent,/B_EXIT_NOT_REPORTED/);assert.match(disclosure.textContent,/보고 없음/);assert.match(disclosure.textContent,/하드웨어 인증이 아닙니다/);
 assert.equal(query('#content img,#content script,#content svg'),null);
 assert.match(disclosure.textContent,/FILE_CLEANUP · 정리 실패 보고 · PID 12345 · 종료 코드 31028 · Windows 오류 5 · 경과 732 ms/);
 // Missing or malformed optional diagnostics must not become a synthetic zero
 // or HTML; numeric ranges match the server lifecycle report contract.
 assert.equal(w.desktopMemberLifecycleNumbers({}),'');
 for(const value of [null,undefined,'5','<img src=x onerror=bad()>',NaN,Infinity,-1,0.5,0x100000000])assert.equal(w.desktopMemberLifecycleNumbers({pid:value,exitCode:value,win32Error:value,elapsedMs:value}),'');
 assert.equal(w.desktopMemberLifecycleNumbers({elapsedMs:600001}),'');
 assert.equal(w.desktopMemberLifecycleNumbers({pid:0xffffffff,exitCode:0xffffffff,win32Error:0xffffffff,elapsedMs:600000}),' · PID 4294967295 · 종료 코드 4294967295 · Windows 오류 4294967295 · 경과 600000 ms');
 assert.equal(w.desktopMemberLifecycleNumbers({exitCode:0}),' · 종료 코드 0','explicit zero is retained, absence is not filled with zero');
 const withoutNumbers=w.desktopMemberLifecycleMarkup({roles:{},events:[{at:now,role:'B',event:'FILE_CLEANUP',status:'FAILED',source:'CLIENT_REPORTED'}]});assert.doesNotMatch(withoutNumbers,/Windows 오류|종료 코드|PID |경과 /);
 const search=query('#desktop-member-search');search.value='아직 보내지 않은 검색';search.focus();const nested=disclosure.querySelector('.desktop-member-category');nested.open=true;
 await w.renderCurrent();assert.equal(query('#desktop-member-search'),search);assert.equal(search.value,'아직 보내지 않은 검색');assert.equal(w.document.activeElement,search);assert.equal(query('[data-desktop-member-id="'+memberId+'"]'),disclosure);assert.equal(disclosure.open,true);assert.equal(nested.open,true);
 click('[data-member-action="detail-page"][data-member-id="'+memberId+'"][data-member-category="licenses"][data-member-page="2"]');await idle();await until(()=>disclosure.textContent.includes('두 번째 페이지'),'category page');assert.equal(disclosure.open,true);assert.equal(nested.open,true);
 assert.ok(requests.some(row=>row.url.includes('category=licenses&page=2')));
 // Reproduce the real cache refresh path: a loading notice appears and then
 // disappears after delayed responses. Check AFTER the completion redraw too.
 for(let round=0;round<3;round++){
  const api=w.api,pending=[];w.api=(url,options)=>url.startsWith('/api/desktop/members')&&!options?.method?new Promise((resolve,reject)=>pending.push(()=>api(url,options).then(resolve,reject))):api(url,options);
  w.eval('desktopMemberInvalidate()');await w.renderCurrent();assert.ok(pending.length>0);
  disclosure.open=true;nested.open=true;search.value='갱신 중 작성 '+round;search.focus();w.content.scrollTop=331;const scroller=disclosure.querySelector('.table-wrap');scroller.scrollLeft=77;
  for(const finish of pending)finish();w.api=api;
  await until(()=>w.eval('[...desktopPanels.values()].every(e=>!e.pending)'),'delayed panels settled');await delay(130);
  assert.equal(query('[data-desktop-member-id="'+memberId+'"]'),disclosure);assert.equal(disclosure.open,true);assert.equal(nested.open,true);assert.equal(query('#desktop-member-search'),search);assert.equal(search.value,'갱신 중 작성 '+round);assert.equal(w.document.activeElement,search);assert.equal(w.content.scrollTop,331);assert.equal(scroller.scrollLeft,77);
 }
 // Explicit owner selection is not inferred from a PC or copied from another row.
 click('[data-desktop-member-id="'+memberId+'"] [data-member-action="assign"]');await until(()=>dialog?.options.title==='회원 연결 변경','assign modal');
 assert.equal(query('[data-modal-field="memberId"]').value,memberId);dialog.resolve({memberId:otherId});await idle();
 assert.equal(query('[data-desktop-member-id="'+memberId+'"]'),disclosure);assert.equal(disclosure.open,true);assert.equal(nested.open,true);
 const assignment=requests.find(row=>row.url==='/api/desktop/members/assignment');assert.equal(assignment.body.memberId,otherId);assert.equal(assignment.body.expectedMemberId,memberId);assert.equal(assignment.body.kind,'LICENSE');assert.equal(assignment.body.targetId,targetId);assert.match(assignment.body.requestId,/^[a-z0-9-]{16,80}$/i);
 await until(()=>query('[data-member-action="create"]')?.disabled===false,'refreshed members');
 // A committed write with a lost response is retried with exactly the same body.
 failWrite=true;click('[data-member-action="create"]');await until(()=>dialog?.options.title==='회원 등록','create modal');dialog.resolve({displayName:'새 회원',note:'운영 메모'});await idle();
 assert.ok(errors.includes('응답 유실'));errors.splice(errors.indexOf('응답 유실'),1);await w.renderCurrent();await until(()=>query('[data-member-action="retry"]'),'retry receipt');
 const first=requests.filter(row=>row.method==='POST'&&row.url==='/api/desktop/members').at(-1),count=mutationCount;
 click('[data-member-action="retry"]');await until(()=>dialog?.options.title==='이전 회원 관리 결과 확인','retry confirmation');dialog.resolve({});await idle();
 const retried=requests.filter(row=>row.method==='POST'&&row.url==='/api/desktop/members').at(-1);assert.deepEqual(retried.body,first.body);assert.equal(mutationCount,count);assert.equal(w.eval('desktopMemberPending'),null);
 await until(()=>query('[data-member-action="create"]')?.disabled===false,'create available');
 // A background response cannot silently upgrade the revision of an open form.
 click('[data-member-action="edit"][data-member-id="'+memberId+'"]');await until(()=>dialog?.options.title==='회원 정보 수정','edit revision capture');
 const originalRevision=revision,beforeConflict=mutationCount;revision++;
 w.eval('desktopPanels.get("members").data.revision='+revision);
 dialog.resolve({displayName:'오래된 양식 변경',note:''});await idle();
 const conflict=requests.filter(row=>row.method==='POST'&&row.url==='/api/desktop/members/'+memberId).at(-1);assert.equal(conflict.body.expectedRevision,originalRevision);assert.equal(mutationCount,beforeConflict);assert.equal(w.eval('desktopMemberPending'),null);
 const conflictError=errors.findIndex(text=>text.includes('다른 관리 작업으로 회원 정보가 변경'));assert.ok(conflictError>=0);errors.splice(conflictError,1);
 await w.renderCurrent();await until(()=>query('[data-member-action="create"]')?.disabled===false,'conflict refresh');
 // Changing administrator while a form is open prevents the mutation.
 click('[data-member-action="create"]');await until(()=>dialog,'owner modal');const before=requests.filter(row=>row.method==='POST').length;w.session={csrf:'OWNER2'};dialog.resolve({displayName:'보내지 않을 회원',note:''});await idle();assert.equal(requests.filter(row=>row.method==='POST').length,before);
 await w.renderCurrent();assert.equal(w.eval('desktopMemberPending'),null);assert.equal(w.eval('desktopMemberQuery'),'');
 assert.equal(errors.length,0,errors.join('\n'));
 console.log('MEMBER UI PASS: removed support UI and explicit member registration, member/unassigned disclosures, explicit assignment and direct-owner precondition, category paging, escaped hostile labels/evidence, hash/CRC details, lifecycle reported Windows error/process/elapsed details with absent and invalid numbers omitted, lifecycle unknown states, stable focus/drafts/details, exact response-loss retry, stale-form revision rejection and administrator-session replacement. No automatic capture in member operations.');
 }finally{w.close();}})().catch(error=>{console.error(error.stack);process.exitCode=1;});
