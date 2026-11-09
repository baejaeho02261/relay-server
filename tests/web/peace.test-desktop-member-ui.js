'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM,VirtualConsole}=require('jsdom');
const root=path.resolve(__dirname,'../..'),errors=[],requests=[],now=Date.now();
const vc=new VirtualConsole();vc.on('jsdomError',error=>errors.push(error.message));
const dom=new JSDOM('<!doctype html><main><div id="content"></div></main><div id="modal"><div id="modal-body"></div><button id="modal-confirm"></button></div>',{url:'https://fixture.invalid',runScripts:'outside-only',pretendToBeVisual:true,virtualConsole:vc});
const w=dom.window;w.eval=code=>vm.runInContext(code,dom.getInternalVMContext());
const clone=value=>JSON.parse(JSON.stringify(value));
const memberId='A'.repeat(24),otherId='B'.repeat(24),targetId='C'.repeat(24);
let revision=3,failWrite=false,dialog=null,mutationCount=0,licenseOwner=memberId;
const members=[{id:memberId,displayName:'<img src=x onerror=bad()>',note:'고객 메모 <script>bad()</script>',status:'ACTIVE',createdAt:now,updatedAt:now,counts:{licenses:25,launchers:1,flows:1,devices:1,integrity:1,incidents:1}},{id:otherId,displayName:'두 번째 회원',note:'',status:'ACTIVE',createdAt:now,updatedAt:now,counts:{licenses:0,launchers:0,flows:0,devices:0,integrity:0,incidents:0}}];
const receipts=new Map();
function category(items,totalCount=items.length,page=1){return {items,totalCount,page,pageSize:20};}
function detail(id,categoryName,page){
 const owner=id==='unassigned'?'':id,person=members.find(row=>row.id===id),unassigned=id==='unassigned';
 const assignment={assignmentKind:'LICENSE',assignmentTargetId:unassigned?'9'.repeat(24):targetId,assignedMemberId:unassigned?'':owner,memberId:owner,memberDisplayName:person?.displayName||'',assignmentOrigin:unassigned?'UNASSIGNED':'DIRECT'};
 const linked={assignmentKind:'FLOW',assignmentTargetId:'F'.repeat(24),assignedMemberId:'',memberId:owner,assignmentOrigin:unassigned?'UNASSIGNED':'LINKED'};
 const reason=unassigned?'UNASSIGNED_RECORD':id===memberId?'MEMBER_A_FAILURE':'MEMBER_B_FAILURE';
 const categories={
  licenses:category(unassigned||owner===licenseOwner?[{id:assignment.assignmentTargetId,label:page===2?'두 번째 페이지':'라이선스 <svg onload=bad()>',status:'USED',consumed:true,issuedAt:now,...assignment}]:[],unassigned?1:owner===licenseOwner?25:0,page),
  launchers:category([{id:'D'.repeat(24),label:'A 발급',status:'ISSUED',issuedAt:now,...linked,assignmentKind:'LAUNCHER',assignmentTargetId:'D'.repeat(24)}]),
  flows:category([{id:'F'.repeat(24),status:'EXPIRED',createdAt:now,lifecycle:{roles:{A:{role:'A',status:'HANDED_OFF',authorityEnded:true,processExit:'CLIENT_REPORTED',fileCleanup:'REMOVED'},B:{role:'B',status:'EXPIRED',authorityEnded:true,processExit:'NOT_REPORTED',fileCleanup:'NOT_REPORTED'}},events:[{at:now,role:'B',event:'LEASE_EXPIRED',status:'EXPIRED',source:'SERVER_CONFIRMED'},{at:now,role:'B',event:'FILE_CLEANUP',status:'FAILED',source:'CLIENT_REPORTED',pid:12345,exitCode:31028,win32Error:5,elapsedMs:732}],bResidual:{code:'B_EXIT_NOT_REPORTED',summary:'종료 관측 보고가 없습니다.'}},...linked}]),
  devices:category([{id:'e'.repeat(64),status:'ACTIVE',blocked:true,blockSource:'SINGLE_USE',assurance:'APP_KEY_POSSESSION',firstSeenAt:now,...assignment,assignmentKind:'DEVICE',assignmentTargetId:'e'.repeat(64)}]),
  integrity:category([{id:'report-'+(unassigned?'unassigned':id[0]),at:now,stage:'B',check:'OWN_CODE',status:'REJECTED',reason,machineId:'5'.repeat(64),expectedSha512:'ab'.repeat(64),observedSha512:'cd'.repeat(64),expectedCrc64:'123456789ABCDEF0',observedCrc64:'1111111111111111',...linked}]),
  detections:category([{id:'detection-'+id,detectionId:unassigned?'UNASSIGNED_DETECTION':id===memberId?'dkWriteWatch':'OTHER_MEMBER_DETECTION',category:'WRITE_WATCH',sensor:'Cozy.NHW.Sensor.<img src=x onerror=bad()>',responsePath:'integrity',firstAt:now-5000,lastAt:now,count:7,confirmationCount:2,evidenceFamilies:['INTEGRITY','<svg onload=bad()>'],confidence:85,correlation:true,evidenceLevel:'CLIENT_CORROBORATED',epoch:'1793706297585',flowId:'F'.repeat(24),sessionId:'8'.repeat(24),role:'B',attestation:{sequence:'0000000000000009',status:'ACCEPTED'},invalidated:true,handoffStatus:'CLOSED',handoff:{A:'HANDED_OFF',B:'REVOKED',O:'NOT_STARTED'},rawPath:'PRIVATE_RAW_PATH',...linked}]),
  incidents:category([{id:'incident1',at:now,kind:'INTEGRITY_REJECTION',source:'SERVER_INTEGRITY',stage:'B',status:'REJECTED',reason,flowId:'F'.repeat(24),...linked}])
 };
 return {version:1,revision,member:unassigned?null:person,counts:Object.fromEntries(Object.entries(categories).map(([key,value])=>[key,value.totalCount])),categories:categoryName==='all'?categories:{[categoryName]:categories[categoryName]}};
}
w.content=w.document.getElementById('content');w.modalEl=w.document.getElementById('modal');w.modalBody=w.document.getElementById('modal-body');w.modalConfirm=w.document.getElementById('modal-confirm');
w.session={csrf:'OWNER1'};w.currentView='desktop-licenses';w.roleIsAdmin=()=>true;w.esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));w.fmtTime=value=>new Date(value).toISOString();w.toast=()=>{};w.showDesktopFirstDeviceApproval=async()=>{};w.detailCalls=[];w.showDesktopUnifiedDetail=async(id,options)=>{w.detailCalls.push({id,options:clone(options)});};
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
 if(u.pathname==='/api/desktop/members/assignment'&&body.kind==='LICENSE'&&body.targetId===targetId)licenseOwner=body.memberId;
 if(u.pathname.endsWith('/archive'))members.find(row=>row.id===u.pathname.split('/').at(-2)).status=body.archived?'ARCHIVED':'ACTIVE';
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
// Native buttons emit a zero-detail click for keyboard activation; jsdom does
// not synthesize that browser default from an Enter/Space key event itself.
function keyboardActivate(selector){const node=query(selector);assert.ok(node,selector);assert.equal(node.tagName,'BUTTON');node.focus();node.dispatchEvent(new w.MouseEvent('click',{bubbles:true,detail:0}));}
async function idle(){await until(()=>w.eval('!desktopLicenseActionPending'),'action idle');}
(async()=>{try{
 await w.renderCurrent();await until(()=>query('[data-member-record="'+memberId+'"]'),'member table');
 assert.ok(query('.desktop-members-table'));assert.equal(query('details[data-desktop-member-id]'),null);
 assert.match(w.content.textContent,/미배정 기록/);assert.match(w.content.textContent,/<img src=x onerror=bad\(\)>/);assert.equal(query('#content img,#content script,#content svg'),null);
 assert.equal(requests.some(row=>new URL(row.url,'https://fixture.invalid').pathname==='/api/desktop/members/'+memberId),false,'member details are fetched only after explicit selection');
 assert.equal(query('[data-member-captures],[data-capture-action]'),null);assert.doesNotMatch(w.content.textContent,/지원 화면|사용자 동의 자료|최초 기기 승인 1회 사용/);
 const viewSettings=w.desktopIntegrityMarkup({items:[{id:'FOREIGN',stage:'B',check:'OWN_CODE',reason:'GLOBAL_PRIVATE_RECORD'}]},{items:[]},null);assert.ok(!viewSettings.includes('GLOBAL_PRIVATE_RECORD'));assert.ok(!viewSettings.includes('desktop-integrity-record'));
 click('[data-member-action="create"]');await until(()=>dialog?.options.title==='회원 등록','member registration');dialog.resolve(null);await idle();assert.equal(requests.some(row=>row.url.includes('/captures')),false);
 const filter=query('#desktop-member-filter');filter.value='ALL';filter.dispatchEvent(new w.Event('change',{bubbles:true}));await delay(130);assert.equal(w.eval('desktopMemberStatus'),'ALL');
 const search=query('#desktop-member-search');search.value='아직 보내지 않은 검색';search.focus();await w.renderCurrent();assert.equal(query('#desktop-member-search'),search);assert.equal(search.value,'아직 보내지 않은 검색');assert.equal(w.document.activeElement,search);
 w.content.scrollTop=700;keyboardActivate('[data-member-action="open-detail"][data-member-id="'+memberId+'"]');await idle();await until(()=>query('#desktop-member-workspace')?.textContent.includes('라이선스 <svg'),'member workspace');
 assert.equal(w.content.scrollTop,0);assert.equal(w.document.activeElement,query('#desktop-member-workspace-title'));assert.equal(query('#desktop-member-workspace-title').getAttribute('tabindex'),'-1');
 click('[data-member-action="license-detail"]');await idle();assert.deepEqual(w.detailCalls.at(-1),{id:targetId,options:{memberId}});
 assert.equal(query('#desktop-members-panel'),null);assert.equal(query('.desktop-member-category'),null);assert.equal(query('[data-member-action="category"]').tagName,'BUTTON');assert.equal(query('[data-member-action="category"][aria-current="page"]').dataset.memberCategory,'licenses');
 const choose=async name=>{click('[data-member-action="category"][data-member-category="'+name+'"]');await idle();};
 await choose('integrity');assert.match(w.content.textContent,/MEMBER_A_FAILURE/);assert.doesNotMatch(w.content.textContent,/MEMBER_B_FAILURE|UNASSIGNED_RECORD/);assert.match(w.content.textContent,/CRC64/);assert.match(w.content.textContent,/123456789ABCDEF0/);assert.match(w.content.textContent,/하드웨어 인증이 아닙니다/);
 await choose('detections');assert.match(w.content.textContent,/dkWriteWatch/);assert.match(w.content.textContent,/클라이언트 교차 확인 보고/);assert.match(w.content.textContent,/7회 · 2회/);assert.match(w.content.textContent,/1793706297585/);assert.match(w.content.textContent,/0000000000000009/);assert.match(w.content.textContent,/서버 세션 무효화/);assert.match(w.content.textContent,/B REVOKED · O NOT_STARTED/);assert.doesNotMatch(w.content.textContent,/OTHER_MEMBER_DETECTION|UNASSIGNED_DETECTION|PRIVATE_RAW_PATH/);assert.equal(query('#content img,#content svg'),null);
 const detectionPlain=w.desktopSecurityDetectionsMarkup([{id:'unknown',detectionId:'dkUnknown',invalidated:false,sessionInvalidated:true,confidence:0,correlation:false,count:1,confirmationCount:0,attestation:{status:'TPM_UNSUPPORTED'}}]);assert.match(detectionPlain,/무효화 기록 없음/);assert.match(detectionPlain,/TPM_UNSUPPORTED/);assert.doesNotMatch(detectionPlain,/서버 세션 무효화|인증 완료/);
 await choose('flows');assert.match(w.content.textContent,/B_EXIT_NOT_REPORTED/);assert.match(w.content.textContent,/FILE_CLEANUP · 정리 실패 보고 · PID 12345 · 종료 코드 31028 · Windows 오류 5 · 경과 732 ms/);
 assert.equal(w.desktopMemberLifecycleNumbers({}),'');for(const value of [null,undefined,'5','<img src=x onerror=bad()>',NaN,Infinity,-1,0.5,0x100000000])assert.equal(w.desktopMemberLifecycleNumbers({pid:value,exitCode:value,win32Error:value,elapsedMs:value}),'');
 assert.equal(w.desktopMemberLifecycleNumbers({elapsedMs:600001}),'');assert.equal(w.desktopMemberLifecycleNumbers({pid:0xffffffff,exitCode:0xffffffff,win32Error:0xffffffff,elapsedMs:600000}),' · PID 4294967295 · 종료 코드 4294967295 · Windows 오류 4294967295 · 경과 600000 ms');assert.equal(w.desktopMemberLifecycleNumbers({exitCode:0}),' · 종료 코드 0');
 assert.doesNotMatch(w.desktopMemberLifecycleMarkup({roles:{},events:[{at:now,role:'B',event:'FILE_CLEANUP',status:'FAILED',source:'CLIENT_REPORTED'}]}),/Windows 오류|종료 코드|PID |경과 /);
 await choose('licenses');click('[data-member-action="detail-page"][data-member-page="2"]');await idle();await until(()=>w.content.textContent.includes('두 번째 페이지'),'category pagination');assert.ok(requests.some(row=>row.url.includes('category=licenses&page=2')));
 const workspace=query('#desktop-member-workspace'),scroller=query('.desktop-member-workspace-content .table-wrap'),nav=query('[data-member-action="category"][data-member-category="licenses"]');
 for(let round=0;round<2;round++){
  const api=w.api,pending=[];w.api=(url,options)=>url.startsWith('/api/desktop/members')&&!options?.method?new Promise((resolve,reject)=>pending.push(()=>api(url,options).then(resolve,reject))):api(url,options);
  w.eval('desktopMemberInvalidate()');await w.renderCurrent();assert.ok(pending.length);nav.focus();w.content.scrollTop=331;scroller.scrollLeft=77;for(const finish of pending)finish();w.api=api;
  await until(()=>w.eval('[...desktopPanels.values()].every(e=>!e.pending)'),'refresh settlement');await delay(130);assert.equal(query('#desktop-member-workspace'),workspace);assert.equal(query('.desktop-member-workspace-content .table-wrap'),scroller);assert.equal(w.document.activeElement,nav);assert.equal(w.content.scrollTop,331);assert.equal(scroller.scrollLeft,77);
 }
 // Reject mismatched top-level identity and per-record identity even when a PC
 // fingerprint is the same; no global report list is used as a fallback.
 await choose('integrity');const detailKey='member:'+memberId+':all:1',base=w.eval('desktopPanels.get('+JSON.stringify(detailKey)+').data'),saved=clone(base);
 base.categories.integrity.items.push({...base.categories.integrity.items[0],id:'cross-member',memberId:otherId,reason:'FOREIGN_MEMBER_RECORD'});await w.renderCurrent();assert.match(w.content.textContent,/기록의 연결 범위를 확인하지 못했습니다/);assert.doesNotMatch(w.content.textContent,/FOREIGN_MEMBER_RECORD|MEMBER_A_FAILURE/);
 w.eval('desktopPanels.get('+JSON.stringify(detailKey)+').data='+JSON.stringify(saved));w.eval('desktopPanels.get('+JSON.stringify(detailKey)+').data.member='+JSON.stringify(members[1]));await w.renderCurrent();assert.match(w.content.textContent,/상세 응답을 확인하지 못했습니다/);assert.doesNotMatch(w.content.textContent,/두 번째 회원|MEMBER_B_FAILURE/);
 w.eval('desktopPanels.get('+JSON.stringify(detailKey)+').data='+JSON.stringify(saved));await w.renderCurrent();await choose('licenses');
 click('[data-member-action="assign"]');await until(()=>dialog?.options.title==='회원 연결 변경','assignment');assert.equal(query('[data-modal-field="memberId"]').value,memberId);dialog.resolve({memberId:otherId});await idle();
 const assignment=requests.find(row=>row.url==='/api/desktop/members/assignment');assert.equal(assignment.body.memberId,otherId);assert.equal(assignment.body.expectedMemberId,memberId);assert.equal(assignment.body.kind,'LICENSE');assert.equal(assignment.body.targetId,targetId);assert.match(assignment.body.requestId,/^[a-z0-9-]{16,80}$/i);
 await until(()=>!query('.desktop-member-workspace-content [data-member-action="assign"]'),'old attribution removed');
 keyboardActivate('[data-member-action="back"]');await idle();assert.equal(query('#desktop-member-search').value,'아직 보내지 않은 검색');assert.equal(query('#desktop-member-filter').value,'ALL');assert.equal(w.content.scrollTop,700);assert.equal(w.document.activeElement,query('[data-member-action="open-detail"][data-member-id="'+memberId+'"]'));
 // A delayed response from the previously selected member must not populate
 // the next member's workspace. Both fixtures deliberately use the same PC.
 const api=w.api,pendingA=[];w.eval('desktopMemberInvalidate(true)');w.api=(url,options)=>!options?.method&&new URL(url,'https://fixture.invalid').pathname==='/api/desktop/members/'+memberId?new Promise((resolve,reject)=>pendingA.push(()=>api(url,options).then(resolve,reject))):api(url,options);
 click('[data-member-action="open-detail"][data-member-id="'+memberId+'"]');await idle();await until(()=>pendingA.length,'held old member');click('[data-member-action="back"]');await idle();click('[data-member-action="open-detail"][data-member-id="'+otherId+'"]');await idle();await until(()=>query('#desktop-member-workspace')?.textContent.includes('두 번째 회원'),'other member selected');await choose('integrity');await until(()=>w.content.textContent.includes('MEMBER_B_FAILURE'),'other member records');for(const finish of pendingA)finish();w.api=api;await delay(150);assert.match(w.content.textContent,/MEMBER_B_FAILURE/);assert.doesNotMatch(w.content.textContent,/MEMBER_A_FAILURE/);assert.equal(query('#desktop-member-workspace').dataset.memberWorkspaceId,otherId);
 click('[data-member-action="back"]');await idle();click('[data-member-action="open-detail"][data-member-id="unassigned"]');await idle();await until(()=>query('[data-member-action="license-detail"]'),'unassigned license');click('[data-member-action="license-detail"]');await idle();assert.equal(w.detailCalls.at(-1).options.memberId,'');await choose('integrity');await until(()=>w.content.textContent.includes('UNASSIGNED_RECORD'),'unassigned scope');assert.doesNotMatch(w.content.textContent,/MEMBER_A_FAILURE|MEMBER_B_FAILURE/);assert.match(w.content.textContent,/기기가 같아도 사람을 자동으로 연결하지 않습니다/);
 click('[data-member-action="back"]');await idle();await until(()=>query('[data-member-action="create"]')?.disabled===false,'member list available');
 failWrite=true;click('[data-member-action="create"]');await until(()=>dialog?.options.title==='회원 등록','create');dialog.resolve({displayName:'새 회원',note:'운영 메모'});await idle();assert.ok(errors.includes('응답 유실'));errors.splice(errors.indexOf('응답 유실'),1);await w.renderCurrent();await until(()=>query('[data-member-action="retry"]'),'pending receipt');
 const first=requests.filter(row=>row.method==='POST'&&row.url==='/api/desktop/members').at(-1),count=mutationCount;click('[data-member-action="retry"]');await until(()=>dialog?.options.title==='이전 회원 관리 결과 확인','retry confirmation');dialog.resolve({});await idle();const retried=requests.filter(row=>row.method==='POST'&&row.url==='/api/desktop/members').at(-1);assert.deepEqual(retried.body,first.body);assert.equal(mutationCount,count);assert.equal(w.eval('desktopMemberPending'),null);
 await until(()=>query('[data-member-action="create"]')?.disabled===false,'members current');click('[data-member-action="open-detail"][data-member-id="'+memberId+'"]');await idle();await until(()=>query('[data-member-action="edit"]'),'edit available');click('[data-member-action="edit"]');await until(()=>dialog?.options.title==='회원 정보 수정','edit revision');const originalRevision=revision,beforeConflict=mutationCount;revision++;w.eval('desktopPanels.get("members").data.revision='+revision);dialog.resolve({displayName:'오래된 양식 변경',note:''});await idle();const conflict=requests.filter(row=>row.method==='POST'&&row.url==='/api/desktop/members/'+memberId).at(-1);assert.equal(conflict.body.expectedRevision,originalRevision);assert.equal(mutationCount,beforeConflict);assert.equal(w.eval('desktopMemberPending'),null);const conflictError=errors.findIndex(text=>text.includes('다른 관리 작업으로 회원 정보가 변경'));assert.ok(conflictError>=0);errors.splice(conflictError,1);await w.renderCurrent();await delay(130);
 click('[data-member-action="archive"]');await until(()=>dialog?.options.title==='회원 보관','archive');dialog.resolve({});await idle();assert.equal(members[0].status,'ARCHIVED');await until(()=>query('[data-member-action="archive"]')?.textContent==='보관 해제','archive state');click('[data-member-action="archive"]');await until(()=>dialog?.options.title==='회원 보관 해제','unarchive');dialog.resolve({});await idle();assert.equal(members[0].status,'ACTIVE');
 await until(()=>query('[data-member-action="edit"]'),'unarchive refresh');click('[data-member-action="edit"]');await until(()=>dialog,'owner replacement');const before=requests.filter(row=>row.method==='POST').length;w.session={csrf:'OWNER2'};dialog.resolve({displayName:'보내지 않을 회원',note:''});await idle();assert.equal(requests.filter(row=>row.method==='POST').length,before);await w.renderCurrent();assert.equal(w.eval('desktopMemberPending'),null);assert.equal(w.eval('desktopMemberQuery'),'');assert.equal(w.eval('desktopMemberSelectedId'),'');assert.equal(w.eval('desktopMemberListScroll'),0);assert.equal(query('#desktop-member-workspace'),null);
 // Completing an old route render cannot steal focus or reset scroll from a
 // newer member or a different administrator's screen.
 const marker=w.document.createElement('button');marker.textContent='current navigation focus';w.document.body.append(marker);
 for(const change of ['member','owner']){
  await until(()=>query('[data-member-action="open-detail"][data-member-id="'+memberId+'"]'),'member list after owner reset');
  const render=w.renderCurrent;let firstRender=true,release=null;
  w.renderCurrent=async()=>{const hold=firstRender;firstRender=false;await render();if(hold)await new Promise(resolve=>{release=resolve;});};
  keyboardActivate('[data-member-action="open-detail"][data-member-id="'+memberId+'"]');await until(()=>release,'held route render');
  if(change==='member')w.eval('desktopMemberSelectedId='+JSON.stringify(otherId));else w.session={csrf:'OWNER3'};
  await render();marker.focus();w.content.scrollTop=444;release();await idle();w.renderCurrent=render;
  assert.equal(w.document.activeElement,marker);assert.equal(w.content.scrollTop,444);
  if(change==='member'){assert.equal(query('#desktop-member-workspace').dataset.memberWorkspaceId,otherId);click('[data-member-action="back"]');await idle();}
  else{assert.equal(w.eval('desktopMemberListScroll'),0);assert.equal(query('#desktop-member-workspace'),null);}
 }
 marker.remove();assert.equal(errors.length,0,errors.join('\n'));console.log('MEMBER UI PASS: immediate member table, full member workspace, direct categories, strict per-member/unassigned records, same-PC separation, delayed-response isolation, category paging, keyboard route focus and list scroll restoration, poll focus/scroll preservation, late-owner/member focus guards, safe diagnostics, explicit assignment, CRUD/archive, exact retry and stale revision.');
 }finally{w.close();}})().catch(error=>{console.error(error.stack);process.exitCode=1;});
