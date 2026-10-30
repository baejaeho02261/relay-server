'use strict';
// Support images are intentionally requested and uploaded by the customer.
// Capabilities and image bytes remain transient, isolated to the current admin.
let desktopCaptureOwner='',desktopCapturePending=null,desktopCapturePreview=null,desktopCaptureLink=null;
let desktopCaptureGeneration=0,desktopCapturePageActive=true;
const desktopCapturePages=new Map();
function desktopCaptureLive(owner,generation){return desktopCapturePageActive&&generation===desktopCaptureGeneration&&session?.csrf===owner&&roleIsAdmin();}
function desktopCaptureSuspend(){
 // A BFCache restore retains JavaScript promises as well as DOM. Retire their
 // generation before scrubbing so neither a late PNG nor a create receipt can
 // reopen sensitive content under the restored, otherwise unchanged session.
 desktopCapturePageActive=false;desktopCaptureGeneration++;desktopCapturePending=null;
 desktopCaptureClosePreview();desktopCaptureCloseLink();
}
window.addEventListener('pagehide',desktopCaptureSuspend);
window.addEventListener('pageshow',event=>{if(event.persisted)desktopCaptureSuspend();desktopCapturePageActive=true;});
function desktopCaptureResetOwner(owner){
 if(desktopCaptureOwner===owner)return;
 desktopCaptureGeneration++;desktopCaptureClosePreview();desktopCaptureCloseLink();desktopCaptureOwner=owner;desktopCapturePending=null;desktopCapturePages.clear();
}
function desktopCaptureKey(id){return 'capture:'+id+':'+(desktopCapturePages.get(id)||1);}
function desktopCaptureBase(id){if(!/^[A-F0-9]{24}$/.test(id||''))throw Error('회원 연결을 확인하세요.');return '/api/desktop/members/'+id+'/captures';}
function desktopCaptureRequest(id){
 if(!desktopCapturePageActive||!roleIsAdmin()||!session||!desktopMemberRow(id))return;
 desktopRequestPanel(desktopCaptureKey(id),desktopCaptureBase(id)+'?'+new URLSearchParams({page:String(desktopCapturePages.get(id)||1),pageSize:'20'}),session.csrf);
}
function desktopCaptureRequestPanels(owner){
 if(!desktopCapturePageActive)return;
 desktopCaptureResetOwner(owner);
 const keep=new Set();
 for(const node of content.querySelectorAll('[data-desktop-member-id][open] [data-member-captures][open]')){const id=node.dataset.memberCaptures;keep.add(desktopCaptureKey(id));desktopCaptureRequest(id);}
 for(const key of desktopPanels.keys())if(key.startsWith('capture:')&&desktopPanels.size>96&&!keep.has(key))desktopPanels.delete(key);
 if(desktopCapturePages.size>80)for(const id of desktopCapturePages.keys())if(!keep.has(desktopCaptureKey(id)))desktopCapturePages.delete(id);
 desktopCaptureCheckContext();
}
function desktopCaptureInvalidate(id){for(const key of desktopPanels.keys())if(key.startsWith('capture:'+id+':'))desktopInvalidatePanels(key);}
function desktopCaptureStatus(value){return ({AVAILABLE:'전송 대기',RECEIVING:'전송 처리 중',UPLOADED:'전송 완료',REVOKED:'요청 취소',EXPIRED:'만료',DELETE_PENDING:'삭제 처리 중',DELETED:'삭제됨'})[value]||'상태 확인 필요';}
function desktopCaptureConsentMarkup(row){
 if(!Number.isSafeInteger(row.uploadedAt)||row.uploadedAt<=0)return '<small class="desktop-block">화면 전송 동의 · 접수 기록 없음</small>';
 if(!Number.isSafeInteger(row.consentVersion)||row.consentVersion<1)return '<small class="desktop-block">화면 전송 동의 · 버전 확인 안 됨</small>';
 return `<small class="desktop-block">전송 요청의 동의 기록 v${esc(row.consentVersion)} · 서버 접수 ${desktopDate(row.uploadedAt)}</small>`;
}
function desktopCaptureContextMarkup(row){
 if(!row.context)return '<small class="desktop-block">회원 지원 자료 · 실행 연결 없음</small>';
 const value=row.context;if(!/^[A-F0-9]{24}$/.test(value.flowId||'')||!['A','B','O'].includes(value.role))return '<small class="desktop-block">지원 요청의 실행 연결을 확인하지 못했습니다.</small>';
 return `<small class="desktop-block">지원 대상 ${esc(value.role)} · 실행 <span class="code desktop-wrap">${esc(value.flowId)}</span></small>`;
}
function desktopCaptureContextOptions(memberId){
 const options=[{value:'',label:'회원 지원 · 실행 연결 없이 요청'}],seen=new Set();
 if(typeof desktopMemberKey!=='function')return options;
 const page=typeof desktopMemberPages!=='undefined'?(desktopMemberPages.get(memberId+':flows')||1):1;
 const data=desktopPanels.get(desktopMemberKey(memberId,page>1?'flows':'all',page>1?page:1))?.data;
 if(data?.member?.id!==memberId)return options;
 for(const row of Array.isArray(data.categories?.flows?.items)?data.categories.flows.items:[]){
  const flowId=row.id||row.flowId;if(!/^[A-F0-9]{24}$/.test(flowId||''))continue;
  for(const context of Array.isArray(row.supportContexts)?row.supportContexts:[]){
   if(context?.flowId!==flowId||!['A','B','O'].includes(context.role))continue;
   const value=flowId+':'+context.role;if(seen.has(value))continue;seen.add(value);
   options.push({value,label:context.role+' · '+flowId+' · '+desktopDate(row.createdAt)});
  }
 }
 return options;
}
function desktopMemberCapturesMarkup(id,status){
 const entry=desktopPanels.get(desktopCaptureKey(id)),data=entry?.data,valid=Number.isSafeInteger(data?.revision)&&Array.isArray(data?.items),rows=valid?data.items:[],page=data?.page||desktopCapturePages.get(id)||1,pages=Math.max(1,Math.ceil((data?.totalCount||0)/20));
 return `<details class="desktop-member-category" data-desktop-key="member-captures-${esc(id)}" data-member-captures="${esc(id)}"><summary><strong>지원 화면 · 사용자 동의 자료</strong><span>${valid?desktopMemberCount(data.totalCount)+'건':'열어서 조회'}</span></summary><div class="desktop-member-category-body"><p class="small-note">고객에게 요청 링크를 전달하면 고객이 촬영에 동의하고 화면을 직접 선택합니다. 미리보기에서 민감한 내용을 가린 뒤 별도의 전송 동의로 정지 사진 한 장을 보냅니다. 고객이 선택하는 지원 절차이며 A/B/O 프로그램 내부 동의 기록은 포함하지 않습니다. 사진은 위변조·공격을 입증하지 않습니다. 요청은 10분 동안 1회 사용하며 자료는 24시간 후 열람이 만료되고 서버 정리 시 삭제됩니다. 서버 중단 중에는 실제 삭제가 지연될 수 있습니다.</p><div class="actions"><button type="button" data-capture-action="create" data-capture-member="${esc(id)}" ${status!=='ACTIVE'||!valid?'disabled':''}>지원 화면 요청 링크 만들기</button><button type="button" data-capture-action="refresh" data-capture-member="${esc(id)}">새로고침</button></div><div data-desktop-key="capture-notice-${esc(id)}">${entry?.error?'<p role="status">지원 자료 목록을 확인하지 못했습니다. 이전 내용은 최신 상태가 아닙니다.</p>':entry?.pending?'<p class="small-note" role="status">최신 자료 확인 중</p>':!valid?'<p class="small-note">드롭다운을 열면 지원 자료를 조회합니다.</p>':''}${desktopCapturePending?.memberId===id?`<p role="status">완료를 확인하지 못한 요청이 있습니다. <button type="button" data-capture-action="retry" data-capture-member="${esc(id)}">같은 요청 결과 확인</button></p>`:''}</div><div data-desktop-key="capture-list-${esc(id)}" class="desktop-member-captures-list">${rows.map(row=>`<article class="desktop-capture-row" data-desktop-key="capture-${esc(row.id)}"><div><strong>${esc(desktopCaptureStatus(row.status))}</strong><span class="code desktop-wrap desktop-block">${esc(row.id)}</span>${desktopCaptureContextMarkup(row)}${desktopCaptureConsentMarkup(row)}<small class="desktop-block">요청 ${desktopDate(row.createdAt)} · 요청 만료 ${desktopDate(row.expiresAt)}</small>${row.uploadedAt?`<small class="desktop-block">전송 ${desktopDate(row.uploadedAt)} · 보관 종료 ${desktopDate(row.retainedUntil)} · ${esc(row.width)} × ${esc(row.height)} · ${Math.ceil((Number(row.bytes)||0)/1024)}KiB</small>`:''}</div><div class="actions">${row.status==='UPLOADED'&&status==='ACTIVE'?`<button type="button" data-capture-action="view" data-capture-member="${esc(id)}" data-capture-id="${esc(row.id)}">자료 보기</button>`:''}${['AVAILABLE','RECEIVING'].includes(row.status)?`<button type="button" data-capture-action="revoke" data-capture-member="${esc(id)}" data-capture-id="${esc(row.id)}">요청 취소</button>`:''}${!['DELETED','DELETE_PENDING'].includes(row.status)?`<button type="button" class="danger" data-capture-action="delete" data-capture-member="${esc(id)}" data-capture-id="${esc(row.id)}">자료 삭제</button>`:''}</div></article>`).join('')||(valid?'<p class="small-note">요청하거나 전송받은 지원 자료가 없습니다.</p>':'')}</div><div class="desktop-pagination"><span>${page} / ${pages}</span><div class="actions"><button type="button" data-capture-action="page" data-capture-member="${esc(id)}" data-capture-page="${page-1}" ${page<=1?'disabled':''}>이전 자료</button><button type="button" data-capture-action="page" data-capture-member="${esc(id)}" data-capture-page="${page+1}" ${page>=pages?'disabled':''}>다음 자료</button></div></div></div></details>`;
}
function desktopCaptureMemberOpen(id){return currentView==='desktop-licenses'&&desktopLicenseTab==='members'&&[...content.querySelectorAll('[data-desktop-member-id][open]')].some(node=>node.dataset.desktopMemberId===id);}
function desktopCaptureClosePreview(){
 const view=desktopCapturePreview;if(!view)return;desktopCapturePreview=null;
 clearInterval(view.timer);clearTimeout(view.deadline);view.controller.abort();view.image?.removeAttribute('src');if(view.objectUrl)URL.revokeObjectURL(view.objectUrl);view.objectUrl=null;
 view.root?.replaceChildren();if(view.modal?.active)view.modal.close(null);
}
function desktopCaptureCloseLink(){
 const link=desktopCaptureLink;if(!link)return;desktopCaptureLink=null;clearInterval(link.timer);if(link.input)link.input.value='';link.root?.replaceChildren();if(link.modal?.active)link.modal.close(null);
}
function desktopCaptureCheckContext(){
 for(const view of [desktopCapturePreview,desktopCaptureLink]){
  if(!view)continue;
  const row=desktopMemberRow(view.memberId),entry=desktopPanels.get(desktopCaptureKey(view.memberId));
  const capture=view.captureId&&entry?.data?.items?.find(item=>item.id===view.captureId);
  const invalid=!desktopCaptureLive(view.owner,view.generation)||!desktopCaptureMemberOpen(view.memberId)||row?.status!=='ACTIVE'||!view.modal?.active||!!entry?.error;
  if(invalid||view===desktopCapturePreview&&capture&&capture.status!=='UPLOADED'){
   if(view===desktopCapturePreview)desktopCaptureClosePreview();else desktopCaptureCloseLink();
  }
 }
}
async function desktopCaptureShowLink(result,memberId,owner,generation=desktopCaptureGeneration){
 if(!desktopCaptureLive(owner,generation))return;
 const token=result?.token,path=result?.fragmentPath;
 if(!token||!path){toast('이 요청은 더 이상 새 링크를 표시할 수 없습니다. 목록에서 현재 상태를 확인하세요.');return;}
 if(!/^[A-F0-9]{24}\.[a-f0-9]{64}$/.test(token)||path!=='/diagnostics.html#token='+encodeURIComponent(token))throw Error('지원 요청 링크의 형식을 확인하지 못했습니다.');
 if(session?.csrf!==owner||!roleIsAdmin()||!desktopCaptureMemberOpen(memberId))return;
 desktopCaptureCloseLink();
 const done=openModal({title:'사용자에게 전달할 지원 화면 요청',message:'확인한 회원에게만 직접 전달하세요. 이 링크를 받은 사람은 자료를 1회 전송할 수 있습니다. 고객의 명시적인 화면 선택·미리보기·전송이 필요합니다.',html:'<div id="desktop-capture-link"><label>10분 · 1회용 요청 링크<input id="desktop-capture-link-input" type="text" readonly autocomplete="off" spellcheck="false"></label><button type="button" id="desktop-capture-copy">요청 링크 복사</button><p id="desktop-capture-copy-status" role="status"></p></div>',confirmLabel:'닫기'});
 const root=document.getElementById('desktop-capture-link'),input=document.getElementById('desktop-capture-link-input'),status=document.getElementById('desktop-capture-copy-status');
 const view={owner,generation,memberId,root,input,modal:adminMainModal};desktopCaptureLink=view;input.value=location.origin+path;
 document.getElementById('desktop-capture-copy').onclick=async()=>{if(desktopCaptureLink!==view||session?.csrf!==owner)return;try{await navigator.clipboard.writeText(input.value);if(desktopCaptureLink===view)status.textContent='요청 링크를 복사했습니다.';}catch(_){if(desktopCaptureLink===view){input.focus();input.select();status.textContent='링크를 선택했습니다. 직접 복사하세요.';}}};
 view.timer=setInterval(desktopCaptureCheckContext,300);
 try{await done;}finally{if(desktopCaptureLink===view)desktopCaptureCloseLink();}
}
async function desktopCaptureShowImage(memberId,captureId,owner){
 const generation=desktopCaptureGeneration;if(!desktopCaptureLive(owner,generation))return;
 if(!/^[A-F0-9]{24}$/.test(captureId||''))throw Error('지원 자료 ID를 확인하세요.');
 desktopCaptureClosePreview();
 const done=openModal({title:'사용자가 전송한 지원 화면',message:'사용자가 확인·전송한 자료; 위변조/공격 입증 아님. 필요한 확인을 마친 뒤 닫으세요.',html:'<div id="desktop-capture-preview"><p role="status">자료 접근 권한을 확인하고 있습니다.</p><img alt="사용자가 선택하고 직접 전송한 지원 화면" hidden></div>',confirmLabel:'닫기'});
 const root=document.getElementById('desktop-capture-preview'),image=root.querySelector('img'),status=root.querySelector('[role=status]');
 const view={owner,generation,memberId,captureId,root,image,modal:adminMainModal,controller:new AbortController(),objectUrl:null};desktopCapturePreview=view;
 view.timer=setInterval(desktopCaptureCheckContext,300);view.deadline=setTimeout(()=>{if(desktopCapturePreview===view){status.textContent='자료 조회 시간이 초과되었습니다. 닫고 다시 시도하세요.';view.controller.abort();}},30000);
 const download=(async()=>{try{
  const result=await api(desktopCaptureBase(memberId)+'/'+captureId+'/image',{responseType:'png',headers:{Accept:'image/png'},signal:view.controller.signal});
  desktopCaptureCheckContext();if(desktopCapturePreview!==view||view.controller.signal.aborted||!root.isConnected)return;
  view.objectUrl=URL.createObjectURL(result.blob);image.src=view.objectUrl;image.hidden=false;status.textContent=result.width+' × '+result.height+' · 사용자 전송 자료';
 }catch(error){if(desktopCapturePreview===view&&!view.controller.signal.aborted){status.textContent=error.message||'자료를 확인하지 못했습니다.';image.removeAttribute('src');}}finally{clearTimeout(view.deadline);}})();
 try{await done;}finally{if(desktopCapturePreview===view)desktopCaptureClosePreview();}
 // Do not wait for a stalled network response before closing the preview.
 void download;
}
async function desktopCaptureSendPending(){
 const pending=desktopCapturePending;if(!pending||!desktopCaptureLive(pending.owner,pending.generation))return;
 let result;try{result=await api(pending.url,{method:'POST',body:pending.body});}
 catch(error){if(!desktopCaptureLive(pending.owner,pending.generation))return;if(error.status>=400&&error.status<500&&desktopCapturePending===pending)desktopCapturePending=null;desktopCaptureInvalidate(pending.memberId);throw error;}
 if(desktopCapturePending===pending)desktopCapturePending=null;
 if(!desktopCaptureLive(pending.owner,pending.generation))return;
 desktopCaptureInvalidate(pending.memberId);await renderCurrent();
 if(!desktopCaptureLive(pending.owner,pending.generation))return;
 if(pending.action==='create')await desktopCaptureShowLink(result,pending.memberId,pending.owner,pending.generation);else toast('지원 자료 요청을 서버에 반영했습니다.');
}
async function handleDesktopCaptureAction(target){
 const action=target.dataset.captureAction;if(!action)return false;if(!desktopCapturePageActive)return true;
 if(!roleIsAdmin()||!session)throw Error('관리자만 지원 자료를 관리할 수 있습니다.');
 desktopCaptureResetOwner(session.csrf);if(desktopLicenseActionPending)return true;
 const owner=session.csrf,generation=desktopCaptureGeneration,memberId=target.dataset.captureMember;desktopCaptureBase(memberId);desktopLicenseActionPending=true;target.disabled=true;
 try{
  if(action==='refresh'){desktopCaptureInvalidate(memberId);desktopCaptureRequest(memberId);await renderCurrent(true);return true;}
  if(action==='page'){const page=Number(target.dataset.capturePage);if(Number.isSafeInteger(page)&&page>0){desktopCapturePages.set(memberId,page);desktopCaptureRequest(memberId);await renderCurrent(true);}return true;}
  if(action==='view'){if(desktopMemberRow(memberId)?.status!=='ACTIVE')throw Error('사용 중인 회원의 자료만 볼 수 있습니다.');await desktopCaptureShowImage(memberId,target.dataset.captureId,owner);return true;}
  if(action==='retry'){const yes=await openModal({title:'이전 지원 자료 요청 확인',message:'동일한 요청 ID와 내용으로 결과를 확인합니다.',confirmLabel:'같은 요청 확인'});if(yes&&desktopCaptureLive(owner,generation))await desktopCaptureSendPending();return true;}
  if(!['create','revoke','delete'].includes(action))return false;
  if(desktopCapturePending)throw Error('이전 지원 자료 요청의 결과를 먼저 확인하세요.');
  const expectedRevision=desktopPanels.get(desktopCaptureKey(memberId))?.data?.revision;if(!Number.isSafeInteger(expectedRevision))throw Error('지원 자료 목록을 새로고침하세요.');
  const captureId=target.dataset.captureId;if(action!=='create'&&!/^[A-F0-9]{24}$/.test(captureId||''))throw Error('지원 자료 ID를 확인하세요.');
  const contextOptions=action==='create'?desktopCaptureContextOptions(memberId):[];
  const yes=await openModal({title:action==='create'?'사용자에게 지원 화면 요청':action==='revoke'?'지원 화면 요청 취소':'지원 자료 삭제',message:action==='create'?'고객이 화면 선택·미리보기 후 별도로 전송에 동의하는 10분·1회용 링크를 만듭니다. 관련 실행과 A/B/O를 선택하면 고객에게도 지원 대상을 표시합니다.':action==='revoke'?'사용하지 않은 전송 링크를 취소합니다.': '지원 자료의 열람을 막고 서버 파일을 삭제합니다. 이미 전달된 화면은 회수할 수 없습니다.',html:action==='create'?'<p class="small-note">실행 연결은 선택 사항입니다. 현재 불러온 회원 실행 목록에서 서버가 연결을 허용한 대상만 표시합니다. 다른 실행은 회원의 실행 목록에서 해당 페이지를 조회한 뒤 선택하세요.</p>':'',fields:action==='create'?[{name:'captureContext',type:'select',label:'관련 실행 · 프로그램 (선택)',value:'',options:contextOptions}]:[],danger:action==='delete',confirmLabel:action==='create'?'요청 링크 만들기':action==='revoke'?'요청 취소':'자료 삭제'});
  if(!yes||!desktopCaptureLive(owner,generation))return true;
  let context;
  if(action==='create'){
   const selected=yes.captureContext||'';if(!contextOptions.some(option=>option.value===selected))throw Error('지원 요청의 실행 연결을 다시 선택하세요.');
   if(selected){const match=/^([A-F0-9]{24}):([ABO])$/.exec(selected);if(!match)throw Error('지원 요청의 실행 연결을 다시 선택하세요.');context={flowId:match[1],role:match[2]};}
  }
  desktopCapturePending={action,memberId,owner,generation,url:desktopCaptureBase(memberId)+(action==='create'?'':'/'+captureId+'/'+action),body:{expectedRevision,requestId:crypto.randomUUID(),...(context?{context}:{})}};
  if(action==='delete')desktopCaptureClosePreview();
  await desktopCaptureSendPending();return true;
 }finally{desktopLicenseActionPending=false;if(target.isConnected)target.disabled=false;}
}
content.addEventListener('toggle',event=>{
 const node=event.target;if(!node.matches?.('details'))return;
 if(node.dataset.memberCaptures){if(node.open&&currentView==='desktop-licenses'&&desktopLicenseTab==='members')desktopCaptureRequest(node.dataset.memberCaptures);else if(desktopCapturePreview?.memberId===node.dataset.memberCaptures)desktopCaptureClosePreview();}
 if(node.dataset.desktopMemberId){if(node.open){if(desktopCapturePreview&&desktopCapturePreview.memberId!==node.dataset.desktopMemberId)desktopCaptureClosePreview();if(desktopCaptureLink&&desktopCaptureLink.memberId!==node.dataset.desktopMemberId)desktopCaptureCloseLink();}desktopCaptureCheckContext();}
},true);
