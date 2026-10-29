'use strict';
// Membership is explicit administrative attribution, never a claim that a PC
// fingerprint identifies a person. No license keys or client memory are stored.
let desktopMemberQuery='',desktopMemberStatus='ACTIVE',desktopMemberPage=1;
let desktopMemberRenderedQuery=null,desktopMemberRenderedStatus=null;
let desktopMemberOwner='',desktopMemberPending=null;
const desktopMemberPages=new Map();
const desktopMemberCategories=[['licenses','라이선스'],['launchers','일회용 A 발급'],['flows','실행 · 종료 관측'],['devices','기기 · PC 차단'],['integrity','모듈 · CRC · 무결성'],['incidents','보안 사건 · 서버 기록']];
function desktopMemberResetOwner(owner){
 if(desktopMemberOwner===owner)return;
 if(typeof desktopCaptureResetOwner==='function')desktopCaptureResetOwner(owner);
 desktopMemberOwner=owner;desktopMemberPending=null;desktopMemberPages.clear();desktopMemberQuery='';desktopMemberStatus='ACTIVE';desktopMemberPage=1;desktopMemberRenderedQuery=null;desktopMemberRenderedStatus=null;
}
function desktopMemberCount(value){return Number.isSafeInteger(value)&&value>=0?value.toLocaleString():'—';}
function desktopMemberKey(id,category='all',page=1){return 'member:'+id+':'+category+':'+page;}
function desktopMemberRequest(id,category='all',page=1){
 if(!roleIsAdmin()||!session||!id)return;
 desktopRequestPanel(desktopMemberKey(id,category,page),'/api/desktop/members/'+encodeURIComponent(id)+'?'+new URLSearchParams({category,page:String(page),pageSize:'20'}),session.csrf);
}
function desktopMemberRequestPanels(owner){
 const current=desktopPanels.get('members')?.data;
 if(current&&desktopMemberPage>1&&Number.isSafeInteger(current.totalCount)&&Number.isSafeInteger(current.pageSize)){
  const last=Math.max(1,Math.ceil(current.totalCount/current.pageSize));if(desktopMemberPage>last){desktopMemberPage=last;desktopPanels.delete('members');}
 }
 const open=[...content.querySelectorAll('[data-desktop-member-id][open]')].map(node=>node.dataset.desktopMemberId),keep=new Set();
 for(const id of open){keep.add(desktopMemberKey(id));for(const [category]of desktopMemberCategories)keep.add(desktopMemberKey(id,category,desktopMemberPages.get(id+':'+category)||1));}
 const cached=[...desktopPanels.keys()].filter(key=>key.startsWith('member:'));
 for(const key of cached)if(desktopPanels.size>96&&!keep.has(key))desktopPanels.delete(key);
 if(desktopMemberPages.size>120)for(const key of desktopMemberPages.keys())if(!open.some(id=>key.startsWith(id+':')))desktopMemberPages.delete(key);
 desktopRequestPanel('members','/api/desktop/members?'+new URLSearchParams({q:desktopMemberQuery,status:desktopMemberStatus,page:String(desktopMemberPage),pageSize:'20'}),owner);
 if(typeof desktopCaptureRequestPanels==='function')desktopCaptureRequestPanels(owner);
 for(const node of content.querySelectorAll('[data-desktop-member-id][open]')){
  const id=node.dataset.desktopMemberId;desktopMemberRequest(id);
  for(const [category]of desktopMemberCategories){const page=desktopMemberPages.get(id+':'+category)||1;if(page>1)desktopMemberRequest(id,category,page);}
 }
}
function desktopMemberInvalidate(){
 for(const key of [...desktopPanels.keys()])if(key==='members'||key.startsWith('member:'))desktopInvalidatePanels(key);
 desktopInvalidatePanels('bootstrap','integrity','machines');
}
function desktopMemberNotice(entry,label){
 const text=entry?.error?`<p class="desktop-panel-pending" role="status">${esc(label)} 조회에 실패했습니다. 이전 내용은 최신 상태가 아닙니다. <button type="button" data-member-action="refresh">다시 조회</button></p>`:!entry?.data?'<p class="small-note" role="status">서버에서 기록을 불러오는 중입니다.</p>':entry.pending?'<p class="small-note" role="status">최신 기록 확인 중</p>':'';
 return `<div data-desktop-key="member-notice-${esc(label)}">${text}</div>`;
}
function desktopMemberCountsMarkup(counts){return desktopMemberCategories.map(([key,label])=>`<span>${label} <b>${desktopMemberCount(counts?.[key])}</b></span>`).join('');}
function desktopMemberDisclosure(row,id,unassigned=false){
 const title=unassigned?'미배정 기록':row.displayName,counts=row.counts||{};
 return `<details class="desktop-member-record" data-desktop-key="member-${esc(id)}" data-desktop-member-id="${esc(id)}"><summary><span class="desktop-member-heading"><strong>${esc(title)}</strong><span>${unassigned?'담당 회원을 직접 연결하세요':row.status==='ARCHIVED'?'보관된 회원':'사용 중인 회원'}</span></span><span class="desktop-member-counts">${desktopMemberCountsMarkup(counts)}</span></summary><div class="desktop-member-body">${unassigned?'<p class="small-note">기존 기록은 자동으로 사람에게 배정하지 않습니다. PC 지문이 같아도 같은 회원으로 추정하지 않습니다.</p>':`<div class="desktop-member-meta"><p class="desktop-wrap">${esc(row.note||'운영 메모 없음')}</p><span class="code desktop-wrap">회원 ID ${esc(row.id)}</span><span>등록 ${desktopDate(row.createdAt)} · 변경 ${desktopDate(row.updatedAt)}</span><div class="actions"><button type="button" data-member-action="edit" data-member-id="${esc(row.id)}">회원 정보 수정</button><button type="button" data-member-action="archive" data-member-id="${esc(row.id)}">${row.status==='ARCHIVED'?'보관 해제':'회원 보관'}</button></div></div>`}<div data-desktop-key="member-detail-${esc(id)}">${desktopMemberDetailMarkup(id)}</div>${!unassigned&&typeof desktopMemberCapturesMarkup==='function'?desktopMemberCapturesMarkup(id,row.status):''}</div></details>`;
}
function desktopMembersMarkup(){
 const entry=desktopPanels.get('members'),data=entry?.data;
 const valid=!!data&&Array.isArray(data.items)&&Number.isSafeInteger(data.revision),rows=valid?data.items:[];
 const page=valid&&Number.isSafeInteger(data.page)?data.page:desktopMemberPage,pages=valid?Math.max(1,Math.ceil(data.totalCount/data.pageSize)):1;
 return `<section id="desktop-members-panel" class="section-card"><div class="section-head"><div><h3>회원별 운영 관리</h3><p class="small-note">회원 → 라이선스 · A 발급 → 실행 · 기기 · 무결성 기록 순서로 확인합니다. 회원 연결은 운영자가 확인한 분류이며 기기 증명이나 실행 허가를 대신하지 않습니다. 보안 근거는 해시·CRC·서버 기록입니다. 지원 화면은 별도 요청으로 사용자가 확인하고 전송한 경우에만 표시합니다.</p></div><div class="actions"><button type="button" data-member-action="create" class="primary" ${valid?'':'disabled'}>+ 회원 등록</button><button type="button" data-member-action="approval">최초 기기 연결 승인</button><button type="button" data-member-action="refresh">새로고침</button></div></div><form id="desktop-member-search-form" class="desktop-license-toolbar"><label class="desktop-search"><span class="sr-only">회원 이름 · 메모 검색</span><input id="desktop-member-search" type="search" maxlength="80" autocomplete="off" placeholder="회원 이름 · 회원 ID · 운영 메모 검색" value="${esc(desktopMemberQuery)}"></label><label><span class="sr-only">회원 상태</span><select id="desktop-member-filter">${[['ACTIVE','사용 중인 회원'],['ARCHIVED','보관된 회원'],['ALL','모든 회원']].map(([value,label])=>`<option value="${value}" ${value===desktopMemberStatus?'selected':''}>${label}</option>`).join('')}</select></label><button type="submit">검색</button><button type="button" data-member-action="clear">검색 초기화</button></form><p class="small-note" role="status">회원 검색 결과 ${desktopMemberCount(data?.totalCount)}명 · PC 지문으로 회원을 자동 추정하지 않습니다.</p><div data-desktop-key="member-pending-operation">${desktopMemberPending?'<div class="desktop-panel-pending" role="status">완료를 확인하지 못한 회원 관리 요청이 있습니다. <button type="button" data-member-action="retry">같은 요청의 결과 확인</button></div>':''}</div>${desktopMemberNotice(entry,'회원 목록')}${valid?`<div class="desktop-members-list" data-desktop-key="member-list">${desktopMemberDisclosure({counts:data.unassigned?.counts||{}},'unassigned',true)}${rows.map(row=>desktopMemberDisclosure(row,row.id)).join('')||'<p class="desktop-empty">검색 조건에 맞는 회원이 없습니다. 회원을 등록한 뒤 미배정 기록을 연결하세요.</p>'}</div><div class="desktop-pagination"><span>${page} / ${pages}</span><div class="actions"><button type="button" data-member-action="page" data-member-page="${page-1}" ${page<=1?'disabled':''}>이전 회원</button><button type="button" data-member-action="page" data-member-page="${page+1}" ${page>=pages?'disabled':''}>다음 회원</button></div></div>`:''}</section>`;
}
function desktopMemberAssignmentButton(row){
 if(!['LICENSE','LAUNCHER','FLOW','DEVICE'].includes(row.assignmentKind)||!row.assignmentTargetId)return '';
 return `<button type="button" data-member-action="assign" data-member-kind="${esc(row.assignmentKind)}" data-member-target="${esc(row.assignmentTargetId)}" data-member-direct="${esc(row.assignedMemberId||'')}">회원 연결 변경</button>`;
}
function desktopMemberOrigin(row){return `<small class="desktop-block">${row.assignmentOrigin==='DIRECT'?'직접 연결':row.assignmentOrigin==='LINKED'?'라이선스·발급·실행 연결을 따른 기록':'미배정'}${row.memberDisplayName?' · '+esc(row.memberDisplayName):''}</small>`;}
function desktopMemberLifecycleMarkup(lifecycle){
 if(!lifecycle||!lifecycle.roles||typeof lifecycle.roles!=='object')return '';
 const roles=Array.isArray(lifecycle.roles)?lifecycle.roles:Object.values(lifecycle.roles);
 const status=value=>esc(({CLIENT_REPORTED:'클라이언트 관측 보고',NOT_REPORTED:'보고 없음',REMOVED:'파일 제거 관측 보고',FAILED:'정리 실패 보고',HANDED_OFF:'인수인계 완료',EXPIRED:'만료',CLOSED:'종료',REVOKED:'폐기',CLAIMED:'활성',NOT_STARTED:'시작 전'})[value]||value||'확인 안 됨');
 return `<details class="desktop-member-evidence"><summary>서버 권한 · 종료 관측 구분</summary><p class="small-note">서버 권한 만료와 실제 프로세스 종료는 다릅니다. 보고 없음은 정상 정리나 실제 잔류의 증거가 아닙니다.</p>${lifecycle.bResidual?`<p class="small-note"><strong>${esc(lifecycle.bResidual.code)}</strong> · ${esc(lifecycle.bResidual.summary)}</p>`:''}<div class="table-wrap"><table><thead><tr><th>역할</th><th>서버 권한</th><th>프로세스 종료</th><th>파일 정리</th></tr></thead><tbody>${roles.map(row=>`<tr><td>${esc(row.role||'—')}</td><td>${status(row.status)}<small class="desktop-block">${row.authorityEnded?'서버 권한 종료':'서버 권한 상태 확인'}</small></td><td>${status(row.processExit)}</td><td>${status(row.fileCleanup)}</td></tr>`).join('')}</tbody></table></div>${Array.isArray(lifecycle.events)?`<ol class="desktop-member-lifecycle-events">${lifecycle.events.map(event=>`<li>${desktopDate(event.at)} · ${esc(event.role)} · ${esc(event.event)} · ${status(event.status)} <small>${event.source==='SERVER_CONFIRMED'?'서버 확인':'클라이언트 보고'}</small></li>`).join('')}</ol>`:''}</details>`;
}
function desktopMemberCategoryRows(category,items){
 if(!items.length)return '<p class="small-note">이 범위의 기록이 없습니다. 보안 검사 성공이나 실행 종료를 의미하지 않습니다.</p>';
 if(category==='integrity')return `<p class="small-note">서버 기준 비교와 클라이언트 보고를 구분합니다. 원격 하드웨어 인증이 아닙니다.</p><div class="desktop-integrity-list">${items.map(row=>`<div data-desktop-key="member-integrity-${esc(row.id)}">${desktopMemberOrigin(row)}${desktopMemberAssignmentButton(row)}${desktopIntegrityRecordsMarkup([row],desktopIntegrityPolicy,'member-report-')}</div>`).join('')}</div>`;
 if(category==='incidents')return `<p class="small-note">무결성 사유·서버 사건의 연결 기록입니다. 악의적 공격자를 식별했다는 판정이 아닙니다.</p><div class="desktop-member-events">${items.map(row=>`<details data-desktop-key="member-incident-${esc(row.id)}"><summary><strong>${esc(row.reason||row.kind||'보안 사건')}</strong><span>${desktopDate(row.at)}</span></summary><div class="kv"><div>근거 출처</div><div>${esc(({SERVER_COMPARISON:'서버 기준 비교',SIGNED_CLIENT_REPORT:'서명된 클라이언트 보고',SERVER_CONFIRMED:'서버 확인',CLIENT_REPORTED:'클라이언트 보고'})[row.source]||row.source||'확인 안 됨')}</div><div>역할 · 상태</div><div>${esc(row.stage||'—')} · ${esc(row.status||'—')}</div><div>실행 ID</div><div class="code desktop-wrap">${esc(row.flowId||'연결 정보 없음')}</div></div>${desktopMemberOrigin(row)}${desktopMemberAssignmentButton(row)}</details>`).join('')}</div>`;
 return `<div class="table-wrap"><table class="desktop-member-table"><thead><tr><th>${category==='devices'?'기기':category==='flows'?'실행':category==='launchers'?'A 발급':'라이선스'}</th><th>상태 · 최근 시각</th><th>회원 연결</th></tr></thead><tbody>${items.map(row=>{
  let status=esc(row.status||'—'),detail='';
  if(category==='licenses'){status=desktopStatus(row.status);detail=`<small class="desktop-block">${row.consumed?'최초 사용 완료 · 재사용 불가':'최초 사용 대기'}</small><button type="button" data-member-action="license-detail" data-member-target="${esc(row.id)}">라이선스 상세</button>`;}
  if(category==='devices')detail=`<small class="desktop-block">${row.blocked===true?'PC 새 실행 차단':row.blocked===false?'PC 차단 없음':'PC 차단 상태 확인 안 됨'} · ${esc(row.blockSource||'—')}</small><small class="desktop-block">증명 범위: ${esc(row.assurance||'확인 안 됨')}</small>`;
  if(category==='flows')detail=`<small class="desktop-block">A ${esc(row.launcherId||'—')} · 라이선스 ${esc(row.licenseId||'—')}</small>${row.machineBindingId?`<small class="code desktop-wrap desktop-block">실행 기기 연결 ID ${esc(row.machineBindingId)}</small>`:''}<small class="desktop-block">${row.firstDeviceApproval?.status==='CONSUMED'?'최초 기기 승인 1회 사용 · '+desktopDate(row.firstDeviceApproval.consumedAt):'최초 기기 승인 사용 기록 없음'}</small>${desktopMemberLifecycleMarkup(row.lifecycle)}`;
  return `<tr data-desktop-key="member-${category}-${esc(row.id||row.flowId)}"><td><strong>${esc(row.label||row.id||row.flowId||'—')}</strong><span class="code desktop-wrap desktop-block">${esc(row.id||row.flowId||'')}</span>${detail}</td><td>${status}<small class="desktop-block">${desktopDate(row.lastVerifiedAt||row.lastSeenAt||row.issuedAt||row.createdAt||row.firstSeenAt)}</small></td><td>${desktopMemberOrigin(row)}${desktopMemberAssignmentButton(row)}</td></tr>`;
 }).join('')}</tbody></table></div>`;
}
function desktopMemberDetailMarkup(id){
 const entry=desktopPanels.get(desktopMemberKey(id)),base=entry?.data;
 if(!base)return '<p class="small-note">드롭다운을 열면 회원에게 연결된 기록을 조회합니다.</p>'+desktopMemberNotice(entry,'회원 상세');
 if(!base.categories||(!base.member&&id!=='unassigned')||(base.member&&base.member.id!==id))return '<p role="alert">선택한 회원의 상세 응답을 확인하지 못했습니다. 다시 조회하세요.</p>';
 return desktopMemberNotice(entry,'회원 상세')+desktopMemberCategories.map(([category,title])=>{
  const wanted=desktopMemberPages.get(id+':'+category)||1,extra=wanted>1?desktopPanels.get(desktopMemberKey(id,category,wanted)):null;
  const extraMatches=extra?.data&&(id==='unassigned'?extra.data.member===null:extra.data.member?.id===id);
  const part=wanted>1?(extraMatches?extra.data.categories?.[category]:null):base.categories[category];
  const rows=Array.isArray(part?.items)?part.items:[],page=part?.page||wanted,pages=Math.max(1,Math.ceil((part?.totalCount||0)/(part?.pageSize||20)));
  return `<details class="desktop-member-category" data-desktop-key="member-category-${esc(id)}-${category}"><summary><strong>${title}</strong><span>${desktopMemberCount(part?.totalCount??base.categories[category]?.totalCount)}건</span></summary><div class="desktop-member-category-body">${wanted>1?desktopMemberNotice(extra,title):''}${part?desktopMemberCategoryRows(category,rows):''}<div class="desktop-pagination"><span>${page} / ${pages}</span><div class="actions"><button type="button" data-member-action="detail-page" data-member-id="${esc(id)}" data-member-category="${category}" data-member-page="${page-1}" ${page<=1?'disabled':''}>이전 기록</button><button type="button" data-member-action="detail-page" data-member-id="${esc(id)}" data-member-category="${category}" data-member-page="${page+1}" ${page>=pages?'disabled':''}>다음 기록</button></div></div></div></details>`;
 }).join('');
}
function desktopMemberError(error){
 const messages={MEMBER_REVISION_CONFLICT:'다른 관리 작업으로 회원 정보가 변경되었습니다. 목록을 새로고침하고 다시 확인하세요.',MEMBER_ASSIGNMENT_CONFLICT:'선택한 기록의 직접 연결 회원이 바뀌었습니다. 새로고침 후 다시 선택하세요.',MEMBER_ASSIGNMENT_NOT_DIRECT:'이 기록은 라이선스·A 발급에 연결된 회원을 따릅니다. 직접 연결된 원래 라이선스 또는 A 발급의 회원 연결을 변경하세요.',MEMBER_ASSOCIATION_CONFLICT:'연결된 라이선스·A 발급·실행의 회원이 서로 다릅니다. 기존 연결을 확인하고 해제한 뒤 같은 회원으로 배정하세요.',MEMBER_ARCHIVED:'보관된 회원은 새 기록에 연결할 수 없습니다. 보관을 해제하거나 다른 회원을 선택하세요.',MEMBER_TARGET_NOT_FOUND:'연결할 기록이 더 이상 없습니다. 목록을 새로고침하세요.',MEMBER_NOT_FOUND:'회원을 확인하지 못했습니다. 목록을 새로고침하세요.',MEMBER_INPUT_INVALID:'회원 이름·메모·연결 대상의 입력 범위를 확인하세요.',MEMBER_QUERY_INVALID:'검색 조건을 확인하세요.',MEMBER_CAPACITY:'회원 관리 저장 한도에 도달했습니다. 서버 운영 상태를 확인하세요.',MEMBER_REQUEST_REUSED:'다른 내용에 사용된 요청입니다. 목록을 새로고침한 뒤 다시 확인하세요.'};
 if(messages[error.code])error.message=messages[error.code];return error;
}
function desktopMemberCurrentRevision(){const revision=desktopPanels.get('members')?.data?.revision;if(!Number.isSafeInteger(revision)||revision<0)throw Error('회원 목록을 새로고침한 뒤 다시 시도하세요.');return revision;}
function desktopMemberRow(id){return desktopPanels.get('members')?.data?.items?.find(row=>row.id===id)||desktopPanels.get(desktopMemberKey(id))?.data?.member;}
async function desktopMemberSave(url,body,owner,expectedRevision){
 if(!roleIsAdmin()||session?.csrf!==owner)return;
 if(desktopMemberPending)throw Error('이전 회원 관리 요청의 결과를 먼저 확인하세요.');
 if(!Number.isSafeInteger(expectedRevision)||expectedRevision<0)throw Error('회원 목록을 새로고침한 뒤 다시 시도하세요.');
 desktopMemberPending={url,body:{...body,expectedRevision,requestId:crypto.randomUUID()},owner};
 return desktopMemberSendPending();
}
async function desktopMemberSendPending(){
 const pending=desktopMemberPending;if(!pending||!roleIsAdmin()||session?.csrf!==pending.owner)return;
 try{await api(pending.url,{method:'POST',body:pending.body});}
 catch(error){if(error.status>=400&&error.status<500&&desktopMemberPending===pending){desktopMemberPending=null;desktopMemberInvalidate();}throw error;}
 if(desktopMemberPending===pending)desktopMemberPending=null;
 if(!roleIsAdmin()||session?.csrf!==pending.owner)return;
 desktopMemberInvalidate();toast('회원 관리 변경을 서버에 반영했습니다.');await renderCurrent();
}
async function desktopMemberAssign(target,owner){
 const kind=target.dataset.memberKind,targetId=target.dataset.memberTarget,expectedMemberId=target.dataset.memberDirect||'';
 if(!['LICENSE','LAUNCHER','FLOW','DEVICE'].includes(kind)||!targetId)throw Error('연결 대상이 올바르지 않습니다.');
 const expectedRevision=desktopMemberCurrentRevision();
 const first=await api('/api/desktop/members?'+new URLSearchParams({status:'ACTIVE',page:'1',pageSize:'100'}));
 if(!roleIsAdmin()||session?.csrf!==owner)return;
 const blankLabel=expectedMemberId?'직접 연결 해제 · 상위 연결은 유지':'연결할 회원을 선택하세요';
 const options=[{value:'',label:blankLabel},...(first.items||[]).map(row=>({value:row.id,label:row.displayName+' · '+row.id}))];
 const promise=openModal({title:'회원 연결 변경',message:'확인한 회원만 직접 선택하세요. 기기가 같다는 이유로 다른 실행 기록이 자동 배정되지 않습니다. 직접 연결을 해제해도 라이선스·A 발급에 연결된 회원 정보는 남을 수 있습니다.',html:`<p class="code desktop-wrap">${esc(kind)} · ${esc(targetId)}</p><label>회원 검색<input id="desktop-member-picker-search" maxlength="80" type="search" autocomplete="off"></label><button type="button" id="desktop-member-picker-refresh">회원 검색</button><p id="desktop-member-picker-status" role="status">최대 100명 표시 · 찾는 회원이 없으면 이름 또는 ID로 검색하세요.</p>`,fields:[{name:'memberId',label:'확인한 회원',type:'select',value:options.some(row=>row.value===expectedMemberId)?expectedMemberId:'',options}],confirmLabel:'회원 연결 저장'});
 const select=modalBody.querySelector('[data-modal-field="memberId"]'),search=document.getElementById('desktop-member-picker-search'),button=document.getElementById('desktop-member-picker-refresh'),status=document.getElementById('desktop-member-picker-status');
 let serial=0,closed=false;
 button.onclick=async()=>{const generation=++serial;if(closed||!roleIsAdmin()||session?.csrf!==owner)return;button.disabled=true;modalConfirm.disabled=true;try{const result=await api('/api/desktop/members?'+new URLSearchParams({q:search.value.trim(),status:'ACTIVE',page:'1',pageSize:'100'}));if(closed||generation!==serial||session?.csrf!==owner||!select.isConnected)return;select.replaceChildren();for(const row of [{id:'',displayName:blankLabel},...(result.items||[])]){const option=document.createElement('option');option.value=row.id;option.textContent=row.displayName+(row.id?' · '+row.id:'');select.append(option);}status.textContent='검색 결과 '+desktopMemberCount(result.totalCount)+'명 · 최대 100명 표시';}catch(error){if(!closed&&status.isConnected)status.textContent=error.message||'회원 검색 결과를 확인하지 못했습니다.';}finally{if(!closed&&button.isConnected){button.disabled=false;modalConfirm.disabled=false;}}};
 let values;try{values=await promise;}finally{closed=true;serial++;}
 if(!values||!roleIsAdmin()||session?.csrf!==owner)return;
 if(!expectedMemberId&&!values.memberId)throw Error('직접 연결을 해제할 회원이 없습니다. 연결할 회원을 선택하거나 원래 라이선스·A 발급의 연결을 변경하세요.');
 await desktopMemberSave('/api/desktop/members/assignment',{kind,targetId,memberId:String(values.memberId||''),expectedMemberId},owner,expectedRevision);
}
async function handleDesktopMemberAction(target){
 const action=target.dataset.memberAction;if(!action)return false;
 if(!roleIsAdmin()||!session)throw Error('관리자만 회원을 관리할 수 있습니다.');
 desktopMemberResetOwner(session.csrf);
 if(desktopLicenseActionPending)return true;
 const owner=session.csrf;desktopLicenseActionPending=true;target.disabled=true;
 try{
  if(action==='refresh'){desktopMemberInvalidate();await renderCurrent();return true;}
  if(action==='clear'){desktopMemberQuery='';desktopMemberStatus='ACTIVE';desktopMemberPage=1;desktopPanels.delete('members');await renderCurrent();return true;}
  if(action==='page'){const page=Number(target.dataset.memberPage);if(Number.isSafeInteger(page)&&page>0){desktopMemberPage=page;desktopPanels.delete('members');await renderCurrent();}return true;}
  if(action==='detail-page'){const page=Number(target.dataset.memberPage),id=target.dataset.memberId,category=target.dataset.memberCategory;if(Number.isSafeInteger(page)&&page>0&&desktopMemberCategories.some(([name])=>name===category)){desktopMemberPages.set(id+':'+category,page);desktopMemberRequest(id,category,page);await renderCurrent();}return true;}
  if(action==='approval'){await showDesktopFirstDeviceApproval();desktopMemberInvalidate();await renderCurrent();return true;}
  if(action==='license-detail'){await showDesktopUnifiedDetail(target.dataset.memberTarget);return true;}
  if(action==='retry'){const yes=await openModal({title:'이전 회원 관리 결과 확인',message:'완료를 확인하지 못한 요청을 같은 요청 ID와 내용으로 다시 확인합니다.',confirmLabel:'같은 요청 확인'});if(yes&&session?.csrf===owner)await desktopMemberSendPending();return true;}
  if(desktopMemberPending)throw Error('이전 회원 관리 요청의 결과를 먼저 확인하세요.');
  if(action==='assign'){await desktopMemberAssign(target,owner);return true;}
  const row=desktopMemberRow(target.dataset.memberId);
  if(action==='create'||action==='edit'){
   if(action==='edit'&&!row)throw Error('회원 목록을 새로고침하세요.');
   const expectedRevision=desktopMemberCurrentRevision();
   const values=await openModal({title:action==='create'?'회원 등록':'회원 정보 수정',message:'고객을 구분할 표시 이름과 운영 메모만 입력하세요. 비밀번호·라이선스 키·주민번호 등 민감한 정보는 넣지 마세요.',fields:[{name:'displayName',label:'회원 표시 이름 (1~80자)',value:row?.displayName||''},{name:'note',label:'운영 메모 (선택, 최대 1000자)',type:'textarea',value:row?.note||''}],confirmLabel:'회원 정보 저장'});
   if(!values||session?.csrf!==owner)return true;
   const displayName=String(values.displayName||'').trim(),note=String(values.note||'').trim();if(!displayName||displayName.length>80||note.length>1000)throw Error('회원 이름은 1~80자, 메모는 1000자 이하로 입력하세요.');
   await desktopMemberSave('/api/desktop/members'+(row?'/'+encodeURIComponent(row.id):''),{displayName,note},owner,expectedRevision);return true;
  }
  if(action==='archive'){
   if(!row)throw Error('회원 목록을 새로고침하세요.');const archived=row.status!=='ARCHIVED',expectedRevision=desktopMemberCurrentRevision();
   const yes=await openModal({title:archived?'회원 보관':'회원 보관 해제',message:row.displayName+'\n목록 분류만 바뀝니다. 라이선스·실행·보안 기록은 유지되며 서버 실행 권한은 변경하지 않습니다.',confirmLabel:archived?'회원 보관':'보관 해제'});
   if(yes&&session?.csrf===owner)await desktopMemberSave('/api/desktop/members/'+encodeURIComponent(row.id)+'/archive',{archived},owner,expectedRevision);return true;
  }
  return false;
 }catch(error){throw desktopMemberError(error);}finally{desktopLicenseActionPending=false;if(target.isConnected)target.disabled=false;}
}
content.addEventListener('toggle',event=>{
 const node=event.target;if(!node.matches?.('details[data-desktop-member-id]')||!node.open||currentView!=='desktop-licenses'||desktopLicenseTab!=='members')return;
 desktopMemberRequest(node.dataset.desktopMemberId);
},true);
content.addEventListener('submit',async event=>{
 if(event.target.id!=='desktop-member-search-form')return;event.preventDefault();
 desktopMemberQuery=document.getElementById('desktop-member-search').value.trim();desktopMemberStatus=document.getElementById('desktop-member-filter').value;desktopMemberPage=1;desktopPanels.delete('members');await renderCurrent();
});
content.addEventListener('change',async event=>{
 if(event.target.id!=='desktop-member-filter')return;desktopMemberStatus=event.target.value;desktopMemberPage=1;desktopPanels.delete('members');await renderCurrent();
});
