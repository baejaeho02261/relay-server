'use strict';
// The matching projection publishes a server alias for an authenticated PC.
// Operator contacts and their notes remain distinct administrative records.
let desktopMemberQuery='',desktopMemberStatus='ACTIVE',desktopMemberPage=1;
let desktopMemberRenderedQuery=null,desktopMemberRenderedStatus=null;
let desktopMemberOwner='',desktopMemberPending=null;
let desktopMemberSelectedId='',desktopMemberCategory='licenses',desktopMemberListDraft=null;
let desktopMemberMatch=null;
let desktopRecordMatchSequence=0;
const desktopMemberPages=new Map();
const desktopMemberCategories=[['licenses','라이선스'],['launchers','일회용 A 발급'],['flows','실행 · 종료 관측'],['devices','기기 · PC 차단'],['integrity','모듈 · CRC · 무결성'],['incidents','보안 사건 · 서버 기록'],['nhw','SpaceX 감지']];
const desktopMemberMonitorPolicyKey='nhw-policy';
const desktopMemberMonitorPolicyUrl='/api/desktop/members/nhw-policy';
let desktopMemberMonitorQuery='',desktopMemberMonitorDraft=null,desktopMemberMonitorFeedback='',desktopMemberMonitorSaving=false;
function desktopMemberMonitorId(value){return Number.isInteger(value)&&value>=0&&value<=255;}
function desktopMemberResetOwner(owner){
 if(desktopMemberOwner===owner)return;
 if(desktopMemberMatch)desktopMemberCloseMatching();
 desktopMemberOwner=owner;desktopMemberPending=null;desktopMemberPages.clear();desktopMemberQuery='';desktopMemberStatus='ACTIVE';desktopMemberPage=1;desktopMemberRenderedQuery=null;desktopMemberRenderedStatus=null;desktopMemberSelectedId='';desktopMemberCategory='licenses';desktopMemberListDraft=null;desktopMemberMonitorQuery='';
 desktopMemberMonitorDraft=null;desktopMemberMonitorFeedback='';desktopMemberMonitorSaving=false;
}
function desktopMemberCount(value){return Number.isSafeInteger(value)&&value>=0?value.toLocaleString():'—';}
function desktopMemberKey(id,category='all',page=1){return 'member:'+id+':'+category+':'+page;}
function desktopMemberQueryParams(values){return new URLSearchParams({scope:'MATCH',...values});}
function desktopMemberRequestPanels(owner){
 const current=desktopPanels.get('members')?.data;
 if(current&&desktopMemberPage>1&&Number.isSafeInteger(current.totalCount)&&Number.isSafeInteger(current.pageSize)){
  const last=Math.max(1,Math.ceil(current.totalCount/current.pageSize));if(desktopMemberPage>last){desktopMemberPage=last;desktopPanels.delete('members');}
 }
 const id=desktopMemberSelectedId,keep=new Set();
 if(id){keep.add(desktopMemberKey(id));keep.add(desktopMemberKey(id,desktopMemberCategory,desktopMemberPages.get(id+':'+desktopMemberCategory)||1));}
 for(const key of [...desktopPanels.keys()])if(key.startsWith('member:')&&desktopPanels.size>96&&!keep.has(key))desktopPanels.delete(key);
 if(desktopMemberPages.size>120)for(const key of desktopMemberPages.keys())if(!id||!key.startsWith(id+':'))desktopMemberPages.delete(key);
 desktopRequestPanel('members','/api/desktop/members?'+desktopMemberQueryParams({q:desktopMemberQuery,status:desktopMemberStatus,page:String(desktopMemberPage),pageSize:'20'}),owner);
}
function desktopMemberInvalidate(dropDetails=false){
 for(const key of [...desktopPanels.keys()])if(key==='members'||key.startsWith('member:')){if(dropDetails&&key.startsWith('member:'))desktopPanels.delete(key);else desktopInvalidatePanels(key);}
 desktopInvalidatePanels('bootstrap','integrity','machines');
 desktopInvalidatePanels(desktopMemberMonitorPolicyKey);
}
function desktopMemberNotice(entry,label){
 const text=entry?.error?`<p class="desktop-panel-pending" role="status">${esc(label)} 조회에 실패했습니다. 이전 내용은 최신 상태가 아닙니다. <button type="button" data-member-action="refresh">다시 조회</button></p>`:!entry?.data?'<p class="small-note" role="status">서버에서 기록을 불러오는 중입니다.</p>':entry.pending?'<p class="small-note" role="status">최신 기록 확인 중</p>':'';
 return `<div data-desktop-key="member-notice-${esc(label)}">${text}</div>`;
}
function desktopMemberValidId(id){return typeof id==='string'&&/^[A-F0-9]{24}$/.test(id);}
function desktopMemberPcIdentity(member){
 const code=member?.memberCode;
 return member?.identitySource==='VERIFIED_PC_BINDING'&&desktopMemberValidId(code)&&member.nickname==='PC-'+code
  ? {code,nickname:member.nickname}:null;
}
function desktopMemberListRow(member){
 const pc=desktopMemberPcIdentity(member),id=member.id;
 const label=pc?.nickname||member.displayName||'회원';
 const archived=member.status==='ARCHIVED';
 return `<li class="desktop-match-row" data-desktop-key="member-row-${esc(id)}" data-member-record="${esc(id)}">
  <div class="desktop-match-caption"><span class="desktop-match-avatar" aria-hidden="true">${pc?'PC':'M'}</span>
   <div class="desktop-member-name"><strong>${esc(label)}</strong>${pc?`<small class="code">회원 ID ${esc(pc.code)}</small>`:'<small>인증된 PC 연결 정보 없음</small>'}
   ${pc&&member.contactDisplayName?`<small>연락처 ${esc(member.contactDisplayName)}</small>`:''}</div>
  </div>
  <dl class="desktop-match-counts"><div><dt>라이선스</dt><dd>${desktopMemberCount(member.counts?.licenses)}</dd></div><div><dt>실행</dt><dd>${desktopMemberCount(member.counts?.flows)}</dd></div><div><dt>무결성</dt><dd>${desktopMemberCount(member.counts?.integrity)}</dd></div></dl>
  <div class="desktop-match-row-actions"><span class="desktop-member-state ${archived?'archived':pc?'active':''}">${archived?'보관':pc?'PC 인증':'운영 연락처'}</span><button type="button" class="desktop-member-open" aria-haspopup="dialog" data-member-action="open-detail" data-member-id="${esc(id)}" aria-label="${esc(label)} 매칭 기록 열기">기록 열기 <span aria-hidden="true">↗</span></button></div>
 </li>`;
}
function desktopMembersMarkup(){
 const entry=desktopPanels.get('members'),data=entry?.data;
 const valid=!!data&&Array.isArray(data.items)&&Number.isSafeInteger(data.revision),rows=valid?data.items.filter(row=>desktopMemberValidId(row?.id)):[];
 const page=valid&&Number.isSafeInteger(data.page)?data.page:desktopMemberPage,pages=valid?Math.max(1,Math.ceil(data.totalCount/data.pageSize)):1;
 return `<section id="desktop-members-panel" class="desktop-match-panel section-card">
  <header class="section-head"><div class="desktop-match-heading"><span class="desktop-match-avatar desktop-match-heading-icon" aria-hidden="true">↔</span><div><h3>1:1 매칭</h3><p class="small-note">${valid?'검색 결과 '+desktopMemberCount(data.totalCount)+'건':'회원별 PC 및 운영 기록'}</p></div></div>
  <div class="actions"><button type="button" data-member-action="approval">PC 연결 승인</button><button type="button" data-member-action="create" class="primary" ${valid?'':'disabled'}>운영 연락처 등록</button></div></header>
  <form id="desktop-member-search-form" class="desktop-license-toolbar desktop-match-toolbar"><label class="desktop-search"><span class="sr-only">회원 ID · 닉네임 검색</span><input id="desktop-member-search" type="search" maxlength="80" autocomplete="off" placeholder="PC 닉네임, 회원 ID 또는 메모" value="${esc(desktopMemberListDraft??desktopMemberQuery)}"></label><label><span class="sr-only">회원 상태</span><select id="desktop-member-filter">${[['ACTIVE','운영 중'],['ARCHIVED','보관'],['ALL','모든 회원']].map(([value,label])=>`<option value="${value}" ${value===desktopMemberStatus?'selected':''}>${label}</option>`).join('')}</select></label><button type="submit">검색</button><button type="button" data-member-action="clear">초기화</button><button type="button" data-member-action="refresh">새로고침</button></form>
  <div data-desktop-key="member-pending-operation">${desktopMemberPending?'<div class="desktop-panel-pending" role="status">완료를 확인하지 못한 회원 관리 요청이 있습니다. <button type="button" data-member-action="retry">같은 요청의 결과 확인</button></div>':''}</div>
  ${desktopMemberNotice(entry,'매칭 목록')}
  ${valid?`<ul class="desktop-match-list" aria-label="1:1 매칭 목록">${rows.map(desktopMemberListRow).join('')||'<li class="desktop-empty">검색 조건에 맞는 매칭이 없습니다.</li>'}</ul><div class="desktop-pagination"><span>${page} / ${pages}</span><div class="actions"><button type="button" data-member-action="page" data-member-page="${page-1}" ${page<=1?'disabled':''}>이전</button><button type="button" data-member-action="page" data-member-page="${page+1}" ${page>=pages?'disabled':''}>다음</button></div></div>`:''}
 </section>`;
}
function desktopMemberWorkspaceMarkup(){
 const id=desktopMemberSelectedId,base=desktopPanels.get(desktopMemberKey(id))?.data;
 const matches=base?.member?.id===id,member=matches?base.member:desktopMemberRow(id),pc=desktopMemberPcIdentity(member);
 const counts=matches?base.counts:member?.counts;
 return `<section id="desktop-member-workspace" class="desktop-member-workspace desktop-match-mini" data-member-workspace-id="${esc(id)}">
  <div class="desktop-match-mini-profile"><div class="desktop-match-caption"><span class="desktop-match-avatar" aria-hidden="true">${pc?'PC':'M'}</span><div class="desktop-member-name"><strong id="desktop-member-workspace-title">${esc(pc?.nickname||member?.displayName||'회원 기록')}</strong>${pc?`<small class="code">회원 ID ${esc(pc.code)}</small>`:'<small>인증된 PC 연결 정보 없음</small>'}${member?.contactDisplayName?`<small>연락처 ${esc(member.contactDisplayName)}</small>`:''}${member?.note?`<small>${esc(member.note)}</small>`:''}</div></div>
  <div class="actions"><button type="button" data-member-action="refresh">새로고침</button>${pc&&desktopMemberValidId(member.contactId)?`<button type="button" data-member-action="edit-contact" data-member-id="${esc(member.contactId)}">연락처 수정</button>`:''}${member&&!pc?`<button type="button" data-member-action="edit" data-member-id="${esc(id)}">회원 정보 수정</button><button type="button" data-member-action="archive" data-member-id="${esc(id)}">${member.status==='ARCHIVED'?'보관 해제':'회원 보관'}</button>`:''}</div></div>
  ${desktopMemberPending?'<div class="desktop-panel-pending" role="status">이전 회원 관리 요청의 완료 확인이 필요합니다. <button type="button" data-member-action="retry">같은 요청 결과 확인</button></div>':''}
  <nav class="desktop-match-mini-nav" aria-label="매칭 기록 종류">${desktopMemberCategories.map(([category,label])=>`<button type="button" data-member-action="category" data-member-id="${esc(id)}" data-member-category="${category}" aria-current="${desktopMemberCategory===category?'page':'false'}"><span>${label}</span><b>${desktopMemberCount(counts?.[category])}</b></button>`).join('')}</nav>
  <div class="desktop-member-workspace-content" data-desktop-key="member-workspace-content-${esc(id)}-${desktopMemberCategory}">${desktopMemberDetailMarkup(id)}</div>
 </section>`;
}
function desktopMemberMatchCurrent(match){
 return desktopMemberMatch===match&&match.modalActive()&&session?.csrf===match.owner&&roleIsAdmin()&&
  currentView==='desktop-licenses'&&desktopLicenseTab==='members'&&desktopMemberSelectedId===match.id;
}
function desktopMemberPaintMatching(match=desktopMemberMatch,keepAnchor=false){
 if(!match||!desktopMemberMatchCurrent(match)||!match.root.isConnected)return;
 const layout=document.createElement('template');
 layout.innerHTML=desktopMemberWorkspaceMarkup();
 const current=match.root.firstElementChild;
 if(!current){match.root.append(layout.content);return;}
 const scroll=modalBody;
 const box=keepAnchor?scroll.getBoundingClientRect():null;
 const anchor=box?[...current.querySelectorAll('details[data-desktop-key],tr[data-desktop-key]')].find(node=>{
  if(node.closest('[hidden]'))return false;
  const rect=node.getBoundingClientRect();
  return rect.height>0&&rect.bottom>box.top&&rect.top<box.bottom;
 }):null;
 const anchorTop=anchor?.getBoundingClientRect().top;
 const scrollTop=scroll.scrollTop;
 desktopPatchNode(current,layout.content.firstElementChild,false);
 if(anchor?.isConnected)scroll.scrollTop=scrollTop+anchor.getBoundingClientRect().top-anchorTop;
}
function desktopMemberCloseMatching(){
 const match=desktopMemberMatch;if(!match)return;
 desktopMemberMatch=null;desktopMemberSelectedId='';
 match.root.replaceChildren();
 if(match.modalActive())modalCancel.click();
 for(const key of match.requests){
  if(desktopPanels.get(key)?.pending)desktopPanels.delete(key);
 }
}
async function desktopMemberRequestMatchingPanel(match,key,url,force){
 if(!desktopMemberMatchCurrent(match))return;
 const previous=desktopPanels.get(key);
 if(!force&&previous&&(previous.pending||!previous.error&&Date.now()-previous.at<10000))return;
 const entry={...previous,at:Date.now(),pending:true,error:null};
 match.requests.add(key);
 desktopPanels.set(key,entry);
 desktopMemberPaintMatching(match);
 try{
  const data=await api(url);
  if(desktopMemberMatchCurrent(match)&&desktopPanels.get(key)===entry)entry.data=data;
 }catch(error){if(desktopMemberMatchCurrent(match)&&desktopPanels.get(key)===entry)entry.error=error;}
 finally{
  entry.pending=false;
  if(desktopPanels.get(key)===entry){if(desktopMemberMatchCurrent(match))desktopMemberPaintMatching(match,true);else desktopPanels.delete(key);}
 }
}
function desktopMemberLoadMatching(match,force=false){
 const id=match.id,category=desktopMemberCategory,page=desktopMemberPages.get(id+':'+category)||1;
 const url='/api/desktop/members/'+encodeURIComponent(id)+'?';
 const request=(key,category,page)=>desktopMemberRequestMatchingPanel(match,key,url+
  desktopMemberQueryParams({category,page:String(page),pageSize:'20'}),force);
 request(desktopMemberKey(id),'all',1);
 if(page>1)request(desktopMemberKey(id,category,page),category,page);
 if(category==='nhw')desktopMemberRequestMatchingPanel(match,desktopMemberMonitorPolicyKey,desktopMemberMonitorPolicyUrl,force);
}
function desktopMemberRefreshMatching(){
 const match=desktopMemberMatch;
 if(match&&desktopMemberMatchCurrent(match)&&!desktopLicenseActionPending)desktopMemberLoadMatching(match);
}
function desktopMemberOpenMatching(id,category='licenses',trigger=null){
 if(!desktopMemberValidId(id)||!roleIsAdmin()||!session||currentView!=='desktop-licenses'||desktopLicenseTab!=='members')return;
 desktopMemberCloseMatching();
 const closed=openModal({title:'1:1 매칭 기록',html:'<div id="desktop-match-dialog"></div>',confirmLabel:'닫기',hideCancel:true});
 const root=document.getElementById('desktop-match-dialog'),modalActive=captureAdminModalOwner();
 if(!root||!modalActive)return;
 const match={id,root,trigger,owner:session.csrf,modalActive,requests:new Set()};
 desktopMemberMatch=match;desktopMemberSelectedId=id;desktopMemberCategory=category;
 desktopMemberPaintMatching(match);
 desktopMemberLoadMatching(match);
 closed.finally(()=>{
  if(desktopMemberMatch!==match)return;
  desktopMemberCloseMatching();
  if(!captureAdminModalOwner()&&trigger?.isConnected&&!trigger.disabled)trigger.focus({preventScroll:true});
 });
}
function desktopMemberAssignmentButton(row){
 if(!['LICENSE','LAUNCHER','FLOW','DEVICE'].includes(row.assignmentKind)||!row.assignmentTargetId)return '';
 return `<button type="button" data-member-action="assign" data-member-kind="${esc(row.assignmentKind)}" data-member-target="${esc(row.assignmentTargetId)}" data-member-direct="${esc(row.assignedMemberId||'')}">회원 연결 변경</button>`;
}
function desktopMemberOrigin(row){
 const origin=row.assignmentOrigin;
 const label=origin==='DIRECT'?'직접 연결':origin==='LINKED'?'연결된 라이선스·발급·실행':origin==='VERIFIED_PC_BINDING'?'인증된 PC 기준':'매칭 근거 확인 필요';
 return `<small class="desktop-block">${label}${row.assignedContactName?' · 연락처 '+esc(row.assignedContactName):row.memberDisplayName?' · '+esc(row.memberDisplayName):''}</small>`;
}
function desktopMemberLifecycleNumbers(event){
 const details=[];
 if(event.event==='STARTUP_FAILURE'&&event.startupStage?.label)details.push('단계 '+esc(event.startupStage.label));
 for(const [key,label,max,suffix]of [['pid','PID',0xffffffff,''],['exitCode',event.event==='STARTUP_FAILURE'?'시작 단계 코드':'종료 코드',0xffffffff,''],['win32Error','Windows 오류',0xffffffff,''],['elapsedMs','경과',600000,' ms']]){
  const value=event[key];if(Object.hasOwn(event,key)&&Number.isSafeInteger(value)&&value>=0&&value<=max)details.push(label+' '+value+suffix);
 }
 if(event.event==='STARTUP_FAILURE'&&Number.isSafeInteger(event.childExitCode)&&event.childExitCode>=0&&event.childExitCode<=0xffffffff){details.push('자식 실제 종료 코드 '+event.childExitCode);if(event.childStartupStage?.label)details.push(esc(event.childStartupStage.label));}
 return details.length?' · '+details.join(' · '):'';
}
function desktopMemberLifecycleMarkup(lifecycle){
 if(!lifecycle||!lifecycle.roles||typeof lifecycle.roles!=='object')return '';
 const roles=Array.isArray(lifecycle.roles)?lifecycle.roles:Object.values(lifecycle.roles);
 const status=value=>esc(({CLIENT_REPORTED:'클라이언트 관측 보고',NOT_REPORTED:'보고 없음',REMOVED:'파일 제거 관측 보고',FAILED:'정리 실패 보고',HANDED_OFF:'인수인계 완료',EXPIRED:'만료',CLOSED:'종료',REVOKED:'폐기',CLAIMED:'활성',NOT_STARTED:'세션 인수 미등록'})[value]||value||'확인 안 됨');
 return `<details class="desktop-member-evidence"><summary>서버 권한 · 종료 관측 구분</summary><p class="small-note">서버 권한 만료와 실제 프로세스 종료는 다릅니다. 보고 없음은 정상 정리나 실제 잔류의 증거가 아닙니다.</p>${lifecycle.bResidual?`<p class="small-note"><strong>${esc(lifecycle.bResidual.code)}</strong> · ${esc(lifecycle.bResidual.summary)}</p>`:''}<div class="table-wrap"><table><thead><tr><th>역할</th><th>서버 권한</th><th>프로세스 종료</th><th>파일 정리</th></tr></thead><tbody>${roles.map(row=>`<tr><td>${esc(row.role||'—')}</td><td>${status(row.status)}<small class="desktop-block">${row.authorityEnded?'서버 권한 종료':'서버 권한 상태 확인'}</small></td><td>${status(row.processExit)}</td><td>${status(row.fileCleanup)}</td></tr>`).join('')}</tbody></table></div>${Array.isArray(lifecycle.events)?`<ol class="desktop-member-lifecycle-events">${lifecycle.events.map(event=>`<li>${desktopDate(event.at)} · ${esc(event.role)} · ${esc(event.event==='STARTUP_FAILURE'?'시작 실패':event.event)} · ${event.event==='STARTUP_FAILURE'&&event.status==='FAILED'?'실패 보고':status(event.status)}${desktopMemberLifecycleNumbers(event)} <small>${event.source==='SERVER_CONFIRMED'?'서버 확인':'클라이언트 보고'}</small></li>`).join('')}</ol>`:''}</details>`;
}
function desktopMemberCategoryRows(category,items){
 if(!items.length)return '<p class="small-note">이 범위의 기록이 없습니다. 보안 검사 성공이나 실행 종료를 의미하지 않습니다.</p>';
 if(category==='integrity')return `<p class="small-note">서버 기준 비교와 클라이언트 보고를 구분합니다. 원격 하드웨어 인증이 아닙니다.</p><div class="desktop-integrity-list">${items.map(row=>`<div data-desktop-key="member-integrity-${esc(row.id)}">${desktopMemberOrigin(row)}${desktopMemberAssignmentButton(row)}${desktopIntegrityRecordsMarkup([row],desktopIntegrityPolicy,'member-report-')}</div>`).join('')}</div>`;
 if(category==='incidents')return `<p class="small-note">무결성 사유·서버 사건의 연결 기록입니다. 악의적 공격자를 식별했다는 판정이 아닙니다.</p><div class="desktop-member-events">${items.map(row=>`<details data-desktop-key="member-incident-${esc(row.id)}"><summary><strong>${esc(row.reason||row.kind||'보안 사건')}</strong><span>${desktopDate(row.at)}</span></summary><div class="kv"><div>근거 출처</div><div>${esc(({SERVER_COMPARISON:'서버 기준 비교',SIGNED_CLIENT_REPORT:'서명된 클라이언트 보고',SERVER_CONFIRMED:'서버 확인',CLIENT_REPORTED:'클라이언트 보고'})[row.source]||row.source||'확인 안 됨')}</div><div>역할 · 상태</div><div>${esc(row.stage||'—')} · ${esc(row.status||'—')}</div><div>실행 ID</div><div class="code desktop-wrap">${esc(row.flowId||'연결 정보 없음')}</div></div>${desktopMemberOrigin(row)}${desktopMemberAssignmentButton(row)}</details>`).join('')}</div>`;
 return `<div class="table-wrap"><table class="desktop-member-table"><thead><tr><th>${category==='devices'?'기기':category==='flows'?'실행':category==='launchers'?'A 발급':'라이선스'}</th><th>상태 · 최근 시각</th><th>회원 연결</th></tr></thead><tbody>${items.map(row=>{
  let status=esc(row.status||'—'),detail='';
  if(category==='licenses'){status=desktopStatus(row.status);detail=`<small class="desktop-block">${desktopProductMarkup(row)}</small><small class="desktop-block">${row.consumed?'최초 사용 완료 · 재사용 불가':'최초 사용 대기'}</small><button type="button" data-member-action="license-detail" data-member-target="${esc(row.id)}">라이선스 상세</button>`;}
  if(category==='devices')detail=`<small class="desktop-block">${row.blocked===true?'PC 새 실행 차단':row.blocked===false?'PC 차단 없음':'PC 차단 상태 확인 안 됨'} · ${esc(row.blockSource||'—')}</small><small class="desktop-block">증명 범위: ${esc(row.assurance||'확인 안 됨')}</small>`;
  if(category==='flows')detail=`<small class="desktop-block">A ${esc(row.launcherId||'—')} · 라이선스 ${esc(row.licenseId||'—')}</small>${row.machineBindingId?`<small class="code desktop-wrap desktop-block">실행 기기 연결 ID ${esc(row.machineBindingId)}</small>`:''}${desktopMemberLifecycleMarkup(row.lifecycle)}`;
  return `<tr data-desktop-key="member-${category}-${esc(row.id||row.flowId)}"><td><strong>${esc(row.label||row.id||row.flowId||'—')}</strong><span class="code desktop-wrap desktop-block">${esc(row.id||row.flowId||'')}</span>${detail}</td><td>${status}<small class="desktop-block">${desktopDate(row.lastVerifiedAt||row.lastSeenAt||row.issuedAt||row.createdAt||row.firstSeenAt)}</small></td><td>${desktopMemberOrigin(row)}${desktopMemberAssignmentButton(row)}</td></tr>`;
 }).join('')}</tbody></table></div>`;
}
function desktopMemberMonitorCatalog(raw){
 const entries=new Map();
 if(!Array.isArray(raw)||raw.length>256)return entries;
 for(const row of raw){
  if(!row||!desktopMemberMonitorId(row.id)||entries.has(row.id))continue;
  if(typeof row.label!=='string'||!/^[\x20-\x7e]{1,96}$/.test(row.label))continue;
  const legacyLabel=typeof row.legacyLabel==='string'&&/^[\x20-\x7e]{1,89} Detect$/.test(row.legacyLabel)?row.legacyLabel:'';
  const symbol=typeof row.symbol==='string'&&/^dk[A-Za-z][A-Za-z0-9]{0,62}$/.test(row.symbol)?row.symbol:'';
  const mode=['observation','corroborated'].includes(row.mode)?row.mode:'reported';
  entries.set(row.id,{id:row.id,label:row.label,legacyLabel,symbol,mode});
 }
 return entries;
}
function desktopMemberMonitorPolicy(catalog,response=desktopPanels.get(desktopMemberMonitorPolicyKey)?.data){
 const policy=response?.nhwPolicy;
 if(policy?.version!==1||!Number.isSafeInteger(policy.revision)||policy.revision<0||!Array.isArray(policy.disabledIds)||policy.disabledIds.length>catalog.size)return null;
 const ids=policy.disabledIds;
 if(ids.some((id,index)=>!catalog.has(id)||(index>0&&ids[index-1]>=id)))return null;
 return {revision:policy.revision,disabledIds:new Set(ids),manageable:response.canManageNhwPolicy===true};
}
function desktopMemberMonitorSameIds(a,b){return a.size===b.size&&[...a].every(id=>b.has(id));}
function desktopMemberMonitorOptions(catalog){
 const entry=desktopPanels.get(desktopMemberMonitorPolicyKey),policy=desktopMemberMonitorPolicy(catalog);
 const draft=desktopMemberMonitorDraft,disabledIds=draft?.disabledIds??policy?.disabledIds;
 const outdated=!!draft&&!!policy&&draft.revision!==policy.revision;
 const dirty=!!draft&&!!policy&&!desktopMemberMonitorSameIds(draft.disabledIds,policy.disabledIds);
 const editable=!!policy?.manageable&&!entry?.error&&!desktopMemberMonitorSaving&&!outdated;
 const counts=new Map(),filter=desktopMemberMonitorQuery.trim().toLowerCase();
 for(const {label} of catalog.values())counts.set(label,(counts.get(label)||0)+1);
 const options=[...catalog.values()].map(({id,label,symbol,mode})=>{
  const qualifier=counts.get(label)>1?(symbol||String(id)):'';
  const observationOnly=mode==='observation';
  const policyLabel=observationOnly?'관측 전용':mode==='corroborated'?'교차 확인 후 종료':'';
  const detail=[qualifier,policyLabel].filter(Boolean).join(' · ');
  const search=(label+' '+symbol+' '+id+' '+policyLabel).toLowerCase();
  return `<label class="desktop-member-monitor-option" data-desktop-key="monitor-option-${id}" data-monitor-search="${esc(search)}" ${search.includes(filter)?'':'hidden'}><span class="desktop-member-monitor-check"><input type="checkbox" data-monitor-detection-id="${id}" ${disabledIds&&!observationOnly&&!disabledIds.has(id)?'checked':''} ${editable&&!observationOnly?'':'disabled'}></span><span class="desktop-member-monitor-text">${esc(label)}${detail?` <small>${esc(detail)}</small>`:''}</span></label>`;
 });
 const status=desktopMemberMonitorSaving?'종료 정책 저장 중':outdated?'서버 정책이 바뀌었습니다. 서버 설정을 다시 불러온 후 선택하세요.':entry?.error?'종료 정책을 불러오지 못했습니다.':!policy?'서버에서 종료 정책을 불러오는 중입니다.':!policy.manageable?'종료 정책 조회 권한만 있습니다.':desktopMemberMonitorFeedback||(dirty?'저장할 변경 사항이 있습니다.':'');
 return `<details class="desktop-member-monitor-filters" data-desktop-key="monitor-filters"><summary>SpaceX 세션 종료 정책</summary><p class="small-note">전체 A/B/O에 적용됩니다. 일반 유형은 체크하면 감지 시 종료됩니다. 교차 확인 유형은 체크하고 추가 근거가 확인되면 종료됩니다. 관측 전용과 체크 해제 유형은 기록만 남깁니다.</p><div class="desktop-member-monitor-controls"><label for="desktop-member-monitor-filter" class="sr-only">감지 이름 검색</label><input type="search" id="desktop-member-monitor-filter" placeholder="감지 이름 검색" maxlength="96" autocomplete="off" value="${esc(desktopMemberMonitorQuery)}"><button type="button" data-member-action="nhw-policy-all" ${editable?'':'disabled'}>종료 항목 모두 선택</button><button type="button" data-member-action="nhw-policy-none" ${editable?'':'disabled'}>모두 해제</button></div><div class="desktop-member-monitor-options">${options.join('')}</div><div class="desktop-member-monitor-controls"><button type="button" class="primary" data-member-action="nhw-policy-save" ${editable&&dirty?'':'disabled'}>종료 정책 저장</button><button type="button" data-member-action="nhw-policy-reset" ${desktopMemberMonitorSaving?'disabled':''}>서버 설정 다시 읽기</button></div><p class="small-note" role="status">${esc(status)}</p></details>`;
}
function desktopMemberMonitorMarkup(rawCatalog,items){
 const catalog=desktopMemberMonitorCatalog(rawCatalog);
 if(!catalog.size)return '<p class="small-note" role="status">감지 유형을 확인하지 못했습니다.</p>';
 const records=items.map((row,index)=>{
  if(!['A','B','O'].includes(row.stage)||!Array.isArray(row.detectionIds)||row.detectionIds.length>256)return '';
  const enforced=new Set(Array.isArray(row.enforcedIds)&&row.enforcedIds.length<=256?row.enforcedIds:[]);
  const labels=new Map();
  for(const id of row.detectionIds){
   const entry=catalog.get(id);
   if(!entry)continue;
   const label=entry.legacyLabel||entry.label+' Detect',ended=enforced.has(id),key=label+'\0'+ended;
   if(!labels.has(key))labels.set(key,{label,id,ended});
  }
  return [...labels.values()].map(({label,id,ended})=>`<li class="${ended?'monitor-ended':'monitor-observed'}" data-desktop-key="monitor-record-${esc(row.id||index)}-${id}"><span>${esc(label)} / ${row.stage}</span><small>${ended?'종료 확정':'관측'}</small></li>`).join('');
 });
 return desktopMemberMonitorOptions(catalog)+`<ul class="desktop-member-monitor-feed" aria-label="감지 기록">${records.join('')}</ul>`+(records.some(Boolean)?'':'<p class="small-note">이 범위의 감지 기록이 없습니다.</p>');
}

function desktopMemberMonitorCurrentCatalog(){
 return desktopMemberMonitorCatalog(desktopPanels.get(desktopMemberKey(desktopMemberSelectedId))?.data?.nhwCatalog);
}
function desktopMemberEditNhwPolicy(catalog,ids,enabled){
 const policy=desktopMemberMonitorPolicy(catalog);
 if(!policy?.manageable||desktopPanels.get(desktopMemberMonitorPolicyKey)?.error||desktopMemberMonitorSaving)return;
 const draft=desktopMemberMonitorDraft||{revision:policy.revision,disabledIds:new Set(policy.disabledIds)};
 if(draft.revision!==policy.revision)return;
 for(const id of ids){
  const detection=catalog.get(id);
  if(!detection||detection.mode==='observation')continue;
  if(enabled)draft.disabledIds.delete(id);else draft.disabledIds.add(id);
 }
 desktopMemberMonitorDraft=desktopMemberMonitorSameIds(draft.disabledIds,policy.disabledIds)?null:draft;
 desktopMemberMonitorFeedback='';
}
async function desktopMemberSaveNhwPolicy(catalog,owner){
 const policy=desktopMemberMonitorPolicy(catalog),draft=desktopMemberMonitorDraft;
 if(!policy?.manageable||!draft||draft.revision!==policy.revision||desktopMemberMonitorSameIds(draft.disabledIds,policy.disabledIds))return;
 desktopMemberMonitorSaving=true;
 try{
  desktopMemberPaintMatching();
  if(session?.csrf!==owner||!roleIsAdmin()||!desktopMemberMatch)return;
  const reply=await api(desktopMemberMonitorPolicyUrl,{method:'POST',body:{expectedRevision:draft.revision,disabledIds:[...draft.disabledIds].sort((a,b)=>a-b)}});
  if(session?.csrf!==owner||!roleIsAdmin())return;
  const saved=desktopMemberMonitorPolicy(catalog,reply);
  if(!saved||saved.revision!==draft.revision+1||!desktopMemberMonitorSameIds(saved.disabledIds,draft.disabledIds))throw Error('서버가 저장한 종료 정책을 확인하지 못했습니다.');
  desktopPanels.set(desktopMemberMonitorPolicyKey,{data:reply,at:Date.now(),pending:false,error:null});
  desktopMemberMonitorDraft=null;desktopMemberMonitorFeedback='종료 정책을 저장했습니다.';
 }catch(error){
  if(session?.csrf!==owner||!roleIsAdmin())return;
  if(error.code==='NHW_POLICY_CONFLICT'){
   desktopMemberMonitorDraft=null;
   desktopMemberMonitorFeedback='다른 관리자가 종료 정책을 변경했습니다. 최신 설정에서 다시 선택하세요.';
  }else desktopMemberMonitorFeedback=error.message||'종료 정책 저장 결과를 확인하지 못했습니다.';
  desktopInvalidatePanels(desktopMemberMonitorPolicyKey);
  if(desktopMemberMatch&&desktopMemberCategory==='nhw')desktopMemberRequestMatchingPanel(desktopMemberMatch,desktopMemberMonitorPolicyKey,desktopMemberMonitorPolicyUrl,true);
 }finally{
  if(session?.csrf===owner){desktopMemberMonitorSaving=false;desktopMemberPaintMatching();}
 }
}
function desktopMemberDetailMarkup(id){
 const entry=desktopPanels.get(desktopMemberKey(id)),base=entry?.data;
 if(!base)return desktopMemberNotice(entry,'회원 상세');
 const owner=id,baseMatches=base.member?.id===id;
 if(!base.categories||!baseMatches)return '<p class="desktop-member-scope-warning" role="alert">선택한 회원의 상세 응답을 확인하지 못했습니다. 다시 조회하세요.</p>';
 const category=desktopMemberCategory,title=desktopMemberCategories.find(([key])=>key===category)?.[1]||'회원 기록';
 const wanted=desktopMemberPages.get(id+':'+category)||1,extra=wanted>1?desktopPanels.get(desktopMemberKey(id,category,wanted)):null;
 const extraMatches=extra?.data?.member?.id===id;
 const part=wanted>1?(extraMatches?extra.data.categories?.[category]:null):base.categories[category];
 const valid=!!part&&Array.isArray(part.items)&&Number.isSafeInteger(part.page)&&part.page===wanted&&Number.isSafeInteger(part.pageSize)&&part.pageSize>=1&&part.pageSize<=100&&Number.isSafeInteger(part.totalCount)&&part.totalCount>=0&&part.items.length<=part.pageSize;
 const scoped=valid&&part.items.every(row=>row&&row.memberId===owner);
 const page=valid?part.page:wanted,pages=valid?Math.max(1,Math.ceil(part.totalCount/part.pageSize)):1;
 const view=!part?'<p class="small-note" role="status">해당 페이지를 불러오는 중입니다.</p>':!scoped?'<p class="desktop-member-scope-warning" role="alert">선택한 회원과 기록의 연결 범위를 확인하지 못했습니다. 자료를 표시하지 않았습니다. 다시 조회하세요.</p>':category==='nhw'?desktopMemberMonitorMarkup(base.nhwCatalog,part.items):desktopMemberCategoryRows(category,part.items);
 return desktopMemberNotice(entry,'매칭 상세')+`<div class="desktop-match-section-heading"><h3>${title}</h3><span>${desktopMemberCount(part?.totalCount)}건</span></div>${wanted>1?desktopMemberNotice(extra,title):''}${view}<div class="desktop-pagination"><span>${page} / ${pages}</span><div class="actions"><button type="button" data-member-action="detail-page" data-member-id="${esc(id)}" data-member-category="${category}" data-member-page="${page-1}" ${!scoped||page<=1?'disabled':''}>이전 기록</button><button type="button" data-member-action="detail-page" data-member-id="${esc(id)}" data-member-category="${category}" data-member-page="${page+1}" ${!scoped||page>=pages?'disabled':''}>다음 기록</button></div></div>`;
}
function desktopMemberError(error){
 const messages={MEMBER_REVISION_CONFLICT:'다른 관리 작업으로 회원 정보가 변경되었습니다. 목록을 새로고침하고 다시 확인하세요.',MEMBER_ASSIGNMENT_CONFLICT:'선택한 기록의 직접 연결 회원이 바뀌었습니다. 새로고침 후 다시 선택하세요.',MEMBER_ASSIGNMENT_NOT_DIRECT:'이 기록은 라이선스·A 발급에 연결된 회원을 따릅니다. 직접 연결된 원래 라이선스 또는 A 발급의 회원 연결을 변경하세요.',MEMBER_ASSOCIATION_CONFLICT:'연결된 라이선스·A 발급·실행의 회원이 서로 다릅니다. 기존 연결을 확인하고 해제한 뒤 같은 회원으로 배정하세요.',MEMBER_ARCHIVED:'보관된 회원은 새 기록에 연결할 수 없습니다. 보관을 해제하거나 다른 회원을 선택하세요.',MEMBER_TARGET_NOT_FOUND:'연결할 기록이 더 이상 없습니다. 목록을 새로고침하세요.',MEMBER_NOT_FOUND:'회원을 확인하지 못했습니다. 목록을 새로고침하세요.',MEMBER_INPUT_INVALID:'회원 이름·메모·연결 대상의 입력 범위를 확인하세요.',MEMBER_QUERY_INVALID:'검색 조건을 확인하세요.',MEMBER_CAPACITY:'회원 관리 저장 한도에 도달했습니다. 서버 운영 상태를 확인하세요.',MEMBER_REQUEST_REUSED:'다른 내용에 사용된 요청입니다. 목록을 새로고침한 뒤 다시 확인하세요.'};
 if(messages[error.code])error.message=messages[error.code];return error;
}
function desktopMemberCurrentRevision(){const revision=desktopPanels.get('members')?.data?.revision;if(!Number.isSafeInteger(revision)||revision<0)throw Error('회원 목록을 새로고침한 뒤 다시 시도하세요.');return revision;}
function desktopMemberRow(id){const row=desktopPanels.get('members')?.data?.items?.find(value=>value.id===id),detail=desktopPanels.get(desktopMemberKey(id))?.data?.member;return row||(detail?.id===id?detail:undefined);}
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
 catch(error){if(error.status>=400&&error.status<500&&desktopMemberPending===pending){desktopMemberPending=null;desktopMemberInvalidate(true);}throw error;}
 if(desktopMemberPending===pending)desktopMemberPending=null;
 if(!roleIsAdmin()||session?.csrf!==pending.owner)return;
 desktopMemberInvalidate(true);toast('회원 관리 변경을 서버에 반영했습니다.');await renderCurrent();
}
async function desktopMemberContactForm(row,owner,expectedRevision){
 const values=await openModal({title:row?'운영 연락처 수정':'운영 연락처 등록',message:'확인한 연락처의 표시 이름과 운영 메모를 입력하세요. PC의 회원 ID와 닉네임은 인증된 연결에서 정해집니다.',fields:[{name:'displayName',label:'연락처 표시 이름 (1~80자)',value:row?.displayName||''},{name:'note',label:'운영 메모 (선택, 최대 1000자)',type:'textarea',value:row?.note||''}],confirmLabel:'연락처 저장'});
 if(!values||session?.csrf!==owner||!roleIsAdmin())return;
 const displayName=String(values.displayName||'').trim(),note=String(values.note||'').trim();
 if(!displayName||displayName.length>80||note.length>1000)throw Error('연락처 이름은 1~80자, 메모는 1000자 이하로 입력하세요.');
 await desktopMemberSave('/api/desktop/members'+(row?'/'+encodeURIComponent(row.id):''),{displayName,note},owner,expectedRevision);
}
async function desktopMemberAssign(target,owner){
 const kind=target.dataset.memberKind,targetId=target.dataset.memberTarget,expectedMemberId=target.dataset.memberDirect||'';
 if(!['LICENSE','LAUNCHER','FLOW','DEVICE'].includes(kind)||!targetId)throw Error('연결 대상이 올바르지 않습니다.');
 const first=await api('/api/desktop/members?'+new URLSearchParams({status:'ACTIVE',page:'1',pageSize:'100'}));
 if(!roleIsAdmin()||session?.csrf!==owner)return;
 const expectedRevision=first.revision;
 const blankLabel=expectedMemberId?'직접 연결 해제 · 상위 연결은 유지':'연결할 회원을 선택하세요';
 const options=[{value:'',label:blankLabel},...(first.items||[]).map(row=>({value:row.id,label:row.displayName+' · '+row.id}))];
 const promise=openModal({title:'운영 연락처 연결',message:'이 기록에 연결할 운영 연락처를 선택하세요. PC 닉네임과 회원 ID는 인증된 PC가 정합니다.',html:`<p class="code desktop-wrap">${esc(kind)} · ${esc(targetId)}</p><label>회원 검색<input id="desktop-member-picker-search" maxlength="80" type="search" autocomplete="off"></label><button type="button" id="desktop-member-picker-refresh">회원 검색</button><p id="desktop-member-picker-status" role="status">최대 100명 표시 · 찾는 회원이 없으면 이름 또는 ID로 검색하세요.</p>`,fields:[{name:'memberId',label:'확인한 회원',type:'select',value:options.some(row=>row.value===expectedMemberId)?expectedMemberId:'',options}],confirmLabel:'연락처 연결 저장'});
 const select=modalBody.querySelector('[data-modal-field="memberId"]'),search=document.getElementById('desktop-member-picker-search'),button=document.getElementById('desktop-member-picker-refresh'),status=document.getElementById('desktop-member-picker-status');
 let serial=0,closed=false;
 button.onclick=async()=>{const generation=++serial;if(closed||!roleIsAdmin()||session?.csrf!==owner)return;button.disabled=true;modalConfirm.disabled=true;try{const result=await api('/api/desktop/members?'+new URLSearchParams({q:search.value.trim(),status:'ACTIVE',page:'1',pageSize:'100'}));if(closed||generation!==serial||session?.csrf!==owner||!select.isConnected)return;select.replaceChildren();for(const row of [{id:'',displayName:blankLabel},...(result.items||[])]){const option=document.createElement('option');option.value=row.id;option.textContent=row.displayName+(row.id?' · '+row.id:'');select.append(option);}status.textContent='검색 결과 '+desktopMemberCount(result.totalCount)+'명 · 최대 100명 표시';}catch(error){if(!closed&&status.isConnected)status.textContent=error.message||'회원 검색 결과를 확인하지 못했습니다.';}finally{if(!closed&&button.isConnected){button.disabled=false;modalConfirm.disabled=false;}}};
 let values;try{values=await promise;}finally{closed=true;serial++;}
 if(!values||!roleIsAdmin()||session?.csrf!==owner)return;
 if(!expectedMemberId&&!values.memberId)throw Error('직접 연결을 해제할 회원이 없습니다. 연결할 회원을 선택하거나 원래 라이선스·A 발급의 연결을 변경하세요.');
 await desktopMemberSave('/api/desktop/members/assignment',{kind,targetId,memberId:String(values.memberId||''),expectedMemberId},owner,expectedRevision);
}
async function showDesktopRecordMatching(kind,id){
 if(!roleIsAdmin()||!session||!['LICENSE','LAUNCHER','FLOW','DEVICE'].includes(kind)||typeof id!=='string'||!id)return;
 const owner=session.csrf,view=currentView,parent=captureAdminModalOwner(),request=++desktopRecordMatchSequence;
 const {match}=await api('/api/desktop/members/record/'+kind+'/'+encodeURIComponent(id));
 if(!roleIsAdmin()||session?.csrf!==owner||currentView!==view||request!==desktopRecordMatchSequence||(parent&&!parent()))return;
 if(!match||!['MATCHED','CONTACT','AWAITING_PC'].includes(match.state))throw Error('매칭 정보를 확인하지 못했습니다.');
 const pc=desktopMemberPcIdentity(match),memberId=match.memberId;
 if((match.state==='MATCHED'&&(!pc||!desktopMemberValidId(memberId)))||
    (match.state==='CONTACT'&&!desktopMemberValidId(memberId)))throw Error('기록에 연결된 회원을 확인하지 못했습니다.');
 const name=pc?.nickname||match.memberDisplayName||'PC 인증 대기';
 const code=pc?.code;
 const labels={LICENSE:'라이선스',LAUNCHER:'A 발급',FLOW:'실행',DEVICE:'PC'};
 const html=`<div id="desktop-record-match-dialog" class="desktop-match-mini"><div class="desktop-match-caption">
  <span class="desktop-match-avatar" aria-hidden="true">${pc?'PC':match.state==='CONTACT'?'M':'—'}</span>
  <div class="desktop-member-name"><strong>${esc(name)}</strong>${code?`<small class="code">회원 ID ${esc(code)}</small>`:'<small>인증된 PC 연결 정보 없음</small>'}</div>
 </div><div class="desktop-match-source"><span>${labels[kind]}</span><code>${esc(id)}</code></div>${match.state==='AWAITING_PC'
 ?'<p>인증된 PC가 이 기록을 사용하면 이곳에 회원 ID와 닉네임이 표시됩니다.</p>':''}
 ${kind===match.assignmentKind&&id===match.assignmentTargetId?'<div class="actions"><button type="button" id="desktop-record-contact">운영 연락처 연결</button></div>':''}</div>`;
 let attach=false;
 const canOpen=desktopMemberValidId(memberId)&&view==='desktop-licenses';
 const closed=openModal({title:'1:1 매칭',html,confirmLabel:canOpen?'매칭 기록 열기':'닫기',hideCancel:!canOpen});
 const root=document.getElementById('desktop-record-match-dialog');
 const contact=document.getElementById('desktop-record-contact');
 if(contact)contact.onclick=()=>{attach=true;modalConfirm.click();};
 let result;
 try{result=await closed;}finally{if(root?.isConnected)root.replaceChildren();}
 if(!result||!roleIsAdmin()||session?.csrf!==owner||currentView!==view||request!==desktopRecordMatchSequence)return;
 if(attach){await desktopMemberAssign({dataset:{memberKind:kind,memberTarget:id,memberDirect:match.assignedMemberId}},owner);return;}
 if(canOpen){
  desktopSelectTab('members');
  await renderCurrent();
  desktopMemberOpenMatching(memberId);
 }
}
async function handleDesktopMemberAction(target){
 const action=target.dataset.memberAction;if(!action)return false;
 if(!roleIsAdmin()||!session)throw Error('관리자만 회원을 관리할 수 있습니다.');
 desktopMemberResetOwner(session.csrf);
 if(desktopLicenseActionPending)return true;
 const owner=session.csrf;
 if(action==='open-detail'){
  const id=target.dataset.memberId;
  if(!desktopMemberValidId(id)||!desktopMemberRow(id))throw Error('매칭 목록을 새로고침하세요.');
  desktopMemberListDraft=document.getElementById('desktop-member-search')?.value??desktopMemberListDraft;
  desktopMemberOpenMatching(id,'licenses',target);
  return true;
 }
 if(action==='record-match'){
  await showDesktopRecordMatching(target.dataset.memberKind,target.dataset.memberTarget);
  return true;
 }
 const match=desktopMemberMatch;
 const fromMatch=match&&desktopMemberMatchCurrent(match)&&match.root.contains(target);
 const restoreMatch=fromMatch&&['edit','edit-contact','archive','assign','license-detail','retry'].includes(action);
 const restoreCategory=desktopMemberCategory;
 desktopLicenseActionPending=true;target.disabled=true;
 try{
  if(action==='category'){
   const id=target.dataset.memberId,category=target.dataset.memberCategory;
   if(!fromMatch||id!==match.id||!desktopMemberCategories.some(([name])=>name===category))return true;
   desktopMemberCategory=category;desktopMemberPaintMatching(match);desktopMemberLoadMatching(match);return true;
  }
  if(action==='refresh'){
   desktopMemberInvalidate();
   if(fromMatch)desktopMemberLoadMatching(match,true);else await renderCurrent();
   return true;
  }
  if(['nhw-policy-save','nhw-policy-reset','nhw-policy-all','nhw-policy-none'].includes(action)){
   if(!fromMatch||desktopMemberCategory!=='nhw')return true;
   const catalog=desktopMemberMonitorCurrentCatalog();
   if(action==='nhw-policy-save'){await desktopMemberSaveNhwPolicy(catalog,owner);return true;}
   if(action==='nhw-policy-reset'){
    desktopMemberMonitorDraft=null;desktopMemberMonitorFeedback='';
    desktopInvalidatePanels(desktopMemberMonitorPolicyKey);
    desktopMemberRequestMatchingPanel(match,desktopMemberMonitorPolicyKey,desktopMemberMonitorPolicyUrl,true);
   }else desktopMemberEditNhwPolicy(catalog,catalog.keys(),action==='nhw-policy-all');
   desktopMemberPaintMatching(match);return true;
  }
  if(action==='clear'){desktopMemberQuery='';desktopMemberListDraft=null;desktopMemberStatus='ACTIVE';desktopMemberPage=1;desktopPanels.delete('members');await renderCurrent();return true;}
  if(action==='page'){const page=Number(target.dataset.memberPage);if(Number.isSafeInteger(page)&&page>0){desktopMemberPage=page;desktopPanels.delete('members');await renderCurrent();}return true;}
  if(action==='detail-page'){
   const page=Number(target.dataset.memberPage),id=target.dataset.memberId,category=target.dataset.memberCategory;
   if(fromMatch&&id===match.id&&category===desktopMemberCategory&&Number.isSafeInteger(page)&&page>0){
    desktopMemberPages.set(id+':'+category,page);desktopMemberPaintMatching(match);desktopMemberLoadMatching(match);
   }
   return true;
  }
  if(action==='approval'){await showDesktopFirstDeviceApproval();desktopMemberInvalidate();await renderCurrent();return true;}
  if(action==='license-detail'){
   if(!fromMatch||desktopMemberCategory!=='licenses')throw Error('회원의 라이선스 목록에서 다시 선택하세요.');
   await showDesktopUnifiedDetail(target.dataset.memberTarget,{memberId:match.id});return true;
  }
  if(action==='retry'){const yes=await openModal({title:'이전 회원 관리 결과 확인',message:'완료를 확인하지 못한 요청을 같은 요청 ID와 내용으로 다시 확인합니다.',confirmLabel:'같은 요청 확인'});if(yes&&session?.csrf===owner)await desktopMemberSendPending();return true;}
  if(desktopMemberPending)throw Error('이전 회원 관리 요청의 결과를 먼저 확인하세요.');
  if(action==='assign'){await desktopMemberAssign(target,owner);return true;}
  if(action==='edit-contact'){
   if(!fromMatch)return true;
   const profile=desktopPanels.get(desktopMemberKey(match.id))?.data?.member,contactId=target.dataset.memberId;
   if(!desktopMemberPcIdentity(profile)||!desktopMemberValidId(contactId)||profile.contactId!==contactId)return true;
   const detail=await api('/api/desktop/members/'+encodeURIComponent(contactId)+'?category=licenses');
   if(!desktopMemberMatchCurrent(match))return true;
   if(detail.member?.id!==contactId||desktopMemberPcIdentity(detail.member))throw Error('연결된 운영 연락처를 확인하지 못했습니다.');
   await desktopMemberContactForm(detail.member,owner,detail.revision);
   return true;
  }
  const row=desktopMemberRow(target.dataset.memberId);
  if(action==='create'||action==='edit'){
   if(action==='edit'&&!row)throw Error('회원 목록을 새로고침하세요.');
   if(desktopMemberPcIdentity(row))throw Error('인증된 PC의 ID와 닉네임은 자동으로 설정됩니다.');
   await desktopMemberContactForm(row,owner,desktopMemberCurrentRevision());return true;
  }
  if(action==='archive'){
   if(!row||desktopMemberPcIdentity(row))throw Error('보관할 운영 연락처를 확인하세요.');
   const archived=row.status!=='ARCHIVED',expectedRevision=desktopMemberCurrentRevision();
   const yes=await openModal({title:archived?'회원 보관':'회원 보관 해제',message:row.displayName+'\n목록 분류만 바뀝니다. 라이선스·실행·보안 기록은 유지되며 서버 실행 권한은 변경하지 않습니다.',confirmLabel:archived?'회원 보관':'보관 해제'});
   if(yes&&session?.csrf===owner)await desktopMemberSave('/api/desktop/members/'+encodeURIComponent(row.id)+'/archive',{archived},owner,expectedRevision);return true;
  }
  return false;
 }catch(error){throw desktopMemberError(error);}finally{
  desktopLicenseActionPending=false;
  if(target.isConnected&&action!=='nhw-policy-save')target.disabled=false;
  if(restoreMatch&&!desktopMemberMatch&&!captureAdminModalOwner()&&session?.csrf===owner&&roleIsAdmin()){
   desktopMemberOpenMatching(match.id,restoreCategory,match.trigger);
  }
 }
}
content.addEventListener('submit',async event=>{
 if(event.target.id!=='desktop-member-search-form')return;event.preventDefault();
 desktopMemberQuery=document.getElementById('desktop-member-search').value.trim();desktopMemberListDraft=null;desktopMemberStatus=document.getElementById('desktop-member-filter').value;desktopMemberPage=1;desktopPanels.delete('members');await renderCurrent();
});
modalBody.addEventListener('click',async event=>{
 const target=event.target.closest('[data-member-action]');
 if(!target||!desktopMemberMatch?.root.contains(target))return;
 try{await handleDesktopMemberAction(target);}catch(error){toast(error.message||'매칭 기록을 처리하지 못했습니다.',true);}
});
modalBody.addEventListener('change',event=>{
 if(event.target.matches('input[type="checkbox"][data-monitor-detection-id]')){
  const id=Number(event.target.dataset.monitorDetectionId);
  const catalog=desktopMemberMonitorCurrentCatalog();
  if(!desktopMemberMatch||!desktopMemberMatchCurrent(desktopMemberMatch)||desktopMemberCategory!=='nhw'||desktopLicenseActionPending||!catalog.has(id))return;
  desktopMemberEditNhwPolicy(catalog,[id],event.target.checked);
  desktopMemberPaintMatching();
 }
});
content.addEventListener('change',async event=>{
 if(event.target.id!=='desktop-member-filter')return;desktopMemberStatus=event.target.value;desktopMemberPage=1;desktopPanels.delete('members');await renderCurrent();
});
modalBody.addEventListener('input',event=>{
 if(event.target.id!=='desktop-member-monitor-filter')return;
 desktopMemberMonitorQuery=event.target.value;
 const term=desktopMemberMonitorQuery.trim().toLowerCase();
 for(const row of event.target.closest('.desktop-member-monitor-filters').querySelectorAll('[data-monitor-search]'))row.hidden=!row.dataset.monitorSearch.includes(term);
});
