'use strict';
// License keys are shown only at issuance. Detail, list and live events never expose keys.
let desktopLicenseQuery = '';
let desktopLicenseStatus = 'ALL';
let desktopLicensePage = 0;
let desktopLicenseTab = 'licenses';
const desktopTabScroll = new Map();
let desktopRenderedQuery = null;
let desktopRenderedStatus = null;
let desktopLicenseRows = new Map();
let desktopLicenseActionPending = false;
let desktopPendingIssue = null;
let desktopPendingLauncher = null;
let desktopBootstrap = null;
let desktopIntegrityPolicy = null;
let desktopMachineRows = new Map();
let desktopBootstrapSessions = new Map();
const desktopStatusLabels = {AVAILABLE:'사용 전',USED:'사용됨',REVOKED:'폐기됨',EXPIRED:'만료됨'};
function desktopStatus(status) {
  if (['ACTIVE','RELEASED'].includes(status)) status='USED';
  return `<span class="desktop-status desktop-status-${esc(String(status).toLowerCase())}"><i aria-hidden="true"></i>${esc(desktopStatusLabels[status] || status)}</span>`;
}
// Preserve the original identifier for API paths; only its presentation changes.
function desktopDisplayId(value) { return String(value || '').replace(/^(?:DL|LA|BF|DS|DA|BA|FLOW)[_-]/i,'').replace(/-/g,''); }
function desktopDate(value) { return value ? esc(fmtTime(value)) : '—'; }
function desktopLicenseDevice(row) {
  const device = String(row.deviceName || '').trim();
  const id = String(row.deviceId || '').trim();
  return device || id ? `<strong>${esc(device || '등록된 PC')}</strong><span class="code muted" title="${esc(id)}">${esc(id ? id.slice(0,18)+(id.length>18?'…':'') : '—')}</span>` : '<span class="muted">아직 연결되지 않음</span>';
}
// Keep native controls and disclosure nodes mounted through every refresh. A
// selected option, text draft, open details and nested scroller belong to the user.
function desktopNodeKey(node) { return node.nodeType===1?(node.id||node.dataset.desktopKey||''):''; }
function desktopPatchNode(previous,next,silent) {
  if(previous.nodeType!==1){if(previous.nodeValue!==next.nodeValue)previous.nodeValue=next.nodeValue;return;}
  const control=previous.matches('input,textarea,select');
  if(control){
    const committed=previous.id==='desktop-license-search'?desktopRenderedQuery!==desktopLicenseQuery:previous.id==='desktop-license-filter'?desktopRenderedStatus!==desktopLicenseStatus:false;
    if(committed&&previous.value!==next.value)previous.value=next.value;
    return;
  }
  for(const attribute of [...previous.attributes])if(!next.hasAttribute(attribute.name)&&!(previous.tagName==='DETAILS'&&attribute.name==='open'))previous.removeAttribute(attribute.name);
  for(const attribute of [...next.attributes])if(previous.getAttribute(attribute.name)!==attribute.value&&!(previous.tagName==='DETAILS'&&attribute.name==='open'))previous.setAttribute(attribute.name,attribute.value);
  const keyed=new Map([...previous.childNodes].filter(node=>desktopNodeKey(node)).map(node=>[desktopNodeKey(node),node]));
  let cursor=previous.firstChild;
  for(const wanted of [...next.childNodes]){
    const key=desktopNodeKey(wanted);
    let existing=key?keyed.get(key):cursor;
    if(!existing||existing.nodeType!==wanted.nodeType||existing.nodeName!==wanted.nodeName||(!key&&desktopNodeKey(existing))){existing=wanted.cloneNode(true);previous.insertBefore(existing,cursor);}
    else {if(existing!==cursor)previous.insertBefore(existing,cursor);desktopPatchNode(existing,wanted,silent);}
    cursor=existing.nextSibling;
  }
  while(cursor){const stale=cursor;cursor=cursor.nextSibling;stale.remove();}
}
function desktopScrollElements() {
  const nodes=[...content.querySelectorAll('.table-wrap,.desktop-integrity-list'),content];
  for(let parent=content.parentElement;parent;parent=parent.parentElement)nodes.push(parent);
  if(document.scrollingElement)nodes.push(document.scrollingElement);
  return [...new Set(nodes)];
}
function desktopCaptureScroll() {
  return desktopScrollElements().map(element=>{
    const rect=element.getBoundingClientRect();
    const anchor=[...element.querySelectorAll('details[data-desktop-key],tr[data-desktop-key]')].find(node=>{
      if(node.closest('[hidden]'))return false;
      const box=node.getBoundingClientRect();return box.height>0&&box.bottom>rect.top&&box.top<rect.bottom;
    });
    return {element,top:element.scrollTop,left:element.scrollLeft,anchor,anchorTop:anchor?.getBoundingClientRect().top};
  });
}
function desktopRestoreScroll(state,anchor=true) {
  for(const saved of state){
    if(!saved.element.isConnected)continue;
    const delta=anchor&&saved.anchor?.isConnected?saved.anchor.getBoundingClientRect().top-saved.anchorTop:0;
    saved.element.scrollTop=saved.top+delta;saved.element.scrollLeft=saved.left;
  }
}
function desktopSelectTab(tab) {
  if(!['licenses','modules'].includes(tab)||tab===desktopLicenseTab)return;
  desktopTabScroll.set(desktopLicenseTab,desktopCaptureScroll());desktopLicenseTab=tab;
  content.querySelectorAll('[data-desktop-tab]').forEach(button=>{const active=button.dataset.desktopTab===tab;button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;});
  content.querySelectorAll('[data-desktop-tab-panel]').forEach(panel=>{panel.hidden=panel.dataset.desktopTabPanel!==tab;});
  const saved=desktopTabScroll.get(tab);if(saved)desktopRestoreScroll(saved,false);
  else for(const element of desktopScrollElements())if(!content.contains(element)||element===content){element.scrollTop=0;element.scrollLeft=0;}
}
async function renderDesktopLicenses(silent = false) {
  if (!roleIsAdmin()) { content.innerHTML='<div class="empty">관리자만 라이선스를 관리할 수 있습니다.</div>'; return; }
  const requestedQuery=desktopLicenseQuery,requestedStatus=desktopLicenseStatus;
  const query = new URLSearchParams({q:requestedQuery});
  if (desktopLicenseStatus !== 'ALL') query.set('status', desktopLicenseStatus);
  const owner = session?.csrf;
  const [data, bootstrapData, integrityData, baselineData, machineData, policyData] = await Promise.all([api('/api/desktop/licenses?'+query), api('/api/desktop/bootstrap'), api('/api/desktop/bootstrap/integrity-reports'), api('/api/desktop/bootstrap/module-baselines'), api('/api/desktop/machines'), api('/api/desktop/bootstrap/integrity-policy')]);
  if (currentView !== 'desktop-licenses' || !session || session.csrf !== owner) return;
  if(requestedQuery!==desktopLicenseQuery||requestedStatus!==desktopLicenseStatus)return;
  if(silent&&(desktopLicenseActionPending||!modalEl.classList.contains('hidden')))return;
  desktopBootstrap = bootstrapData.bootstrap || {};
  desktopIntegrityPolicy = policyData.policy || null;
  desktopMachineRows = new Map((machineData.items||[]).map(row=>[row.machineId,row]));
  desktopBootstrapSessions = new Map((desktopBootstrap.sessions || []).map(row=>[String(row.id),row]));
  const rows = Array.isArray(data.items) ? data.items : [];
  desktopLicenseRows = new Map(rows.map(row=>[String(row.id),row]));
  const pageSize=25,pages=Math.max(1,Math.ceil(rows.length/pageSize));
  desktopLicensePage=Math.min(Math.max(0,desktopLicensePage),pages-1);
  const page=rows.slice(desktopLicensePage*pageSize,(desktopLicensePage+1)*pageSize);
  const counts=data.counts || {};
  const countLabel=status=>Number.isSafeInteger(counts[status])?counts[status].toLocaleString():'—';
  const totalLabel=Number.isSafeInteger(data.totalCount)?data.totalCount.toLocaleString():'—';
  const filtered=!!desktopLicenseQuery || desktopLicenseStatus!=='ALL';
  const html=`<div class="desktop-workspace">
    <div class="desktop-tabs" role="tablist" aria-label="라이선스 관리 메뉴">${[['licenses','라이선스 · A / B 배포'],['modules','모듈 · 무결성']].map(([tab,label])=>`<button type="button" id="desktop-tab-${tab}" role="tab" data-desktop-tab="${tab}" aria-controls="desktop-tabpanel-${tab}" aria-selected="${desktopLicenseTab===tab}" tabindex="${desktopLicenseTab===tab?0:-1}">${label}</button>`).join('')}</div>
    <div id="desktop-tabpanel-licenses" class="desktop-tab-panel" role="tabpanel" aria-labelledby="desktop-tab-licenses" data-desktop-tab-panel="licenses" ${desktopLicenseTab==='licenses'?'':'hidden'}>
    <section class="desktop-hero"><div class="desktop-platform" aria-hidden="true"><svg viewBox="0 0 40 40"><path d="M4 8h32v21H4zM13 35h14M20 29v6M9 13h8v5H9zM21 13h10v5H21zM9 21h8v4H9zM21 21h10v4H21z"/></svg></div><div><span class="desktop-eyebrow">WINDOWS 64-BIT</span><h3>한 번 실행하고, 서버에서 인증</h3><p>무작위 이름으로 발급한 실행기가 프로그램을 받아 연결합니다. 사용자는 빈 콘솔에 라이선스 키를 입력하거나 붙여넣고 Enter를 누릅니다. 입력한 문자는 그대로 표시됩니다. 성공 후에는 빈 화면을 유지하고, 배포와 사용 기록은 서버에서 관리합니다.</p></div><button type="button" id="desktop-license-create" class="primary">+ 라이선스 발급</button></section>
    <div class="desktop-stats" aria-label="필터와 무관한 전체 라이선스 상태">${Object.entries(desktopStatusLabels).map(([status,label])=>`<button type="button" class="desktop-stat${desktopLicenseStatus===status?' selected':''}" data-desktop-status="${status}"><span>${label}</span><strong>${countLabel(status)}</strong></button>`).join('')}</div>
    ${desktopBootstrapMarkup(desktopBootstrap)}
    ${desktopMachineListMarkup(machineData)}
    <section class="section-card desktop-license-list"><div class="section-head"><div><h3>Windows 라이선스</h3><p class="small-note" id="desktop-license-result-summary">전체 ${totalLabel}개 · 현재 ${rows.length.toLocaleString()}개${filtered?` · 필터 적용: ${esc(desktopStatusLabels[desktopLicenseStatus]||'전체 상태')}${desktopLicenseQuery?' · 검색어 '+esc(desktopLicenseQuery):''}`:' · 전체 보기'} · 위 상태 수치는 전체 기준</p></div><div class="actions"><span class="small-note" id="desktop-license-updated">자동 갱신 · ${desktopDate(data.serverTime)}</span></div></div>
    <form id="desktop-license-search-form" class="desktop-license-toolbar"><label class="desktop-search"><span class="sr-only">라이선스 검색</span><input id="desktop-license-search" type="search" maxlength="120" autocomplete="off" placeholder="라이선스 ID, 이름, PC 검색" value="${esc(desktopLicenseQuery)}"></label><label><span class="sr-only">상태</span><select id="desktop-license-filter"><option value="ALL">전체 상태</option>${Object.entries(desktopStatusLabels).map(([value,label])=>`<option value="${value}" ${value===desktopLicenseStatus?'selected':''}>${label}</option>`).join('')}</select></label><button type="submit">검색</button>${desktopLicenseQuery||desktopLicenseStatus!=='ALL'?'<button type="button" id="desktop-license-clear" class="ghost">전체 보기</button>':''}</form>
    <div class="table-wrap"><table id="desktop-license-records" class="desktop-license-table"><thead><tr><th>라이선스</th><th>상태</th><th>연결된 PC</th><th>최초 사용 · 사용 정책</th><th>최근 인증</th><th>관리</th></tr></thead><tbody>${page.map(row=>`<tr data-desktop-key="license-${esc(row.id)}"><td><div class="desktop-cell"><strong>${esc(row.label||'이름 없는 라이선스')}</strong><span class="code muted">${esc(desktopDisplayId(row.displayId||row.id))}</span><small>${row.consumed?'최초 사용 완료 · 재사용 불가':'최초 사용 대기'} · ${desktopDate(row.issuedAt)}</small></div></td><td>${desktopStatus(row.status)}</td><td><div class="desktop-cell">${desktopLicenseDevice(row)}${row.appVersion?`<small>v${esc(row.appVersion)}</small>`:''}${row.machineBlocked?'<small class="desktop-machine-blocked">이 PC 차단됨</small>':''}</div></td><td><div class="desktop-cell"><span>${desktopDate(row.activatedAt)}</span><small>${row.expiresAt?'이전 발급 기한 '+desktopDate(row.expiresAt):'1회 사용 · 재사용 불가'}</small></div></td><td>${desktopDate(row.lastVerifiedAt)}</td><td><div class="actions"><button type="button" data-desktop-action="detail" data-id="${esc(row.id)}">상세</button>${row.status!=='REVOKED'?`<button type="button" class="danger" data-desktop-action="revoke" data-id="${esc(row.id)}">폐기</button>`:''}<button type="button" data-desktop-action="reissue" data-id="${esc(row.id)}">새 키 발급</button></div></td></tr>`).join('')||'<tr><td colspan="6"><div class="desktop-empty"><span aria-hidden="true">◇</span><strong>라이선스가 없습니다.</strong><p>검색 조건을 바꾸거나 새 라이선스를 발급하세요.</p></div></td></tr>'}</tbody></table></div>
    <div class="desktop-pagination"><span>${rows.length?desktopLicensePage*pageSize+1:0}–${Math.min(rows.length,(desktopLicensePage+1)*pageSize)} / ${rows.length}</span><div class="actions"><button type="button" data-desktop-page="-1" ${desktopLicensePage===0?'disabled':''}>이전</button><span>${desktopLicensePage+1} / ${pages}</span><button type="button" data-desktop-page="1" ${desktopLicensePage+1>=pages?'disabled':''}>다음</button></div></div></section>
  </div><div id="desktop-tabpanel-modules" class="desktop-tab-panel" role="tabpanel" aria-labelledby="desktop-tab-modules" data-desktop-tab-panel="modules" ${desktopLicenseTab==='modules'?'':'hidden'}>${desktopIntegrityMarkup(integrityData,baselineData,desktopIntegrityPolicy)}</div></div>`;
  const previous=content.querySelector('.desktop-workspace');
  if(previous){
    // Capture at commit time: a user can scroll while the request is in flight.
    const scroll=desktopCaptureScroll(),template=document.createElement('template');template.innerHTML=html;
    desktopPatchNode(previous,template.content.firstElementChild,silent);desktopRestoreScroll(scroll);
  }else content.innerHTML=html;
  desktopRenderedQuery=desktopLicenseQuery;desktopRenderedStatus=desktopLicenseStatus;
}
function desktopIssueFields(label='',replacement=false) {
  return [{name:'label',label:'라이선스 이름 (선택, 최대 120자)',value:label},
    ...(replacement?[{name:'reason',label:'교체 사유 (3~300자)',type:'textarea',value:''}]:[])];
}
function desktopIssueBody(values) {
  const label=String(values.label||'').trim();if(label.length>120)throw Error('라이선스 이름은 120자 이하로 입력해주세요.');
  return {label};
}
function desktopReason(value) {
  const reason=String(value||'').trim();if(reason.length<3||reason.length>300)throw Error('처리 사유를 3~300자로 입력해주세요.');return reason;
}
function desktopBindKeyCopy(button,input,owner) {
  button.addEventListener('click',async()=>{
    if(!roleIsAdmin()||session?.csrf!==owner||!input.isConnected||modalEl.classList.contains('hidden'))return;
    try{
      if(navigator.clipboard?.writeText)await navigator.clipboard.writeText(input.value);
      else{input.focus();input.select();if(!document.execCommand('copy'))throw Error('복사할 키를 직접 선택해주세요.');}
      if(session?.csrf===owner)toast('라이선스 키를 복사했습니다.');
    }catch(error){if(session?.csrf===owner)toast(error.message||'복사하지 못했습니다.',true);}
  });
}
async function showDesktopLicenseDetail(id) {
  if(!roleIsAdmin()||!session)throw Error('관리자만 라이선스 상세를 볼 수 있습니다.');
  const owner=session.csrf;
  const data=await api('/api/desktop/licenses/'+encodeURIComponent(id));
  if(!roleIsAdmin()||session?.csrf!==owner||currentView!=='desktop-licenses')return;
  const row=data.license;
  if(!row||String(row.id)!==String(id))throw Error('라이선스 상세를 확인하지 못했습니다.');
  let machineAction='';
  const promise=openModal({title:row.label||'라이선스 상세',html:`${desktopMachineSecurityMarkup(row)}<div class="kv"><div>라이선스 ID</div><div class="code desktop-wrap">${esc(desktopDisplayId(row.displayId||row.id))}</div><div>상태</div><div>${desktopStatus(row.status)}</div><div>발급</div><div>${desktopDate(row.issuedAt)}</div><div>최초 등록</div><div>${desktopDate(row.activatedAt)}</div><div>사용 정책</div><div>1회 등록 · 등록 즉시 사용됨 · 재사용 불가</div>${row.expiresAt?'<div>이전 발급 기한</div><div>'+desktopDate(row.expiresAt)+'</div>':''}<div>최초 사용</div><div>${row.consumed?'완료 · 다시 사용 불가':'대기 중'}</div><div>PC</div><div>${esc(row.deviceName||'—')}</div><div>기기 식별자</div><div class="code desktop-wrap">${esc(row.deviceId||'—')}</div><div>버전</div><div>${esc(row.appVersion||'—')}</div><div>최근 인증</div><div>${desktopDate(row.lastVerifiedAt)}</div><div>실행 세션 인증 기한</div><div>${desktopDate(row.leaseExpiresAt)}</div><div>실행 종료</div><div>${desktopDate(row.releasedAt)}</div><div>관리자 폐기</div><div>${desktopDate(row.revokedAt)}</div><div>사유</div><div class="desktop-wrap">${esc(row.reason||'—')}</div></div>`,confirmLabel:'닫기'});
  const machineButton=document.getElementById('desktop-machine-action');
  if(machineButton)machineButton.addEventListener('click',()=>{
    if(!roleIsAdmin()||session?.csrf!==owner||!machineButton.isConnected)return;
    machineAction='unblock';modalConfirm.click();
  });
  try{await promise;}finally{if(session?.csrf===owner)modalBody.replaceChildren();}
  if(machineAction&&roleIsAdmin()&&session?.csrf===owner&&currentView==='desktop-licenses')await showDesktopMachineAction(row,machineAction,owner);
}
function desktopMachineSecurityMarkup(row) {
  const fingerprint=/^[A-F0-9]{64}$/.test(row.machineId||'')?row.machineId:'',blocked=!!row.machineBlocked;
  const digest=/^[a-fA-F0-9]{64}$/.test(row.binarySha256||'')?row.binarySha256:'',crc=/^[A-F0-9]{16}$/.test(row.binaryCrc64||'')?row.binaryCrc64:'';
  return `<section class="desktop-machine-security" aria-labelledby="desktop-machine-security-title"><h3 id="desktop-machine-security-title">PC 접근 · 파일 무결성</h3><div class="kv"><div>PC 지문 (해시)</div><div class="code desktop-wrap">${esc(fingerprint||'연결 후 확인 가능')}</div><div>PC 접근 정책</div><div class="${blocked?'desktop-machine-blocked':''}">${blocked?(row.machinePolicy?.source==='SINGLE_USE'?'1회 사용으로 새 실행 자동 차단':'관리자 차단 기록'):'새 실행 허용'}</div>${row.machinePolicy?`<div>정책 변경</div><div>${desktopDate(row.machinePolicy.changedAt)}</div><div>변경 사유</div><div class="desktop-wrap">${esc(row.machinePolicy.reason||'—')}</div>`:''}<div>B SHA-256</div><div class="code desktop-wrap">${esc(digest||'연결 후 확인 가능')}</div><div>B CRC64</div><div class="code desktop-wrap">${esc(crc||'연결 후 확인 가능')}</div></div><p class="small-note">라이선스를 사용하면 이 PC의 다음 실행이 자동 차단됩니다. 현재 인증된 실행은 계속되며, 관리자 해제 후에는 새 A와 새 키가 필요합니다. 해제해도 사용된 키와 이전 세션은 복구되지 않습니다. 아래 파일 값은 등록된 B 기준이며 실제 검사 결과는 무결성 기록에서 확인하세요.</p>${fingerprint&&blocked?'<button type="button" id="desktop-machine-action">이 PC 차단 해제</button>':''}</section>`;
}
async function showDesktopMachineAction(row,action,owner) {
  if(!roleIsAdmin()||!session||session.csrf!==owner)throw Error('관리자 로그인을 확인해주세요.');
  if(!/^[A-F0-9]{64}$/.test(row.machineId||'')||action!=='unblock')throw Error('해제할 PC 식별 정보를 확인하지 못했습니다.');
  const values=await openModal({title:'이 PC 접근 차단 해제',message:'새 A와 새 키를 이용한 다음 실행을 허용합니다. 현재 실행을 포함한 이전 세션은 폐기되며 사용된 키는 복구되지 않습니다.',html:`<div class="code desktop-wrap desktop-machine-confirm">${esc(row.machineId)}</div>`,fields:[{name:'reason',label:'처리 사유 (3~300자)',type:'textarea',value:''}],confirmLabel:'차단 해제'});
  if(!values||!roleIsAdmin()||session?.csrf!==owner)return;
  await api('/api/desktop/machines/'+encodeURIComponent(row.machineId)+'/unblock',{method:'POST',body:{reason:desktopReason(values.reason),requestId:crypto.randomUUID()}});
  if(!roleIsAdmin()||session?.csrf!==owner)return;
  toast('이 PC 차단을 해제했습니다. 새 A와 새 키가 필요합니다.');
  if(currentView==='desktop-licenses')await renderCurrent();
}
async function showDesktopLicenseReceipt(data) {
  if(typeof data.licenseKey!=='string'||!data.licenseKey)throw Error('발급 응답에 라이선스 키가 없습니다. 관리자 기록을 확인해주세요.');
  const id=desktopDisplayId(data.license?.id||'license');
  const promise=openModal({title:'라이선스 발급 완료',message:'키 원문은 발급 화면에서만 확인할 수 있습니다. 대상 PC의 빈 콘솔에 키를 입력하거나 붙여넣고 Enter를 누르세요. 입력한 문자는 그대로 보이며, 성공 후에는 빈 화면을 유지합니다.',html:`<div class="desktop-key-receipt"><label for="desktop-issued-key">새 라이선스 키</label><textarea id="desktop-issued-key" class="code" readonly spellcheck="false" autocomplete="off">${esc(data.licenseKey)}</textarea><div class="actions"><button type="button" id="desktop-key-copy">키 복사</button><button type="button" id="desktop-key-download">텍스트 저장</button></div><p class="small-note">등록이 성공하는 즉시 사용됨으로 처리되며 다시 등록할 수 없습니다. 실행을 마친 뒤 다시 이용하려면 새 실행 파일과 새 키가 필요합니다.</p></div>`,confirmLabel:'저장했어요'});
  const input=document.getElementById('desktop-issued-key');
  const copy=document.getElementById('desktop-key-copy'),download=document.getElementById('desktop-key-download');
  desktopBindKeyCopy(copy,input,session?.csrf);
  download.addEventListener('click',()=>{const blob=new Blob([`Game Windows64\n라이선스 ID: ${id}\n${input.value}\n`],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='Game-License-'+id.replace(/[^a-zA-Z0-9_-]/g,'')+'.txt';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  try{await promise;}finally{input.value='';if(document.getElementById('desktop-issued-key')===input)modalBody.replaceChildren();}
}
function desktopBootstrapStatus(status) {
  const labels={AVAILABLE:'발급 완료 · 실행 대기',CONSUMED:'다운로드 시작 · 사용됨',STARTED:'A 연결됨',DOWNLOADED:'B 다운로드 완료',CLAIMED:'B 인증 중',EXPIRED:'만료됨',CLOSED:'연결 종료',REVOKED:'폐기됨'};
  return esc(labels[status]||status||'—');
}
function desktopBootstrapMarkup(data) {
  const artifacts=data.artifacts||{},sessions=Array.isArray(data.sessions)?data.sessions:[],launchers=Array.isArray(data.launchers)?data.launchers:[];
  const ready=!!artifacts.A&&!!artifacts.B;
  return `<section id="desktop-bootstrap-panel" class="section-card desktop-license-list">
    <div class="section-head"><div><h3>A / B 실행 파일 배포</h3><p class="small-note">A 실행기와 B 프로그램을 등록한 뒤, 고객 PC에서 한 번 실행할 파일을 발급하세요. A/B는 관리자 구분이며 실제 파일 이름은 무작위입니다.</p></div><button type="button" id="desktop-launcher-create" class="primary" ${ready?'':'disabled'}>+ 일회용 A 발급</button></div>
    <div class="table-wrap"><table id="desktop-bootstrap-artifacts" class="desktop-license-table"><thead><tr><th>구성 요소</th><th>게시 상태 · 버전</th><th>파일 무결성</th><th>등록 시각 · 크기</th><th>관리</th></tr></thead><tbody>${['A','B'].map(component=>{
      const artifact=artifacts[component];
      return `<tr><td><div class="desktop-cell"><strong>${component==='A'?'A · 일회용 실행기 템플릿':'B · 라이선스 프로그램'}</strong><small>${component==='A'?'무작위 이름의 일회용 실행 파일 발급':'서버 인계 확인 후 라이선스 키 입력창만 표시'}</small></div></td><td><div class="desktop-cell"><strong>${artifact?'게시됨':'미등록'}</strong><span>${artifact?'v'+esc(artifact.version):'등록이 필요합니다'}</span></div></td><td><div class="desktop-cell"><small>SHA-256</small><span class="code desktop-wrap">${esc(artifact?.sha256||'—')}</span><small>CRC64</small><span class="code desktop-wrap">${esc(artifact?.crc64||'—')}</span></div></td><td><div class="desktop-cell"><span>${desktopDate(artifact?.createdAt)}</span><small>${artifact?Number(artifact.size||0).toLocaleString()+' bytes':'—'}</small></div></td><td><button type="button" data-desktop-action="artifact-upload" data-component="${component}">${component} 파일 등록</button></td></tr>`;
    }).join('')}</tbody></table></div>
    <div class="section-head"><div><h3>발급한 A</h3><p class="small-note">${ready?'발급한 무작위 이름의 실행 파일 한 개를 전달하세요. 한 번 사용한 파일은 재사용할 수 없습니다. 아래 기한은 라이선스 기간이 아닌 미사용 실행기의 보안 기한입니다.':'A와 B를 모두 등록하면 일회용 A를 발급할 수 있습니다.'}</p></div></div>
    <div class="table-wrap"><table id="desktop-bootstrap-launchers" class="desktop-license-table"><thead><tr><th>이름 · A 발급 ID</th><th>상태</th><th>발급 · 실행 보안 기한</th><th>흐름 ID</th></tr></thead><tbody>${launchers.map(row=>`<tr data-desktop-key="launcher-${esc(row.id)}"><td><div class="desktop-cell"><strong>${esc(row.label||'이름 없는 A')}</strong><span class="code">${esc(desktopDisplayId(row.displayId||row.id))}</span><small class="code">${esc(row.downloadName||'—')}</small></div></td><td>${desktopBootstrapStatus(row.status)}</td><td><div class="desktop-cell"><span>${desktopDate(row.issuedAt)}</span><small>미사용 실행 기한 ${desktopDate(row.expiresAt)}</small></div></td><td class="code desktop-wrap">${esc(desktopDisplayId(row.flowId)||'실행 대기')}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">발급한 A가 없습니다.</td></tr>'}</tbody></table></div>
    <div class="section-head"><div><h3>A → B 실행 · 서버 인증</h3><p class="small-note">다운로드, B 실행과 연결된 라이선스의 인증 상태를 확인합니다. 세션 기한은 연결 보안을 위한 제한이며 라이선스 이용 기간이 아닙니다.</p></div></div>
    <div class="table-wrap"><table id="desktop-bootstrap-sessions" class="desktop-license-table"><thead><tr><th>흐름 · PC</th><th>실행 상태 · B 버전</th><th>연결된 라이선스</th><th>최근 인증</th><th>관리</th></tr></thead><tbody>${sessions.map(row=>`<tr data-desktop-key="session-${esc(row.id)}"><td><div class="desktop-cell"><strong class="code">${esc(desktopDisplayId(row.flowId||row.id))}</strong><span class="code">${esc(row.deviceId||'PC 연결 대기')}</span><small>A ${esc(desktopDisplayId(row.launcherId)||'—')} · ${desktopDate(row.createdAt)}</small></div></td><td><div class="desktop-cell"><strong>${row.status==='CLAIMED'&&['USED','ACTIVE'].includes(row.licenseStatus)?'실행 중':desktopBootstrapStatus(row.status)}</strong><small>${row.version?'B v'+esc(row.version):'B 연결 대기'}</small>${row.codeIntegrityStatus==='REJECTED'?'<small class="desktop-machine-blocked">무결성 불일치 · 실행 거부</small>':''}${row.reason?`<small>${esc(row.reason)}</small>`:''}</div></td><td><div class="desktop-cell"><span class="code">${esc(desktopDisplayId(row.licenseId)||'연결 전')}</span>${row.licenseStatus?desktopStatus(row.licenseStatus):'<span class="muted">라이선스 연결 대기</span>'}</div></td><td><div class="desktop-cell"><span>${desktopDate(row.licenseLastVerifiedAt||row.lastVerifiedAt)}</span><small>세션 만료 ${desktopDate(row.expiresAt)}</small></div></td><td>${['REVOKED','CLOSED','EXPIRED'].includes(row.status)?'—':`<button type="button" class="danger" data-desktop-action="session-revoke" data-id="${esc(row.id)}">실행 폐기</button>`}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">아직 실행 기록이 없습니다.</td></tr>'}</tbody></table></div>
  </section>`;
}
async function showDesktopArtifactUpload(component) {
  if(!roleIsAdmin()||!session)throw Error('관리자만 실행 파일을 등록할 수 있습니다.');
  if(!['A','B'].includes(component))throw Error('등록할 구성 요소를 확인해주세요.');
  const owner=session.csrf,maxBytes=desktopBootstrap?.limits?.maxArtifactBytes||67108864;
  const promise=openModal({title:component+' 실행 파일 등록',message:component==='A'?'일회용 A 발급에 사용할 Windows64 실행기 템플릿을 등록합니다.':'A가 서버에서 다운로드할 Windows64 B 프로그램을 게시합니다. 유효한 인계가 확인될 때만 라이선스 키 입력창이 열립니다.',html:`<label>실행 파일 (.exe)<input id="desktop-artifact-file" type="file" accept=".exe,application/octet-stream"></label><p class="small-note">최대 ${Math.floor(maxBytes/1048576)}MB</p><p id="desktop-artifact-status" role="status" aria-live="polite"></p>`,fields:[{name:'version',label:'버전',value:desktopBootstrap?.artifacts?.[component]?.version||'1.0.0'}],confirmLabel:'등록 · 게시'});
  const fileInput=document.getElementById('desktop-artifact-file'),versionInput=modalBody.querySelector('[data-modal-field="version"]'),status=document.getElementById('desktop-artifact-status'),finish=modalConfirm.onclick;
  let uploaded=false,busy=false;
  modalConfirm.onclick=async()=>{
    if(busy||!session||session.csrf!==owner)return;
    try {
      const file=fileInput.files?.[0],version=versionInput.value.trim();
      if(!file||!file.size||!/\.exe$/i.test(file.name))throw Error('비어 있지 않은 .exe 실행 파일을 선택해주세요.');
      if(file.size>maxBytes)throw Error('실행 파일이 서버의 업로드 크기 제한을 초과합니다.');
      if(!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(version))throw Error('버전을 1.0.0 형식으로 입력해주세요.');
      busy=true;modalConfirm.disabled=true;fileInput.disabled=true;versionInput.disabled=true;
      status.textContent='실행 파일을 업로드하고 서버에서 검증하고 있습니다.';
      const query=new URLSearchParams({component,version,fileName:file.name});
      await api('/api/desktop/bootstrap/artifacts?'+query,{method:'POST',rawBody:file});
      uploaded=true;
      if(session?.csrf===owner&&document.getElementById('desktop-artifact-file')===fileInput&&!modalEl.classList.contains('hidden')){toast(component+' 실행 파일을 게시했습니다.');finish();}
    } catch(error) { if(document.getElementById('desktop-artifact-file')===fileInput)status.textContent=error.message||'업로드하지 못했습니다. 같은 파일로 다시 시도해주세요.'; }
    finally {busy=false;if(document.getElementById('desktop-artifact-file')===fileInput){modalConfirm.disabled=false;fileInput.disabled=false;versionInput.disabled=false;}}
  };
  try {await promise;} finally {if(document.getElementById('desktop-artifact-file')===fileInput)modalBody.replaceChildren();}
  if(uploaded&&session?.csrf===owner)await renderCurrent();
}
async function downloadDesktopLauncher(data,owner) {
  if(!roleIsAdmin()||!session||session.csrf!==owner)throw Error('관리자 로그인을 확인해주세요.');
  const id=String(data.launcherId||''),path='/api/desktop/bootstrap/launchers/'+encodeURIComponent(id)+'/download';
  if(!id||data.downloadUrl!==path)throw Error('A 다운로드 경로를 확인하지 못했습니다.');
  const downloadName=String(data.downloadName||'');
  if(!/^[a-f0-9]{32}\.exe$/.test(downloadName))throw Error('서버가 발급한 실행 파일 이름을 확인하지 못했습니다.');
  const response=await fetch(path,{method:'GET',credentials:'same-origin',headers:{Accept:'application/octet-stream'}});
  if(response.status===401){showLogin();throw Error('로그인이 만료되었습니다.');}
  if(!response.ok){let error;try{error=await response.json();}catch(_){}throw Error(error?.message||readableApiError(error?.error||'HTTP_'+response.status));}
  const disposition=response.headers?.get('Content-Disposition');
  if(disposition!==('attachment; filename=\"'+downloadName+'\"'))throw Error('실행 파일 이름이 발급 내역과 일치하지 않습니다.');
  const blob=await response.blob();
  if(!session||session.csrf!==owner)return;
  const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=downloadName;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function showDesktopLauncherReceipt(data,owner) {
  const promise=openModal({title:'일회용 A 발급 완료',message:'아래 무작위 이름으로 저장되는 실행 파일 한 개를 전달하세요. 사용자에게는 라이선스 키 입력창만 표시됩니다.',html:`<div class="kv"><div>A 발급 ID</div><div class="code desktop-wrap">${esc(desktopDisplayId(data.launcherId))}</div><div>파일 이름</div><div class="code desktop-wrap">${esc(data.downloadName)}</div><div>미사용 실행 보안 기한</div><div>${desktopDate(data.expiresAt)}</div></div><button type="button" id="desktop-launcher-download" class="primary wide">실행 파일 다운로드</button><p id="desktop-launcher-download-status" role="status" aria-live="polite"></p>`,confirmLabel:'닫기'});
  const button=document.getElementById('desktop-launcher-download'),status=document.getElementById('desktop-launcher-download-status');
  button.onclick=async()=>{button.disabled=true;status.textContent='A 실행 파일을 준비하고 있습니다.';try{await downloadDesktopLauncher(data,owner);if(session?.csrf===owner){status.textContent='다운로드를 시작했습니다. 발급한 이름 그대로 실행할 PC에 전달하세요.';button.textContent='다시 다운로드';}}catch(error){status.textContent=error.message||'다운로드하지 못했습니다. 다시 시도해주세요.';}finally{button.disabled=false;}};
  try{await promise;}finally{if(document.getElementById('desktop-launcher-download')===button)modalBody.replaceChildren();}
}
async function createDesktopLauncher() {
  if(!roleIsAdmin()||!session)throw Error('관리자만 A를 발급할 수 있습니다.');
  if(desktopPendingLauncher&&desktopPendingLauncher.owner!==session.csrf)desktopPendingLauncher=null;
  if(desktopPendingLauncher){
    const confirm=await openModal({title:'이전 A 발급 결과 확인',message:'응답을 받지 못한 요청을 동일한 발급 ID로 다시 확인합니다.',confirmLabel:'결과 다시 확인'});if(!confirm)return;
  } else {
    const values=await openModal({title:'일회용 A 발급',message:'현재 게시된 A 템플릿으로 고객용 실행 파일을 발급합니다. A 실행 시 서버에서 B를 받아 연결합니다.',fields:[{name:'label',label:'발급 이름 (선택, 최대 120자)',value:''}],confirmLabel:'A 발급'});if(!values)return;
    const label=String(values.label||'').trim();if(label.length>120)throw Error('발급 이름은 120자 이하로 입력해주세요.');
    desktopPendingLauncher={owner:session.csrf,body:{requestId:crypto.randomUUID(),label}};
  }
  const pending=desktopPendingLauncher;if(!pending||session?.csrf!==pending.owner)return;
  let data;try{data=await api('/api/desktop/bootstrap/launchers',{method:'POST',body:pending.body});}catch(error){if(error.status&&error.status<500)desktopPendingLauncher=null;throw error;}
  desktopPendingLauncher=null;if(session?.csrf!==pending.owner)return;
  await showDesktopLauncherReceipt(data,pending.owner);await renderCurrent();
}
async function handleDesktopLicenseAction(event) {
  const target=event.target.closest('button');if(!target)return false;
  if(target.dataset.desktopTab){desktopSelectTab(target.dataset.desktopTab);return true;}
  if(target.dataset.desktopStatus){desktopLicenseStatus=target.dataset.desktopStatus;desktopLicensePage=0;await renderCurrent();return true;}
  if(target.dataset.desktopPage){desktopLicensePage+=Number(target.dataset.desktopPage);await renderCurrent();return true;}
  if(target.id==='desktop-license-clear'){desktopLicenseQuery='';desktopLicenseStatus='ALL';desktopLicensePage=0;document.getElementById('desktop-license-search').value='';document.getElementById('desktop-license-filter').value='ALL';await renderCurrent();return true;}
  const action=target.id==='desktop-integrity-policy-edit'?'integrity-policy':target.id==='desktop-module-baseline-add'?'baseline-upload':target.dataset.desktopMachine?'machine-unblock':target.id==='desktop-license-create'?'create':target.id==='desktop-launcher-create'?'launcher-create':target.dataset.desktopAction;
  if(!action)return false;if(!roleIsAdmin())throw Error('관리자만 사용할 수 있습니다.');
  if(desktopLicenseActionPending)return true;
  const row=action==='machine-unblock'?desktopMachineRows.get(target.dataset.desktopMachine):action==='session-revoke'?desktopBootstrapSessions.get(target.dataset.id):desktopLicenseRows.get(target.dataset.id);
  if(!['create','artifact-upload','launcher-create','baseline-upload','integrity-policy'].includes(action)&&!row)throw Error('목록을 새로고침한 후 다시 선택해주세요.');
  desktopLicenseActionPending=true;target.disabled=true;
  try{
    if(action==='integrity-policy'){await showDesktopIntegrityPolicy();return true;}
    if(action==='baseline-upload'){await showDesktopBaselineUpload();return true;}
    if(action==='machine-unblock'){await showDesktopMachineAction(row,'unblock',session.csrf);return true;}
    if(action==='artifact-upload'){await showDesktopArtifactUpload(target.dataset.component);return true;}
    if(action==='launcher-create'){await createDesktopLauncher();return true;}
    if(action==='session-revoke'){
      const values=await openModal({title:'A → B 실행 폐기',message:`${desktopDisplayId(row.flowId||row.id)}\n이 실행의 서버 인증을 종료합니다. 기록은 유지됩니다.`,fields:[{name:'reason',label:'폐기 사유 (3~300자)',type:'textarea',value:''}],danger:true,confirmLabel:'실행 폐기'});
      if(!values)return true;
      await api('/api/desktop/bootstrap/sessions/'+encodeURIComponent(row.id)+'/revoke',{method:'POST',body:{reason:desktopReason(values.reason)}});toast('실행 인증을 폐기했습니다.');await renderCurrent();return true;
    }
    if(action==='detail'){await showDesktopLicenseDetail(row.id);return true;}
    if(action==='revoke'){
      const values=await openModal({title:'라이선스 폐기',message:`${row.label||desktopDisplayId(row.id)}\n이 라이선스의 인증을 종료합니다. 사용 기록은 유지되며 되돌릴 수 없습니다.`,fields:[{name:'reason',label:'폐기 사유 (3~300자)',type:'textarea',value:''}],danger:true,confirmLabel:'폐기'});
      if(!values)return true;await api('/api/desktop/licenses/'+encodeURIComponent(row.id)+'/revoke',{method:'POST',body:{reason:desktopReason(values.reason)}});toast('라이선스를 폐기했습니다.');await renderCurrent();return true;
    }
    if(action==='create'||action==='reissue'){
      if(desktopPendingIssue && desktopPendingIssue.owner !== session.csrf) desktopPendingIssue=null;
      if(desktopPendingIssue){
        const pending=desktopPendingIssue;
        const confirm=await openModal({title:'이전 발급 결과 확인',message:'응답을 받지 못한 발급 요청이 있습니다. 중복 발급 없이 동일한 요청의 결과를 다시 확인합니다.',confirmLabel:'결과 다시 확인'});
        if(!confirm)return true;
        if(!session||session.csrf!==pending.owner)return true;
        const data=await api(pending.url,{method:'POST',body:pending.body});desktopPendingIssue=null;if(!session||session.csrf!==pending.owner)return true;await showDesktopLicenseReceipt(data);await renderCurrent();return true;
      }
      const replacement=action==='reissue';
      const values=await openModal({title:replacement?'기존 키를 폐기하고 새 키 발급':'Windows 라이선스 발급',message:replacement?'기존 라이선스는 즉시 폐기됩니다. 사용 이력을 초기화하지 않고 별개의 키를 새로 발급합니다.':'기간 선택 없이 한 번만 등록할 수 있는 Windows64 라이선스를 발급합니다. 등록 즉시 사용됨으로 처리되며 재사용할 수 없습니다.',fields:desktopIssueFields(row?.label||'',replacement),danger:replacement,confirmLabel:replacement?'교체 발급':'발급'});
      if(!values)return true;const body=desktopIssueBody(values);if(replacement)body.reason=desktopReason(values.reason);
      body.requestId=crypto.randomUUID();
      desktopPendingIssue={owner:session.csrf,url:'/api/desktop/licenses'+(replacement?'/'+encodeURIComponent(row.id)+'/reissue':''),body};
      const owner=session.csrf;
      let data;try{data=await api(desktopPendingIssue.url,{method:'POST',body});}catch(error){if(error.status && error.status<500)desktopPendingIssue=null;throw error;}
      desktopPendingIssue=null;
      if(!session||session.csrf!==owner)return true;
      await showDesktopLicenseReceipt(data);await renderCurrent();return true;
    }
    return false;
  }finally{desktopLicenseActionPending=false;if(target.isConnected)target.disabled=false;}
}
content.addEventListener('keydown',event=>{
  const tab=event.target.closest('[data-desktop-tab]');if(!tab||!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
  event.preventDefault();const next=event.key==='Home'?'licenses':event.key==='End'?'modules':desktopLicenseTab==='licenses'?'modules':'licenses';desktopSelectTab(next);document.getElementById('desktop-tab-'+next).focus({preventScroll:true});
});
content.addEventListener('submit',async event=>{
  if(event.target.id!=='desktop-license-search-form')return;event.preventDefault();
  desktopLicenseQuery=document.getElementById('desktop-license-search').value.trim();desktopLicenseStatus=document.getElementById('desktop-license-filter').value;desktopLicensePage=0;await renderCurrent();
});
content.addEventListener('change',async event=>{
  if(event.target.id!=='desktop-license-filter')return;desktopLicenseStatus=event.target.value;desktopLicensePage=0;await renderCurrent();
});
function desktopMachineListMarkup(data) {
 const rows=(data.items||[]).slice(0,100);
 return `<section id="desktop-machine-panel" class="section-card"><div class="section-head"><div><h3>PC 자동 차단 기록</h3><p class="small-note">키 사용 즉시 다음 실행이 차단됩니다. 현재 인증된 실행은 허용하며, 해제는 관리자만 가능합니다.</p></div></div><div class="table-wrap"><table><thead><tr><th>PC 지문</th><th>정책</th><th>변경 시각</th><th>관리</th></tr></thead><tbody>${rows.map(row=>`<tr data-desktop-key="machine-${esc(row.machineId)}"><td class="code desktop-wrap">${esc(row.machineId)}</td><td>${row.blocked?(row.source==='SINGLE_USE'?'1회 사용 · 새 실행 차단':'관리자 차단 기록'):'새 실행 허용'}<small class="desktop-block">${esc(row.reason||'')}</small></td><td>${desktopDate(row.changedAt)}</td><td>${row.blocked?`<button type="button" data-desktop-machine="${esc(row.machineId)}">차단 해제</button>`:'—'}</td></tr>`).join('')||'<tr><td colspan="4">아직 차단 기록이 없습니다.</td></tr>'}</tbody></table></div></section>`;
}
function desktopIntegrityPolicyMarkup(policy) {
 if(!policy)return '<div class="desktop-integrity-policy"><strong>서버 검사 정책을 확인하지 못했습니다.</strong></div>';
 const names=Array.isArray(policy.requiredModules)?policy.requiredModules:[],missing=Array.isArray(policy.missingBaselines)?policy.missingBaselines:[];
 const missingExtended=Array.isArray(policy.missingExtendedBaselines)?policy.missingExtendedBaselines:[];
 const unsupported=Array.isArray(policy.unsupportedRequiredModules)?policy.unsupportedRequiredModules:names.filter(name=>String(name).length>64);
 return `<div class="desktop-integrity-policy"><div class="desktop-integrity-policy-head"><div><strong>필수 모듈 서버 기준 검사 · ${policy.enabled?'켜짐':'꺼짐'}</strong><p class="small-note">기본값은 꺼짐입니다. 켜면 전체 모듈 목록의 측정 완료와 필수 DLL의 등록 기준 일치를 확인해야 다음 인증을 허용합니다.</p></div><button type="button" id="desktop-integrity-policy-edit">정책 설정</button></div><div class="desktop-integrity-policy-info"><span>필수 DLL <b class="code">${esc(names.join(', ')||'없음')}</b></span><span>확장 해시 필수 검증 <b>${policy.requireExtendedHashes?'켜짐':'꺼짐 · 기본값'}</b></span><span>정책 버전 ${Number(policy.revision)||0} · ${desktopDate(policy.updatedAt)}</span><span>허용 측정 간격 A ${Math.round(Number(policy.freshnessMs?.A||0)/1000)}초 / B ${Math.round(Number(policy.freshnessMs?.B||0)/1000)}초</span></div>${unsupported.length?'<p class="small-note desktop-machine-blocked">지원하지 않는 이전 필수 DLL 이름 (확장자 포함 64자 초과): '+unsupported.map(name=>esc(name)).join(', ')+'</p>':''}<p class="small-note ${missing.length?'desktop-machine-blocked':''}">${missing.length?'내보내기 테이블(EAT) 기준이 없는 필수 DLL: '+esc(missing.join(', ')):'필수 DLL 이름의 실행 코드·EAT 기준 등록 완료 · 접속 PC의 실제 파일 버전까지 일치해야 통과합니다.'}</p>${missingExtended.length?'<p class="small-note">XXH64 / BLAKE3 기준 보완 필요: '+esc(missingExtended.join(', '))+' · 같은 신뢰할 DLL 원본을 재등록하세요.</p>':''}<p class="small-note">정상 PC도 Windows 업데이트로 DLL 버전이 달라지면 거부될 수 있습니다. 사용하는 각 Windows 버전의 신뢰할 원본을 먼저 등록하세요. 파일 기준만 있는 이전 등록 DLL은 같은 원본을 다시 등록해 EAT와 XXH64 / BLAKE3 기준을 추가해야 합니다. 정책 변경 후에는 새 정책에 맞는 측정이 필요하며, 꺼도 이미 폐기된 세션은 복구되지 않습니다.</p></div>`;
}
function desktopModuleCoverage(module) {
 const names={SECTION_HASHED:'읽기 전용 실행 섹션으로 검사',NO_EXPORTS:'내보내기 없음',INVALID_EXPORT_TABLE:'내보내기 정보 오류',NOT_MEASURED:'내보내기 정보 미측정'};
 const count=value=>Number.isSafeInteger(value)&&value>=0?value.toLocaleString():'—';
 return `<small class="desktop-block">API 범위 안내: ${esc(names[module.exportCoverage]||'정보 없음')}<br>실행 섹션 ${count(module.executableSections)} · 내보내기 ${count(module.exportCount)} · 코드 내보내기 ${count(module.codeExportCount)} · 전달 내보내기 ${count(module.forwardedExportCount)}</small>`;
}
function desktopExportTableStatus(value) {
 const states={MEASURED:'측정 완료',NO_EXPORTS:'내보내기 없음',UNSUPPORTED_EXPORT_LAYOUT:'지원하지 않는 내보내기 배치',READ_ERROR:'측정 실패'};
 return states[value]||'측정 정보 없음';
}
function desktopExtendedHashMarkup(title,expectedXxh64,observedXxh64,expectedBlake3,observedBlake3,verified) {
 const measured=!!observedXxh64&&!!observedBlake3,registered=!!expectedXxh64&&!!expectedBlake3;
 const mismatch=measured&&registered&&(String(expectedXxh64).toLowerCase()!==String(observedXxh64).toLowerCase()||String(expectedBlake3).toLowerCase()!==String(observedBlake3).toLowerCase());
 const status=!measured?'미측정 · 검증 안 됨':!registered?'서버 기준 미등록 · 검증 안 됨':mismatch?'서버 기준 불일치':verified===true?'서버 확장 해시 기준 일치':'서버 검증 안 됨';
 return `<div class="desktop-extended-hashes"><strong class="${mismatch?'desktop-machine-blocked':''}">${esc(title)} · ${status}</strong><span class="code desktop-wrap">XXH64 기준: ${esc(expectedXxh64||'미등록')}<br>XXH64 측정: ${esc(observedXxh64||'미측정')}<br>BLAKE3 기준: ${esc(expectedBlake3||'미등록')}<br>BLAKE3 측정: ${esc(observedBlake3||'미측정')}</span></div>`;
}
function desktopExportTableMarkup(module) {
 const comparable=!!module.expectedExportTableSha256&&!!module.expectedExportTableCrc64;
 const mismatch=comparable&&module.exportTableStatus!==undefined&&(module.exportTableStatus!=='MEASURED'||module.exportTableSha256!==module.expectedExportTableSha256||module.exportTableCrc64!==module.expectedExportTableCrc64);
 const result=module.exportTableVerified?'서버 EAT 기준 일치':mismatch?'서버 EAT 기준 불일치':comparable?'서버 EAT 확인 안 됨':'서버 EAT 기준 없음 · 검증 안 됨';
 return `<div class="desktop-export-table"><strong class="${mismatch?'desktop-machine-blocked':''}">내보내기 테이블(EAT) · ${esc(result)}</strong><small class="desktop-block">${esc(desktopExportTableStatus(module.exportTableStatus))}</small><span class="code desktop-wrap">측정 SHA-256: ${esc(module.exportTableSha256||'없음')}<br>측정 CRC64: ${esc(module.exportTableCrc64||'없음')}<br>서버 SHA-256: ${esc(module.expectedExportTableSha256||'미등록')}<br>서버 CRC64: ${esc(module.expectedExportTableCrc64||'미등록')}</span>${desktopExtendedHashMarkup('EAT 확장 해시',module.expectedExportTableXxh64,module.exportTableXxh64,module.expectedExportTableBlake3,module.exportTableBlake3,module.exportTableExtendedVerified)}</div>`;
}
function desktopSnapshotMarkup(row,policy) {
 if(!row.snapshotId)return '';
 const states={RECEIVING:'묶음 수신 중',COMPLETE_PASS:'전체 묶음 수신 완료',COMPLETE_REJECTED:'전체 묶음 수신 · 거부',INCOMPLETE:'불완전한 측정',TIMED_OUT:'측정 수신 시간 초과'};
 const reasons={REQUIRED_MODULE_MISSING:'필수 모듈 누락',REQUIRED_MODULE_UNVERIFIED:'필수 모듈 기준 미등록 또는 버전 불일치',REQUIRED_MODULE_READ_FAILED:'필수 모듈 측정 실패',REQUIRED_MODULE_CODE_MISMATCH:'필수 모듈 코드·내보내기 테이블 불일치',INCOMPLETE_SNAPSHOT:'일부 모듈 측정 생략',INVALID_SNAPSHOT_COUNTS:'측정 개수 불일치',POLICY_CHANGED:'이후 서버 정책 변경',BASELINE_MATCH:'등록 기준 일치'};
 const state=states[row.snapshotStatus]||'서버 완료 판정 없음';
 const received=Number.isSafeInteger(row.snapshotReceivedBatches)?row.snapshotReceivedBatches:'—';
 const batch=Number.isInteger(row.batchIndex)&&Number.isInteger(row.batchCount)?`${row.batchIndex+1}/${row.batchCount}`:'최종 집계';
 const count=value=>Number.isSafeInteger(value)&&value>=0?value:'—';
 const final=policy?.enabled&&Number(row.strictPolicyRevision)!==Number(policy.revision)?' · 현재 정책으로 재측정 필요':'';
 return `<div class="desktop-snapshot-status"><strong>${esc(state)}${row.snapshotStatus==='COMPLETE_PASS'&&row.status==='VERIFIED'?' · 당시 필수 기준 일치':''}${final}</strong><p class="small-note">스냅샷 ${esc(row.snapshotId)} · 이 기록 ${batch} · 서버 수신 ${received}개 · 정책 ${Number(row.strictPolicyRevision)||0}</p><p class="small-note">측정 집계: ${row.complete?'측정 완료':'일부 측정'}${row.truncated?' · 한도 초과로 생략 있음':''} · 총 ${count(row.totalModules)}개 / 측정 ${count(row.measuredModules)}개</p>${Array.isArray(row.snapshotReasons)&&row.snapshotReasons.length?'<p class="small-note">'+row.snapshotReasons.map(reason=>esc(reasons[reason]||reason)).join(' · ')+'</p>':''}${Array.isArray(row.requiredModuleResults)?'<ul class="desktop-required-module-results">'+row.requiredModuleResults.map(result=>'<li><span class="code">'+esc(result.name)+'</span> · '+esc(reasons[result.reason]||result.reason)+'</li>').join('')+'</ul>':''}</div>`;
}
function desktopIntegrityMarkup(data,baselineData,policy) {
 const labels={VERIFIED:'등록 기준 일치',REJECTED:'불일치 · 거부',CLIENT_DIAGNOSTIC:'클라이언트 진단',MATCH_REGISTERED_BASELINE:'등록 기준 일치',REGISTERED_BASELINE_MISMATCH:'등록 기준 불일치',UNVERIFIED_BASELINE:'미등록 기준 · 검증 안 됨',LOCAL_DIFFERENCE:'로컬 파일과 차이',READ_ERROR:'측정 실패',SKIPPED_LIMIT:'측정 한도',NAME_TOO_LONG:'모듈 이름 64자 초과 · 측정 미지원',FILE_UNAVAILABLE:'파일 없음',MATCH_LOCAL_FILE:'로컬 파일 일치',INTEGRITY_SNAPSHOT_REQUIRED:'필수 모듈 측정 필요',INTEGRITY_SNAPSHOT_STALE:'모듈 측정 유효 시간 초과',INTEGRITY_SNAPSHOT_POLICY_CHANGED:'서버 정책 변경 · 재측정 필요',KNOWN_MODULE_CODE_MISMATCH:'등록 모듈 코드·내보내기 테이블 불일치'};
 const label=value=>esc(labels[value]||value||'—'),digest=(title,expected,observed)=>expected||observed?`<div>${title}</div><div class="code desktop-wrap">기준: ${esc(expected||'미등록')}<br>측정: ${esc(observed||'없음')}</div>`:'';
 const rows=data.items||[],baselines=baselineData.items||[];
 return `<section id="desktop-integrity-panel" class="section-card"><div class="section-head"><div><h3>모듈 기준 · 서버 검사 정책 · A / B 무결성 기록</h3><p class="small-note">서버 등록 파일과 읽기 전용 실행 코드의 측정값을 비교합니다. 클라이언트가 보낸 측정값이며 하드웨어 인증은 아닙니다. 쓰기 가능한 데이터와 모든 메모리를 검사하는 기능은 아닙니다.</p></div><button type="button" id="desktop-module-baseline-add">모듈 기준 등록</button></div>${desktopIntegrityPolicyMarkup(policy)}<p class="small-note">Windows API 코드는 해당 DLL의 읽기 전용 실행 섹션 안에서 함께 검사됩니다. Kernel32.ReadFile처럼 다른 DLL로 전달되는 API는 실제 코드가 있는 KernelBase 등의 기준도 필요합니다. 서버 기준이 있는 DLL은 내보내기 테이블(EAT)의 측정값도 비교합니다. 아래 내보내기 개수는 범위 안내이며, 실행 코드·EAT 검사는 개별 API의 동작이나 전체 호출 경로를 인증한 결과는 아닙니다.</p><p class="small-note">시스템 모듈은 신뢰할 수 있는 동일 Windows 버전의 DLL을 관리자가 등록한 경우에만 서버 기준과 비교합니다. 미등록 DLL은 정상 판정하지 않습니다. 등록 기준 ${baselines.length}개 · 최근 기록 ${rows.length}개</p><div class="desktop-integrity-list">${rows.map(row=>`<details data-desktop-key="report-${esc(row.id||[row.at,row.stage,row.check,row.snapshotId,row.batchIndex].join(':'))}" class="desktop-integrity-record ${row.status==='REJECTED'?'desktop-integrity-rejected':''}"><summary><strong>${esc(row.stage)} · ${label(row.status)}</strong><span>${esc(row.check)} · ${desktopDate(row.at)}</span></summary><div class="kv"><div>범위 · 사유</div><div>${esc(row.check)} · ${label(row.reason)}</div><div>세션</div><div class="code desktop-wrap">${esc(desktopDisplayId(row.sessionId)||'A 시작 전')}</div><div>PC 지문</div><div class="code desktop-wrap">${esc(row.machineId||'확인 전')}</div>${digest('SHA-256',row.expectedSha256,row.observedSha256)}${digest('CRC64',row.expectedCrc64,row.observedCrc64)}</div>${row.check==='OWN_CODE'?desktopExtendedHashMarkup('파일 확장 해시',row.expectedFileXxh64,row.observedFileXxh64,row.expectedFileBlake3,row.observedFileBlake3,row.extendedHashesVerified)+desktopExtendedHashMarkup('코드 확장 해시',row.expectedXxh64,row.observedXxh64,row.expectedBlake3,row.observedBlake3,row.extendedHashesVerified):''}${desktopSnapshotMarkup(row,policy)}${row.modules?`<div class="table-wrap"><table><thead><tr><th>모듈 · 실행 코드 범위</th><th>서버 비교 / 클라이언트 상태</th><th>파일 · 코드 측정값</th></tr></thead><tbody>${row.modules.map((m,moduleIndex)=>`<tr data-desktop-key="module-${esc(m.name)}-${esc(m.fileSha256)}-${moduleIndex}"><td>${esc(m.name)}${desktopModuleCoverage(m)}</td><td>${label(m.serverComparison)}<small class="desktop-block">${label(m.status)} / ${label(m.codeStatus)}</small></td><td class="code desktop-wrap">파일 SHA-256: ${esc(m.fileSha256||'없음')}<br>파일 CRC64: ${esc(m.fileCrc64||'없음')}<br>코드 SHA-256: ${esc(m.codeSha256||'없음')}<br>코드 CRC64: ${esc(m.codeCrc64||'없음')}${m.expectedCodeSha256?`<br>서버 코드 기준: ${esc(m.expectedCodeSha256)}<br>서버 CRC64 기준: ${esc(m.expectedCodeCrc64)}`:''}${desktopExtendedHashMarkup('파일 확장 해시',m.expectedFileXxh64,m.fileXxh64,m.expectedFileBlake3,m.fileBlake3,m.fileExtendedVerified)}${desktopExtendedHashMarkup('코드 확장 해시',m.expectedCodeXxh64,m.codeXxh64,m.expectedCodeBlake3,m.codeBlake3,m.codeExtendedVerified)}${desktopExportTableMarkup(m)}</td></tr>`).join('')}</tbody></table></div>`:''}</details>`).join('')||'<div class="desktop-empty">검사 기록이 없습니다. 기록 없음은 검사 성공을 의미하지 않습니다. 새 A / B로 실행한 뒤 확인하세요.</div>'}</div>${baselines.length?`<details id="desktop-module-baselines"><summary>등록한 모듈 기준 ${baselines.length}개</summary><div class="table-wrap"><table><thead><tr><th>파일 · 버전 메모</th><th>서버 파일 기준</th><th>내보내기 테이블(EAT) 기준</th><th>등록</th></tr></thead><tbody>${baselines.map(b=>`<tr data-desktop-key="baseline-${esc(b.name)}-${esc(b.fileSha256)}"><td>${esc(b.name)}${String(b.name||'').length>64?'<small class="desktop-machine-blocked desktop-block">이전 등록 · 64자 초과 이름은 현재 클라이언트에서 지원하지 않음</small>':''}<small class="desktop-block">${esc(b.label)}</small></td><td class="code desktop-wrap">SHA-256: ${esc(b.fileSha256)}<br>CRC64: ${esc(b.fileCrc64)}<br>XXH64: ${esc(b.fileXxh64||'미등록 · 원본 재등록 필요')}<br>BLAKE3: ${esc(b.fileBlake3||'미등록 · 원본 재등록 필요')}<br>코드 XXH64: ${esc(b.codeXxh64||'미등록')}<br>코드 BLAKE3: ${esc(b.codeBlake3||'미등록')}</td><td><strong>${esc(b.exportTableStatus==='MEASURED'?'EAT 기준 등록됨':b.exportTableStatus?'EAT 기준 사용 불가':'EAT 기준 미등록 · 원본 재등록 필요')}</strong><small class="desktop-block">${esc(desktopExportTableStatus(b.exportTableStatus))}</small><span class="code desktop-wrap">${esc(b.exportTableSha256||'—')}<br>${esc(b.exportTableCrc64||'—')}<br>XXH64: ${esc(b.exportTableXxh64||'미등록')}<br>BLAKE3: ${esc(b.exportTableBlake3||'미등록')}</span></td><td>${desktopDate(b.createdAt)}</td></tr>`).join('')}</tbody></table></div></details>`:''}</section>`;
}
async function showDesktopIntegrityPolicy() {
 if(!roleIsAdmin()||!session)throw Error('관리자만 서버 검사 정책을 변경할 수 있습니다.');
 const owner=session.csrf,data=await api('/api/desktop/bootstrap/integrity-policy');
 if(!roleIsAdmin()||session?.csrf!==owner||currentView!=='desktop-licenses')return;
 const policy=data.policy;if(!policy||!Array.isArray(policy.requiredModules))throw Error('서버 검사 정책을 확인하지 못했습니다.');
 const promise=openModal({title:'필수 모듈 서버 검사 정책',message:'강제 검증을 켜면 미등록 Windows DLL 버전, 누락된 측정, 오래된 측정으로 실행이 거부될 수 있습니다. 대상 PC의 신뢰할 DLL 원본을 먼저 등록한 뒤 적용하세요. 예전에 파일 기준만 등록했다면 같은 원본을 다시 등록해 내보내기 테이블(EAT) 기준을 추가해야 합니다. 클라이언트 자체가 변조된 경우까지 보장하는 원격 하드웨어 인증은 아닙니다.',html:`<label class="desktop-extended-option"><input id="desktop-policy-extended-hashes" type="checkbox" ${policy.requireExtendedHashes?'checked':''}> XXH64 / BLAKE3 확장 해시 필수 검증 (기본값 꺼짐)</label><p class="small-note">켜면 파일·코드·EAT의 확장 해시 기준과 새 측정값이 모두 필요합니다. SHA-256 / CRC64 검사도 유지됩니다. 이전 DLL은 같은 원본을 재등록해 확장 기준을 보완하세요.</p><p id="desktop-integrity-policy-status" role="status" aria-live="polite"></p>`,fields:[{name:'enabled',label:'필수 모듈 강제 검증',type:'select',value:String(policy.enabled),options:[{value:'false',label:'꺼짐 · 등록 기준 비교 기록 유지'},{value:'true',label:'켜짐 · 필수 모듈 검증 후 인증 허용'}]},{name:'requiredModules',label:'필수 DLL 이름 (쉼표 또는 줄바꿈으로 구분, 1~16개, 확장자 포함 64자 이하)',type:'textarea',value:policy.requiredModules.join(', ')}],danger:true,confirmLabel:'위 조건을 확인하고 정책 적용'});
 const extended=document.getElementById('desktop-policy-extended-hashes'),mode=modalBody.querySelector('[data-modal-field="enabled"]'),names=modalBody.querySelector('[data-modal-field="requiredModules"]'),status=document.getElementById('desktop-integrity-policy-status'),finish=modalConfirm.onclick;
 let busy=false,saved=false;
 modalConfirm.onclick=async()=>{
  if(busy||!roleIsAdmin()||session?.csrf!==owner||!names.isConnected)return;
  try{
   const requiredModules=[...new Set(names.value.split(/[,\r\n]+/).map(name=>name.trim().toLowerCase()).filter(Boolean))];
   if(requiredModules.length<1||requiredModules.length>16||requiredModules.some(name=>name.length>64||!/^[-a-z0-9_.]{1,60}\.dll$/.test(name)))throw Error('경로를 제외하고 확장자를 포함해 64자 이하인 DLL 이름을 1~16개 입력하세요.');
   if(!['true','false'].includes(mode.value))throw Error('검사 정책 상태를 선택하세요.');
   busy=true;modalConfirm.disabled=true;mode.disabled=true;names.disabled=true;extended.disabled=true;status.textContent='서버 기준을 확인하고 정책을 적용하고 있습니다.';
   await api('/api/desktop/bootstrap/integrity-policy',{method:'POST',body:{enabled:mode.value==='true',requireExtendedHashes:extended.checked,requiredModules}});saved=true;
   if(roleIsAdmin()&&session?.csrf===owner&&names.isConnected){toast('서버 검사 정책을 적용했습니다.');finish();}
  }catch(error){if(names.isConnected)status.textContent=error.code==='INTEGRITY_POLICY_BASELINE_MISSING'?'필수 DLL의 실행 코드·EAT 또는 필수 확장 해시 서버 기준이 없습니다. 모듈 기준을 먼저 등록하세요. 이전에 등록한 DLL도 같은 신뢰할 원본을 다시 등록해야 할 수 있습니다.':error.message||'정책을 적용하지 못했습니다.';}
  finally{busy=false;if(names.isConnected){modalConfirm.disabled=false;mode.disabled=false;names.disabled=false;extended.disabled=false;}}
 };
 try{await promise;}finally{if(document.getElementById('desktop-integrity-policy-status')===status)modalBody.replaceChildren();}
 if(saved&&roleIsAdmin()&&session?.csrf===owner&&currentView==='desktop-licenses')await renderCurrent();
}
async function showDesktopBaselineUpload() {
 if(!roleIsAdmin()||!session)throw Error('관리자만 모듈 기준을 등록할 수 있습니다.');const owner=session.csrf;
 const promise=openModal({title:'신뢰할 수 있는 모듈 기준 등록',message:'해당 Windows 버전의 정상 DLL을 선택하세요. 서버가 파일·실행 코드·내보내기 테이블(EAT) 해시를 계산하며 DLL 원본은 저장하지 않습니다. 같은 DLL 원본을 다시 올리면 기존 등록에 없던 EAT와 XXH64 / BLAKE3 기준을 보완합니다. SHA-256 / CRC64 기준도 유지됩니다. 서로 다른 파일 버전은 별도 기준으로 등록됩니다.',html:'<label>Windows 64비트 DLL<input id="desktop-baseline-file" type="file" accept=".dll"></label><p class="small-note">최대 32MB · 파일 이름은 확장자 포함 64자 이하 · 경로와 메모리 원문은 수집하지 않습니다.</p><p id="desktop-baseline-status" role="status"></p>',fields:[{name:'label',label:'Windows 버전 · 설명 (선택)',value:''}],confirmLabel:'기준 등록'});
 const input=document.getElementById('desktop-baseline-file'),status=document.getElementById('desktop-baseline-status'),note=modalBody.querySelector('[data-modal-field="label"]'),finish=modalConfirm.onclick;let busy=false,uploaded=false;
 modalConfirm.onclick=async()=>{if(busy||session?.csrf!==owner)return;try{const file=input.files?.[0];if(!file||!file.size||file.size>33554432||!/\.dll$/i.test(file.name))throw Error('32MB 이하의 비어 있지 않은 DLL을 선택하세요.');if(file.name.length>64)throw Error('DLL 파일 이름은 확장자를 포함해 64자 이하여야 합니다.');if(note.value.length>120)throw Error('설명은 120자 이하여야 합니다.');busy=true;modalConfirm.disabled=true;input.disabled=true;status.textContent='서버에서 모듈 기준을 계산하고 있습니다.';await api('/api/desktop/bootstrap/module-baselines?'+new URLSearchParams({fileName:file.name,label:note.value}),{method:'POST',rawBody:file});uploaded=true;if(session?.csrf===owner&&input.isConnected){toast('모듈 기준을 등록했습니다. 다음 측정부터 비교합니다.');finish();}}catch(error){if(input.isConnected)status.textContent=error.message||'등록하지 못했습니다.';}finally{busy=false;if(input.isConnected){modalConfirm.disabled=false;input.disabled=false;}}};
 try{await promise;}finally{if(document.getElementById('desktop-baseline-file')===input)modalBody.replaceChildren();}if(uploaded&&session?.csrf===owner)await renderCurrent();
}
