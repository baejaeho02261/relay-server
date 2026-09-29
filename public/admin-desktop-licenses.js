'use strict';
// License keys are issuance receipts only: never cached in browser storage or
// included in the list/detail projections. Consumed keys cannot be reset.
let desktopLicenseQuery = '';
let desktopLicenseStatus = 'ALL';
let desktopLicensePage = 0;
let desktopLicenseRows = new Map();
let desktopLicenseActionPending = false;
let desktopPendingIssue = null;
const desktopStatusLabels = {AVAILABLE:'사용 전',ACTIVE:'사용 중',RELEASED:'사용 종료',REVOKED:'폐기됨',EXPIRED:'만료됨'};
function desktopStatus(status) {
  return `<span class="desktop-status desktop-status-${esc(String(status).toLowerCase())}"><i aria-hidden="true"></i>${esc(desktopStatusLabels[status] || status)}</span>`;
}
function desktopDate(value) { return value ? esc(fmtTime(value)) : '—'; }
function desktopLicenseDevice(row) {
  const device = String(row.deviceName || '').trim();
  const id = String(row.deviceId || '').trim();
  return device || id ? `<strong>${esc(device || '등록된 PC')}</strong><span class="code muted" title="${esc(id)}">${esc(id ? id.slice(0,18)+(id.length>18?'…':'') : '—')}</span>` : '<span class="muted">아직 연결되지 않음</span>';
}
async function renderDesktopLicenses() {
  if (!roleIsAdmin()) { content.innerHTML='<div class="empty">관리자만 라이선스를 관리할 수 있습니다.</div>'; return; }
  const query = new URLSearchParams({q:desktopLicenseQuery});
  if (desktopLicenseStatus !== 'ALL') query.set('status', desktopLicenseStatus);
  const data = await api('/api/desktop/licenses?'+query);
  if (currentView !== 'desktop-licenses') return;
  const rows = Array.isArray(data.items) ? data.items : [];
  desktopLicenseRows = new Map(rows.map(row=>[String(row.id),row]));
  const pageSize=25,pages=Math.max(1,Math.ceil(rows.length/pageSize));
  desktopLicensePage=Math.min(Math.max(0,desktopLicensePage),pages-1);
  const page=rows.slice(desktopLicensePage*pageSize,(desktopLicensePage+1)*pageSize);
  const counts=Object.fromEntries(Object.keys(desktopStatusLabels).map(status=>[status,rows.filter(row=>row.status===status).length]));
  content.innerHTML=`<div class="desktop-workspace">
    <section class="desktop-hero"><div class="desktop-platform" aria-hidden="true"><svg viewBox="0 0 40 40"><path d="M4 8h32v21H4zM13 35h14M20 29v6M9 13h8v5H9zM21 13h10v5H21zM9 21h8v4H9zM21 21h10v4H21z"/></svg></div><div><span class="desktop-eyebrow">WINDOWS 64-BIT</span><h3>하나의 키, 하나의 PC</h3><p>최초 활성화에 한 번 사용되는 라이선스입니다. 활성화한 PC의 인증 상태를 여기서 관리하세요.</p></div><button type="button" id="desktop-license-create" class="primary">+ 라이선스 발급</button></section>
    <div class="desktop-stats">${[['AVAILABLE','사용 전'],['ACTIVE','사용 중'],['RELEASED','사용 종료'],['REVOKED','폐기됨'],['EXPIRED','만료됨']].map(([status,label])=>`<button type="button" class="desktop-stat${desktopLicenseStatus===status?' selected':''}" data-desktop-status="${status}"><span>${label}</span><strong>${counts[status].toLocaleString()}</strong></button>`).join('')}</div>
    <section class="section-card desktop-license-list"><div class="section-head"><div><h3>Windows 라이선스</h3><p class="small-note">${rows.length.toLocaleString()}개${desktopLicenseQuery||desktopLicenseStatus!=='ALL'?' · 검색 결과 기준':''}</p></div><span class="small-note">자동 갱신 · ${desktopDate(data.serverTime)}</span></div>
    <form id="desktop-license-search-form" class="desktop-license-toolbar"><label class="desktop-search"><span class="sr-only">라이선스 검색</span><input id="desktop-license-search" type="search" maxlength="120" autocomplete="off" placeholder="라이선스 ID, 이름, PC 검색" value="${esc(desktopLicenseQuery)}"></label><label><span class="sr-only">상태</span><select id="desktop-license-filter"><option value="ALL">전체 상태</option>${Object.entries(desktopStatusLabels).map(([value,label])=>`<option value="${value}" ${value===desktopLicenseStatus?'selected':''}>${label}</option>`).join('')}</select></label><button type="submit">검색</button>${desktopLicenseQuery||desktopLicenseStatus!=='ALL'?'<button type="button" id="desktop-license-clear" class="ghost">초기화</button>':''}</form>
    <div class="table-wrap"><table class="desktop-license-table"><thead><tr><th>라이선스</th><th>상태</th><th>연결된 PC</th><th>활성화 · 만료</th><th>최근 인증</th><th>관리</th></tr></thead><tbody>${page.map(row=>`<tr><td><div class="desktop-cell"><strong>${esc(row.label||'이름 없는 라이선스')}</strong><span class="code muted">${esc(row.id)}</span><small>${row.consumed?'최초 사용 완료 · 재사용 불가':'최초 사용 대기'} · ${desktopDate(row.issuedAt)}</small></div></td><td>${desktopStatus(row.status)}</td><td><div class="desktop-cell">${desktopLicenseDevice(row)}${row.appVersion?`<small>v${esc(row.appVersion)}</small>`:''}</div></td><td><div class="desktop-cell"><span>${desktopDate(row.activatedAt)}</span><small>${row.expiresAt?'만료 '+desktopDate(row.expiresAt):'만료일 없음'}</small></div></td><td>${desktopDate(row.lastVerifiedAt)}</td><td><div class="actions"><button type="button" data-desktop-action="detail" data-id="${esc(row.id)}">상세</button>${row.status!=='REVOKED'?`<button type="button" class="danger" data-desktop-action="revoke" data-id="${esc(row.id)}">폐기</button>`:''}<button type="button" data-desktop-action="reissue" data-id="${esc(row.id)}">새 키 발급</button></div></td></tr>`).join('')||'<tr><td colspan="6"><div class="desktop-empty"><span aria-hidden="true">◇</span><strong>라이선스가 없습니다.</strong><p>검색 조건을 바꾸거나 새 라이선스를 발급하세요.</p></div></td></tr>'}</tbody></table></div>
    <div class="desktop-pagination"><span>${rows.length?desktopLicensePage*pageSize+1:0}–${Math.min(rows.length,(desktopLicensePage+1)*pageSize)} / ${rows.length}</span><div class="actions"><button type="button" data-desktop-page="-1" ${desktopLicensePage===0?'disabled':''}>이전</button><span>${desktopLicensePage+1} / ${pages}</span><button type="button" data-desktop-page="1" ${desktopLicensePage+1>=pages?'disabled':''}>다음</button></div></div></section>
  </div>`;
}
function desktopIssueFields(label='',replacement=false) {
  return [{name:'label',label:'라이선스 이름 (선택, 최대 120자)',value:label},
    {name:'term',label:'유효 기간',type:'select',value:'unlimited',options:[{value:'7',label:'7일'},{value:'30',label:'30일'},{value:'90',label:'90일'},{value:'365',label:'365일'},{value:'custom',label:'직접 입력'},{value:'unlimited',label:'만료일 없음'}]},
    {name:'days',label:'직접 입력 시 일수 (1~3,650일)',type:'number',value:'30'},
    ...(replacement?[{name:'reason',label:'교체 사유 (3~300자)',type:'textarea',value:''}]:[])];
}
function desktopIssueBody(values) {
  const label=String(values.label||'').trim();if(label.length>120)throw Error('라이선스 이름은 120자 이하로 입력해주세요.');
  if(values.term==='unlimited')return {label,expiresAt:0};
  const validDays=Number(values.term==='custom'?values.days:values.term);
  if(!Number.isSafeInteger(validDays)||validDays<1||validDays>3650)throw Error('유효 기간은 1~3,650일로 입력해주세요.');
  return {label,validDays};
}
function desktopReason(value) {
  const reason=String(value||'').trim();if(reason.length<3||reason.length>300)throw Error('처리 사유를 3~300자로 입력해주세요.');return reason;
}
async function showDesktopLicenseReceipt(data) {
  if(typeof data.licenseKey!=='string'||!data.licenseKey)throw Error('발급 응답에 라이선스 키가 없습니다. 관리자 기록을 확인해주세요.');
  const id=String(data.license?.id||'license');
  const promise=openModal({title:'라이선스 발급 완료',message:'이 키는 지금 한 번만 표시됩니다. 복사하거나 파일로 저장한 뒤 대상 PC에서 입력하세요.',html:`<div class="desktop-key-receipt"><label for="desktop-issued-key">새 라이선스 키</label><textarea id="desktop-issued-key" class="code" readonly spellcheck="false" autocomplete="off">${esc(data.licenseKey)}</textarea><div class="actions"><button type="button" id="desktop-key-copy">키 복사</button><button type="button" id="desktop-key-download">텍스트 저장</button></div><p class="small-note">최초 사용 후 다른 PC나 새 설치에 재사용할 수 없습니다. 키가 필요한 경우 기존 키를 폐기하고 새 키를 발급하세요.</p></div>`,confirmLabel:'저장했어요'});
  const input=document.getElementById('desktop-issued-key');
  const copy=document.getElementById('desktop-key-copy'),download=document.getElementById('desktop-key-download');
  copy.addEventListener('click',async()=>{try{if(navigator.clipboard?.writeText)await navigator.clipboard.writeText(input.value);else{input.focus();input.select();if(!document.execCommand('copy'))throw Error('복사할 키를 직접 선택해주세요.');}toast('라이선스 키를 복사했습니다.');}catch(error){toast(error.message||'복사하지 못했습니다.',true);}});
  download.addEventListener('click',()=>{const blob=new Blob([`MoaPlay Windows64\n라이선스 ID: ${id}\n${input.value}\n`],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='MoaPlay-License-'+id.replace(/[^a-zA-Z0-9_-]/g,'')+'.txt';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  try{await promise;}finally{input.value='';modalBody.replaceChildren();}
}
async function handleDesktopLicenseAction(event) {
  const target=event.target.closest('button');if(!target)return false;
  if(target.dataset.desktopStatus){desktopLicenseStatus=target.dataset.desktopStatus;desktopLicensePage=0;await renderCurrent();return true;}
  if(target.dataset.desktopPage){desktopLicensePage+=Number(target.dataset.desktopPage);await renderCurrent();return true;}
  if(target.id==='desktop-license-clear'){desktopLicenseQuery='';desktopLicenseStatus='ALL';desktopLicensePage=0;await renderCurrent();return true;}
  const action=target.id==='desktop-license-create'?'create':target.dataset.desktopAction;
  if(!action)return false;if(!roleIsAdmin())throw Error('관리자만 사용할 수 있습니다.');
  if(desktopLicenseActionPending)return true;
  const row=desktopLicenseRows.get(target.dataset.id);
  if(action!=='create'&&!row)throw Error('목록을 새로고침한 후 다시 선택해주세요.');
  desktopLicenseActionPending=true;target.disabled=true;
  try{
    if(action==='detail'){
      await openModal({title:row.label||'라이선스 상세',html:`<div class="kv"><div>라이선스 ID</div><div class="code">${esc(row.id)}</div><div>상태</div><div>${desktopStatus(row.status)}</div><div>발급</div><div>${desktopDate(row.issuedAt)}</div><div>최초 활성화</div><div>${desktopDate(row.activatedAt)}</div><div>만료</div><div>${row.expiresAt?desktopDate(row.expiresAt):'만료일 없음'}</div><div>최초 사용</div><div>${row.consumed?'완료 · 다시 사용 불가':'대기 중'}</div><div>PC</div><div>${esc(row.deviceName||'—')}</div><div>기기 식별자</div><div class="code desktop-wrap">${esc(row.deviceId||'—')}</div><div>버전</div><div>${esc(row.appVersion||'—')}</div><div>최근 인증</div><div>${desktopDate(row.lastVerifiedAt)}</div><div>인증 유효 시각</div><div>${desktopDate(row.leaseExpiresAt)}</div><div>폐기</div><div>${desktopDate(row.revokedAt)}</div><div>사유</div><div class="desktop-wrap">${esc(row.reason||'—')}</div></div>`,confirmLabel:'닫기'});return true;
    }
    if(action==='revoke'){
      const values=await openModal({title:'라이선스 폐기',message:`${row.label||row.id}\n이 라이선스의 인증을 종료합니다. 사용 기록은 유지되며 되돌릴 수 없습니다.`,fields:[{name:'reason',label:'폐기 사유 (3~300자)',type:'textarea',value:''}],danger:true,confirmLabel:'폐기'});
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
      const values=await openModal({title:replacement?'기존 키를 폐기하고 새 키 발급':'Windows 라이선스 발급',message:replacement?'기존 라이선스는 즉시 폐기됩니다. 사용 이력을 초기화하지 않고 별개의 키를 새로 발급합니다.':'한 번 활성화할 수 있는 Windows64 라이선스를 발급합니다.',fields:desktopIssueFields(row?.label||'',replacement),danger:replacement,confirmLabel:replacement?'교체 발급':'발급'});
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
content.addEventListener('submit',async event=>{
  if(event.target.id!=='desktop-license-search-form')return;event.preventDefault();
  desktopLicenseQuery=document.getElementById('desktop-license-search').value.trim();desktopLicenseStatus=document.getElementById('desktop-license-filter').value;desktopLicensePage=0;await renderCurrent();
});
content.addEventListener('change',async event=>{
  if(event.target.id!=='desktop-license-filter')return;desktopLicenseStatus=event.target.value;desktopLicensePage=0;await renderCurrent();
});
