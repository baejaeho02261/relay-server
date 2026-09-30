'use strict';
// License keys are revealed only in issuance receipts and an explicit admin
// detail request. Never cache them in lists, browser storage, or live events.
let desktopLicenseQuery = '';
let desktopLicenseStatus = 'ALL';
let desktopLicensePage = 0;
let desktopLicenseRows = new Map();
let desktopLicenseActionPending = false;
let desktopPendingIssue = null;
let desktopPendingLauncher = null;
let desktopBootstrap = null;
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
async function renderDesktopLicenses(silent = false) {
  if (!roleIsAdmin()) { content.innerHTML='<div class="empty">관리자만 라이선스를 관리할 수 있습니다.</div>'; return; }
  const query = new URLSearchParams({q:desktopLicenseQuery});
  if (desktopLicenseStatus !== 'ALL') query.set('status', desktopLicenseStatus);
  const owner = session?.csrf;
  const [data, bootstrapData] = await Promise.all([api('/api/desktop/licenses?'+query), api('/api/desktop/bootstrap')]);
  if (currentView !== 'desktop-licenses' || !session || session.csrf !== owner) return;
  if(silent&&(desktopLicenseActionPending||!modalEl.classList.contains('hidden')))return;
  desktopBootstrap = bootstrapData.bootstrap || {};
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
    <section class="desktop-hero"><div class="desktop-platform" aria-hidden="true"><svg viewBox="0 0 40 40"><path d="M4 8h32v21H4zM13 35h14M20 29v6M9 13h8v5H9zM21 13h10v5H21zM9 21h8v4H9zM21 21h10v4H21z"/></svg></div><div><span class="desktop-eyebrow">WINDOWS 64-BIT</span><h3>한 번 실행하고, 서버에서 인증</h3><p>무작위 이름으로 발급한 실행기가 프로그램을 받아 연결합니다. 사용자는 빈 입력창에 라이선스 키를 붙여넣고 Enter를 누르며, 배포와 사용 기록은 서버에서 관리합니다.</p></div><button type="button" id="desktop-license-create" class="primary">+ 라이선스 발급</button></section>
    <div class="desktop-stats" aria-label="필터와 무관한 전체 라이선스 상태">${Object.entries(desktopStatusLabels).map(([status,label])=>`<button type="button" class="desktop-stat${desktopLicenseStatus===status?' selected':''}" data-desktop-status="${status}"><span>${label}</span><strong>${countLabel(status)}</strong></button>`).join('')}</div>
    ${desktopBootstrapMarkup(desktopBootstrap)}
    <section class="section-card desktop-license-list"><div class="section-head"><div><h3>Windows 라이선스</h3><p class="small-note" id="desktop-license-result-summary">전체 ${totalLabel}개 · 현재 ${rows.length.toLocaleString()}개${filtered?` · 필터 적용: ${esc(desktopStatusLabels[desktopLicenseStatus]||'전체 상태')}${desktopLicenseQuery?' · 검색어 '+esc(desktopLicenseQuery):''}`:' · 전체 보기'} · 위 상태 수치는 전체 기준</p></div><div class="actions"><span class="small-note" id="desktop-license-updated">자동 갱신 · ${desktopDate(data.serverTime)}</span></div></div>
    <form id="desktop-license-search-form" class="desktop-license-toolbar"><label class="desktop-search"><span class="sr-only">라이선스 검색</span><input id="desktop-license-search" type="search" maxlength="120" autocomplete="off" placeholder="라이선스 ID, 이름, PC 검색" value="${esc(desktopLicenseQuery)}"></label><label><span class="sr-only">상태</span><select id="desktop-license-filter"><option value="ALL">전체 상태</option>${Object.entries(desktopStatusLabels).map(([value,label])=>`<option value="${value}" ${value===desktopLicenseStatus?'selected':''}>${label}</option>`).join('')}</select></label><button type="submit">검색</button>${desktopLicenseQuery||desktopLicenseStatus!=='ALL'?'<button type="button" id="desktop-license-clear" class="ghost">전체 보기</button>':''}</form>
    <div class="table-wrap"><table id="desktop-license-records" class="desktop-license-table"><thead><tr><th>라이선스</th><th>상태</th><th>연결된 PC</th><th>최초 사용 · 사용 정책</th><th>최근 인증</th><th>관리</th></tr></thead><tbody>${page.map(row=>`<tr><td><div class="desktop-cell"><strong>${esc(row.label||'이름 없는 라이선스')}</strong><span class="code muted">${esc(desktopDisplayId(row.displayId||row.id))}</span><small>${row.consumed?'최초 사용 완료 · 재사용 불가':'최초 사용 대기'} · ${desktopDate(row.issuedAt)}</small></div></td><td>${desktopStatus(row.status)}</td><td><div class="desktop-cell">${desktopLicenseDevice(row)}${row.appVersion?`<small>v${esc(row.appVersion)}</small>`:''}</div></td><td><div class="desktop-cell"><span>${desktopDate(row.activatedAt)}</span><small>${row.expiresAt?'이전 발급 기한 '+desktopDate(row.expiresAt):'1회 사용 · 재사용 불가'}</small></div></td><td>${desktopDate(row.lastVerifiedAt)}</td><td><div class="actions"><button type="button" data-desktop-action="detail" data-id="${esc(row.id)}">상세</button>${row.status!=='REVOKED'?`<button type="button" class="danger" data-desktop-action="revoke" data-id="${esc(row.id)}">폐기</button>`:''}<button type="button" data-desktop-action="reissue" data-id="${esc(row.id)}">새 키 발급</button></div></td></tr>`).join('')||'<tr><td colspan="6"><div class="desktop-empty"><span aria-hidden="true">◇</span><strong>라이선스가 없습니다.</strong><p>검색 조건을 바꾸거나 새 라이선스를 발급하세요.</p></div></td></tr>'}</tbody></table></div>
    <div class="desktop-pagination"><span>${rows.length?desktopLicensePage*pageSize+1:0}–${Math.min(rows.length,(desktopLicensePage+1)*pageSize)} / ${rows.length}</span><div class="actions"><button type="button" data-desktop-page="-1" ${desktopLicensePage===0?'disabled':''}>이전</button><span>${desktopLicensePage+1} / ${pages}</span><button type="button" data-desktop-page="1" ${desktopLicensePage+1>=pages?'disabled':''}>다음</button></div></div></section>
  </div>`;
  if (silent && content.querySelector('.desktop-workspace')) {
    // Leave all form controls in place, including a focused status selector or
    // an unsent search draft. Only server-owned result fragments are replaced.
    const template=document.createElement('template');template.innerHTML=html;
    for(const selector of ['#desktop-bootstrap-panel','.desktop-stats','#desktop-license-result-summary','#desktop-license-updated','#desktop-license-records tbody','.desktop-pagination']) {
      const previous=content.querySelector(selector),next=template.content.querySelector(selector);
      if(previous&&next)previous.replaceWith(next);
    }
  } else content.innerHTML=html;
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
  const hasKey=typeof data.licenseKey==='string'&&data.licenseKey.length>0;
  const keyMarkup=hasKey?`<div class="desktop-key-receipt"><label for="desktop-detail-key">발급한 라이선스 키</label><textarea id="desktop-detail-key" class="code" readonly aria-readonly="true" spellcheck="false" autocomplete="off">${esc(data.licenseKey)}</textarea><div class="actions"><button type="button" id="desktop-detail-key-copy">키 복사</button></div><p class="small-note">${row.consumed?'사용된 키입니다. 확인·복사만 가능하며 다시 등록할 수 없습니다.':'등록이 성공하면 즉시 사용됨으로 처리됩니다.'}</p></div>`:'<p class="small-note">이전 발급 키는 원문이 보관되지 않아 표시할 수 없습니다.</p>';
  const promise=openModal({title:row.label||'라이선스 상세',html:`${keyMarkup}<div class="kv"><div>라이선스 ID</div><div class="code desktop-wrap">${esc(desktopDisplayId(row.displayId||row.id))}</div><div>상태</div><div>${desktopStatus(row.status)}</div><div>발급</div><div>${desktopDate(row.issuedAt)}</div><div>최초 등록</div><div>${desktopDate(row.activatedAt)}</div><div>사용 정책</div><div>1회 등록 · 등록 즉시 사용됨 · 재사용 불가</div>${row.expiresAt?'<div>이전 발급 기한</div><div>'+desktopDate(row.expiresAt)+'</div>':''}<div>최초 사용</div><div>${row.consumed?'완료 · 다시 사용 불가':'대기 중'}</div><div>PC</div><div>${esc(row.deviceName||'—')}</div><div>기기 식별자</div><div class="code desktop-wrap">${esc(row.deviceId||'—')}</div><div>버전</div><div>${esc(row.appVersion||'—')}</div><div>최근 인증</div><div>${desktopDate(row.lastVerifiedAt)}</div><div>실행 세션 인증 기한</div><div>${desktopDate(row.leaseExpiresAt)}</div><div>실행 종료</div><div>${desktopDate(row.releasedAt)}</div><div>관리자 폐기</div><div>${desktopDate(row.revokedAt)}</div><div>사유</div><div class="desktop-wrap">${esc(row.reason||'—')}</div></div>`,confirmLabel:'닫기'});
  const input=document.getElementById('desktop-detail-key');
  if(input)desktopBindKeyCopy(document.getElementById('desktop-detail-key-copy'),input,owner);
  data.licenseKey='';
  try{await promise;}finally{
    if(input)input.value='';
    if(!input||document.getElementById('desktop-detail-key')===input)modalBody.replaceChildren();
  }
}
async function showDesktopLicenseReceipt(data) {
  if(typeof data.licenseKey!=='string'||!data.licenseKey)throw Error('발급 응답에 라이선스 키가 없습니다. 관리자 기록을 확인해주세요.');
  const id=desktopDisplayId(data.license?.id||'license');
  const promise=openModal({title:'라이선스 발급 완료',message:'이 키는 라이선스 상세에서도 확인할 수 있습니다. 대상 PC에서 발급한 실행 파일을 열고 빈 입력창에 키를 붙여넣은 다음 Enter를 누르세요.',html:`<div class="desktop-key-receipt"><label for="desktop-issued-key">새 라이선스 키</label><textarea id="desktop-issued-key" class="code" readonly spellcheck="false" autocomplete="off">${esc(data.licenseKey)}</textarea><div class="actions"><button type="button" id="desktop-key-copy">키 복사</button><button type="button" id="desktop-key-download">텍스트 저장</button></div><p class="small-note">등록이 성공하는 즉시 사용됨으로 처리되며 다시 등록할 수 없습니다. 실행을 마친 뒤 다시 이용하려면 새 실행 파일과 새 키가 필요합니다.</p></div>`,confirmLabel:'저장했어요'});
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
    <div class="table-wrap"><table id="desktop-bootstrap-artifacts" class="desktop-license-table"><thead><tr><th>구성 요소</th><th>게시 상태 · 버전</th><th>SHA-256</th><th>등록 시각 · 크기</th><th>관리</th></tr></thead><tbody>${['A','B'].map(component=>{
      const artifact=artifacts[component];
      return `<tr><td><div class="desktop-cell"><strong>${component==='A'?'A · 일회용 실행기 템플릿':'B · 라이선스 프로그램'}</strong><small>${component==='A'?'무작위 이름의 일회용 실행 파일 발급':'서버 인계 확인 후 라이선스 키 입력창만 표시'}</small></div></td><td><div class="desktop-cell"><strong>${artifact?'게시됨':'미등록'}</strong><span>${artifact?'v'+esc(artifact.version):'등록이 필요합니다'}</span></div></td><td><span class="code desktop-wrap">${esc(artifact?.sha256||'—')}</span></td><td><div class="desktop-cell"><span>${desktopDate(artifact?.createdAt)}</span><small>${artifact?Number(artifact.size||0).toLocaleString()+' bytes':'—'}</small></div></td><td><button type="button" data-desktop-action="artifact-upload" data-component="${component}">${component} 파일 등록</button></td></tr>`;
    }).join('')}</tbody></table></div>
    <div class="section-head"><div><h3>발급한 A</h3><p class="small-note">${ready?'발급한 무작위 이름의 실행 파일 한 개를 전달하세요. 한 번 사용한 파일은 재사용할 수 없습니다. 아래 기한은 라이선스 기간이 아닌 미사용 실행기의 보안 기한입니다.':'A와 B를 모두 등록하면 일회용 A를 발급할 수 있습니다.'}</p></div></div>
    <div class="table-wrap"><table id="desktop-bootstrap-launchers" class="desktop-license-table"><thead><tr><th>이름 · A 발급 ID</th><th>상태</th><th>발급 · 실행 보안 기한</th><th>흐름 ID</th></tr></thead><tbody>${launchers.map(row=>`<tr><td><div class="desktop-cell"><strong>${esc(row.label||'이름 없는 A')}</strong><span class="code">${esc(desktopDisplayId(row.displayId||row.id))}</span><small class="code">${esc(row.downloadName||'—')}</small></div></td><td>${desktopBootstrapStatus(row.status)}</td><td><div class="desktop-cell"><span>${desktopDate(row.issuedAt)}</span><small>미사용 실행 기한 ${desktopDate(row.expiresAt)}</small></div></td><td class="code desktop-wrap">${esc(desktopDisplayId(row.flowId)||'실행 대기')}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">발급한 A가 없습니다.</td></tr>'}</tbody></table></div>
    <div class="section-head"><div><h3>A → B 실행 · 서버 인증</h3><p class="small-note">다운로드, B 실행과 연결된 라이선스의 인증 상태를 확인합니다. 세션 기한은 연결 보안을 위한 제한이며 라이선스 이용 기간이 아닙니다.</p></div></div>
    <div class="table-wrap"><table id="desktop-bootstrap-sessions" class="desktop-license-table"><thead><tr><th>흐름 · PC</th><th>실행 상태 · B 버전</th><th>연결된 라이선스</th><th>최근 인증</th><th>관리</th></tr></thead><tbody>${sessions.map(row=>`<tr><td><div class="desktop-cell"><strong class="code">${esc(desktopDisplayId(row.flowId||row.id))}</strong><span class="code">${esc(row.deviceId||'PC 연결 대기')}</span><small>A ${esc(desktopDisplayId(row.launcherId)||'—')} · ${desktopDate(row.createdAt)}</small></div></td><td><div class="desktop-cell"><strong>${row.status==='CLAIMED'&&['USED','ACTIVE'].includes(row.licenseStatus)?'실행 중':desktopBootstrapStatus(row.status)}</strong><small>${row.version?'B v'+esc(row.version):'B 연결 대기'}</small></div></td><td><div class="desktop-cell"><span class="code">${esc(desktopDisplayId(row.licenseId)||'연결 전')}</span>${row.licenseStatus?desktopStatus(row.licenseStatus):'<span class="muted">라이선스 연결 대기</span>'}</div></td><td><div class="desktop-cell"><span>${desktopDate(row.licenseLastVerifiedAt||row.lastVerifiedAt)}</span><small>세션 만료 ${desktopDate(row.expiresAt)}</small></div></td><td>${['REVOKED','CLOSED','EXPIRED'].includes(row.status)?'—':`<button type="button" class="danger" data-desktop-action="session-revoke" data-id="${esc(row.id)}">실행 폐기</button>`}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">아직 실행 기록이 없습니다.</td></tr>'}</tbody></table></div>
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
  if(target.dataset.desktopStatus){desktopLicenseStatus=target.dataset.desktopStatus;desktopLicensePage=0;await renderCurrent();return true;}
  if(target.dataset.desktopPage){desktopLicensePage+=Number(target.dataset.desktopPage);await renderCurrent();return true;}
  if(target.id==='desktop-license-clear'){desktopLicenseQuery='';desktopLicenseStatus='ALL';desktopLicensePage=0;await renderCurrent();return true;}
  const action=target.id==='desktop-license-create'?'create':target.id==='desktop-launcher-create'?'launcher-create':target.dataset.desktopAction;
  if(!action)return false;if(!roleIsAdmin())throw Error('관리자만 사용할 수 있습니다.');
  if(desktopLicenseActionPending)return true;
  const row=action==='session-revoke'?desktopBootstrapSessions.get(target.dataset.id):desktopLicenseRows.get(target.dataset.id);
  if(!['create','artifact-upload','launcher-create'].includes(action)&&!row)throw Error('목록을 새로고침한 후 다시 선택해주세요.');
  desktopLicenseActionPending=true;target.disabled=true;
  try{
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
content.addEventListener('submit',async event=>{
  if(event.target.id!=='desktop-license-search-form')return;event.preventDefault();
  desktopLicenseQuery=document.getElementById('desktop-license-search').value.trim();desktopLicenseStatus=document.getElementById('desktop-license-filter').value;desktopLicensePage=0;await renderCurrent();
});
content.addEventListener('change',async event=>{
  if(event.target.id!=='desktop-license-filter')return;desktopLicenseStatus=event.target.value;desktopLicensePage=0;await renderCurrent();
});
