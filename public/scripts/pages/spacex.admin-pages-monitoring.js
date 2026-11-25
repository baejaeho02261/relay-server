'use strict';

function renderStatsPanel(stats) {
  const rows = stats.buckets || [];
  return `<div class="section-card stats-panel"><div class="section-head"><h3>트래픽 추이</h3><div class="actions"><button data-stats-range="1H" class="${statsRange==='1H'?'primary':''}">1시간</button><button data-stats-range="6H" class="${statsRange==='6H'?'primary':''}">6시간</button><button data-stats-range="24H" class="${statsRange==='24H'?'primary':''}">24시간</button><button data-stats-range="7D" class="${statsRange==='7D'?'primary':''}">7일</button></div></div><div class="stats-grid"><div class="chart-box"><div class="chart-title">연결 · 전송</div>${svgLineChart(rows,[{key:'connections',label:"접속 수"},{key:'sends',label:"전송"}])}</div><div class="chart-box"><div class="chart-title">처리 응답 결과</div>${svgLineChart(rows,[{key:'ackOk',label:"응답 성공"},{key:'ackError',label:"응답 오류"},{key:'ackTimeout',label:"시간 초과"}])}</div></div><div class="stats-summary"><span>접속 수 <strong>${stats.totals.connections}</strong></span><span>전송 <strong>${stats.totals.sends}</strong></span><span>응답 성공 <strong>${stats.totals.ackOk}</strong></span><span>오류 <strong>${stats.totals.ackError}</strong></span><span>시간 초과 <strong>${stats.totals.ackTimeout}</strong></span><span>성공 <strong>${stats.totals.ackSuccessRate}%</strong></span></div></div>`;
}

let overviewWorkspaceCache;

function overviewWorkspace() {
  if (!roleIsAdmin()) return Promise.resolve(null);
  const owner = session?.csrf;
  if (overviewWorkspaceCache?.owner === owner && Date.now() < overviewWorkspaceCache.until)
    return overviewWorkspaceCache.data;
  const paths = ['/api/desktop/members?scope=MATCH&status=ACTIVE&page=1&pageSize=4',
    '/api/desktop/workspace/licenses?page=0&pageSize=1', '/api/desktop/bootstrap'];
  const data = Promise.allSettled(paths.map(path => api(path))).then(results => {
    const [members, licenses, distribution] = results.map(result => result.status === 'fulfilled' ? result.value : null);
    return {members, licenses, distribution: distribution?.bootstrap};
  });
  overviewWorkspaceCache = {owner, until: Date.now() + 15000, data};
  return data;
}

function overviewCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : '—';
}

function overviewWorkspaceCards(workspace) {
  const {members, licenses, distribution} = workspace;
  const memberItems = Array.isArray(members?.items) ? members.items.slice(0,4) : [];
  const memberMarkup = memberItems.map(row => {
    const heading = row.nickname || row.displayName || '등록 PC';
    const publicId = row.memberCode || row.id || '';
    return `<li><span class="aurora-member-avatar" aria-hidden="true">${esc(Array.from(heading)[0]||'P')}</span><div class="aurora-member-profile"><strong>${esc(heading)}</strong><small class="code">${esc(publicId)}</small></div><span class="aurora-member-last">${row.updatedAt ? esc(fmtTime(row.updatedAt)) : '—'}</span></li>`;
  }).join('');
  const total = Number.isSafeInteger(licenses?.totalCount) && licenses.totalCount > 0 ? licenses.totalCount : 0;
  const licenseMarkup = Object.entries(desktopStatusLabels).map(([status,label]) => {
    const count = licenses?.counts?.[status];
    const fill = total && Number.isSafeInteger(count) ? Math.min(100, Math.max(0, 100 * count / total)) : 0;
    return `<li><div><span>${esc(label)}</span><strong>${overviewCount(count)}</strong></div><progress max="100" value="${fill}" aria-label="${esc(label)} 비율"></progress></li>`;
  }).join('');
  const arrow = '<svg class="aurora-link-arrow" width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 12 12 4M5 4h7v7"/></svg>';
  const cards = ['A', 'B', 'O'].map((role,index) => {
    const item = distribution?.artifacts?.[role];
    return `<li><span class="aurora-build-icon ${item?'ready':''}" aria-hidden="true">${role}</span><div><strong>${['실행기 템플릿','라이선스 프로그램','오버레이'][index]}</strong><small>${item?'v'+esc(item.version)+' · 게시됨':distribution?'게시 대기':'조회할 수 없음'}</small></div></li>`;
  });
  cards.push(`<li><span class="aurora-build-icon" aria-hidden="true">${arrow}</span><div><strong>일회용 실행기</strong><small>${Array.isArray(distribution?.launchers) ? overviewCount(distribution.launchers.length)+'건 발급' : '조회할 수 없음'}</small></div></li>`);
  return `<div class="aurora-overview-pair" id="aurora-overview-workspace">
    <section class="section-card aurora-overview-members" aria-labelledby="aurora-members-title"><div class="section-head"><div><h3 id="aurora-members-title">회원 목록</h3><p class="small-note">활성 회원 ${overviewCount(members?.totalCount)}명</p></div><button type="button" class="primary" data-open-view="desktop-licenses" data-open-desktop-tab="members">1대1 매칭 ${arrow}</button></div><ul class="aurora-member-rows">${memberMarkup || `<li class="aurora-overview-empty">${members?'등록된 활성 회원이 없습니다.':'회원 목록을 조회하지 못했습니다.'}</li>`}</ul></section>
    <section class="section-card aurora-overview-licenses" aria-labelledby="aurora-licenses-title"><div class="section-head"><div><h3 id="aurora-licenses-title">라이선스</h3><p class="small-note">Windows 라이선스 재고</p></div></div><div class="aurora-license-total"><span>전체 라이선스</span><strong>${overviewCount(licenses?.totalCount)}</strong><button type="button" class="ghost" data-open-view="desktop-licenses" data-open-desktop-tab="licenses">라이선스 관리 ${arrow}</button></div><ul class="aurora-license-bars">${licenseMarkup}</ul></section>
  </div><section class="section-card aurora-overview-build" id="aurora-overview-deployment" aria-labelledby="aurora-deploy-title"><div class="section-head"><div><h3 id="aurora-deploy-title">빌드 배포</h3><p class="small-note">운영 중인 A/B/O 조합과 일회용 실행기</p></div><button type="button" data-open-view="desktop-licenses" data-open-desktop-tab="distribution">A/B/O 배포 열기 ${arrow}</button></div><ol class="aurora-build-track">${cards.join('')}</ol></section>`;
}

async function renderDashboard() {
  const [{ dashboard: d }, { statistics: stats }, workspace] = await Promise.all([
    api('/api/dashboard'), api(`/api/statistics?range=${encodeURIComponent(statsRange)}`), overviewWorkspace()
  ]);
  guardAdminViewCommit('dashboard');
  if (typeof updateAuroraRail === 'function') updateAuroraRail(d, stats);
  const successRate = Math.max(0, Math.min(100, Number(d.ack.successRate) || 0));
  adminViewContent.html = `<div class="aurora-overview" id="aurora-overview"><div class="aurora-overview-title"><span class="badge ${d.serviceEnabled&&!d.maintenanceMode?'online':'warning'}">${d.maintenanceMode?'점검 중':d.serviceEnabled?'서비스 운영 중':'서비스 중지'}</span><span>중계 서버 ${esc(d.versions.server)} · 프로토콜 ${esc(d.versions.protocol)}</span></div>
    ${workspace?overviewWorkspaceCards(workspace):''}
    <div class="cards overview-primary" aria-label="실시간 운영 지표"><div class="card"><div class="stat-label">서버 연결</div><div class="stat-value">${d.servers.online} / ${d.servers.total}</div><div class="stat-sub">비활성 ${d.servers.disabled} · 연결 정리 중 ${d.servers.draining}</div></div>
    <div class="card"><div class="stat-label">처리 성공률</div><div class="stat-value">${successRate}%</div><div class="stat-sub">대기 중 ${d.ack.pending} · 시간 초과 ${d.ack.timeout}</div></div>
    <div class="card"><div class="stat-label">확인할 알림</div><div class="stat-value">${d.notifications.unread}</div><div class="stat-sub">긴급 ${d.notifications.critical} · 주의 ${d.notifications.warning}</div></div>
    <div class="card"><div class="stat-label">연속 운영 시간</div><div class="stat-value aurora-uptime">${esc(fmtDuration(d.uptimeMs))}</div><div class="stat-sub">누적 접속 ${d.totalConnections}</div></div></div>
    <div class="aurora-overview-traffic">${renderStatsPanel(stats)}<section class="section-card"><div class="section-head"><h3>최근 이벤트</h3><span class="small-note">최근 30건</span></div><div class="event-list">${d.recentEvents.map(e=>`<div class="event"><span>${esc(fmtTime(e.time))}</span><span class="type">${esc(uiText(e.type))}</span><span>${esc(e.detail)}</span></div>`).join('')||'<div class="empty">이벤트 없음</div>'}</div></section></div>
    <details class="metric-details section-card" id="dashboard-additional-metrics"><summary>상세 운영 지표 <span class="small-note">서비스 · 가동 시간 · 프로토콜 · 복구 · 이중화</span></summary><div class="section-body"><div class="cards overview-secondary"><div class="card"><div class="stat-label">서비스 상태</div><div class="stat-value">${d.serviceEnabled?'온라인':'오프라인'}</div><div class="stat-sub">점검 ${d.maintenanceMode?'켜짐':'꺼짐'}</div></div>
    <div class="card"><div class="stat-label">연속 운영 시간</div><div class="stat-value">${esc(fmtDuration(d.uptimeMs))}</div><div class="stat-sub">접속 수 ${d.totalConnections}</div></div>
    <div class="card"><div class="stat-label">프로토콜 버전</div><div class="stat-value">P${d.versions.protocol}</div><div class="stat-sub">서버 ${esc(d.versions.server)}</div></div>
    <div class="card"><div class="stat-label">복구 대기</div><div class="stat-value">${d.recovery.queued} / ${d.recovery.deadLetters}</div><div class="stat-sub">대기열 / 활성 실패 보관함 · 재전송 ${d.recovery.replayed}</div></div>
    <div class="card"><div class="stat-label">이중화 상태</div><div class="stat-value">${esc(uiText(d.ha.role))}</div><div class="stat-sub">${esc(d.ha.instanceId)} · ${d.ha.acceptsTraffic?'트래픽 켜짐':'조회 전용'}</div></div>
    </div></div></details></div>`;
}

async function renderConsole() {
  if (!consoleHistoryLoaded) {
    const { events } = await api('/api/audit');
    if (!liveConsoleEvents.length) liveConsoleEvents = events.slice(-300);
    consoleHistoryLoaded = true;
  }
  guardAdminViewCommit('console');
  const previousList=document.getElementById('live-console-list'),followOutput=!previousList||previousList.scrollHeight-previousList.clientHeight-previousList.scrollTop<8;
  const recent=liveConsoleEvents.slice(-300);
  adminViewContent.html = `<div class="aurora-operational-layout"><div class="aurora-operational-main"><section class="terminal-panel" aria-label="실시간 이벤트 기록"><div id="live-console-list" class="live-console">${recent.map(e => `<div class="console-line"><span class="console-time">${esc(fmtTime(e.time))}</span><span class="console-type">${esc(uiText(e.type))}</span><span class="console-detail">${esc(e.detail)}</span></div>`).join('') || '<div class="empty">이벤트 없음</div>'}</div></section></div><aside class="aurora-operational-side" aria-label="실시간 이벤트 제어"><section class="section-card aurora-stream-tools"><div class="section-head"><h3>${consolePaused?'일시정지 중':'이벤트 수신 중'}</h3></div><div class="section-body"><p class="small-note">표시 중인 이벤트 ${overviewCount(recent.length)}건</p><div class="actions"><button id="console-pause-btn">${consolePaused?'갱신 재개':'갱신 일시정지'}</button><button id="console-clear-btn">지우기</button></div></div></section></aside></div>`;
  const list = document.getElementById('live-console-list');
  if (list&&followOutput) list.scrollTop = list.scrollHeight;
}

async function renderTrace() {
  const { traces } = await api(`/api/request-traces?query=${encodeURIComponent(traceQuery)}`);
  traceRows = new Map(traces.map(t => [t.key, t]));
  guardAdminViewCommit('trace');
  const rows=traces.map(t => `<tr><td><strong class="list-primary code">${esc(t.requestId)}</strong><small class="list-secondary">${esc(t.source||'CLIENT')}</small></td><td><span class="list-primary code">${esc(t.clientId)}</span><small class="list-secondary code">→ ${esc(t.serverId)}</small></td><td class="code">${esc(t.number)}</td><td>${badge(t.status)}<small class="list-secondary">재시도 ${t.retries}회</small></td><td>${t.completedAt ? `${t.durationMs} ms` : '진행 중'}</td><td>${esc(fmtTime(t.forwardedAt))}</td><td><div class="actions"><button data-trace-detail="${esc(t.key)}">상세</button>${roleIsAdmin()&&['ERROR','TIMEOUT','DLQ'].includes(String(t.status||'').toUpperCase())?`<button class="warning" data-trace-replay="${esc(t.key)}">재전송</button>`:''}</div></td></tr>`).join('');
  adminViewContent.html = `<div class="aurora-operational-layout"><aside class="aurora-operational-side" aria-label="요청 검색과 이력 작업"><section class="section-card aurora-stream-tools"><div class="section-head"><h3>요청 검색</h3></div><div class="section-body"><label class="toolbar-group"><span class="sr-only">요청 검색</span><input id="trace-search" type="search" placeholder="요청 ID, 기기, 서버, 입력값 검색" value="${esc(traceQuery)}"></label><div class="actions"><button id="trace-search-btn" class="primary">검색</button>${roleIsAdmin()?'<button class="ghost" data-history-clean="REQUEST_TRACES">완료 이력 정리</button>':''}</div></div></section></aside><div class="aurora-operational-main"><section class="section-card"><div class="section-head"><h3>요청 처리 이력</h3><span class="small-note">조회 ${overviewCount(traces.length)}건</span></div><div class="table-wrap"><table><thead><tr><th>요청</th><th>기기 · 서버</th><th>입력값</th><th>상태</th><th>처리 시간</th><th>전달 시각</th><th>관리</th></tr></thead><tbody>${rows||'<tr><td colspan="7" class="empty">검색 조건에 맞는 요청이 없습니다.</td></tr>'}</tbody></table></div></section></div></div>`;
}

async function renderMonitor() {
  const { servers } = await api('/api/servers');
  const good=servers.filter(x=>x.health==='GOOD').length,online=servers.filter(x=>x.online).length;
  guardAdminViewCommit('monitor');
  adminViewContent.html=`<div class="cards"><div class="card"><div class="stat-label">서버 정상</div><div class="stat-value">${good}</div><div class="stat-sub">문제 ${servers.filter(x=>!['GOOD','OFFLINE'].includes(x.health)).length}</div></div><div class="card"><div class="stat-label">서버 온라인</div><div class="stat-value">${online}</div><div class="stat-sub">전체 ${servers.length}</div></div></div><div class="section-card"><div class="section-head"><h3>서버 연결 상태</h3><span class="small-note">실시간 갱신</span></div><div class="table-wrap"><table><thead><tr><th>별칭</th><th>서버 식별자</th><th>상태</th><th>건강 상태</th><th>왕복 지연</th><th>처리 응답</th><th>재연결</th><th>마지막 확인</th></tr></thead><tbody>${servers.map(x=>`<tr><td>${esc(x.alias||'—')}</td><td class="code">${esc(x.id)}</td><td>${badge(x.status)}</td><td>${badge(x.health)}</td><td>${x.rttMs>=0?x.rttMs+' ms':'—'}</td><td>${x.ack.successRate}%</td><td>${x.reconnectCount}</td><td>${esc(fmtTime(x.lastSeen))}</td></tr>`).join('')||'<tr><td colspan="8" class="empty">연결된 서버가 없습니다.</td></tr>'}</tbody></table></div></div>`;
}
