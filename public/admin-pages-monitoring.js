'use strict';

function renderStatsPanel(stats) {
  const rows = stats.buckets || [];
  return `<div class="section-card stats-panel"><div class="section-head"><h3>트래픽 추이</h3><div class="actions"><button data-stats-range="1H" class="${statsRange==='1H'?'primary':''}">1시간</button><button data-stats-range="6H" class="${statsRange==='6H'?'primary':''}">6시간</button><button data-stats-range="24H" class="${statsRange==='24H'?'primary':''}">24시간</button><button data-stats-range="7D" class="${statsRange==='7D'?'primary':''}">7일</button></div></div><div class="stats-grid"><div class="chart-box"><div class="chart-title">연결 · 전송</div>${svgLineChart(rows,[{key:'connections',label:"접속 수"},{key:'sends',label:"전송"}])}</div><div class="chart-box"><div class="chart-title">처리 응답 결과</div>${svgLineChart(rows,[{key:'ackOk',label:"응답 성공"},{key:'ackError',label:"응답 오류"},{key:'ackTimeout',label:"시간 초과"}])}</div></div><div class="stats-summary"><span>접속 수 <strong>${stats.totals.connections}</strong></span><span>전송 <strong>${stats.totals.sends}</strong></span><span>응답 성공 <strong>${stats.totals.ackOk}</strong></span><span>오류 <strong>${stats.totals.ackError}</strong></span><span>시간 초과 <strong>${stats.totals.ackTimeout}</strong></span><span>성공 <strong>${stats.totals.ackSuccessRate}%</strong></span></div></div>`;
}

async function renderDashboard() {
  const [{ dashboard: d }, { statistics: stats }, licenses] = await Promise.all([api('/api/dashboard'), api(`/api/statistics?range=${encodeURIComponent(statsRange)}`),roleIsAdmin()?api('/api/desktop/licenses'):Promise.resolve(null)]);
  const rows=licenses?.items||[];
  content.innerHTML = `<div class="cards">
    <div class="card"><div class="stat-label">서버 연결</div><div class="stat-value">${d.servers.online} / ${d.servers.total}</div><div class="stat-sub">비활성 ${d.servers.disabled} · 연결 정리 중 ${d.servers.draining}</div></div>
    ${licenses?`<div class="card"><div class="stat-label">Windows 라이선스</div><div class="stat-value">${rows.filter(x=>x.status==='ACTIVE').length}</div><div class="stat-sub">사용 중 · 전체 ${rows.length}</div></div>`:''}
    <div class="card"><div class="stat-label">처리 성공률</div><div class="stat-value">${d.ack.successRate}%</div><div class="stat-sub">대기 중 ${d.ack.pending} · 시간 초과 ${d.ack.timeout}</div></div>
    <div class="card"><div class="stat-label">확인할 알림</div><div class="stat-value">${d.notifications.unread}</div><div class="stat-sub">긴급 ${d.notifications.critical} · 주의 ${d.notifications.warning}</div></div>
    <div class="card"><div class="stat-label">서비스 상태</div><div class="stat-value">${d.serviceEnabled?'온라인':'오프라인'}</div><div class="stat-sub">점검 ${d.maintenanceMode?'켜짐':'꺼짐'}</div></div>
    <div class="card"><div class="stat-label">연속 운영 시간</div><div class="stat-value">${esc(fmtDuration(d.uptimeMs))}</div><div class="stat-sub">접속 수 ${d.totalConnections}</div></div>
    <div class="card"><div class="stat-label">프로토콜 버전</div><div class="stat-value">P${d.versions.protocol}</div><div class="stat-sub">서버 ${esc(d.versions.server)}</div></div>
    <div class="card"><div class="stat-label">복구 대기</div><div class="stat-value">${d.recovery.queued} / ${d.recovery.deadLetters}</div><div class="stat-sub">대기열 / 활성 실패 보관함 · 재전송 ${d.recovery.replayed}</div></div>
    <div class="card"><div class="stat-label">이중화 상태</div><div class="stat-value">${esc(uiText(d.ha.role))}</div><div class="stat-sub">${esc(d.ha.instanceId)} · ${d.ha.acceptsTraffic?'트래픽 켜짐':'조회 전용'}</div></div>
  </div>${renderStatsPanel(stats)}<div class="grid-2"><div class="section-card"><div class="section-head"><h3>최근 이벤트</h3><span class="small-note">최근 30건</span></div><div class="section-body"><div class="event-list">${d.recentEvents.map(e=>`<div class="event"><span>${esc(fmtTime(e.time))}</span><span class="type">${esc(uiText(e.type))}</span><span>${esc(e.detail)}</span></div>`).join('')||'<div class="empty">이벤트 없음</div>'}</div></div></div>${licenses?`<div class="section-card"><div class="section-head"><h3>Windows 라이선스 현황</h3><button data-open-view="desktop-licenses">라이선스 관리</button></div><div class="section-body"><div class="kv">${Object.entries(desktopStatusLabels).map(([key,label])=>`<div>${label}</div><div>${rows.filter(x=>x.status===key).length}</div>`).join('')}</div></div></div>`:''}</div>`;
}

async function renderConsole() {
  if (!consoleHistoryLoaded) {
    const { events } = await api('/api/audit');
    if (!liveConsoleEvents.length) liveConsoleEvents = events.slice(-300);
    consoleHistoryLoaded = true;
  }
  content.innerHTML = `<div class="terminal-panel"><div class="terminal-head"><span>실시간 이벤트 기록</span><div class="actions"><button id="console-pause-btn">${consolePaused ? "이용 재개" : "일시 중지"}</button><button id="console-clear-btn">지우기</button></div></div><div id="live-console-list" class="live-console">${liveConsoleEvents.slice(-300).map(e => `<div class="console-line"><span class="console-time">${esc(fmtTime(e.time))}</span><span class="console-type">${esc(uiText(e.type))}</span><span class="console-detail">${esc(e.detail)}</span></div>`).join('') || '<div class="empty">이벤트 없음</div>'}</div></div>`;
  const list = document.getElementById('live-console-list');
  if (list) list.scrollTop = list.scrollHeight;
}

async function renderTrace() {
  const { traces } = await api(`/api/request-traces?query=${encodeURIComponent(traceQuery)}`);
  traceRows = new Map(traces.map(t => [t.key, t]));
  content.innerHTML = `<div class="toolbar"><input id="trace-search" placeholder="요청 식별자 / 요청 기기 / 서버 / 입력값" value="${esc(traceQuery)}"><button id="trace-search-btn">요청 추적</button>${roleIsAdmin()?"<button class=\"danger\" data-history-clean=\"REQUEST_TRACES\">이력 정리</button>":''}<span class="small-note">처리 중·대기열 요청은 보존</span></div><div class="table-wrap"><table><thead><tr><th>요청 식별자</th><th>소스</th><th>요청 기기</th><th>서버</th><th>입력값</th><th>상태</th><th>다시 시도</th><th>기간</th><th>전달됨</th><th>작업</th></tr></thead><tbody>${traces.map(t => `<tr><td class="code">${esc(t.requestId)}</td><td>${esc(t.source||'CLIENT')}</td><td class="code">${esc(t.clientId)}</td><td class="code">${esc(t.serverId)}</td><td class="code">${esc(t.number)}</td><td>${badge(t.status)}</td><td>${t.retries}</td><td>${t.completedAt ? `${t.durationMs} ms` : '-'}</td><td>${esc(fmtTime(t.forwardedAt))}</td><td><div class="actions"><button data-trace-detail="${esc(t.key)}">상세</button>${roleIsAdmin()&&['ERROR','TIMEOUT','DLQ'].includes(String(t.status||'').toUpperCase())?`<button class="warning" data-trace-replay="${esc(t.key)}">재전송</button>`:''}</div></td></tr>`).join('') || "<tr><td colspan=\"10\" class=\"empty\">요청 추적 없음</td></tr>"}</tbody></table></div>`;
}

async function renderMonitor() {
  const { servers } = await api('/api/servers');
  const good=servers.filter(x=>x.health==='GOOD').length,online=servers.filter(x=>x.online).length;
  content.innerHTML=`<div class="cards"><div class="card"><div class="stat-label">서버 정상</div><div class="stat-value">${good}</div><div class="stat-sub">문제 ${servers.filter(x=>!['GOOD','OFFLINE'].includes(x.health)).length}</div></div><div class="card"><div class="stat-label">서버 온라인</div><div class="stat-value">${online}</div><div class="stat-sub">전체 ${servers.length}</div></div></div><div class="section-card"><div class="section-head"><h3>서버 연결 상태</h3><span class="small-note">실시간 갱신</span></div><div class="table-wrap"><table><thead><tr><th>별칭</th><th>서버 식별자</th><th>상태</th><th>건강 상태</th><th>왕복 지연</th><th>처리 응답</th><th>재연결</th><th>마지막 확인</th></tr></thead><tbody>${servers.map(x=>`<tr><td>${esc(x.alias||'—')}</td><td class="code">${esc(x.id)}</td><td>${badge(x.status)}</td><td>${badge(x.health)}</td><td>${x.rttMs>=0?x.rttMs+' ms':'—'}</td><td>${x.ack.successRate}%</td><td>${x.reconnectCount}</td><td>${esc(fmtTime(x.lastSeen))}</td></tr>`).join('')||'<tr><td colspan="8" class="empty">연결된 서버가 없습니다.</td></tr>'}</tbody></table></div></div>`;
}
