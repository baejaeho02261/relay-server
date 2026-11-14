'use strict';

async function renderServers() {
  const { servers } = await api('/api/servers');
  const actions = server => {
    const id = esc(server.id);
    const detail = `<button data-server-action="detail" data-id="${id}">상세</button>`;
    const note = roleCanOperate() ? `<button data-server-action="note" data-id="${id}">메모</button>` : '';
    if (!roleIsAdmin()) return `<div class="actions">${detail}${note}</div>`;
    const alias = `<button data-server-action="alias" data-id="${id}">별칭</button>`;

    const kick = server.online && server.status !== 'DISABLED' ? `<button class="warning" data-server-action="kick" data-id="${id}">60초간 연결 차단</button>` : '';
    const drain = server.status === 'DRAINING'
      ? `<button data-server-action="drain-off" data-id="${id}">연결 정리 꺼짐</button>`
      : server.status !== 'DISABLED' ? `<button data-server-action="drain-on" data-id="${id}">연결 정리 켜짐</button>` : '';
    const enabled = server.status === 'DISABLED'
      ? `<button class="primary" data-server-action="enable" data-id="${id}">활성화</button>`
      : `<button class="danger" data-server-action="disable" data-id="${id}">비활성화</button>`;
    return `<div class="actions">${detail}<details class="row-actions" id="server-actions-${id}"><summary aria-label="서버 ${id}의 추가 작업">더 보기</summary><div class="row-actions-menu">${alias}${note}${kick}${drain}${enabled}<button class="danger" data-server-action="delete" data-id="${id}">삭제</button></div></details></div>`;
  };

  guardAdminViewCommit('servers');
  adminViewContent.html = `<div class="cards overview-primary"><div class="card"><div class="stat-label">등록된 서버</div><div class="stat-value">${servers.length}</div><div class="stat-sub">운영 기기 전체</div></div><div class="card"><div class="stat-label">온라인</div><div class="stat-value">${servers.filter(s=>s.online).length}</div><div class="stat-sub">현재 연결된 기기</div></div><div class="card"><div class="stat-label">확인 필요</div><div class="stat-value">${servers.filter(s=>!['GOOD','OFFLINE'].includes(s.health)).length}</div><div class="stat-sub">연결·상태 신호</div></div><div class="card"><div class="stat-label">연결 정리 중</div><div class="stat-value">${servers.filter(s=>s.drain?.active).length}</div><div class="stat-sub">점검 전 연결 정리</div></div></div><section class="section-card"><div class="section-head"><div><span class="section-kicker">SERVER INVENTORY</span><h3>서버 기기</h3><p class="small-note">서버 상태를 확인하고 상세에서 기기를 관리하세요.</p></div><div class="actions">${roleIsAdmin()?"<button class=\"ghost\" data-history-clean=\"SERVER_HISTORY\">접속 이력 정리</button>":''}</div></div><div class="table-wrap"><table><thead><tr><th>서버</th><th>연결 · 상태</th><th>수용 · 연결 정리</th><th>네트워크</th><th>최근 확인</th><th>메모</th><th class="sticky-actions">관리</th></tr></thead><tbody>
    ${servers.map(s => `<tr><td><strong class="list-primary">${esc(s.alias || '이름 없는 서버')}</strong><small class="list-secondary code">${esc(s.id)}</small><small class="list-secondary">버전 ${esc(s.appVersion || '미확인')}</small></td><td>${badge(s.status)}<small class="list-secondary">${badge(s.health)}</small></td><td>${badge(s.acceptState || (s.canAcceptClients ? 'READY' : 'OFFLINE'))}${s.drain && s.drain.active ? `<div class="drain-inline"><strong>${s.drain.ready ? "점검 준비됨" : `${s.drain.progress}%`}</strong><span>연결 ${s.drain.currentClients}개</span></div>` : ''}</td><td><span class="code">${esc(s.lastIP || '미확인')}</span><small class="list-secondary">왕복 ${s.rttMs >= 0 ? `${s.rttMs} ms` : '미측정'}</small></td><td>${esc(fmtTime(s.lastSeen))}<small class="list-secondary">재연결 ${s.reconnectCount}회</small></td><td class="note-cell" title="${esc(s.note || '')}">${esc(s.note || '—')}</td><td class="sticky-actions">${actions(s)}</td></tr>`).join('') || "<tr><td colspan=\"7\" class=\"empty\">등록된 서버가 없습니다. 서버가 연결되면 이곳에 표시됩니다.</td></tr>"}
  </tbody></table></div><div class="section-body small-note">기기 삭제는 등록 식별자와 연결된 바인딩을 제거합니다. 접속 이력 정리는 접속·재연결 기록에만 적용됩니다.</div></section>`;
}

