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
    return `<div class="actions">${detail}${alias}${note}${kick}${drain}${enabled}<button class="danger" data-server-action="delete" data-id="${id}">삭제</button></div>`;
  };

  content.innerHTML = `<div class="toolbar">${roleIsAdmin()?"<button class=\"danger\" data-history-clean=\"SERVER_HISTORY\">이력 정리 서버 이력</button>":"<button class=\"danger\" disabled title=\"관리자 권한 필요\">삭제 · 관리자</button>"}<span class="small-note">삭제는 장비 식별자와 종속 바인딩을 제거 · 이력 정리는 접속/연결 반복 이력만 정리</span></div><div class="table-wrap"><table><thead><tr><th>별칭</th><th>서버 식별자</th><th>상태</th><th>상태</th><th>수용</th><th>연결 정리</th><th>왕복 지연</th><th>버전</th><th>IP</th><th>마지막 확인</th><th>재연결 중</th><th>메모</th><th class="sticky-actions">작업</th></tr></thead><tbody>
    ${servers.map(s => `<tr><td>${esc(s.alias || '-')}</td><td class="code">${esc(s.id)}</td><td>${badge(s.status)}</td><td>${badge(s.health)}</td><td>${badge(s.acceptState || (s.canAcceptClients ? 'READY' : 'OFFLINE'))}</td><td>${s.drain && s.drain.active ? `<div class="drain-inline"><strong>${s.drain.ready ? "준비됨" : `${s.drain.progress}%`}</strong><span>${s.drain.currentClients} 실시간 연결</span></div>` : '-'}</td><td>${s.rttMs >= 0 ? `${s.rttMs} ms` : '-'}</td><td>${esc(s.appVersion || '-')}</td><td>${esc(s.lastIP || '-')}</td><td>${esc(fmtTime(s.lastSeen))}</td><td>${s.reconnectCount}</td><td class="note-cell" title="${esc(s.note || '')}">${esc(s.note || '-')}</td><td class="sticky-actions">${actions(s)}</td></tr>`).join('') || "<tr><td colspan=\"13\" class=\"empty\">서버 없음</td></tr>"}
  </tbody></table></div>`;
}

