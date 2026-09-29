'use strict';

async function renderDangerZone() {
  if (!roleIsAdmin()) { content.innerHTML="<div class=\"empty\">접근 권한 없음</div>"; return; }
  const [{ system:s }, { backups }] = await Promise.all([api('/api/system'), api('/api/backups')]);
  content.innerHTML = `<div class="danger-banner"><strong>!! 주의가 필요한 작업 !!</strong><span>위험 작업은 영향 범위를 확인한 뒤 웹 모달에서 한 번 더 승인합니다. 별도 확인 문구 입력은 사용하지 않습니다.</span></div><div class="danger-grid">
    <div class="section-card danger-card"><div class="section-head"><h3>서비스 종료</h3>${badge(s.serviceEnabled?'ONLINE':'OFFLINE')}</div><div class="section-body"><p class="muted">서비스를 중지하고 활성 인증을 종료합니다. 라이선스 발급·사용 기록은 유지됩니다.</p><button id="danger-service-stop" class="danger">서비스 종료</button></div></div>
    <div class="section-card danger-card"><div class="section-head"><h3>백업 복원 / 삭제</h3><span class="small-note">${backups.length} 파일</span></div><div class="section-body"><label>백업<select id="danger-backup-file">${backups.map(b=>`<option value="${esc(b.file)}">${esc(b.file)} // ${esc(fmtBytes(b.size))}</option>`).join('')}</select></label><div class="actions"><button id="danger-backup-restore" class="danger" ${backups.length?'':'disabled'}>복원 백업</button><button id="danger-backup-delete" class="danger" ${backups.length?'':'disabled'}>삭제 백업</button></div></div></div>
    <div class="section-card danger-card"><div class="section-head"><h3>버전 강제 적용</h3><span class="small-note">현재 프로토콜 ${s.currentProtocolVersion}</span></div><div class="section-body"><div class="form-grid"><label>프로토콜<input id="danger-version-protocol" type="number" min="1" max="${s.currentProtocolVersion}" value="${s.minProtocolVersion}"></label><label>서버<input id="danger-version-server" value="${esc(s.minServerVersion)}"></label></div><button id="danger-version-apply" class="danger">버전 정책 적용</button></div></div>
    <div class="section-card danger-card"><div class="section-head"><h3>전체 이력 이력 정리</h3><span class="small-note">진행 중인 데이터 유지</span></div><div class="section-body"><p class="muted">완료된 요청 추적, 설정, 일일, 실패 보관함, 서버 접속, 알림, 감사 기록 이력을 한 번에 정리합니다. 진행 중 데이터와 장비 등록은 보존됩니다.</p><button class="danger" data-history-clean="ALL">이력 정리 전체 이력</button></div></div>
  </div><div class="section-card danger-card future-danger"><div class="section-head"><h3>데이터베이스 초기화</h3>${badge('DISABLED')}</div><div class="section-body"><p class="muted">의도적으로 구현하지 않았습니다. 데이터베이스 삭제/초기화는 웹 관리자에서 제공하지 않습니다.</p></div></div>`;
}

async function updateNotificationBadge() {
  if (!session || !notificationBadge) return;
  try {
    const { summary } = await api('/api/notifications?limit=1');
    notificationBadge.textContent = summary.unread > 99 ? '99+' : String(summary.unread);
    notificationBadge.classList.toggle('hidden', summary.unread <= 0);
    notificationBadge.classList.toggle('critical', summary.critical > 0);
  } catch (_) {}
}

