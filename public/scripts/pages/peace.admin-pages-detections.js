'use strict';

const mergedDetectionPageSize = 100;
let mergedDetectionPage = 0;
let mergedDetectionPageOwner = null;

const mergedDetectionKinds = {
  SECURITY_FINDING: '보안 이상 징후',
  MEASUREMENT_UNAVAILABLE: '측정 불완전',
  POLICY_REJECTION: '정책 거부',
  SENSOR_HEALTH: '센서 상태',
  EXPECTED_OPERATION: '정상 역할 동작',
  INTERNAL_EVIDENCE: '내부 확인 기록',
  UNRESOLVED_EVIDENCE: '추가 확인 필요',
  LEGACY_EVIDENCE: '이전 감지 기록'
};
const mergedDetectionActions = {
  DETECTION_REVOKE: '세션 무효화',
  MEASUREMENT_DENIAL: '측정 정책으로 거부',
  POLICY_DENIAL: '정책에 따라 거부',
  COVERAGE_POLICY_REVOKE: '센서 정책으로 세션 무효화',
  POLICY_REVOKE: '정책으로 세션 무효화',
  EVIDENCE_ONLY: '기록만 저장'
};

content.addEventListener('click', event => {
  const button = event.target.closest('button[data-merged-detection-page]');
  if (currentView !== 'security-detections' || !button || rendering || !roleIsAdmin()) return;
  mergedDetectionPage = Number(button.dataset.mergedDetectionPage);
  renderCurrent();
});

async function renderMergedDetections(silent) {
  if (!roleIsAdmin()) throw new Error('FORBIDDEN');
  if (mergedDetectionPageOwner !== session.csrf) {
    mergedDetectionPageOwner = session.csrf;
    mergedDetectionPage = 0;
  }
  if (silent && mergedDetectionPage > 0) return;

  const requestedOffset = mergedDetectionPage * mergedDetectionPageSize;
  const endpoint = '/api/desktop/bootstrap/security-center/detections';
  const url = `${endpoint}?limit=${mergedDetectionPageSize}&offset=`;
  let result = await api(url + requestedOffset);
  if (result.offset > 0 && result.offset >= result.totalCount) {
    const lastPage = Math.max(0, Math.ceil(result.totalCount / result.limit) - 1);
    result = await api(url + lastPage * result.limit);
  }
  const { items, offset, limit, totalCount } = result;
  const page = Math.floor(offset / limit);
  const pages = Math.max(1, Math.ceil(totalCount / limit));
  const rows = items.map(item => {
    const observedAt = Date.parse(item.observedAt);
    const stage = ['A', 'B', 'O'].includes(item.stage) ? item.stage : '—';
    const source = item.source === 'COZY' ? 'Cozy' : item.source;
    const label = item.label && item.label !== item.code
      ? `<small class="list-secondary">${esc(item.label)}</small>`
      : '';
    const verdict = item.verdict === 'confirmed'
      ? '<span class="badge bad">공격 확인</span>'
      : esc(mergedDetectionKinds[item.kind] || '감지 기록');
    return `<tr>
      <td>${esc(fmtTime(observedAt))}</td>
      <td>${esc(source)}</td>
      <td><span class="list-primary code">${esc(item.code)}</span>${label}</td>
      <td>${stage}</td>
      <td>${esc(item.count ?? '—')}</td>
      <td>${verdict}</td>
      <td>${esc(mergedDetectionActions[item.authorityAction] || '—')}</td>
    </tr>`;
  }).join('');

  guardAdminViewCommit('security-detections');
  mergedDetectionPage = page;
  adminViewContent.html = `<section class="section-card" aria-label="Cozy + NHW 감지">
    <div class="section-head"><span class="small-note">보관 중인 감지 기록 ${esc(totalCount)}건${page === 0 ? ' · 실시간 갱신' : ''}</span></div>
    <div class="table-wrap">
      <table>
        <thead><tr><th scope="col">최근 감지 시각</th><th scope="col">출처</th><th scope="col">감지 코드</th><th scope="col">A/B/O 단계</th><th scope="col">감지 횟수</th><th scope="col">판정</th><th scope="col">서버 조치</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7" class="empty">표시할 감지 기록이 없습니다.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="section-body desktop-pagination">
      <span>${page + 1} / ${pages}</span>
      <div class="actions">
        <button type="button" data-merged-detection-page="${page - 1}" ${page === 0 ? 'disabled' : ''}>이전</button>
        <button type="button" data-merged-detection-page="${page + 1}" ${page + 1 >= pages ? 'disabled' : ''}>다음</button>
      </div>
    </div>
  </section>`;
}
