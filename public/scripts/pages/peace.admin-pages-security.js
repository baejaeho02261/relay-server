'use strict';

async function renderEnrollment() {
  if (!roleIsAdmin()) throw new Error('FORBIDDEN');
  const { enrollment:e } = await api('/api/enrollment');
  const rows=(e.records||[]).filter(r=>r.type==='SERVER').map(r=>`<tr><td><strong class="list-primary code">${esc(r.deviceKey)}</strong><small class="list-secondary">${badge(r.type)}</small></td><td>${badge(r.status)}</td><td><span class="list-primary code">${esc(r.requestId)}</span><small class="list-secondary">앱 ${esc(r.appVersion||'미확인')} · 프로토콜 ${r.protocolVersion||'미확인'}</small></td><td class="code">${esc(r.ip||'미확인')}</td><td><span class="list-primary code">${esc(r.assignedId||'아직 배정되지 않음')}</span><small class="list-secondary">${esc(fmtTime(r.lastSeenAt))}</small></td><td><div class="actions">${r.status==='PENDING'?`<button class="primary" data-enroll-decision="APPROVED" data-request-id="${esc(r.requestId)}">승인</button><button class="danger" data-enroll-decision="REJECTED" data-request-id="${esc(r.requestId)}">거절</button>`:''}<button data-enroll-reset="${esc(r.requestId)}">초기화</button></div></td></tr>`).join('');
  guardAdminViewCommit('enrollment');
  adminViewContent.html=`<div class="cards"><div class="card"><div class="stat-label">정책</div><div class="stat-value">${e.policy.enabled?"켜짐":"꺼짐"}</div><div class="stat-sub">기존 등록 기기는 정책 변경 후에도 재접속할 수 있습니다.</div></div><div class="card"><div class="stat-label">대기 중</div><div class="stat-value">${e.pending}</div></div><div class="card"><div class="stat-label">승인됨</div><div class="stat-value">${e.approved}</div></div><div class="card"><div class="stat-label">거절됨</div><div class="stat-value">${e.rejected}</div></div></div><div class="section-card"><div class="section-head"><h3>새 기기 승인</h3><div class="actions"><button id="enrollment-policy-btn" class="${e.policy.enabled?'warning':'primary'}">${e.policy.enabled?"승인 정책 끄기":"승인 정책 켜기"}</button></div></div><div class="section-body"><p class="muted">정책 켜짐 이후 처음 보는 기기 키만 대기 중 처리됩니다. 이미 등록된 서버는 재접속에 영향 없습니다.</p><div class="table-wrap"><table><thead><tr><th>기기</th><th>상태</th><th>요청 · 실행 버전</th><th>접속 IP</th><th>배정 · 마지막 확인</th><th>관리</th></tr></thead><tbody>${rows||"<tr><td colspan=\"6\" class=\"empty\">서버 등록 요청이 없습니다.</td></tr>"}</tbody></table></div></div></div>`;
}

async function renderSecurityCenter() {
  const [{ security:s }, networkResult] = await Promise.all([
    api('/api/security/dashboard'),
    api('/api/security/network')
  ]);
  const network = networkResult.summary || { total:0, changed:0, critical:0, warning:0, info:0 };
  const geo = networkResult.geo || {};
  const alerts=(s.alerts||[]).map(a=>`<div class="integrity-row">${badge(a.severity)}<span class="code">${esc(a.code)}</span><span>개수 ${a.count}</span><span>${esc(a.message||'')}</span></div>`).join('');
  const rows=(s.devices||[]).filter(d=>d.type==='SERVER').map(d=>{
    const age=d.hasSecret?(d.secretAgeUnknown?'UNKNOWN':`${d.secretAgeDays}d`):'-';
    const hmac=!d.capable?badge('LEGACY'):(d.verified?badge('VERIFIED'):badge(d.online?'UNVERIFIED':'OFFLINE'));
    const secret=!d.hasSecret?badge('NONE'):(d.secretStale?badge('STALE'):badge('OK'));
    return `<tr><td><strong class="list-primary code">${esc(d.id)}</strong><small class="list-secondary">${badge(d.type)}</small></td><td>${d.online?badge('ONLINE'):badge('OFFLINE')}<small class="list-secondary">${hmac}</small></td><td>${d.enforced?badge('ENFORCED'):badge('OPTIONAL')}</td><td>${secret}<small class="list-secondary">경과 ${esc(age)}</small></td><td>${esc(d.authStatus||'미확인')}<small class="list-secondary">교체 ${d.rotationStatus?badge(d.rotationStatus):'기록 없음'}</small></td><td>${d.verifiedAt?esc(fmtTime(d.verifiedAt)):'미검증'}</td></tr>`;
  }).join('');
  const networkRows=(networkResult.devices||[]).filter(n=>n.type==='SERVER').map(n=>{
    const current=n.current||{}, trusted=n.trusted||{};
    const location=[current.country,current.region,current.city].filter(Boolean).join(' / ')||'-';
    const trustedLocation=[trusted.country,trusted.region,trusted.city].filter(Boolean).join(' / ')||'-';
    const action=roleIsAdmin()?`<button data-network-trust data-type="${esc(n.type)}" data-id="${esc(n.id)}" ${n.changed?'':'disabled'}>현재 기준 신뢰</button>`:'-';
    return `<tr><td><strong class="list-primary code">${esc(n.id)}</strong><small class="list-secondary">${badge(n.type)}</small></td><td>${badge(n.status||'TRUSTED')}<small class="list-secondary">${n.severity?badge(n.severity):badge('OK')}</small></td><td><span class="list-primary code">현재 ${esc(current.ip||'미확인')}</span><small class="list-secondary code">기준 ${esc(trusted.ip||'미등록')}</small></td><td><span class="list-primary">${esc(location)}</span><small class="list-secondary">기준 ${esc(trustedLocation)}</small></td><td><span class="list-primary code">${esc(current.subnet||'미확인')}</span><small class="list-secondary code">기준 ${esc(trusted.subnet||'미등록')}</small></td><td>${n.changeCount||0}회<small class="list-secondary">${esc(fmtTime(n.lastChangeAt))}</small></td><td>${action}</td></tr>`;
  }).join('');
  guardAdminViewCommit('security');
  adminViewContent.html=`<div class="cards">
    <div class="card"><div class="stat-label">보안 점수</div><div class="stat-value">${s.score}</div><div class="stat-sub">${esc(s.label)}</div></div>
    <div class="card"><div class="stat-label">HMAC 검증 완료</div><div class="stat-value">${s.verified} / ${s.onlineHmacCapable}</div><div class="stat-sub">온라인 HMAC 지원</div></div>
    <div class="card"><div class="stat-label">네트워크 변경됨</div><div class="stat-value">${network.changed}</div><div class="stat-sub">긴급 ${network.critical} · 주의 ${network.warning}</div></div>
    <div class="card"><div class="stat-label">접속 위치</div><div class="stat-value">${geo.available?"준비됨":'FALLBACK'}</div><div class="stat-sub">${esc(geo.provider||'none')} · 외부 API 호출 없음</div></div>
    <div class="card"><div class="stat-label">인증키 경과 시간</div><div class="stat-value">${s.staleSecrets}</div><div class="stat-sub">90일 이상 · 확인 전 ${s.unknownSecretAge}</div></div>
    <div class="card"><div class="stat-label">이전 방식</div><div class="stat-value">${s.legacy}</div><div class="stat-sub">활성 교체 작업 ${s.activeRotations}</div></div>
  </div>
  <div class="section-card"><div class="section-head"><h3>보안 알림</h3>${badge(s.label)}</div><div class="section-body">${alerts||"<div class=\"integrity-ok\">현재 보안 경고가 없습니다.</div>"}</div></div>
  <div class="section-card"><div class="section-head"><h3>기기별 보안 상태</h3><span class="small-note">HMAC / 기기 등록 / 인증키 경과 시간 / 인증키 교체</span></div><div class="section-body"><div class="table-wrap"><table><thead><tr><th>서버</th><th>연결 · HMAC</th><th>정책</th><th>인증키</th><th>인증 · 교체 상태</th><th>마지막 검증</th></tr></thead><tbody>${rows||"<tr><td colspan=\"6\" class=\"empty\">등록된 서버가 없습니다.</td></tr>"}</tbody></table></div></div></div>
  <div class="section-card"><div class="section-head"><h3>신뢰하는 네트워크 기준</h3><span class="small-note">국가=긴급 · 서브넷=주의 · IP=안내 · 자동 차단 없음</span></div><div class="section-body"><div class="table-wrap"><table><thead><tr><th>서버</th><th>판정</th><th>IP · 신뢰 기준</th><th>위치 · 신뢰 기준</th><th>서브넷 · 신뢰 기준</th><th>변경 이력</th><th>관리</th></tr></thead><tbody>${networkRows||"<tr><td colspan=\"7\" class=\"empty\">등록된 네트워크 프로필이 없습니다.</td></tr>"}</tbody></table></div></div></div>`;
}

async function renderProtocolSecurity() {
  const [{ readiness }, { devices: security }, { devices: sequences }, { rotations }] = await Promise.all([
    api('/api/control/protocol-readiness'), api('/api/control/security'), api('/api/control/sequences'), api('/api/control/security/rotations')
  ]);
  const secMap = new Map((security || []).map(x => [`${x.type}:${x.id}`, x]));
  const seqMap = new Map((sequences || []).map(x => [`${x.type}:${x.id}`, x]));
  const rotationMap = new Map((rotations || []).map(x => [`${x.type}:${x.id}`, x]));
  const rows = (readiness.devices || []).filter(d=>d.type==='SERVER').map(r => {
    const key = `${r.type}:${r.id}`;
    const sec = secMap.get(key) || {};
    const seq = seqMap.get(key) || {};
    const st = seq.stats || {};
    const rot = rotationMap.get(key) || null;
    const actions = roleIsAdmin() && sec.online ? `<div class="actions"><button data-security-challenge data-type="${esc(r.type)}" data-id="${esc(r.id)}">인증 요청</button><button class="warning" data-security-rotate data-type="${esc(r.type)}" data-id="${esc(r.id)}">인증키 교체</button><button class="danger" data-security-reset data-type="${esc(r.type)}" data-id="${esc(r.id)}">재등록</button></div>` : '-';
    return `<tr><td><strong class="list-primary code">${esc(r.id)}</strong><small class="list-secondary">${badge(r.type)}</small></td><td>${r.ready ? badge('READY') : badge('BLOCKED')}<small class="list-secondary">${esc((r.profile && `${r.profile.current} → ${r.profile.candidate}`) || '프로필 미확인')}</small></td><td>${sec.hasSecret ? badge('ENROLLED') : badge('NONE')}<small class="list-secondary">${sec.verified ? badge('VERIFIED') : badge(sec.online ? 'UNVERIFIED' : 'OFFLINE')}</small></td><td>${sec.enforced ? badge('ENFORCED') : badge('OPTIONAL')}<small class="list-secondary">교체 ${rot ? badge(rot.status) : badge('NONE')}</small></td><td>${seq.capable ? badge(seq.enabled ? 'ON' : 'OFF') : badge('LEGACY')}<small class="list-secondary">최근 ${st.rxLast || 0} · 누락 ${st.rxMissing || 0}</small><small class="list-secondary">중복 ${st.rxDuplicates || 0} · 순서 어긋남 ${st.rxOutOfOrder || 0}</small></td><td>${esc((r.blockers || []).join(', ') || '없음')}</td><td>${actions}</td></tr>`;
  }).join('');
  const verified = (security || []).filter(x => x.verified).length;
  const enrolled = (security || []).filter(x => x.hasSecret).length;
  const missing = (sequences || []).reduce((a,x)=>a+Number(x.stats&&x.stats.rxMissing||0),0);
  const anomalies = (sequences || []).reduce((a,x)=>a+Number(x.stats&&x.stats.rxDuplicates||0)+Number(x.stats&&x.stats.rxOutOfOrder||0),0);
  guardAdminViewCommit('protocol');
  adminViewContent.html = `<div class="cards">
    <div class="card"><div class="stat-label">V3 준비 완료</div><div class="stat-value">${readiness.ready} / ${readiness.total}</div><div class="stat-sub">후보 프로토콜 ${readiness.candidateProtocol}</div></div>
    <div class="card"><div class="stat-label">HMAC 검증 완료</div><div class="stat-value">${verified}</div><div class="stat-sub">등록됨 ${enrolled}</div></div>
    <div class="card"><div class="stat-label">이벤트 순서 누락</div><div class="stat-value">${missing}</div><div class="stat-sub">탐지한 누락</div></div>
    <div class="card"><div class="stat-label">이벤트 순서 이상 징후</div><div class="stat-value">${anomalies}</div><div class="stat-sub">중복 / 순서 어긋남</div></div>
  </div><div class="section-card"><div class="section-head"><h3>프로토콜 준비 · 기기 보안</h3><span class="small-note">서버가 보고한 프로토콜 준비 상태와 인증·이벤트 순서를 함께 확인합니다.</span></div><div class="section-body"><div class="table-wrap"><table><thead><tr><th>서버</th><th>프로토콜 준비</th><th>인증키 · HMAC</th><th>정책 · 인증키 교체</th><th>이벤트 순서</th><th>차단 요인</th><th>관리</th></tr></thead><tbody>${rows || "<tr><td colspan=\"7\" class=\"empty\">등록된 서버가 없습니다.</td></tr>"}</tbody></table></div></div></div>`;
}

