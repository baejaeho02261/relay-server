'use strict';

async function serverAction(action, id) {
  const encodedId = encodeURIComponent(id);
  if (action === 'detail') {
    const { server } = await api(`/api/servers/${encodedId}`);
    await openModal({ title: `서버 ${id}`, html: `<div class="kv"><div>별칭</div><div>${esc(server.alias || '-')}</div><div>메모</div><div>${esc(server.note || '-')}</div><div>기기 키</div><div class="code">${esc(server.deviceKey)}</div><div>상태</div><div>${badge(server.status)}</div><div>상태</div><div>${badge(server.health)}</div><div>왕복 지연</div><div>${server.rttMs >= 0 ? `${server.rttMs} ms` : '-'}</div><div>연결 차단 해제 시각</div><div>${esc(fmtTime(server.kickedUntil))}</div><div>IP</div><div>${esc(server.lastIP || '-')}</div><div>프로토콜 / 버전</div><div>${server.protocolVersion || '-'} / ${esc(server.appVersion || '-')}</div><div>재연결 중</div><div>${server.reconnectCount}</div><div>마지막 확인</div><div>${esc(fmtTime(server.lastSeen))}</div></div>`, confirmLabel: '닫기' });
    return;
  }

  if (action === 'alias') {
    const { server } = await api(`/api/servers/${encodedId}`);
    const v = await openModal({ title: "서버 별칭", message: `${id} 표시용 별칭입니다. 실제 서버 식별자는 변경되지 않습니다.`, fields: [{ name: 'alias', label: "별칭", value: server.alias || '', placeholder: 'OFFICE-PC-01' }], confirmLabel: '저장' });
    if (!v) return;
    await api(`/api/servers/${encodedId}/alias`, { method: 'POST', body: v });
    toast("서버 별칭 저장");
    await renderServers();
    return;
  }

  if (action === 'note') {
    const { server } = await api(`/api/servers/${encodedId}`);
    const v = await openModal({ title: "서버 메모", message: `${id} 운영 메모입니다.`, fields: [{ name: 'note', label: "메모", type: 'textarea', value: server.note || '', placeholder: '고객사 / 위치 / 장비 교체 이력 등' }], confirmLabel: '저장' });
    if (!v) return;
    await api(`/api/servers/${encodedId}/note`, { method: 'POST', body: v });
    toast("서버 메모 저장"); await renderServers(); return;
  }

  if (action === 'delete') {
    const v = await openModal({ title: "서버 삭제", message: `${id}\nSERVER-식별자, HMAC, 고정 실행 바인딩과 종속 설정을 삭제합니다. 같은 EXE가 다시 접속하면 신규 서버 등록으로 처리됩니다.`, danger: true, confirmLabel: "삭제" });
    if (!v) return;
    const r = await api(`/api/servers/${encodedId}`, { method: 'DELETE', body: {} });
    toast(`서버 삭제 · released ${r.releasedClients} · reassigned ${r.reassignedClients}`);
    await renderServers();
    return;
  }

  let body = {};
  if (action === 'kick') {
    const v = await openModal({ title: "서버 연결 차단", message: `${id} 연결을 끊고 60초 동안 재등록을 차단합니다.`, confirmLabel: "연결 차단" });
    if (!v) return;
  } else if (action === 'drain-on') {
    const v = await openModal({ title: "연결 정리 켜짐", message: `${id}에 신규 앱 기기 배정을 중지합니다. 기존 앱 기기는 유지됩니다.`, confirmLabel: '적용' });
    if (!v) return;
  } else if (action === 'disable') {
    const v = await openModal({ title: "서버 비활성화", message: `${id} 서버를 비활성화하고 현재 연결을 종료합니다. 계속하시겠습니까?`, danger: true, confirmLabel: "비활성화" });
    if (!v) return;
  }

  await api(`/api/servers/${encodedId}/${action}`, { method: 'POST', body });
  toast(`서버 ${action}: ${id}`);
  await renderServers();
}

