'use strict';
async function handleAccessAction(event) {
    const openViewBtn = event.target.closest('[data-open-view]');
    if (openViewBtn) { switchView(openViewBtn.dataset.openView); await renderCurrent(); return true; }
    const historyClean = event.target.closest('[data-history-clean]');
    if (historyClean) {
      const scope = historyClean.dataset.historyClean;
      const v = await openModal({ title: "이력 이력 정리", message: `${scope} 종료 이력을 정리합니다. 진행 중인 요청 및 활성 실패 보관함는 보존됩니다.`, danger: true, confirmLabel: "이력 정리" });
      if (!v) return true;
      await api('/api/history/clean', { method: 'POST', body: { scope } });
      toast(`${scope} 이력 정리 완료`);
      await renderCurrent();
      return true;
    }
  return false;
}
