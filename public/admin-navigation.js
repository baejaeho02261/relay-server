'use strict';
// Navigation/form state stays independent of page rendering and API actions.
const dirtyViews = new Set();
content.addEventListener('input', event => {
  const el = event.target;
  if (el.matches('input:not([type=search]),textarea,select') &&
      !el.matches('.license-check,#license-check-all') &&
      !/search|filter|query|draft/.test(el.id)) dirtyViews.add(currentView);
});
content.addEventListener('change', event => {
  if (event.target.matches('select') && !/status|filter|expiry/.test(event.target.id)) dirtyViews.add(currentView);
  if (event.target.matches('.license-check,#license-check-all')) queueMicrotask(updateLicenseSelection);
});
function updateLicenseSelection() {
  const boxes = [...content.querySelectorAll('.license-check')];
  const checked = boxes.filter(x => selectedLicenses.has(x.dataset.key)).length;
  const all = document.getElementById('license-check-all');
  if (all) { all.checked = boxes.length > 0 && checked === boxes.length; all.indeterminate = checked > 0 && checked < boxes.length; }
  const button = document.getElementById('license-bulk-btn');
  if (button) { button.textContent = `선택 작업 (${selectedLicenses.size})`; button.disabled = !selectedLicenses.size; }
  const status = document.getElementById('license-selection-status');
  if (status) status.textContent = `필터 결과 ${boxes.length}개 · 선택 ${selectedLicenses.size}개`;
}
function resetServiceUi() {
  dirtyViews.clear(); selectedLicenses.clear(); clearQrSelectedFile(); qrScanResult = null;
  liveConsoleEvents.length = 0; consoleHistoryLoaded = false; traceRows.clear(); failoverRows.clear();
  terminalLines.length = 0;
  if (typeof resetSupportUiState === 'function') resetSupportUiState();
  if (modalEl && !modalEl.classList.contains('hidden')) modalCancel.click();
}
// Remember expanded sections independently from search, and restore their
// previous state after clearing a search. Native wheel/keyboard scrolling is used.
let navBeforeSearch = null;
navFilter?.addEventListener('input', () => {
  if (navFilter.value.trim()) {
    if (!navBeforeSearch) navBeforeSearch = [...nav.querySelectorAll('.nav-group')].map(g => g.dataset.expanded === 'true');
  } else if (navBeforeSearch) {
    [...nav.querySelectorAll('.nav-group')].forEach((g, i) => g.open = navBeforeSearch[i]);
    navBeforeSearch = null;
  }
});
nav.querySelectorAll('.nav-group').forEach(group => {
  group.dataset.expanded = String(group.open);
  group.addEventListener('toggle', () => { if (!navFilter?.value.trim()) group.dataset.expanded = String(group.open); });
  const items = group.querySelector('.nav-items');
  items.tabIndex = 0;
  items.setAttribute('aria-label', `${group.querySelector('summary').textContent} 메뉴`);
});

// Contextual navigation uses the existing view switch and role restrictions.
const navigationIcons = {
 dashboard:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
 support:'M21 11.5a8.5 8.5 0 0 1-8.5 8.5H5l-3 2v-9a9 9 0 0 1 18-1.5z M7 10h9 M7 14h6',
 notifications:'M5 17h14l-2-3V9a5 5 0 0 0-10 0v5z M10 20h4',
 monitor:'M3 4h18v13H3z M8 21h8 M12 17v4 M5 11h4l2-4 3 7 2-3h3',
 console:'M4 5h16v14H4z M7 9l3 3-3 3 M13 15h4',
 servers:'M4 3h16v7H4z M4 14h16v7H4z M7 6.5h.1 M7 17.5h.1 M11 6.5h6 M11 17.5h6',
 clients:'M7 2h10a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z M10 18h4',
 qrauth:'M3 3h6v6H3z M15 3h6v6h-6z M3 15h6v6H3z M15 15h3v3h3v3h-6z',
 licenses:'M4 3h16v18H4z M8 7h8 M8 11h8 M8 16h4',
 security:'M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6z M8 12l3 3 5-6',
 'member-profiles':'M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M4 21v-2a8 8 0 0 1 16 0v2',
 'member-products':'M8 7h8c4 0 6 5 5 11-.6 2-3 2-6-2H9c-3 4-5.4 4-6 2C2 12 4 7 8 7z M6 11v4 M4 13h4 M16 12h.1 M18 14h.1',
 'member-posts':'M5 3h14v18H5z M8 7h8 M8 11h8 M8 15h5',
 'member-comments':'M3 4h18v13H9l-6 4z M7 8h10 M7 12h6',
 'member-news':'M5 3h14v18H5z M8 6h8v4H8z M8 14h8 M8 17h5',
 'member-shop':'M3 8l2-5h14l2 5v3c-1 2-4 2-5 0-1 2-4 2-5 0-1 2-4 2-5 0-1 2-3 2-3 0z M5 13v8h14v-8 M10 21v-6h4v6',
 'member-rewards':'M4 5h16v16H4z M8 2v6 M16 2v6 M4 10h16 M8 15l3 3 5-5',
 'member-walletGrants':'M3 5h17v15H3z M15 10h6v6h-6z M17 13h.1',
 'member-orders':'M5 3h14v19l-3-2-4 2-4-2-3 2z M8 7h8 M8 11h8 M8 15h4',
 'member-ledger':'M5 3h14v18H5z M8 7h8 M8 11h8 M8 15h8 M8 18h4',
 'member-oauthAccounts':'M10 9a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M1 21v-2a5 5 0 0 1 10 0v2 M14 10l2 2 5-5 M15 17h6',
 'member-integrations':'M8 12l8-8 M13 3h6v6 M11 7H4v14h14v-7',
 'member-pointConversions':'M4 7h15l-4-4 M20 17H5l4 4',
 'member-policies':'M5 3h10l4 4v14H5z M14 3v5h5 M8 12h8 M8 16h6',
 'member-reports':'M5 21V3 M5 3h14l-3 5 3 5H5',
 'member-overview':'M4 20V9h4v11 M10 20V4h4v16 M16 20V12h4v8',
 settings:'M12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8 M9 3h6l1 3 3 1 2 5-2 5-3 1-1 3H9l-1-3-3-1-2-5 2-5 3-1z',
 history:'M3 11a9 9 0 1 1 2 7 M3 4v7h7 M12 7v6l4 2'
};
for (const button of nav.querySelectorAll('button[data-view]')) {
 const key=button.dataset.view;
 const family=/audit|history|activity|sessions|trace/.test(key)?'history':/security|enroll|biometric|block|danger/.test(key)?'security':'settings';
 const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
 svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('aria-hidden','true');svg.classList.add('nav-icon');
 const path=document.createElementNS(svg.namespaceURI,'path');path.setAttribute('d',navigationIcons[key]||navigationIcons[family]);svg.append(path);button.prepend(svg);
}
const workspaceTabs=document.getElementById('workspace-tabs');
function updateNavigationWorkspace(){
 const selected=[...nav.querySelectorAll('button[data-view]')].find(button=>button.dataset.view===currentView);
 nav.querySelectorAll('button[data-view]').forEach(button=>{if(button===selected)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');});
 const group=selected?.closest('.nav-group');
 const category=document.getElementById('page-category');
 if(category)category.textContent=group?.querySelector('summary')?.textContent||'운영 콘솔';
 if(!workspaceTabs)return;
 const items=group?[...group.querySelectorAll('button[data-view]')].filter(button=>!button.hidden&&!button.classList.contains('hidden')&&(!button.hasAttribute('data-admin-only')||roleIsAdmin())):[];
 const signature=items.map(button=>button.dataset.view).join('|')+'|'+currentView;
 if(workspaceTabs.dataset.signature===signature)return;
 workspaceTabs.dataset.signature=signature;
 workspaceTabs.replaceChildren(...items.map(source=>{
  const button=document.createElement('button');button.type='button';button.dataset.sectionView=source.dataset.view;
  const label=source.cloneNode(true);label.querySelectorAll('svg,.nav-count').forEach(node=>node.remove());button.textContent=label.textContent.trim();
  if(source===selected)button.setAttribute('aria-current','page');return button;
 }));
 const active=workspaceTabs.querySelector('[aria-current="page"]');
 if(active&&typeof active.scrollIntoView==='function')active.scrollIntoView({block:'nearest',inline:'nearest'});
}
workspaceTabs?.addEventListener('click',event=>{
 const button=event.target.closest('[data-section-view]');if(!button)return;
 const source=[...nav.querySelectorAll('button[data-view]')].find(item=>item.dataset.view===button.dataset.sectionView);
 if(!source||source.hidden||source.classList.contains('hidden')||(source.hasAttribute('data-admin-only')&&!roleIsAdmin()))return;
 closeMobileMenu();switchView(button.dataset.sectionView);renderCurrent();
});
navFilter?.addEventListener('input',()=>{
 const visible=[...nav.querySelectorAll('button[data-view]')].some(button=>!button.classList.contains('nav-filter-hidden')&&!button.classList.contains('hidden')&&!button.hidden);
 document.getElementById('nav-empty')?.classList.toggle('hidden',visible||!navFilter.value.trim());
});
