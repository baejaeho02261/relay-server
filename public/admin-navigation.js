'use strict';
// Navigation/form state stays independent of page rendering and API actions.
const dirtyViews = new Set();
content.addEventListener('input', event => {
  const el = event.target;
  if (el.matches('input:not([type=search]),textarea,select') &&
      !/search|filter|query|draft/.test(el.id)) dirtyViews.add(currentView);
});
content.addEventListener('change', event => {
  if (event.target.matches('select') && !/status|filter|expiry/.test(event.target.id)) dirtyViews.add(currentView);
});
function resetServiceUi() {
  dirtyViews.clear();
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
 dashboard:'M5 5h5v8H5z M14 5h5v4h-5z M5 17h5v2H5z M14 13h5v6h-5z',
 notifications:'M8 18h8 M10 21h4 M6 15l1-2V9a5 5 0 0 1 10 0v4l1 2H6 M12 3V2',
 monitor:'M6 5h12a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2 M9 21h6 M12 18v3 M7 12h2l2-3 2 6 2-3h2',
 console:'M5 5h14v14H5z M5 9h14 M8 12l2 2-2 2 M13 16h3',
 servers:'M5 5h14v6H5z M5 15h14v4H5z M8 8h.01 M11 8h5 M8 17h.01 M11 17h5',
 'desktop-licenses':'M7 4h8l3 3v13H6V4h1 M14 4v4h4 M9 12h6 M9 16h3',
 security:'M12 3l7 3v5c0 5-7 9-7 9s-7-4-7-9V6z M9 11l2 2 4-4',
 settings:'M5 7h14 M5 17h14 M8 5v4 M16 15v4 M5 12h14 M13 10v4',
 history:'M6 7a8 8 0 1 1-2 7 M3 4v5h5 M12 8v5l3 2',
 trace:'M5 5h5v5H5z M14 14h5v5h-5z M10 7h4a3 3 0 0 1 3 3v4 M7 10v4a3 3 0 0 0 3 3h4',
 recovery:'M5 10a7 7 0 1 1 1 8 M5 5v5h5 M9 13h6 M12 10v6',
 processors:'M8 5h8v14H8z M4 8h4 M4 12h4 M4 16h4 M16 8h4 M16 12h4 M16 16h4 M11 9h2v6h-2z',
 terminal:'M5 6h14v12H5z M8 10l2 2-2 2 M13 14h3',
 releases:'M12 3v11 M8 10l4 4 4-4 M5 15v5h14v-5 M5 5h3 M16 5h3',
 production:'M5 7h14 M5 17h14 M8 5v4 M16 15v4 M5 12h14 M13 10v4',
 features:'M5 6h6v4H5z M15 6h4 M13 14h6v4h-6z M5 16h4',
 confighistory:'M6 7a8 8 0 1 1-2 7 M3 4v5h5 M12 8v5l3 2',
 enrollment:'M5 5h14v14H5z M12 8v8 M8 12h8',
 protocol:'M5 7h14 M16 4l3 3-3 3 M19 17H5 M8 14l-3 3 3 3',
 reports:'M5 4h10l4 4v12H5z M14 4v5h5 M8 16v-3 M12 16v-5 M16 16v-2',
 audit:'M6 4h12v16H6z M9 8h6 M9 12h6 M9 16h3',
 activity:'M4 12h4l3-7 3 14 3-7h3',
 sessions:'M9 4h10v16H9 M4 12h10 M11 9l3 3-3 3',
 backups:'M5 4h14v5H5z M6 9v11h12V9 M10 13h4 M12 13v4',
 health:'M12 20S4 15 4 9a4 4 0 0 1 8-1 4 4 0 0 1 8 1c0 6-8 11-8 11 M7 12h3l2-3 2 6 2-3h2',
 ha:'M5 4h5v7H5z M14 13h5v7h-5z M14 5h4v4 M18 5l-5 5 M10 19H6v-4 M6 19l5-5',
 storage:'M5 6c0-3 14-3 14 0s-14 3-14 0 M5 6v12c0 3 14 3 14 0V6 M5 12c0 3 14 3 14 0',
 system:'M4 5h16v12H4z M8 21h8 M12 17v4 M8 9h3 M8 13h8 M14 9h2',
 danger:'M12 4 3 20h18z M12 10v4 M12 17h.01'
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
