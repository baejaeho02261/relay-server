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
  liveConsoleEvents.length = 0; consoleHistoryLoaded = false; traceRows.clear();
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
 notifications:'M5 17h14l-2-3V9a5 5 0 0 0-10 0v5z M10 20h4',
 monitor:'M3 4h18v13H3z M8 21h8 M12 17v4 M5 11h4l2-4 3 7 2-3h3',
 console:'M4 5h16v14H4z M7 9l3 3-3 3 M13 15h4',
 servers:'M4 3h16v7H4z M4 14h16v7H4z M7 6.5h.1 M7 17.5h.1 M11 6.5h6 M11 17.5h6',
 'desktop-licenses':'M4 3h16v18H4z M8 7h8 M8 11h8 M8 16h4',
 security:'M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6z M8 12l3 3 5-6',
 settings:'M12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8 M9 3h6l1 3 3 1 2 5-2 5-3 1-1 3H9l-1-3-3-1-2-5 2-5 3-1z',
 history:'M3 11a9 9 0 1 1 2 7 M3 4v7h7 M12 7v6l4 2'
};
for (const button of nav.querySelectorAll('button[data-view]')) {
 const key=button.dataset.view;
 const family=/audit|history|activity|sessions|trace/.test(key)?'history':/security|enroll|block|danger/.test(key)?'security':'settings';
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
