'use strict';
// Display preferences contain no account, license or operational data.
function setAdminTheme(theme){
 const selected=theme==='dark'?'dark':'light';
 document.documentElement.dataset.theme=selected;
 document.documentElement.style.colorScheme=selected;
 try{localStorage.setItem('relay-admin-theme',selected);}catch(_){}
 const button=document.getElementById('theme-toggle');
 if(button){
  const label=selected==='dark'?'라이트 모드':'다크 모드';
  const text=button.querySelector('[data-theme-label]');
  if(text)text.textContent=label;else button.textContent=label;
  button.setAttribute('aria-label',label+'로 전환');button.setAttribute('aria-pressed',String(selected==='dark'));
 }
 const meta=document.querySelector('meta[name="theme-color"]');
 if(meta)meta.content=selected==='dark'?'#131c19':'#f5f6f3';
}
function setAdminMotion(paused){
 document.documentElement.dataset.motion=paused?'paused':'running';
 try{localStorage.setItem('cozy-admin-motion',paused?'paused':'running');}catch(_){}
 document.querySelectorAll('[data-motion-toggle]').forEach(button=>{
  const label=paused?'애니메이션 켜기':'애니메이션 끄기';
  const text=button.querySelector('[data-motion-label]');
  if(text)text.textContent=label;else button.textContent=label;
  button.setAttribute('aria-label',label);button.title=label;button.setAttribute('aria-pressed',String(paused));
 });
}
let initialAdminTheme='light',initialAdminMotion=false;
try{initialAdminTheme=localStorage.getItem('relay-admin-theme')||'light';initialAdminMotion=localStorage.getItem('cozy-admin-motion')==='paused';}catch(_){}
if(typeof window.matchMedia==='function'&&window.matchMedia('(prefers-reduced-motion: reduce)').matches)initialAdminMotion=true;
setAdminTheme(initialAdminTheme);setAdminMotion(initialAdminMotion);
document.addEventListener('DOMContentLoaded',()=>{setAdminTheme(document.documentElement.dataset.theme);setAdminMotion(document.documentElement.dataset.motion==='paused');});
document.addEventListener('click',event=>{
 if(event.target.closest('#theme-toggle'))setAdminTheme(document.documentElement.dataset.theme==='dark'?'light':'dark');
 if(event.target.closest('[data-motion-toggle]'))setAdminMotion(document.documentElement.dataset.motion!=='paused');
});
