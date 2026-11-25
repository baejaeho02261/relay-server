'use strict';
const adminSpacePalettes = new Set(['pure-black', 'blue-starlink', 'mint-orbit', 'violet-nebula',
  'amber-nova', 'eclipse', 'aurora', 'pulsar', 'deep-space', 'supernova']);
function setAdminPalette(value) {
  const selected = adminSpacePalettes.has(value) ? value : 'pure-black';
  document.documentElement.dataset.spacePalette = selected;
  const palette = document.getElementById('space-palette');
  if (palette) palette.value = selected;
  try { localStorage.setItem('spacex-palette', selected); } catch (_) {}
}
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
 if(meta)meta.content=selected==='dark'?'#000000':'#e9edf7';
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
let initialAdminTheme='dark',initialAdminMotion=false,initialAdminPalette='pure-black';
try{initialAdminTheme=localStorage.getItem('relay-admin-theme')||'dark';initialAdminMotion=localStorage.getItem('cozy-admin-motion')==='paused';initialAdminPalette=localStorage.getItem('spacex-palette');}catch(_){}
if(typeof window.matchMedia==='function'&&window.matchMedia('(prefers-reduced-motion: reduce)').matches)initialAdminMotion=true;
setAdminTheme(initialAdminTheme);setAdminMotion(initialAdminMotion);setAdminPalette(initialAdminPalette);
document.addEventListener('DOMContentLoaded',()=>{setAdminTheme(document.documentElement.dataset.theme);setAdminMotion(document.documentElement.dataset.motion==='paused');setAdminPalette(document.documentElement.dataset.spacePalette);});
document.addEventListener('click',event=>{
 if(event.target.closest('#theme-toggle'))setAdminTheme(document.documentElement.dataset.theme==='dark'?'light':'dark');
 if(event.target.closest('[data-motion-toggle]'))setAdminMotion(document.documentElement.dataset.motion!=='paused');
});

document.addEventListener('change', event => {
 if (event.target.id === 'space-palette') setAdminPalette(event.target.value);
});
