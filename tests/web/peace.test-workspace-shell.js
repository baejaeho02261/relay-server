'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../../public'),html=fs.readFileSync(path.join(root,'index.html'),'utf8');
const appearance=fs.readFileSync(path.join(root,'scripts/interface/peace.admin-appearance.js'),'utf8');
function Open({reduce=false,blocked=false}={}){
 const dom=new JSDOM(html,{url:'https://admin.example.test/',runScripts:'outside-only'}),w=dom.window;
 w.matchMedia=()=>({matches:reduce});
 if(blocked)Object.defineProperty(w,'localStorage',{get(){throw Error('STORAGE_BLOCKED');}});
 w.eval(appearance);return dom;
}
test('appearance controls remain operable when preferences cannot be stored',()=>{
 const dom=Open({blocked:true}),w=dom.window,d=w.document;
 try{
  assert.equal(d.documentElement.dataset.theme,'light');
  d.getElementById('theme-toggle').click();assert.equal(d.documentElement.dataset.theme,'dark');assert.match(d.getElementById('theme-toggle').textContent,/라이트 모드/);
  d.querySelector('[data-motion-toggle]').click();assert.equal(d.documentElement.dataset.motion,'paused');
  const controls=[...d.querySelectorAll('[data-motion-toggle]')];assert.ok(controls.every(x=>x.getAttribute('aria-pressed')==='true'));
  controls[1].click();assert.equal(d.documentElement.dataset.motion,'running');
  assert.ok(d.getElementById('login-password').required);assert.equal(d.getElementById('passkey-login-btn').type,'button');
 }finally{w.close();}
});
test('reduced motion is honored before login and both motion controls stay synchronized',()=>{
 const dom=Open({reduce:true}),w=dom.window,d=w.document;
 try{
  assert.equal(d.documentElement.dataset.motion,'paused');
  assert.ok([...d.querySelectorAll('[data-motion-toggle]')].every(x=>x.getAttribute('aria-label')==='애니메이션 켜기'));
  assert.equal(d.getElementById('login-role').options.length,3);
  assert.equal(d.getElementById('login-password').autocomplete,'current-password');
 }finally{w.close();}
});
test('new shell retains every supported route and loads only existing local application assets',()=>{
 const dom=Open(),w=dom.window,d=w.document;
 try{
  const routes=[...d.querySelectorAll('#nav button[data-view]')].map(x=>x.dataset.view);
  assert.equal(routes.length,26);assert.equal(new Set(routes).size,routes.length);
  for(const route of ['desktop-licenses','dashboard','security','production','audit','sessions','backups','danger'])assert.ok(routes.includes(route));
  for(const retired of ['clients','licenses','qrauth','support','releases'])assert.ok(!routes.includes(retired));
  for(const node of d.querySelectorAll('link[rel="stylesheet"],script[src],img[src]')){
   const url=new URL(node.getAttribute('href')||node.getAttribute('src'),w.location.href);assert.equal(url.origin,w.location.origin);assert.ok(fs.existsSync(path.join(root,url.pathname)),url.pathname);
  }
  assert.equal(d.querySelectorAll('#modal [aria-modal="true"]').length,1);
 }finally{w.close();}
});

test('shared layout keeps caption emphasis inline, metadata on separate lines and grid panels aligned',()=>{
 const styles=['admin-appearance.css','admin.css','admin-theme.css','admin-navigation.css','admin-controls.css','admin-workspace.css','admin-desktop.css','admin-members.css'].map(file=>fs.readFileSync(path.join(root,'styles',file),'utf8')).join('\n');
 const dom=new JSDOM('<!doctype html><style>'+styles+'</style><div class="main"><main class="content"><div class="cards production-summary"></div><div class="production-grid" id="groups"><section class="section-card"></section><section class="section-card" id="second"></section></div><div class="section-body"><label id="caption">확인한 뒤 <strong>전체 초기화</strong> 입력<input id="field"></label><div class="actions" id="submit"><button>실행</button></div></div><table><tbody><tr><td><span>ON</span><small class="list-secondary" id="first-line">최근 123 · 누락 2</small><small class="list-secondary" id="second-line">중복 3 · 순서 어긋남 4</small></td></tr></tbody></table></main></div>');
 const {window:w}=dom,style=id=>w.getComputedStyle(w.document.getElementById(id));
 try{
  w.document.getElementById('field').focus();
  assert.equal(style('caption').display,'block','mixed label text must stay in one caption line');
  assert.equal(style('field').display,'block');assert.equal(style('field').marginTop,'8px');
  assert.equal(style('field').outlineOffset,'-2px');assert.equal(style('field').boxShadow,'none');
  assert.equal(style('submit').marginTop,'18px','a control outline needs space before its action row');
  assert.equal(style('second').marginTop,'0px','the second grid panel must use the grid gap, not an extra flow margin');
  assert.equal(w.getComputedStyle(w.document.querySelector('.content')).display,'flex');
  assert.equal(w.getComputedStyle(w.document.querySelector('.content')).gap,'22px','all root groups need one shared vertical gap');
  assert.equal(style('groups').marginTop,'0px','root groups must not add flow margins on top of the stack gap');
  assert.equal(style('groups').flexShrink,'0','scrolling must not shrink root panel heights');
  assert.equal(style('first-line').display,'block');assert.equal(style('second-line').display,'block');
 }finally{w.close();}
});

test('mobile metric typography leaves room for full nine-digit formatted counts in two columns',()=>{
 const dom=new JSDOM('<!doctype html><style>'+['admin.css','admin-desktop.css'].map(file=>fs.readFileSync(path.join(root,'styles',file),'utf8')).join('\n')+'</style>');
 try{
  const mobileRules=[...dom.window.document.styleSheets[0].cssRules].filter(rule=>/max-width:\s*760px/.test(rule.conditionText||''));
  for(const selector of ['.stat-value','.desktop-stat strong']){
   const rule=mobileRules.flatMap(group=>[...group.cssRules]).find(item=>item.selectorText===selector);
   assert.ok(rule,'missing mobile metric rule: '+selector);
   const sizing=rule.style.fontSize.match(/^clamp\(([\d.]+)px,\s*([\d.]+)vw,\s*([\d.]+)px\)$/);
   assert.ok(sizing,'metric typography must keep an explicit mobile size range');
   const [,min,fluid,max]=sizing.map(Number),fontAt380=Math.max(min,Math.min(3.8*fluid,max));
   assert.ok(min<=20&&fontAt380<=21,'full 987,654,321 must fit the measured mobile card width');
  }
 }finally{dom.window.close();}
});
