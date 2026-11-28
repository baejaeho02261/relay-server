'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../../public'),html=fs.readFileSync(path.join(root,'index.html'),'utf8');
const appearanceCatalog=fs.readFileSync(path.join(root,'scripts/interface/spacex.admin-appearance-catalog.js'),'utf8');
const appearance=fs.readFileSync(path.join(root,'scripts/interface/spacex.admin-appearance.js'),'utf8');
const orbit=fs.readFileSync(path.join(root,'scripts/interface/spacex.admin-login-space.js'),'utf8');
const atlas=JSON.parse(fs.readFileSync(path.join(root,'icons/login-atlas.json'),'utf8'));
function Open({reduce=false,blocked=false}={}){
 const dom=new JSDOM(html,{url:'https://admin.example.test/',runScripts:'outside-only',pretendToBeVisual:true}),w=dom.window;
 w.matchMedia=()=>({matches:reduce});
 if(blocked)Object.defineProperty(w,'localStorage',{get(){throw Error('STORAGE_BLOCKED');}});
 w.eval(appearanceCatalog+'\n'+appearance);return dom;
}
test('appearance controls remain operable when preferences cannot be stored',()=>{
 const dom=Open({blocked:true}),w=dom.window,d=w.document;
 try{
  assert.equal(d.documentElement.dataset.theme,'dark');
  assert.equal(d.documentElement.dataset.spacePalette,'pure-black');
  const palette=d.getElementById('space-palette');
  assert.equal(palette.options.length,10);
  palette.value='pulsar';palette.dispatchEvent(new w.Event('change',{bubbles:true}));
  assert.equal(d.documentElement.dataset.spacePalette,'pulsar');
  d.getElementById('theme-toggle').click();assert.equal(d.documentElement.dataset.theme,'light');assert.match(d.getElementById('theme-toggle').textContent,/다크 모드/);
  d.querySelector('[data-motion-toggle]').click();assert.equal(d.documentElement.dataset.motion,'paused');
  const controls=[...d.querySelectorAll('[data-motion-toggle]')];assert.ok(controls.every(x=>x.getAttribute('aria-pressed')==='true'));
  assert.equal(controls.length,1);
  controls[0].click();assert.equal(d.documentElement.dataset.motion,'running');
  assert.ok(d.getElementById('login-password').required);
  assert.equal(d.getElementById('passkey-login-btn'),null);
  assert.equal(d.querySelector('#login-form button[type="submit"]'),null);
 }finally{w.close();}
});
test('reduced motion is honored and administrator login has no role or pause selector',()=>{
 const dom=Open({reduce:true}),w=dom.window,d=w.document;
 try{
  assert.equal(d.documentElement.dataset.motion,'paused');
  assert.ok([...d.querySelectorAll('[data-motion-toggle]')].every(x=>x.getAttribute('aria-label')==='애니메이션 켜기'));
  assert.equal(d.getElementById('login-role').type,'hidden');
  assert.equal(d.getElementById('login-role').value,'admin');
  assert.equal(d.querySelector('#login-screen [data-motion-toggle]'),null);
  assert.equal(d.getElementById('login-password').autocomplete,'current-password');
 }finally{w.close();}
});
test('new shell retains every supported route and loads only existing local application assets',()=>{
 const dom=Open(),w=dom.window,d=w.document;
 try{
  const routes=[...d.querySelectorAll('#nav button[data-view]')].map(x=>x.dataset.view);
  assert.equal(routes.length,27);assert.equal(new Set(routes).size,routes.length);
  for(const route of ['desktop-licenses','dashboard','security','production','audit','sessions','backups','danger','simulator'])assert.ok(routes.includes(route));
  for(const retired of ['clients','licenses','qrauth','support','releases'])assert.ok(!routes.includes(retired));
  for(const node of d.querySelectorAll('link[rel="stylesheet"],script[src],img[src]')){
   const url=new URL(node.getAttribute('href')||node.getAttribute('src'),w.location.href);assert.equal(url.origin,w.location.origin);assert.ok(fs.existsSync(path.join(root,url.pathname)),url.pathname);
  }
  assert.equal(d.querySelectorAll('#modal [aria-modal="true"]').length,1);
  assert.ok(d.querySelector('#nav button[data-view="simulator"]').hasAttribute('data-admin-only'));
  assert.equal(d.querySelector('#login-screen .login-earth-fallback').getAttribute('src'),'/icons/earth.svg');
  assert.equal(d.getElementById('rail-toggle').getAttribute('aria-controls'),'main-menu');
  assert.equal(d.getElementById('menu-toggle').getAttribute('aria-controls'),'main-menu');
  assert.equal(d.getElementById('rail-close').parentElement.className,'sidebar-brand');
  assert.equal(d.querySelector('.aurora-rail-body #aurora-active-nav').textContent,'운영 개요');
  assert.ok(d.getElementById('aurora-rail-metrics').hidden);
  assert.equal(d.querySelector('.workspace-commandbar #page-title').textContent,'운영 개요');
  assert.equal(d.getElementById('workspace-tabs'),null);
  assert.ok(d.querySelector('[data-rail-desktop-tab="members"]').hasAttribute('data-admin-only'));
 }finally{w.close();}
});

test('Earth opens the masked editor, animates the native map, and clears the password on exit',async()=>{
 const dom=Open(),w=dom.window,d=w.document;
 try{
  const earth=d.getElementById('login-earth'),screen=d.getElementById('login-screen');
  const canvas=d.getElementById('login-space'),password=d.getElementById('login-password');
  const form=d.getElementById('login-form'),calls=[];
  const ctx=new Proxy({}, {
   get(target,key){return target[key]??((...args)=>{calls.push([key,...args]);});},
   set(target,key,value){target[key]=value;calls.push([key,value]);return true;}
  });
  canvas.getContext=()=>ctx;
  canvas.getBoundingClientRect=()=>({left:0,top:0});
  earth.getBoundingClientRect=()=>({left:450,top:200,width:300,height:300});
  Object.defineProperties(canvas,{clientWidth:{value:1200},clientHeight:{value:700}});
  let nextFrame=null,clock=0;
  w.performance.now=()=>clock;
  w.requestAnimationFrame=callback=>{nextFrame=callback;return 1;};
  w.fetch=async url=>{
   assert.equal(url,'/icons/login-atlas.json');
   return {ok:true,json:async()=>atlas};
  };
  const frame=now=>{const run=nextFrame;nextFrame=null;calls.length=0;assert.ok(run);clock=now;run(now);return calls.slice();};
  w.eval(orbit);
  await new Promise(resolve=>w.setTimeout(resolve,0));
  assert.ok(screen.classList.contains('login-atlas-ready'));
  assert.equal(form.hidden,true);
  const initial=frame(20);
  assert.ok(initial.filter(([name])=>name==='lineTo').length>2000);
  const animated=frame(75);
  assert.notDeepEqual(initial.find(([name])=>name==='arc'),animated.find(([name])=>name==='arc'));
  earth.dispatchEvent(new w.Event('pointerenter'));
  const hovered=frame(92);
  const mapColor=operations=>operations.find(([name,value])=>name==='strokeStyle'&&value.startsWith('rgb('))[1];
  assert.notEqual(mapColor(animated),mapColor(hovered),'Earth hover also changes every territory outline');
  earth.dispatchEvent(new w.Event('pointerleave'));
  earth.dispatchEvent(new w.MouseEvent('click',{bubbles:true}));
  assert.equal(earth.getAttribute('aria-expanded'),'true');
  assert.equal(form.hidden,false);
  assert.equal(d.activeElement,password);
  assert.equal(password.type,'password');
  const maskDots=operations=>operations.filter(([name,value])=>name==='fillStyle'&&value==='#e4f1ff').length;
  password.value='A';
  password.dispatchEvent(new w.Event('input',{bubbles:true}));
  assert.equal(maskDots(frame(110)),1,'the first ordinary key is visible on the next frame');
  const secret='LOCAL-SYNTHETIC-TEST-ONLY'.repeat(3).slice(0,64);
  password.value=secret;
  password.dispatchEvent(new w.InputEvent('input',{bubbles:true,inputType:'insertFromPaste'}));
  assert.equal(maskDots(frame(130)),64,'a long paste makes every mark visible immediately');
  for(let now=180;now<=950;now+=50)frame(now);
  const masked=frame(1000);
  assert.ok(masked.filter(([name])=>name==='arc').length>=animated.filter(([name])=>name==='arc').length+secret.length);
  assert.ok(!JSON.stringify(masked).includes(secret),'canvas must receive masks only');
  let submissions=0;
  form.addEventListener('submit',event=>{event.preventDefault();submissions++;});
  password.dispatchEvent(new w.KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
  earth.click();
  assert.equal(submissions,2,'Enter and a second Earth click both submit');
  const orbitControl=w.spacexLoginOrbit;
  orbitControl.begin();password.value='';
  assert.equal(password.readOnly,true);
  assert.equal(screen.getAttribute('aria-busy'),'true');
  const scanning=frame(1310);
  assert.ok(scanning.filter(([name])=>name==='lineTo').length>masked.filter(([name])=>name==='lineTo').length);
  assert.ok(!scanning.some(([name])=>name==='ellipse'),'a scan alone cannot enter the black hole');
  orbitControl.reject();
  assert.equal(password.readOnly,false);
  assert.equal(screen.getAttribute('aria-busy'),null);
  assert.equal(d.activeElement,password,'failed authentication permits immediate retry');
  password.value=secret;
  orbitControl.begin();password.value='';
  const timers=[];
  const realSetTimeout=w.setTimeout;
  w.setTimeout=(callback,ms)=>timers.push({callback,ms});
  const accepted=orbitControl.accept();
  assert.equal(timers[0].ms,660);
  clock+=timers[0].ms;
  timers.shift().callback();
  await Promise.resolve();
  assert.equal(timers[0].ms,580);
  assert.ok(frame(2210).some(([name])=>name==='ellipse'),'black hole follows the authenticated scan');
  timers.shift().callback();
  await accepted;
  w.setTimeout=realSetTimeout;
  screen.classList.add('hidden');
  await new Promise(resolve=>w.setTimeout(resolve,0));
  screen.classList.remove('hidden');
  earth.click();password.value=secret;
  password.dispatchEvent(new w.KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
  assert.equal(earth.getAttribute('aria-expanded'),'false');
  assert.equal(d.activeElement,earth);
  assert.equal(form.hidden,true);
  assert.equal(password.value,'');
  earth.click();password.value=secret;
  screen.classList.add('hidden');
  await new Promise(resolve=>w.setTimeout(resolve,0));
  assert.equal(password.value,'');
  assert.equal(form.hidden,true);
 }finally{w.close();}
});

test('shared layout keeps caption emphasis inline, metadata on separate lines and grid panels aligned',()=>{
 const styles=['admin-appearance.css','admin.css','admin-theme.css','admin-navigation.css','admin-controls.css','admin-workspace.css','admin-desktop.css','admin-members.css','spacex.css'].map(file=>fs.readFileSync(path.join(root,'styles',file),'utf8')).join('\n');
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

test('desktop appearance presets apply immediately and survive a workspace reload', async () => {
 const dom=Open(),w=dom.window,d=w.document;
 try{
  if(d.readyState==='loading')await new Promise(resolve=>d.addEventListener('DOMContentLoaded',resolve,{once:true}));
  assert.equal(d.documentElement.dataset.appearanceFont,'orbitron');
  assert.equal(d.getElementById('appearance-font').options.length,5);
  assert.equal(d.getElementById('appearance-language').options.length,250);
  assert.equal(d.getElementById('appearance-checkbox').options.length,8);
  const change=(id,value)=>{
   const select=d.getElementById(id);
   select.value=value;
   select.dispatchEvent(new w.Event('change',{bubbles:true}));
  };
  change('appearance-font','oxanium');
  change('appearance-checkbox','aurora-green');
  change('appearance-text','ion-cyan');
  change('appearance-language','ja-JP');
  assert.equal(d.documentElement.lang,'ja-JP');
  assert.equal(d.querySelector('[data-appearance-caption="2"]').textContent,'書体');
  assert.equal(d.documentElement.dataset.appearanceFont,'oxanium');
  assert.equal(d.documentElement.style.getPropertyValue('--admin-checkbox'),'#91ecbd');
  assert.equal(d.documentElement.style.getPropertyValue('--admin-ink'),'#7be7f1');
  const stars=d.getElementById('appearance-stars');
  stars.click();
  assert.equal(d.documentElement.dataset.stars,'hidden');
  for(const [key,value] of [['font','oxanium'],['checkbox','aurora-green'],['text','ion-cyan'],['language','ja-JP'],['stars','hidden']]){
   assert.equal(w.localStorage.getItem('spacex-admin-'+key),value);
  }
  const fresh=new JSDOM(html,{url:w.location.href,runScripts:'outside-only'});
  try{
   const restored=fresh.window;
   for(const key of Object.keys(w.localStorage))restored.localStorage.setItem(key,w.localStorage.getItem(key));
   restored.eval(appearanceCatalog+'\n'+appearance);
   assert.equal(restored.document.documentElement.dataset.appearanceFont,'oxanium');
   assert.equal(restored.document.documentElement.dataset.stars,'hidden');
   assert.equal(restored.document.documentElement.lang,'ja-JP');
  }finally{fresh.window.close();}
 }finally{w.close();}
});
