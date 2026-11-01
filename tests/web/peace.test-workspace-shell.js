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
