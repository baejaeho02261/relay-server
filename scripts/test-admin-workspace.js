'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm'),{Readable}=require('node:stream');
const {JSDOM,VirtualConsole}=require('jsdom');
const root=path.resolve(__dirname,'..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-admin-workspace-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.NODE_ENV='test';
require('../core/utils').EnsureDirs();
const api=require('../web/webApi'),store=require('../services/member/store');
const source=fs.readFileSync(root+'/public/index.html','utf8'),windows=[];
async function workspace(role){
 const errors=[],vc=new VirtualConsole();vc.on('jsdomError',e=>errors.push(e.message));
 const dom=new JSDOM(source.replace(/<script[^>]*>[\s\S]*?<\/script>/g,'').replace(/<link[^>]*>/g,''),{url:'https://fixture.invalid',runScripts:'outside-only',virtualConsole:vc}),w=dom.window;windows.push(w);
 w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;w.matchMedia=()=>({matches:false,addListener(){}});w.EventSource=class{addEventListener(){}close(){}};
 const sent=[];
 w.fetch=async(url,options={})=>{
  if(url==='/api/session')return {status:200,ok:true,text:async()=>JSON.stringify({role,csrf:'TEST',expiresAt:Date.now()+100000})};
  const req=Readable.from(options.body?[Buffer.from(options.body)]:[]);Object.assign(req,{url,method:options.method||'GET',headers:{},socket:{remoteAddress:'127.0.0.1'}});
  let status,text;await api.HandleApiRequest(req,{writeHead(n){status=n;},end(v){text=v;}},{role,id:'DOM_WORKSPACE'});
  if(options.body)sent.push(JSON.parse(options.body));return {status,ok:status>=200&&status<300,text:async()=>text};
 };
 for(const m of source.matchAll(/<script src="\/([^?]+)\?/g))new vm.Script(fs.readFileSync(root+'/public/'+m[1],'utf8')).runInContext(dom.getInternalVMContext());
 await new Promise(resolve=>setTimeout(resolve,40));return {w,errors,sent};
}
const settle=()=>new Promise(resolve=>setTimeout(resolve,35));
(async()=>{try{
 const {w,errors,sent}=await workspace('admin'),d=w.document,content=d.querySelector('#content'),tabs=d.querySelector('#workspace-tabs');
 assert.equal(d.querySelector('#main-menu .sidebar-footer .ui-refresh-link').getAttribute('href'),'/ui-refresh','Footer refresh belongs to sidebar, not a separate document row');
 assert.equal(d.querySelectorAll('#nav button[data-view] .nav-icon').length,d.querySelectorAll('#nav button[data-view]').length);
 assert.equal(tabs.querySelector('[aria-current="page"]').dataset.sectionView,'dashboard');
 assert.equal(d.querySelector('#page-category').textContent,'관제');
 tabs.querySelector('[data-section-view="monitor"]').click();await settle();
 assert.equal(d.querySelector('#nav [aria-current="page"]').dataset.view,'monitor');
 assert.equal(d.querySelector('#page-title').textContent,'연결 상태');
 content.scrollTop=184;content.scrollLeft=21;const snap=w.captureScrollState('monitor');content.scrollTop=0;content.scrollLeft=0;w.restoreScrollState(snap);
 assert.equal(content.scrollTop,184);assert.equal(content.scrollLeft,21);
 d.querySelector('#nav [data-view="member-shop"]').click();await settle();
 assert.equal(content.scrollTop,0);assert.equal(d.querySelector('#page-category').textContent,'앱 콘텐츠');
 assert.equal(tabs.querySelector('[aria-current="page"]').dataset.sectionView,'member-shop');
 for(const label of ['댓글 이용권','리포스트 이용권','공유 이용권'])assert.ok(content.textContent.includes(label));
 d.querySelector('[data-member-action="shop.edit"]').click();await settle();
 for(const id of ['NICKNAME_TICKET','NICKNAME_COLOR','COMMENT_TICKET','REPOST_TICKET','SHARE_TICKET']){
  const enabled=d.querySelector(`[data-modal-field="${id}_enabled"]`),price=d.querySelector(`[data-modal-field="${id}_price"]`);assert.ok(enabled&&price,id);
  enabled.value='true';price.value=id==='COMMENT_TICKET'?'7':'11';
 }
 d.querySelector('#modal-confirm').click();await settle();
 const shop=sent.find(x=>x.action==='shop.save');assert.deepEqual(Object.keys(shop.items).sort(),['COMMENT_TICKET','NICKNAME_COLOR','NICKNAME_TICKET','REPOST_TICKET','SHARE_TICKET']);assert.equal(shop.items.COMMENT_TICKET.price,7);
 assert.equal(require('../services/member/customization').Rules().items.COMMENT_TICKET.price,7);
 tabs.querySelector('[data-section-view="member-rewards"]').click();await settle();
 assert.equal(d.querySelector('[data-section-view="member-rewards"]').getAttribute('aria-current'),'page');
 assert.ok(!content.textContent.includes('돌림판'));assert.ok(content.textContent.includes('출석'));
 d.querySelector('[data-member-action="rewards.edit"]').click();await settle();
 assert.equal(d.querySelector('[data-modal-field="enabled"]'),null);assert.equal(d.querySelector('[data-modal-field="points0"]'),null);
 d.querySelector('[data-modal-field="attendanceDays"]').value='7';d.querySelector('[data-modal-field="attendancePoints"]').value='123';
 d.querySelector('#modal-confirm').click();await settle();
 const rewards=sent.find(x=>x.action==='rewards.save');assert.equal(rewards.attendancePoints,123);assert.ok(!Object.hasOwn(rewards,'enabled'));assert.ok(!Object.hasOwn(rewards,'prizes'));
 const search=d.querySelector('#nav-filter');search.value='카카오';search.dispatchEvent(new w.Event('input',{bubbles:true}));
 assert.ok(!d.querySelector('[data-view="member-oauthAccounts"]').classList.contains('nav-filter-hidden'));
 search.value='없는기능검색';search.dispatchEvent(new w.Event('input',{bubbles:true}));assert.equal(d.querySelector('#nav-empty').classList.contains('hidden'),false);
 search.value='';search.dispatchEvent(new w.Event('input',{bubbles:true}));assert.equal(d.querySelector('#nav-empty').classList.contains('hidden'),true);
 assert.equal(errors.length,0,errors.join('\n'));
 const viewer=await workspace('viewer');assert.equal(viewer.errors.length,0,viewer.errors.join('\n'));
 assert.equal(viewer.w.document.querySelector('#workspace-tabs [data-section-view="support"]'),null,'Context tabs cannot expose admin-only destinations');
 assert.equal(viewer.w.document.querySelector('#workspace-tabs [data-section-view="reinstallblocks"]'),null);
 console.log('ADMIN WORKSPACE PASS: contextual navigation, current state, role limits, search empty/clear, independent content scroll preservation, footer, full shop config save and wheel-free attendance settings');
}finally{for(const w of windows)w.close();fs.rmSync(temp,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
