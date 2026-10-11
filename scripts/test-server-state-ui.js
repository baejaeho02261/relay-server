'use strict';
// Execute the actual recovery controller with an isolated DOM and server replies.
// No operating server, browser credentials, or files are used.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom');
const dom=new JSDOM('<!doctype html><body></body>',{url:'https://admin.test/',runScripts:'outside-only'}),w=dom.window;
const calls=[];let close,revision=0;
w.session={csrf:'TEST_SESSION'};w.roleIsAdmin=()=>true;
w.esc=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
w.openModal=options=>{w.document.body.innerHTML=options.html;return new Promise(resolve=>{close=resolve;});};
w.api=async(url,options)=>{
 calls.push({url,options});
 if(options?.method==='POST'){
  assert(url.endsWith('/journal-checkpoint'));
  revision++;
  return revision===1?{committed:true,compacted:false,checkpointRequired:true}:{committed:true,compacted:true};
 }
 if(url.endsWith('/device-identity'))return {revision:0,mode:'COMPATIBLE',requireForEnrolled:true,trustConfigured:false,trust:null,items:[]};
 if(url.endsWith('/devices'))return {revision:0,items:[]};
 if(url.endsWith('/quarantine'))return {items:[]};
 return {epoch:0,licenseRevision:revision,witness:{status:'NOT_CONFIGURED'},auditPending:0,journal:{checkpointPresent:false}};
};
async function waitFor(test){for(let i=0;i<100;i++){if(test())return;await new Promise(resolve=>setTimeout(resolve,5));}throw Error('UI_COMPLETION_TIMEOUT');}
(async()=>{try{
 vm.runInContext(fs.readFileSync(path.join(__dirname,'../public/admin-desktop-server-state.js'),'utf8'),dom.getInternalVMContext());
 const done=w.showDesktopServerState();await waitFor(()=>w.document.querySelector('[data-server-state-action="checkpoint"]'));
 w.document.querySelector('[data-server-state-action="checkpoint"]').click();
 await waitFor(()=>w.document.querySelector('#server-state-status')?.textContent.includes('분할 보관은 완료되지 않았습니다'));
 assert.equal(w.document.querySelector('#server-state-status').dataset.state,'error');
 const first=calls.find(c=>c.options?.method==='POST');assert.equal(first.options.body.expectedRevision,0);
 w.document.querySelector('[data-server-state-action="checkpoint"]').click();
 await waitFor(()=>w.document.querySelector('#server-state-status')?.textContent==='서버에서 처리를 확정했습니다.');
 const posts=calls.filter(c=>c.options?.method==='POST');assert.equal(posts.length,2);assert.equal(posts[1].options.body.expectedRevision,1);assert.notEqual(posts[1].options.body.requestId,posts[0].options.body.requestId);
 close(false);await done;assert.equal(w.document.querySelector('#desktop-server-state-root').childNodes.length,0);
 console.log('SERVER STATE UI PASS: unfinished compaction is explicit; new request uses refreshed revision; modal state cleared.');
}finally{dom.window.close();}})().catch(error=>{console.error(error);process.exitCode=1;});
