'use strict';
// Real administrator controller in an isolated DOM. No browser credentials,
// operating requests, executable runs or first-device approvals are created.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom');
const source=fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-workflow.js'),'utf8');
const base='/api/desktop/bootstrap/security-operations/keyless-approvals';
function Row(seed='a'){return {id:seed.repeat(48),launcherId:'A'.repeat(24),launcherSha512:'b'.repeat(128),appKeyId:'C'.repeat(64),persistentKeyId:'D'.repeat(64),machineId:'E'.repeat(64),createdAt:Date.now(),expiresAt:Date.now()+300000,status:'PENDING_APPROVAL',proof:'PERSISTENT_KEY_POSSESSION',hardwareAttested:false};}
function Harness(rows=[Row()]){
 const dom=new JSDOM('<body></body>',{url:'https://fixture.invalid/',runScripts:'outside-only'}),w=dom.window,calls=[];
 let end,hook=null;
 w.content=w.document.createElement('main');
 w.session={csrf:'ADMIN_1',role:'admin'};w.roleIsAdmin=()=>w.session?.role==='admin';
 w.openModal=options=>{w.document.body.innerHTML=options.html;return new Promise(resolve=>{end=resolve;});};
 w.api=async(url,options={})=>{
  calls.push({url,method:options.method||'GET',body:options.body?JSON.parse(JSON.stringify(options.body)):undefined});
  if(hook)return hook(url,options);
  if(url===base)return {ok:true,requests:structuredClone(rows)};
  if(options.method==='POST')return {version:1,id:url.split('/').at(-2),status:'APPROVED',expiresAt:Date.now()+250000,hardwareAttested:false};
  throw Error('UNEXPECTED_TEST_ENDPOINT');
 };
 vm.runInContext(source,dom.getInternalVMContext());
 const q=id=>w.document.getElementById(id),change=id=>q(id).dispatchEvent(new w.Event('change'));
 return {dom,w,calls,q,change,setHook(value){hook=value;},async open(){const pending=w.showDesktopFirstDeviceApproval();await Wait(()=>q('desktop-first-device-request'));return {pending};},async close(pending){end(false);await pending;assert.equal(q('desktop-first-device-approval').childNodes.length,0);},dispose(){end?.(false);dom.window.close();}};
}
async function Wait(check){for(let i=0;i<100;i++){if(check())return;await new Promise(resolve=>setTimeout(resolve,5));}throw Error('KEYLESS_UI_TEST_TIMEOUT');}
function Select(h,row=Row()){h.q('desktop-first-device-request').value=row.id;h.change('desktop-first-device-request');}
function Confirm(h){h.q('desktop-first-device-confirm').checked=true;h.change('desktop-first-device-confirm');}
test('shows only public identifiers and requires explicit outside identity confirmation',async()=>{
 const row={...Row(),ticket:'DO_NOT_RENDER_TICKET',serverPolicyIR:'DO_NOT_RENDER_POLICY'},h=Harness([row]);
 try{const {pending}=await h.open();Select(h,row);assert.equal(h.q('desktop-first-device-submit').disabled,true);
  await h.q('desktop-first-device-submit').onclick();assert.equal(h.calls.filter(x=>x.method==='POST').length,0);
  const text=h.w.document.body.textContent;assert(text.includes(row.persistentKeyId));assert(text.includes(row.launcherId));assert(!text.includes(row.ticket));assert(!text.includes(row.serverPolicyIR));assert(text.includes('TPM 하드웨어 증명이 아닙니다'));
  Confirm(h);await h.q('desktop-first-device-submit').onclick();const post=h.calls.find(x=>x.method==='POST');
  assert.equal(post.url,base+'/'+row.id+'/approve');assert.deepEqual(post.body,{identityConfirmed:true,persistentKeyId:row.persistentKeyId,launcherId:row.launcherId});
  assert(h.q('desktop-first-device-status').textContent.includes('실행 완료를 확인한 것은 아닙니다'));assert.equal(h.q('desktop-first-device-submit').disabled,true);await h.close(pending);
 }finally{h.dispose();}
});
test('changing request clears confirmation and a busy approval cannot submit twice',async()=>{
 const rows=[Row('a'),{...Row('c'),launcherId:'B'.repeat(24),persistentKeyId:'F'.repeat(64)}],h=Harness(rows);
 try{const {pending}=await h.open();Select(h,rows[0]);Confirm(h);Select(h,rows[1]);assert.equal(h.q('desktop-first-device-confirm').checked,false);
  let finish;h.setHook((url,options)=>options.method==='POST'?new Promise(resolve=>{finish=resolve;}):{ok:true,requests:rows});Confirm(h);
  const first=h.q('desktop-first-device-submit').onclick();await Wait(()=>finish);await h.q('desktop-first-device-submit').onclick();assert.equal(h.calls.filter(x=>x.method==='POST').length,1);
  finish({version:1,id:rows[1].id,status:'APPROVED',expiresAt:Date.now()+10000,hardwareAttested:false});await first;await h.close(pending);
 }finally{h.dispose();}
});
test('session replacement and role loss block stale mutations',async()=>{
 for(const session of [{csrf:'ADMIN_2',role:'admin'},{csrf:'ADMIN_1',role:'viewer'}]){const h=Harness();try{const {pending}=await h.open();Select(h);Confirm(h);h.w.session=session;await h.q('desktop-first-device-submit').onclick();assert.equal(h.calls.filter(x=>x.method==='POST').length,0);await h.close(pending);}finally{h.dispose();}}
});
test('a close during an approval discards the late result',async()=>{
 const h=Harness();try{const {pending}=await h.open();Select(h);Confirm(h);let finish;h.setHook(()=>new Promise(resolve=>{finish=resolve;}));const operation=h.q('desktop-first-device-submit').onclick();await Wait(()=>finish);await h.close(pending);
  finish({version:1,id:Row().id,status:'APPROVED',expiresAt:Date.now()+10000,hardwareAttested:false});await operation;assert.equal(h.q('desktop-first-device-approval').childNodes.length,0);assert.equal(h.calls.length,2);
 }finally{h.dispose();}
});
test('failed or expired approval does not claim success or automatically retry',async()=>{
 const h=Harness();try{const {pending}=await h.open();Select(h);Confirm(h);h.setHook(()=>{throw Object.assign(Error('SERVER_PRIVATE_DETAIL'),{code:'KEYLESS_REQUEST_EXPIRED'});});await h.q('desktop-first-device-submit').onclick();
  assert.equal(h.calls.filter(x=>x.method==='POST').length,1);assert(h.q('desktop-first-device-status').textContent.includes('만료'));assert(!h.w.document.body.textContent.includes('SERVER_PRIVATE_DETAIL'));assert.equal(h.q('desktop-first-device-confirm').checked,false);await h.close(pending);
 }finally{h.dispose();}
});
test('unproven or malformed rows are rejected before opening the approval surface',async()=>{
 for(const row of [{...Row(),hardwareAttested:true},{...Row(),proof:'UNVERIFIED'},{...Row(),persistentKeyId:'<img src=x>'},{...Row(),id:'../approve'}]){const h=Harness([row]);try{await assert.rejects(h.w.showDesktopFirstDeviceApproval(),/형식/);assert.equal(h.w.document.body.childNodes.length,0);assert.equal(h.calls.filter(x=>x.method==='POST').length,0);}finally{h.dispose();}}
});
test('non-admin and replaced-session list responses never open an approval surface',async()=>{
 const h=Harness();try{h.w.session={csrf:'VIEW',role:'viewer'};await h.w.showDesktopFirstDeviceApproval();assert.equal(h.calls.length,0);
  h.w.session={csrf:'ADMIN_1',role:'admin'};let finish;h.setHook(()=>new Promise(resolve=>{finish=resolve;}));const pending=h.w.showDesktopFirstDeviceApproval();await Wait(()=>finish);h.w.session={csrf:'ADMIN_2',role:'admin'};finish({ok:true,requests:[Row()]});await pending;assert.equal(h.w.document.body.childNodes.length,0);
 }finally{h.dispose();}
});
