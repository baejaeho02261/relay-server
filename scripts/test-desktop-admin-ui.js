'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM,VirtualConsole}=require('jsdom');
const root=path.resolve(__dirname,'..'),html=fs.readFileSync(path.join(root,'public/index.html'),'utf8');
const errors=[],requests=[],now=Date.now(),key='MOA-TEST-ONLY-NOT-A-LIVE-KEY';
const rows=Array.from({length:28},(_,i)=>({id:'DL_'+String(i).padStart(3,'0'),label:i===0?'<img src=x onerror=bad()>':'고객 PC '+i,status:i===0?'ACTIVE':'AVAILABLE',issuedAt:now-10000,activatedAt:i===0?now-5000:0,expiresAt:0,lastVerifiedAt:0,deviceName:i===0?'Office <script>bad()</script>':'',deviceId:i===0?'SHA256_DEVICE_FINGERPRINT_0123456789':'',consumed:i===0,appVersion:'1.0.0'}));
const vc=new VirtualConsole();vc.on('jsdomError',e=>errors.push(e.message));
const dom=new JSDOM(html.replace(/<script[^>]*>[\s\S]*?<\/script>/g,'').replace(/<link[^>]*>/g,''),{url:'https://fixture.invalid/',runScripts:'outside-only',virtualConsole:vc});
const w=dom.window;w.CSS={escape:x=>String(x)};w.matchMedia=()=>({matches:false,addEventListener(){},addListener(){}});w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;w.EventSource=class{addEventListener(){}close(){}};
w.URL.createObjectURL=()=> 'blob:fixture';w.URL.revokeObjectURL=()=>{};w.HTMLElement.prototype.scrollIntoView=()=>{};
let copied='',issueFail=false;Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async text=>{copied=text;}}});
w.fetch=async(url,options={})=>{
 const method=options.method||'GET',body=options.body?JSON.parse(options.body):null;requests.push({url,method,body,csrf:options.headers?.['X-CSRF-Token']});let data;
 if(url==='/api/session')data={ok:true,role:'admin',csrf:'DOM_CSRF',expiresAt:now+600000};
 else if(url==='/api/system')data={ok:true,system:{webAdminVersion:'5.0.1'}};
 else if(url.startsWith('/api/notifications?'))data={ok:true,summary:{unread:0,critical:0}};
 else if(url.startsWith('/api/search?'))data={ok:true,results:[]};
 else if(url.startsWith('/api/desktop/licenses?')){const params=new URL(url,'https://fixture.invalid').searchParams,q=params.get('q')||'',status=params.get('status');assert.ok(status===null||['AVAILABLE','ACTIVE','REVOKED','EXPIRED','RELEASED'].includes(status),'The API does not accept the UI-only ALL filter');data={ok:true,items:rows.filter(x=>(!status||x.status===status)&&[x.id,x.label,x.deviceName].join(' ').includes(q)),revision:1,serverTime:now};}
 else if(url==='/api/desktop/licenses'&&method==='POST'){
   if(issueFail){issueFail=false;throw new TypeError('network interrupted');}
   assert.equal(body.expiresAt,0);assert.match(body.requestId,/^[\w-]{16,}$/);data={ok:true,license:{id:'NEW_ID',label:body.label},licenseKey:key};
 }else if(url.endsWith('/revoke')&&method==='POST'){assert.ok(body.reason.length>=3);data={ok:true,license:{id:'DL_000',status:'REVOKED'}};}
 else if(url.endsWith('/reissue')&&method==='POST'){assert.ok(body.reason.length>=3);assert.match(body.requestId,/^[\w-]{16,}$/);data={ok:true,license:{id:'REPLACEMENT_ID'},licenseKey:key};}
 else throw Error('Unexpected endpoint: '+method+' '+url);
 return {ok:true,status:200,text:async()=>JSON.stringify(data)};
};
for(const match of html.matchAll(/<script src="\/(admin[^?"]+)\?/g))new vm.Script(fs.readFileSync(path.join(root,'public',match[1]),'utf8'),{filename:match[1]}).runInContext(dom.getInternalVMContext());
const settle=()=>new Promise(resolve=>setTimeout(resolve,20));
function field(name,value){const input=w.document.querySelector(`[data-modal-field="${name}"]`);assert.ok(input,name);input.value=value;return input;}
(async()=>{try{
 await settle();
 assert.equal(w.document.querySelector('#app').classList.contains('hidden'),false);
 assert.equal(w.document.querySelector('#page-title').textContent,'Windows 라이선스');
 assert.equal(new URL(requests.find(r=>r.url.startsWith('/api/desktop/licenses?')).url,'https://fixture.invalid').searchParams.has('status'),false);
 w.openPalette();w.document.querySelector('#palette-input').value='고객';await w.runPaletteSearch('고객');w.closePalette();
 const paletteRequest=requests.filter(r=>r.url.startsWith('/api/desktop/licenses?')).at(-1);assert.equal(new URL(paletteRequest.url,'https://fixture.invalid').searchParams.has('status'),false);
 assert.equal(w.document.querySelectorAll('#nav [data-view^="member-"]').length,0);
 for(const view of ['clients','licenses','qrauth','clientbiometrics','buildsessions','support','reinstallblocks'])assert.equal(w.document.querySelector(`#nav [data-view="${view}"]`),null);
 for(const view of ['servers','security','audit','reports','sessions','backups','health','system'])assert.ok(w.document.querySelector(`#nav [data-view="${view}"]`));
 assert.equal(w.document.querySelectorAll('.desktop-license-table tbody tr').length,25);
 assert.equal(w.document.querySelectorAll('.desktop-license-table img,.desktop-license-table script').length,0);
 assert.match(w.document.querySelector('.desktop-license-table').textContent,/<img src=x onerror=bad\(\)>/);
 assert.ok(!w.document.querySelector('[data-desktop-action="reset"],[data-desktop-action="unbind"]'));
 w.document.querySelector('[data-desktop-page="1"]').click();await settle();assert.equal(w.document.querySelectorAll('.desktop-license-table tbody tr').length,3);
 w.document.querySelector('[data-desktop-status="ACTIVE"]').click();await settle();assert.equal(w.document.querySelectorAll('.desktop-license-table tbody tr').length,1);
 w.document.querySelector('#desktop-license-clear').click();await settle();
 w.document.querySelector('[data-desktop-action="detail"]').click();await settle();assert.match(w.document.querySelector('#modal-body').textContent,/SHA256_DEVICE/);w.document.querySelector('#modal-confirm').click();await settle();
 // Default issuance has no forced expiry; key is displayed only in its receipt.
 w.document.querySelector('#desktop-license-create').click();await settle();assert.equal(field('term','unlimited').value,'unlimited');field('label','실제 고객');w.document.querySelector('#modal-confirm').click();await settle();
 assert.equal(w.document.querySelector('#desktop-issued-key').value,key);assert.ok(!Object.keys(w.localStorage).some(name=>String(w.localStorage.getItem(name)).includes(key)));
 w.document.querySelector('#desktop-key-copy').click();await settle();assert.equal(copied,key);
 w.document.querySelector('#modal-confirm').click();await settle();assert.equal(w.document.querySelector('#desktop-issued-key'),null);assert.ok(!w.document.body.textContent.includes(key));
 // A lost response retries the same request identifier, never a fresh issuance.
 issueFail=true;w.document.querySelector('#desktop-license-create').click();await settle();field('label','재시도');w.document.querySelector('#modal-confirm').click();await settle();
 const failed=requests.filter(r=>r.method==='POST'&&r.url==='/api/desktop/licenses').at(-1);
 w.document.querySelector('#desktop-license-create').click();await settle();assert.match(w.document.querySelector('#modal-title').textContent,/이전 발급/);w.document.querySelector('#modal-confirm').click();await settle();
 const retried=requests.filter(r=>r.method==='POST'&&r.url==='/api/desktop/licenses').at(-1);assert.equal(retried.body.requestId,failed.body.requestId);w.document.querySelector('#modal-confirm').click();await settle();
 w.document.querySelector('[data-desktop-action="revoke"]').click();await settle();field('reason','사용자 요청');w.document.querySelector('#modal-confirm').click();await settle();
 assert.ok(requests.some(r=>r.url.endsWith('/revoke')&&r.csrf==='DOM_CSRF'));
 w.document.querySelector('[data-desktop-action="reissue"]').click();await settle();field('reason','장비 교체');w.document.querySelector('#modal-confirm').click();await settle();assert.equal(w.document.querySelector('#desktop-issued-key').value,key);w.document.querySelector('#modal-confirm').click();await settle();
 assert.ok(requests.filter(r=>r.method==='POST').every(r=>r.csrf==='DOM_CSRF'));
 assert.ok(!requests.some(r=>/^\/api\/(clients|qr-auth|licenses|member|support)/.test(r.url)));
 assert.equal(errors.length,0,errors.join('\n'));
 console.log('DESKTOP ADMIN UI PASS: actual script shell, retired navigation, retained operations, escaped rows, paging/filters, detailed state, no expiry issuance, one-time receipt scrub, stable request retry, revoke/reissue, CSRF.');
 }finally{w.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
