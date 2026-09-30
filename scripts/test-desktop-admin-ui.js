'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM,VirtualConsole}=require('jsdom');
const crypto=require('node:crypto');
const publicKey=crypto.generateKeyPairSync('rsa',{modulusLength:2048}).publicKey.export({format:'jwk'}),exponent=Buffer.from(publicKey.e,'base64url'),modulus=Buffer.from(publicKey.n,'base64url'),header=Buffer.alloc(24);
header.writeUInt32LE(0x31415352,0);header.writeUInt32LE(2048,4);header.writeUInt32LE(exponent.length,8);header.writeUInt32LE(modulus.length,12);
const publicBlob=Buffer.concat([header,exponent,modulus]);
const connectProfile={version:1,protocol:'MOAPLAY-CONNECT-1',host:'relay.example.test',port:17959,serverKeyId:crypto.createHash('sha256').update(publicBlob).digest('hex'),serverPublicKey:publicBlob.toString('base64')};
const connectionInfo={revision:'windows-connect-3',source:'railway',ready:true,host:connectProfile.host,port:'17959',hostVariable:'RAILWAY_TCP_PROXY_DOMAIN',portVariable:'RAILWAY_TCP_PROXY_PORT',tcpPort:3000,httpPort:8080,probePort:8080,probePortMatches:true};
const root=path.resolve(__dirname,'..'),html=fs.readFileSync(path.join(root,'public/index.html'),'utf8');
const errors=[],requests=[],now=Date.now(),key='MOA-TEST-ONLY-NOT-A-LIVE-KEY';
const rows=Array.from({length:28},(_,i)=>({id:'DL_'+String(i).padStart(3,'0'),label:i===0?'<img src=x onerror=bad()>':'고객 PC '+i,status:i===0?'ACTIVE':'AVAILABLE',issuedAt:now-10000,activatedAt:i===0?now-5000:0,expiresAt:0,lastVerifiedAt:0,deviceName:i===0?'Office <script>bad()</script>':'',deviceId:i===0?'SHA256_DEVICE_FINGERPRINT_0123456789':'',consumed:i===0,appVersion:'1.0.0'}));
const vc=new VirtualConsole();vc.on('jsdomError',e=>errors.push(e.message));
const dom=new JSDOM(html.replace(/<script[^>]*>[\s\S]*?<\/script>/g,'').replace(/<link[^>]*>/g,''),{url:'https://fixture.invalid/',runScripts:'outside-only',virtualConsole:vc});
const w=dom.window;w.CSS={escape:x=>String(x)};w.matchMedia=()=>({matches:false,addEventListener(){},addListener(){}});w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;w.EventSource=class{addEventListener(){}close(){}};
let downloadedBlob=null,downloadedName='';w.Blob=Blob;Object.defineProperty(w.crypto,'subtle',{value:{async digest(...args){
 // Deliberately slower than a browser event tick: this catches accidental fixed
 // sleeps around the real WebCrypto worker completion.
 await new Promise(resolve=>setTimeout(resolve,75));return crypto.webcrypto.subtle.digest(...args);
}}});
w.HTMLAnchorElement.prototype.click=function(){downloadedName=this.download;};
w.URL.createObjectURL=blob=>{downloadedBlob=blob;return 'blob:fixture';};w.URL.revokeObjectURL=()=>{};w.HTMLElement.prototype.scrollIntoView=()=>{};
let copied='',issueFail=false,connectMissing=false;Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async text=>{copied=text;}}});
w.fetch=async(url,options={})=>{
 const method=options.method||'GET',body=options.body?JSON.parse(options.body):null;requests.push({url,method,body,csrf:options.headers?.['X-CSRF-Token']});let data;
 if(url==='/api/session')data={ok:true,role:'admin',csrf:'DOM_CSRF',expiresAt:now+600000};
 else if(url==='/api/system')data={ok:true,system:{webAdminVersion:'5.0.1'}};
 else if(url.startsWith('/api/notifications?'))data={ok:true,summary:{unread:0,critical:0}};
 else if(url==='/api/desktop/connect-profile'){assert.equal(method,'GET');if(connectMissing)return {ok:false,status:503,text:async()=>JSON.stringify({ok:false,error:'CONNECT_PUBLIC_ENDPOINT_REQUIRED',message:'호스트 이름만 입력하세요.',connection:{...connectionInfo,source:'manual',ready:false,host:'<img src=x onerror=bad()>',hostVariable:'DESKTOP_PUBLIC_HOST',portVariable:'DESKTOP_PUBLIC_PORT',probePort:3000,probePortMatches:false}})};data={ok:true,profile:{...connectProfile,privateKey:'MUST_NOT_EXPORT',token:'MUST_NOT_EXPORT',licenseKey:'MUST_NOT_EXPORT'},connection:connectionInfo};}
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
async function waitFor(predicate,label,timeout=3000){
 const until=Date.now()+timeout;
 while(Date.now()<until){if(predicate())return;await new Promise(resolve=>setTimeout(resolve,10));}
 throw Error('DOM wait timeout: '+label+'; modal='+w.document.querySelector('#modal-title').textContent+'; toast='+w.document.querySelector('#toast').textContent+'; errors='+errors.join('; '));
}
const shown=selector=>!!w.document.querySelector(selector);
const actionIdle=()=>!vm.runInContext('desktopLicenseActionPending || rendering',dom.getInternalVMContext());
const modalClosed=()=>w.document.querySelector('#modal').classList.contains('hidden');
async function closeModal(){w.document.querySelector('#modal-confirm').click();await waitFor(()=>modalClosed()&&actionIdle(),'modal close and action completion');}

function field(name,value){const input=w.document.querySelector(`[data-modal-field="${name}"]`);assert.ok(input,name);input.value=value;return input;}
(async()=>{try{
 await waitFor(()=>shown('#desktop-connect-profile')&&actionIdle(),'initial license page');
 assert.equal(w.document.querySelector('#app').classList.contains('hidden'),false);
 assert.equal(w.document.querySelector('#page-title').textContent,'Windows 라이선스');
 assert.equal(new URL(requests.find(r=>r.url.startsWith('/api/desktop/licenses?')).url,'https://fixture.invalid').searchParams.has('status'),false);
 w.openPalette();w.document.querySelector('#palette-input').value='고객';await w.runPaletteSearch('고객');w.closePalette();
 const paletteRequest=requests.filter(r=>r.url.startsWith('/api/desktop/licenses?')).at(-1);assert.equal(new URL(paletteRequest.url,'https://fixture.invalid').searchParams.has('status'),false);
 // The connection profile is fetched only after the administrator asks for it.
 assert.ok(!requests.some(r=>r.url==='/api/desktop/connect-profile'));
 w.document.querySelector('#desktop-connect-profile').click();await waitFor(()=>shown('#desktop-connect-download'),'verified Connect profile dialog');
 assert.match(w.document.querySelector('#modal-body').textContent,/relay\.example\.test/);
 assert.match(w.document.querySelector('#modal-body').textContent,/17959/);
 assert.match(w.document.querySelector('#modal-body').textContent,/Railway 자동 감지/);
 assert.match(w.document.querySelector('#modal-body').textContent,/windows-connect-3/);
 assert.ok(w.document.querySelector('#modal-body').textContent.includes(connectProfile.serverKeyId.match(/.{2}/g).join(':')));
 w.document.querySelector('#desktop-connect-download').click();await waitFor(()=>downloadedBlob&&downloadedName,'Connect settings download');
 assert.equal(downloadedName,'MoaPlayConnect.server.json');assert.deepEqual(JSON.parse(await downloadedBlob.text()),connectProfile);
 assert.ok(!String(await downloadedBlob.text()).includes('MUST_NOT_EXPORT'));
 await closeModal();assert.equal(w.document.querySelector('#desktop-connect-download'),null);
 connectMissing=true;w.document.querySelector('#desktop-connect-profile').click();await waitFor(()=>w.document.querySelector('#modal-body').textContent.includes('DESKTOP_PUBLIC_HOST'),'missing public endpoint instructions');
 assert.match(w.document.querySelector('#modal-body').textContent,/DESKTOP_PUBLIC_HOST/);assert.match(w.document.querySelector('#modal-body').textContent,/DESKTOP_PUBLIC_PORT/);
 assert.match(w.document.querySelector('#modal-body').textContent,/<img src=x onerror=bad\(\)>/);
 assert.equal(w.document.querySelector('#modal-body img'),null);
 assert.match(w.document.querySelector('#modal-body').textContent,/CONNECT_TCP_PORT/);
 assert.equal(w.document.querySelector('#desktop-connect-download'),null);await closeModal();connectMissing=false;
 await assert.rejects(()=>w.desktopConnectProfileData({...connectProfile,serverKeyId:'0'.repeat(64)}),/지문/);
 assert.equal(w.document.querySelectorAll('#nav [data-view^="member-"]').length,0);
 for(const view of ['clients','licenses','qrauth','clientbiometrics','buildsessions','support','reinstallblocks'])assert.equal(w.document.querySelector(`#nav [data-view="${view}"]`),null);
 for(const view of ['servers','security','audit','reports','sessions','backups','health','system'])assert.ok(w.document.querySelector(`#nav [data-view="${view}"]`));
 assert.equal(w.document.querySelectorAll('.desktop-license-table tbody tr').length,25);
 assert.equal(w.document.querySelectorAll('.desktop-license-table img,.desktop-license-table script').length,0);
 assert.match(w.document.querySelector('.desktop-license-table').textContent,/<img src=x onerror=bad\(\)>/);
 assert.ok(!w.document.querySelector('[data-desktop-action="reset"],[data-desktop-action="unbind"]'));
 w.document.querySelector('[data-desktop-page="1"]').click();await waitFor(()=>w.document.querySelectorAll('.desktop-license-table tbody tr').length===3&&actionIdle(),'second license page');assert.equal(w.document.querySelectorAll('.desktop-license-table tbody tr').length,3);
 w.document.querySelector('[data-desktop-status="ACTIVE"]').click();await waitFor(()=>w.document.querySelectorAll('.desktop-license-table tbody tr').length===1&&actionIdle(),'active status filter');assert.equal(w.document.querySelectorAll('.desktop-license-table tbody tr').length,1);
 w.document.querySelector('#desktop-license-clear').click();await waitFor(()=>w.document.querySelectorAll('.desktop-license-table tbody tr').length===25&&actionIdle(),'clear license filter');
 w.document.querySelector('[data-desktop-action="detail"]').click();await waitFor(()=>!modalClosed()&&w.document.querySelector('#modal-body').textContent.includes('SHA256_DEVICE'),'license detail dialog');assert.match(w.document.querySelector('#modal-body').textContent,/SHA256_DEVICE/);await closeModal();
 // Default issuance has no forced expiry; key is displayed only in its receipt.
 w.document.querySelector('#desktop-license-create').click();await waitFor(()=>shown('[data-modal-field="term"]')&&!modalClosed(),'issue form');assert.equal(field('term','unlimited').value,'unlimited');field('label','실제 고객');w.document.querySelector('#modal-confirm').click();await waitFor(()=>shown('#desktop-issued-key'),'new license receipt');
 assert.equal(w.document.querySelector('#desktop-issued-key').value,key);assert.ok(!Object.keys(w.localStorage).some(name=>String(w.localStorage.getItem(name)).includes(key)));
 w.document.querySelector('#desktop-key-copy').click();await waitFor(()=>copied===key,'clipboard write');assert.equal(copied,key);
 await closeModal();assert.equal(w.document.querySelector('#desktop-issued-key'),null);assert.ok(!w.document.body.textContent.includes(key));
 // A lost response retries the same request identifier, never a fresh issuance.
 issueFail=true;w.document.querySelector('#desktop-license-create').click();await waitFor(()=>shown('[data-modal-field="label"]')&&!modalClosed(),'retry fixture issue form');field('label','재시도');w.document.querySelector('#modal-confirm').click();await waitFor(()=>modalClosed()&&actionIdle()&&!issueFail,'failed issuance response');
 const failed=requests.filter(r=>r.method==='POST'&&r.url==='/api/desktop/licenses').at(-1);
 w.document.querySelector('#desktop-license-create').click();await waitFor(()=>!modalClosed()&&w.document.querySelector('#modal-title').textContent.includes('이전 발급'),'retry confirmation');assert.match(w.document.querySelector('#modal-title').textContent,/이전 발급/);w.document.querySelector('#modal-confirm').click();await waitFor(()=>shown('#desktop-issued-key'),'retried issuance receipt');
 const retried=requests.filter(r=>r.method==='POST'&&r.url==='/api/desktop/licenses').at(-1);assert.equal(retried.body.requestId,failed.body.requestId);await closeModal();
 w.document.querySelector('[data-desktop-action="revoke"]').click();await waitFor(()=>shown('[data-modal-field="reason"]')&&!modalClosed(),'revoke form');field('reason','사용자 요청');await closeModal();
 assert.ok(requests.some(r=>r.url.endsWith('/revoke')&&r.csrf==='DOM_CSRF'));
 w.document.querySelector('[data-desktop-action="reissue"]').click();await waitFor(()=>shown('[data-modal-field="reason"]')&&!modalClosed(),'reissue form');field('reason','장비 교체');w.document.querySelector('#modal-confirm').click();await waitFor(()=>shown('#desktop-issued-key'),'replacement receipt');assert.equal(w.document.querySelector('#desktop-issued-key').value,key);await closeModal();
 assert.ok(requests.filter(r=>r.method==='POST').every(r=>r.csrf==='DOM_CSRF'));
 assert.ok(!requests.some(r=>/^\/api\/(clients|qr-auth|licenses|member|support)/.test(r.url)));
 vm.runInContext("session={role:'viewer',csrf:'VIEWER'}",dom.getInternalVMContext());const beforeForbidden=requests.length;await assert.rejects(()=>w.showDesktopConnectProfile(),/관리자/);assert.equal(requests.length,beforeForbidden);
 assert.equal(errors.length,0,errors.join('\n'));
 console.log('DESKTOP ADMIN UI PASS: actual script shell, retired navigation, retained operations, escaped rows, paging/filters, detailed state, no expiry issuance, one-time receipt scrub, stable request retry, revoke/reissue, CSRF, authenticated TCP public-profile download, fingerprint validation, missing endpoint instructions.');
 }finally{w.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
