'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM,VirtualConsole}=require('jsdom');
const crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),html=fs.readFileSync(path.join(root,'public/index.html'),'utf8');
const errors=[],requests=[],now=Date.now(),key='A1B2C3D4'.repeat(8),issuedId='A1B2C3D4'.repeat(3),launcherId='B2C3D4E5'.repeat(3);
const machineId='F1A2B3C4'.repeat(8),binarySha256='ab'.repeat(32),binaryCrc64='12ABCDEF09876543';
const rows=Array.from({length:28},(_,i)=>({id:'DL_'+String(i).padStart(3,'0'),label:i===0?'<img src=x onerror=bad()>':'고객 PC '+i,status:i===0?'USED':'AVAILABLE',issuedAt:now-10000,activatedAt:i===0?now-5000:0,expiresAt:0,lastVerifiedAt:0,deviceName:i===0?'Office <script>bad()</script>':'',deviceId:i===0?'SHA256_DEVICE_FINGERPRINT_0123456789':'',consumed:i===0,appVersion:'1.0.0',machineId:i===0?machineId:'',machineBlocked:i===0,machinePolicy:i===0?{source:'SINGLE_USE',reason:'1회 사용 자동 차단',changedAt:now}:null,binarySha256:i===0?binarySha256:'',binaryCrc64:i===0?binaryCrc64:''}));
const vc=new VirtualConsole();vc.on('jsdomError',e=>errors.push(e.message));
const dom=new JSDOM(html.replace(/<script[^>]*>[\s\S]*?<\/script>/g,'').replace(/<link[^>]*>/g,''),{url:'https://fixture.invalid/',runScripts:'outside-only',virtualConsole:vc,pretendToBeVisual:true});
const eventSources=[],intervals=new Map();
const w=dom.window;
const nativeSetInterval=w.setInterval.bind(w),nativeClearInterval=w.clearInterval.bind(w);
w.setInterval=(fn,delay)=>{const id=nativeSetInterval(fn,delay);intervals.set(id,{fn,delay});return id;};
w.clearInterval=id=>{intervals.delete(id);nativeClearInterval(id);};
w.CSS={escape:x=>String(x)};w.matchMedia=()=>({matches:false,addEventListener(){},addListener(){}});w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;w.EventSource=class{constructor(){this.listeners=new Map();eventSources.push(this);}addEventListener(name,callback){this.listeners.set(name,callback);}close(){this.closed=true;}};
let downloadedBlob=null,downloadedName='';w.Blob=Blob;
w.HTMLAnchorElement.prototype.click=function(){downloadedName=this.download;};
w.URL.createObjectURL=blob=>{downloadedBlob=blob;return 'blob:fixture';};w.URL.revokeObjectURL=()=>{};w.HTMLElement.prototype.scrollIntoView=()=>{};
let copied='',issueFail=false,launcherFail=false,uploadFail=false;
const launcherName='a1b2c3d4'.repeat(4)+'.exe';let downloadHeaderName=launcherName;
const artifacts={A:null,B:null},bootstrapSessions=[{id:'DS_test',flowId:'FLOW_test',launcherId:'DA_test',status:'CLAIMED',deviceId:'PC_fingerprint',version:'1.0.0',createdAt:now-4000,expiresAt:now+300000,licenseId:'DL_000',licenseStatus:'USED',licenseLastVerifiedAt:now-1000}],launchers=[];
Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async text=>{copied=text;}}});
w.fetch=async(url,options={})=>{
 const method=options.method||'GET',body=typeof options.body==='string'?JSON.parse(options.body):options.body||null;requests.push({url,method,body,headers:options.headers,credentials:options.credentials,csrf:options.headers?.['X-CSRF-Token']});let data;
 if(url==='/api/session')data={ok:true,role:'admin',csrf:'DOM_CSRF',expiresAt:now+600000};
 else if(url==='/api/system')data={ok:true,system:{webAdminVersion:'5.0.1'}};
 else if(url.startsWith('/api/notifications?'))data={ok:true,summary:{unread:0,critical:0}};
 else if(url==='/api/desktop/bootstrap/integrity-reports')data={ok:true,items:[{id:'audit1',at:now,stage:'B',check:'OWN_CODE',status:'REJECTED',reason:'CODE_HASH_MISMATCH',sessionId:'SESSION1',machineId,expectedSha256:binarySha256,observedSha256:'cd'.repeat(32),expectedCrc64:binaryCrc64,observedCrc64:'AB'.repeat(8)},{id:'audit2',at:now,stage:'A',check:'MODULE_INVENTORY',status:'CLIENT_DIAGNOSTIC',reason:'PERIODIC',snapshotId:'snapshot1',batchIndex:0,batchCount:1,totalModules:1,measuredModules:1,complete:true,truncated:false,modules:[{name:'ntdll.dll',status:'UNVERIFIED_BASELINE',codeStatus:'MATCH_LOCAL_FILE',serverComparison:'UNVERIFIED_BASELINE',fileSha256:binarySha256,codeSha256:binarySha256}]}]};
 else if(url==='/api/desktop/bootstrap/module-baselines')data={ok:true,items:[]};
 else if(url.startsWith('/api/desktop/bootstrap/module-baselines?')){assert.equal(method,'POST');assert.ok(body instanceof w.File);assert.equal(options.headers['X-CSRF-Token'],'DOM_CSRF');data={ok:true,baseline:{name:'ntdll.dll'}};}
 else if(url==='/api/desktop/machines')data={ok:true,items:rows.filter(row=>row.machineId).map(row=>({machineId:row.machineId,blocked:row.machineBlocked,source:row.machinePolicy?.source||'NONE',reason:row.machinePolicy?.reason||'',changedAt:now}))};
 else if(url==='/api/desktop/bootstrap')data={ok:true,bootstrap:{artifacts:{...artifacts},launchers:[...launchers],sessions:bootstrapSessions.map(row=>({...row})),limits:{maxArtifactBytes:67108864},serverTime:now}};
 else if(url.startsWith('/api/desktop/bootstrap/artifacts?')){
   assert.equal(method,'POST');assert.ok(body instanceof w.File);assert.equal(options.headers['Content-Type'],'application/octet-stream');assert.equal(options.credentials,'same-origin');
   if(uploadFail){uploadFail=false;throw new TypeError('upload interrupted');}
   const params=new URL(url,'https://fixture.invalid').searchParams,component=params.get('component');assert.ok(['A','B'].includes(component));assert.equal(params.get('fileName'),component+'.exe');
   const artifact={id:'ART_'+component,component,version:params.get('version'),sha256:(component==='A'?'a':'b').repeat(64),crc64:binaryCrc64,size:body.size,createdAt:now};artifacts[component]=artifact;data={ok:true,artifact};
 }else if(url==='/api/desktop/bootstrap/launchers'){
   assert.equal(method,'POST');assert.match(body.requestId,/^[\w-]{16,}$/);if(launcherFail){launcherFail=false;throw new TypeError('launcher response interrupted');}
   launchers.push({id:launcherId,label:body.label,issuedAt:now,expiresAt:now+86400000,status:'AVAILABLE',downloadName:launcherName});data={ok:true,launcherId,downloadName:launcherName,expiresAt:now+86400000,downloadUrl:'/api/desktop/bootstrap/launchers/'+launcherId+'/download'};
 }else if(url==='/api/desktop/bootstrap/launchers/'+launcherId+'/download'){
   assert.equal(method,'GET');assert.equal(options.credentials,'same-origin');return {ok:true,status:200,headers:{get:name=>name==='Content-Disposition'?'attachment; filename=\"'+downloadHeaderName+'\"':null},blob:async()=>new Blob(['MZ_PROVISIONED_A_FIXTURE'])};
 }else if(url==='/api/desktop/bootstrap/sessions/DS_test/revoke'){
   assert.equal(method,'POST');assert.ok(body.reason.length>=3);bootstrapSessions[0].status='REVOKED';data={ok:true};
 }
 else if(url.startsWith('/api/desktop/machines/')){
   assert.equal(method,'POST');assert.match(body.requestId,/^[\w-]{8,80}$/);assert.ok(body.reason.length>=3);assert.equal(options.headers['X-CSRF-Token'],'DOM_CSRF');
   const parts=url.split('/'),id=parts.at(-2),action=parts.at(-1);assert.equal(id,machineId);assert.equal(action,'unblock');
   const policy={machineId:id,blocked:action==='block',reason:body.reason,changedAt:now,changedBy:'admin',revision:1};for(const row of rows.filter(row=>row.machineId===id)){row.machineBlocked=policy.blocked;row.machinePolicy=policy;}data={ok:true,machine:policy,revision:1,serverTime:now};
 }
 else if(url.startsWith('/api/search?'))data={ok:true,results:[]};
 else if(url.startsWith('/api/desktop/licenses?')){const params=new URL(url,'https://fixture.invalid').searchParams,q=params.get('q')||'',status=params.get('status');assert.ok(status===null||['AVAILABLE','USED','REVOKED','EXPIRED'].includes(status),'The API does not accept the UI-only ALL filter');data={ok:true,items:rows.filter(x=>(!status||x.status===status)&&[x.id,x.label,x.deviceName].join(' ').includes(q)),counts:Object.fromEntries(['AVAILABLE','USED','REVOKED','EXPIRED'].map(status=>[status,rows.filter(row=>row.status===status).length])),totalCount:rows.length,revision:1,serverTime:now};}
 else if(url==='/api/desktop/licenses'&&method==='POST'){
   if(issueFail){issueFail=false;throw new TypeError('network interrupted');}
   assert.equal('expiresAt' in body,false);assert.equal('validDays' in body,false);assert.match(body.requestId,/^[\w-]{16,}$/);if(!rows.some(row=>row.id===issuedId))rows.push({id:issuedId,label:body.label,status:'AVAILABLE',issuedAt:now,expiresAt:0,consumed:false});data={ok:true,license:{id:issuedId,label:body.label},licenseKey:key};
 }else if(method==='GET'&&/^\/api\/desktop\/licenses\/[^/]+$/.test(url)){
   const id=decodeURIComponent(url.split('/').at(-1)),row=rows.find(row=>row.id===id);assert.ok(row,'detail must use an existing raw ID');data={ok:true,license:{...row}};
 }else if(url.endsWith('/revoke')&&method==='POST'){assert.ok(body.reason.length>=3);data={ok:true,license:{id:'DL_000',status:'REVOKED'}};}
 else if(url.endsWith('/reissue')&&method==='POST'){assert.equal('expiresAt' in body,false);assert.equal('validDays' in body,false);assert.ok(body.reason.length>=3);assert.match(body.requestId,/^[\w-]{16,}$/);data={ok:true,license:{id:'REPLACEMENT_ID'},licenseKey:key};}
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
 await waitFor(()=>shown('#desktop-launcher-create')&&actionIdle(),'initial license page');
 assert.equal(w.document.querySelector('#app').classList.contains('hidden'),false);
 assert.equal(w.document.querySelector('#page-title').textContent,'Windows 라이선스');
 assert.equal(new URL(requests.find(r=>r.url.startsWith('/api/desktop/licenses?')).url,'https://fixture.invalid').searchParams.has('status'),false);
 w.openPalette();w.document.querySelector('#palette-input').value='고객';await w.runPaletteSearch('고객');w.closePalette();
 const paletteRequest=requests.filter(r=>r.url.startsWith('/api/desktop/licenses?')).at(-1);assert.equal(new URL(paletteRequest.url,'https://fixture.invalid').searchParams.has('status'),false);
 // A/B deployment replaces the end-user sidecar download path.
 assert.equal(w.document.querySelector('#desktop-connect-profile'),null);
 assert.equal(w.document.querySelector('#desktop-launcher-create').disabled,true);
 assert.match(w.document.querySelector('#desktop-bootstrap-sessions').textContent,/000/);assert.doesNotMatch(w.document.querySelector('#desktop-bootstrap-sessions').textContent,/DL_|FLOW_|DA_/);
 assert.match(w.document.querySelector('#desktop-bootstrap-sessions').textContent,/사용됨/);
 assert.ok(!requests.some(r=>r.url==='/api/desktop/connect-profile'));
 for(const component of ['A','B']){
   w.document.querySelector(`[data-desktop-action="artifact-upload"][data-component="${component}"]`).click();await waitFor(()=>shown('#desktop-artifact-file')&&!modalClosed(),component+' upload form');
   const fileInput=w.document.querySelector('#desktop-artifact-file'),file=new w.File(['MZ_'+component],component+'.exe',{type:'application/octet-stream'});Object.defineProperty(fileInput,'files',{value:[file]});field('version','1.0.83');
   if(component==='A'){
     uploadFail=true;w.document.querySelector('#modal-confirm').click();await waitFor(()=>w.document.querySelector('#desktop-artifact-status').textContent.includes('interrupted'),'upload retry retains form');
     assert.equal(w.document.querySelector('#desktop-artifact-file'),fileInput);assert.equal(fileInput.files[0],file);assert.equal(field('version','1.0.83').value,'1.0.83');
     const beforeRefresh=requests.length;await w.renderCurrent(true);assert.equal(requests.length,beforeRefresh);assert.equal(w.document.querySelector('#desktop-artifact-file'),fileInput);
   }
   w.document.querySelector('#modal-confirm').click();await waitFor(()=>modalClosed()&&actionIdle(),component+' upload complete');
   assert.match(w.document.querySelector('#desktop-bootstrap-artifacts').textContent,/1\.0\.83/);
 }
 assert.equal(w.document.querySelector('#desktop-launcher-create').disabled,false);
 assert.match(w.document.querySelector('#desktop-bootstrap-artifacts').textContent,/a{64}/);assert.match(w.document.querySelector('#desktop-bootstrap-artifacts').textContent,/b{64}/);assert.match(w.document.querySelector('#desktop-bootstrap-artifacts').textContent,/CRC64/);assert.ok(w.document.querySelector('#desktop-bootstrap-artifacts').textContent.includes(binaryCrc64));
 launcherFail=true;w.document.querySelector('#desktop-launcher-create').click();await waitFor(()=>shown('[data-modal-field="label"]')&&!modalClosed(),'A issue form');field('label','<고객 A>');w.document.querySelector('#modal-confirm').click();await waitFor(()=>modalClosed()&&actionIdle()&&!launcherFail,'failed A response');
 const failedLauncher=requests.filter(r=>r.url==='/api/desktop/bootstrap/launchers').at(-1);
 w.document.querySelector('#desktop-launcher-create').click();await waitFor(()=>!modalClosed()&&w.document.querySelector('#modal-title').textContent.includes('이전 A'),'A retry confirmation');w.document.querySelector('#modal-confirm').click();await waitFor(()=>shown('#desktop-launcher-download'),'A receipt');
 const retriedLauncher=requests.filter(r=>r.url==='/api/desktop/bootstrap/launchers').at(-1);assert.equal(retriedLauncher.body.requestId,failedLauncher.body.requestId);
 w.document.querySelector('#desktop-launcher-download').click();await waitFor(()=>downloadedBlob&&downloadedName,'random-name provisioned A download with strict name/header checks');assert.equal(downloadedName,launcherName);assert.match(downloadedName,/^[a-f0-9]{32}\.exe$/);assert.equal(await downloadedBlob.text(),'MZ_PROVISIONED_A_FIXTURE');await closeModal();
 assert.match(w.document.querySelector('#desktop-bootstrap-launchers').textContent,/<고객 A>/);assert.equal(w.document.querySelector('#desktop-bootstrap-launchers 고객'),null);
 w.document.querySelector('[data-desktop-action="session-revoke"]').click();await waitFor(()=>shown('[data-modal-field="reason"]')&&!modalClosed(),'flow revoke form');field('reason','관리자 실행 종료');await closeModal();assert.match(w.document.querySelector('#desktop-bootstrap-sessions').textContent,/폐기됨/);
 assert.equal(w.document.querySelectorAll('#nav [data-view^="member-"]').length,0);
 for(const view of ['clients','licenses','qrauth','clientbiometrics','buildsessions','support','reinstallblocks'])assert.equal(w.document.querySelector(`#nav [data-view="${view}"]`),null);
 for(const view of ['servers','security','audit','reports','sessions','backups','health','system'])assert.ok(w.document.querySelector(`#nav [data-view="${view}"]`));
 assert.equal(w.document.querySelectorAll('#desktop-license-records tbody tr').length,25);
 assert.equal(w.document.querySelectorAll('#desktop-license-records img,#desktop-license-records script').length,0);
 assert.match(w.document.querySelector('#desktop-license-records').textContent,/<img src=x onerror=bad\(\)>/);
 assert.ok(!w.document.querySelector('[data-desktop-action="reset"],[data-desktop-action="unbind"]'));
 w.document.querySelector('[data-desktop-page="1"]').click();await waitFor(()=>w.document.querySelectorAll('#desktop-license-records tbody tr').length===3&&actionIdle(),'second license page');assert.equal(w.document.querySelectorAll('#desktop-license-records tbody tr').length,3);
 w.document.querySelector('[data-desktop-status="USED"]').click();await waitFor(()=>w.document.querySelectorAll('#desktop-license-records tbody tr').length===1&&actionIdle(),'used status filter');assert.equal(w.document.querySelectorAll('#desktop-license-records tbody tr').length,1);
 // Status cards always use global server counts, including under a status filter.
 assert.equal(w.document.querySelector('[data-desktop-status="AVAILABLE"] strong').textContent,'27');
 w.document.querySelector('[data-desktop-status="AVAILABLE"]').click();await waitFor(()=>w.document.querySelector('#desktop-license-filter')?.value==='AVAILABLE'&&actionIdle(),'available filter');
 assert.equal(w.document.querySelector('[data-desktop-status="USED"] strong').textContent,'1');assert.match(w.document.querySelector('#desktop-license-result-summary').textContent,/필터 적용: 사용 전/);assert.equal(w.document.querySelector('#desktop-license-clear').textContent,'전체 보기');
 // Polling can update data while a selector remains focused. Typed search text
 // remains in its original DOM node until explicitly submitted.
 const filter=w.document.querySelector('#desktop-license-filter');filter.focus();const beforeFocused=requests.length;await w.renderCurrent(true);assert.ok(requests.length>beforeFocused);assert.equal(w.document.querySelector('#desktop-license-filter'),filter);assert.equal(w.document.activeElement,filter);
 const search=w.document.querySelector('#desktop-license-search');search.value='아직 검색하지 않은 입력';search.focus();rows[1].status='USED';await w.renderCurrent(true);
 assert.equal(w.document.querySelector('#desktop-license-search'),search);assert.equal(search.value,'아직 검색하지 않은 입력');assert.equal(w.document.activeElement,search);assert.equal(w.document.querySelector('[data-desktop-status="USED"] strong').textContent,'2');assert.equal(w.document.querySelector('[data-desktop-status="AVAILABLE"] strong').textContent,'26');
 rows[1].status='AVAILABLE';await w.renderCurrent(true);
 // An SSE outage starts a bounded polling fallback; reconnect clears it.
 const source=eventSources.at(-1),beforeDisconnect=requests.length;source.onerror();await waitFor(()=>requests.length>beforeDisconnect&&actionIdle(),'SSE fallback initial refresh');
 assert.match(w.document.querySelector('#live-state').textContent,/15초/);const poll=[...intervals.values()].find(timer=>timer.delay===15000);assert.ok(poll);const beforePoll=requests.length;poll.fn();await waitFor(()=>requests.length>beforePoll&&actionIdle(),'SSE fallback timer refresh');
 source.listeners.get('ready')();await waitFor(actionIdle,'SSE reconnect refresh');assert.equal([...intervals.values()].filter(timer=>timer.delay===15000).length,0);
 const beforeActivation=requests.length;source.listeners.get('relay-event')({data:JSON.stringify({type:'desktop_license_activated',time:now,detail:'safe fixture'})});await waitFor(()=>requests.length>beforeActivation&&actionIdle(),'activation event refresh');
 w.document.querySelector('#desktop-license-clear').click();await waitFor(()=>w.document.querySelectorAll('#desktop-license-records tbody tr').length===25&&actionIdle(),'clear license filter');
 // Details intentionally have no key re-read; one-use machine locks are automatic.
 const detailRequests=()=>requests.filter(r=>r.method==='GET'&&/^\/api\/desktop\/licenses\/[^/]+$/.test(r.url));
 assert.equal(detailRequests().length,0);assert.ok(!w.document.body.textContent.includes(key));
 assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/불일치 · 거부/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/미등록 기준 · 검증 안 됨/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/하드웨어 인증은 아닙니다/);
 w.document.querySelector('[data-desktop-action="detail"]').click();await waitFor(()=>!modalClosed()&&shown('#desktop-machine-security-title'),'license detail dialog');
 assert.equal(shown('#desktop-detail-key'),false);assert.ok(w.document.querySelector('#modal-body').textContent.includes(machineId));assert.ok(w.document.querySelector('#modal-body').textContent.includes(binarySha256));assert.ok(w.document.querySelector('#modal-body').textContent.includes(binaryCrc64));assert.match(w.document.querySelector('#modal-body').textContent,/현재 인증된 실행은 계속/);assert.equal(w.document.querySelector('#desktop-machine-action').textContent,'이 PC 차단 해제');
 assert.equal(detailRequests().at(-1).url,'/api/desktop/licenses/DL_000');assert.match(w.document.querySelector('#modal-body').textContent,/사용됨/);await closeModal();
 assert.ok(!w.document.body.textContent.includes(key));assert.ok(!Object.keys(w.localStorage).some(name=>String(w.localStorage.getItem(name)).includes(key)));
 const machineRequests=()=>requests.filter(r=>r.url.startsWith('/api/desktop/machines/'));
 w.document.querySelector('[data-desktop-action="detail"]').click();await waitFor(()=>shown('#desktop-machine-action')&&!modalClosed(),'machine detail for cancelled unblock');w.document.querySelector('#desktop-machine-action').click();await waitFor(()=>shown('[data-modal-field="reason"]')&&!modalClosed()&&w.document.querySelector('#modal-title').textContent==='이 PC 접근 차단 해제','machine unblock confirmation');w.document.querySelector('#modal-cancel').click();await waitFor(()=>modalClosed()&&actionIdle(),'cancel machine unblock');assert.equal(machineRequests().length,0);
 w.document.querySelector('[data-desktop-machine]').click();await waitFor(()=>shown('[data-modal-field="reason"]')&&!modalClosed(),'unblock from machine panel');assert.match(w.document.querySelector('#modal-body').textContent,/사용된 키는 복구되지 않습니다/);field('reason','관리자 확인 후 허용');await closeModal();assert.equal(machineRequests().length,1);assert.equal(machineRequests()[0].url,'/api/desktop/machines/'+machineId+'/unblock');assert.equal(rows[0].status,'USED');assert.equal(rows[0].machineBlocked,false);
 w.document.querySelector('[data-desktop-action="detail"]').click();await waitFor(()=>shown('#desktop-machine-security-title')&&!modalClosed(),'unblocked detail');assert.equal(shown('#desktop-machine-action'),false);await closeModal();
 // Baseline publication uses authenticated raw upload, never a client report.
 w.document.querySelector('#desktop-module-baseline-add').click();await waitFor(()=>shown('#desktop-baseline-file')&&!modalClosed(),'module baseline upload');const dllInput=w.document.querySelector('#desktop-baseline-file'),dllFile=new w.File(['MZ_DLL'],'ntdll.dll');Object.defineProperty(dllInput,'files',{value:[dllFile]});field('label','Windows test version');await closeModal();assert.ok(requests.some(r=>r.url.startsWith('/api/desktop/bootstrap/module-baselines?')&&r.csrf==='DOM_CSRF'));
 // Pure one-use issuance has no duration/expiry controls or request fields.
 w.document.querySelector('#desktop-license-create').click();await waitFor(()=>shown('[data-modal-field="label"]')&&!modalClosed(),'issue form');assert.equal(shown('[data-modal-field="term"],[data-modal-field="days"],[data-modal-field="expiresAt"],[data-modal-field="validDays"]'),false);assert.equal(w.document.querySelectorAll('[data-modal-field]').length,1);field('label','실제 고객');w.document.querySelector('#modal-confirm').click();await waitFor(()=>shown('#desktop-issued-key'),'new license receipt');
 assert.equal(w.document.querySelector('#desktop-issued-key').value,key);assert.ok(!Object.keys(w.localStorage).some(name=>String(w.localStorage.getItem(name)).includes(key)));
 w.document.querySelector('#desktop-key-copy').click();await waitFor(()=>copied===key,'clipboard write');assert.equal(copied,key);
 assert.match(w.document.querySelector('#modal-body').textContent,/발급 화면에서만/);assert.doesNotMatch(w.document.querySelector('#modal-body').textContent,/KEY:|\*로/);assert.match(w.document.querySelector('#modal-body').textContent,/성공 후에는 빈 화면/);assert.match(key,/^[A-F0-9]{64}$/);
 await closeModal();assert.equal(w.document.querySelector('#desktop-issued-key'),null);assert.ok(!w.document.body.textContent.includes(key));
 // Newly issued key is also absent from its detail.
 const detailSearch=w.document.querySelector('#desktop-license-search');detailSearch.value=issuedId;w.document.querySelector('#desktop-license-search-form').dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await waitFor(()=>w.document.querySelectorAll('#desktop-license-records tbody tr').length===1&&actionIdle(),'issued row search');
 w.document.querySelector('[data-desktop-action="detail"]').click();await waitFor(()=>shown('#desktop-machine-security-title')&&!modalClosed(),'issued key detail');assert.equal(shown('#desktop-detail-key'),false);assert.equal(detailRequests().at(-1).url,'/api/desktop/licenses/'+issuedId);await closeModal();
 w.document.querySelector('#desktop-license-clear').click();await waitFor(()=>w.document.querySelectorAll('#desktop-license-records tbody tr').length===25&&actionIdle(),'clear after issued key detail');
 // A lost response retries the same request identifier, never a fresh issuance.
 issueFail=true;w.document.querySelector('#desktop-license-create').click();await waitFor(()=>shown('[data-modal-field="label"]')&&!modalClosed(),'retry fixture issue form');field('label','재시도');w.document.querySelector('#modal-confirm').click();await waitFor(()=>modalClosed()&&actionIdle()&&!issueFail,'failed issuance response');
 const failed=requests.filter(r=>r.method==='POST'&&r.url==='/api/desktop/licenses').at(-1);
 w.document.querySelector('#desktop-license-create').click();await waitFor(()=>!modalClosed()&&w.document.querySelector('#modal-title').textContent.includes('이전 발급'),'retry confirmation');assert.match(w.document.querySelector('#modal-title').textContent,/이전 발급/);w.document.querySelector('#modal-confirm').click();await waitFor(()=>shown('#desktop-issued-key'),'retried issuance receipt');
 const retried=requests.filter(r=>r.method==='POST'&&r.url==='/api/desktop/licenses').at(-1);assert.equal(retried.body.requestId,failed.body.requestId);await closeModal();
 w.document.querySelector('[data-desktop-action="revoke"]').click();await waitFor(()=>shown('[data-modal-field="reason"]')&&!modalClosed(),'revoke form');field('reason','사용자 요청');await closeModal();
 assert.ok(requests.some(r=>r.url.endsWith('/revoke')&&r.csrf==='DOM_CSRF'));
 w.document.querySelector('[data-desktop-action="reissue"]').click();await waitFor(()=>shown('[data-modal-field="reason"]')&&!modalClosed(),'reissue form');assert.equal(w.document.querySelectorAll('[data-modal-field]').length,2);assert.equal(shown('[data-modal-field="term"],[data-modal-field="days"]'),false);field('reason','장비 교체');w.document.querySelector('#modal-confirm').click();await waitFor(()=>shown('#desktop-issued-key'),'replacement receipt');assert.equal(w.document.querySelector('#desktop-issued-key').value,key);await closeModal();
 assert.ok(requests.filter(r=>r.method==='POST').every(r=>r.csrf==='DOM_CSRF'));
 assert.ok(!requests.some(r=>/^\/api\/(clients|qr-auth|licenses|member|support)/.test(r.url)));
 const issuedDownload={launcherId,downloadName:launcherName,downloadUrl:'/api/desktop/bootstrap/launchers/'+launcherId+'/download'};
 const beforeInvalidName=requests.length;await assert.rejects(()=>w.downloadDesktopLauncher({...issuedDownload,downloadName:'A.exe'},'DOM_CSRF'),/파일 이름/);assert.equal(requests.length,beforeInvalidName);
 downloadHeaderName='f'.repeat(32)+'.exe';await assert.rejects(()=>w.downloadDesktopLauncher(issuedDownload,'DOM_CSRF'),/일치하지/);downloadHeaderName=launcherName;
 // A detail response arriving after logout/session replacement must not reveal
 // the key in a new session, even though the original request was authorized.
 const normalFetch=w.fetch;let finishDetail=null;
 w.fetch=(url,options)=>url==='/api/desktop/licenses/'+issuedId?new Promise(resolve=>{finishDetail=resolve;}):normalFetch(url,options);
 const abandonedDetail=w.showDesktopLicenseDetail(issuedId);await waitFor(()=>finishDetail!==null,'pending detail request');
 vm.runInContext("session={role:'viewer',csrf:'VIEWER'}",dom.getInternalVMContext());finishDetail({ok:true,status:200,text:async()=>JSON.stringify({ok:true,license:{id:issuedId,status:'AVAILABLE'},licenseKey:key})});await abandonedDetail;w.fetch=normalFetch;
 assert.equal(shown('#desktop-detail-key'),false);assert.ok(!w.document.body.textContent.includes(key));
 const beforeForbidden=requests.length;await assert.rejects(()=>w.downloadDesktopLauncher({launcherId,downloadUrl:'/api/desktop/bootstrap/launchers/'+launcherId+'/download'},'DOM_CSRF'),/관리자/);assert.equal(requests.length,beforeForbidden);
 await assert.rejects(()=>w.showDesktopLicenseDetail(issuedId),/관리자/);assert.equal(requests.length,beforeForbidden);assert.equal(shown('#desktop-detail-key'),false);
 assert.equal(errors.length,0,errors.join('\n'));
 console.log('DESKTOP ADMIN UI PASS: actual script shell, retired navigation, retained operations, escaped rows, paging/filters, USED status/counts, no detail key reveal, issuance-only copy/close scrub, raw legacy IDs preserved in API paths with prefix-free display, pure one-use issuance without expiry request fields, receipt scrub, stable request retry, revoke/reissue, CSRF, A/B binary File uploads with retry preservation, random-name provisioned A download with strict name/header checks, launcher idempotency, linked license state, session revoke, global counts under filters, PC fingerprint/CRC64/SHA256 evidence, automatic PC lock, admin-only CSRF unblock, visible blank-console input instructions, server integrity diagnostics and trusted module baseline upload, preserved drafts, focused-select refresh, SSE polling recovery.');
 }finally{w.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
