'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM,VirtualConsole}=require('jsdom');
const crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),html=fs.readFileSync(path.join(root,'public/index.html'),'utf8');
const errors=[],requests=[],now=Date.now(),key='A1B2C3D4'.repeat(8),issuedId='A1B2C3D4'.repeat(3),launcherId='B2C3D4E5'.repeat(3);
const machineId='F1A2B3C4'.repeat(8),binarySha256='ab'.repeat(32),binaryCrc64='12ABCDEF09876543';
const eatSha256='de'.repeat(32),eatCrc64='98ABCDEF01234567',changedEatSha256='ef'.repeat(32),changedEatCrc64='FEDCBA9876543210';
const xxh64='ABCDEF1234567890',blake3='13'.repeat(32),otherXxh64='0123456789ABCDEF',otherBlake3='24'.repeat(32);
const extendedBaseline={fileXxh64:xxh64,fileBlake3:blake3,codeXxh64:xxh64,codeBlake3:blake3,exportTableXxh64:xxh64,exportTableBlake3:blake3};
const moduleBaselines=[];let integrityPolicy={enabled:false,requireExtendedHashes:false,requiredModules:['ntdll.dll','kernel32.dll','kernelbase.dll'],revision:0,updatedAt:0,actor:'',freshnessMs:{A:180000,B:120000},attested:false};
function policyView(){const missingExtendedBaselines=integrityPolicy.requiredModules.filter(name=>!moduleBaselines.some(b=>b.name.toLowerCase()===name&&Object.keys(extendedBaseline).every(key=>b[key]))),missingBaselines=integrityPolicy.requiredModules.filter(name=>!moduleBaselines.some(b=>b.name.toLowerCase()===name&&b.exportTableStatus==='MEASURED')||integrityPolicy.requireExtendedHashes&&missingExtendedBaselines.includes(name));return {...integrityPolicy,baselineReady:missingBaselines.length===0,missingBaselines,missingExtendedBaselines};}
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
const candidates=[],artifacts={A:null,B:null},bootstrapSessions=[{id:'DS_test',flowId:'FLOW_test',launcherId:'DA_test',status:'CLAIMED',deviceId:'PC_fingerprint',version:'1.0.0',createdAt:now-4000,expiresAt:now+300000,licenseId:'DL_000',licenseStatus:'USED',licenseLastVerifiedAt:now-1000}],launchers=[];
let securityPolicy={version:1,revision:0,mode:'enforce',enforceLegacy:false,freshnessMs:45000,challengeMs:15000,requireReadonlyApi:true,dynamicCode:'observe',requireCfg:false,minVersionA:'0',minVersionB:'0',requireReleaseSignature:false,trustedReleaseKeys:[],revokedSha256:[]};
let securityOps={version:1,revision:0,requireBuildContract:false,requireTestEvidence:false,contracts:{},pairEvidence:{},signerStates:{},rollout:{enabled:false,artifactKeys:[],patch:{}},activations:[]};
function securityView(){return{ok:true,policy:securityPolicy,releases:candidates,recentBuildObservations:[],events:[],operations:{operations:securityOps,active:{A:artifacts.A?.id||'',B:artifacts.B?.id||''},candidates:candidates.map(a=>({...a,active:artifacts[a.component]?.id===a.id,contract:null})),auditHealth:{status:'HEALTHY',failedWrites:0},adminProtection:{dualApprovalRequired:false,stepUpRequired:false,provisionedPrincipalCount:0}}};}
Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async text=>{copied=text;}}});
const integrityReports=[{id:'audit1',at:now,stage:'B',check:'OWN_CODE',status:'REJECTED',reason:'CODE_HASH_MISMATCH',sessionId:'SESSION1',machineId,expectedSha256:binarySha256,observedSha256:'cd'.repeat(32),expectedCrc64:binaryCrc64,observedCrc64:'AB'.repeat(8)},{id:'audit2',at:now,stage:'A',check:'MODULE_INVENTORY',status:'CLIENT_DIAGNOSTIC',reason:'PERIODIC',snapshotId:'snapshot1',batchIndex:0,batchCount:1,totalModules:1,measuredModules:1,complete:true,truncated:false,snapshotStatus:'RECEIVING',snapshotReceivedBatches:1,strictPolicyRevision:0,modules:[{name:'ntdll.dll',executableSections:2,exportCount:2000,codeExportCount:1800,forwardedExportCount:200,exportCoverage:'SECTION_HASHED',status:'UNVERIFIED_BASELINE',codeStatus:'MATCH_LOCAL_FILE',serverComparison:'UNVERIFIED_BASELINE',fileSha256:binarySha256,codeSha256:binarySha256}]},{id:'audit3',at:now,stage:'B',check:'MODULE_SNAPSHOT',status:'REJECTED',reason:'INTEGRITY_SNAPSHOT_STALE',snapshotId:'snapshot2',batchCount:2,snapshotReceivedBatches:1,snapshotStatus:'TIMED_OUT',snapshotReasons:['REQUIRED_MODULE_MISSING'],strictPolicyRevision:0,totalModules:24,measuredModules:16,complete:false,truncated:true},{id:'audit4',at:now,stage:'B',check:'MODULE_INVENTORY',status:'REJECTED',reason:'KNOWN_MODULE_CODE_MISMATCH',modules:[{name:'kernel32.dll',status:'MATCH_LOCAL_FILE',codeStatus:'MATCH_LOCAL_FILE',serverComparison:'REGISTERED_BASELINE_MISMATCH',fileSha256:binarySha256,fileCrc64:binaryCrc64,codeSha256:binarySha256,codeCrc64:binaryCrc64,expectedCodeSha256:binarySha256,expectedCodeCrc64:binaryCrc64,exportTableStatus:'MEASURED',exportTableSha256:changedEatSha256,exportTableCrc64:changedEatCrc64,expectedExportTableSha256:eatSha256,expectedExportTableCrc64:eatCrc64,exportTableVerified:false}]}];
integrityReports[1].modules.push({name:'unknown',status:'READ_ERROR'},{name:'unknown',status:'FILE_UNAVAILABLE'});
Object.assign(integrityReports[0],{hashVersion:2,expectedFileXxh64:xxh64,observedFileXxh64:xxh64,expectedFileBlake3:blake3,observedFileBlake3:blake3,expectedXxh64:xxh64,observedXxh64:otherXxh64,expectedBlake3:blake3,observedBlake3:otherBlake3,extendedHashesVerified:false});
Object.assign(integrityReports[3].modules[0],{...extendedBaseline,hashVersion:2,expectedFileXxh64:xxh64,expectedFileBlake3:blake3,expectedCodeXxh64:xxh64,expectedCodeBlake3:blake3,expectedExportTableXxh64:xxh64,expectedExportTableBlake3:blake3,exportTableXxh64:otherXxh64,exportTableBlake3:otherBlake3,fileExtendedVerified:true,codeExtendedVerified:true,exportTableExtendedVerified:false,extendedHashesVerified:false});
w.fetch=async(url,options={})=>{
 const method=options.method||'GET',body=typeof options.body==='string'?JSON.parse(options.body):options.body||null;requests.push({url,method,body,headers:options.headers,credentials:options.credentials,csrf:options.headers?.['X-CSRF-Token']});let data;
 if(url==='/api/session')data={ok:true,role:'admin',csrf:'DOM_CSRF',expiresAt:now+600000};
 else if(url==='/api/system')data={ok:true,system:{webAdminVersion:'5.0.1'}};
 else if(url.startsWith('/api/audit?'))data={ok:true,events:[{type:'TEST_EVENT',time:now,detail:'감사 기록 fixture'}]};
 else if(url.startsWith('/api/notifications?'))data={ok:true,summary:{unread:0,critical:0}};
 else if(url==='/api/desktop/bootstrap/integrity-reports')data={ok:true,items:integrityReports};
 else if(url==='/api/desktop/bootstrap/integrity-policy'){
   if(method==='POST'){assert.equal(options.headers['X-CSRF-Token'],'DOM_CSRF');assert.equal(options.credentials,'same-origin');assert.equal(typeof body.enabled,'boolean');assert.equal(typeof body.requireExtendedHashes,'boolean');assert.ok(Array.isArray(body.requiredModules));if(body.enabled&&body.requiredModules.some(name=>!moduleBaselines.some(b=>b.name.toLowerCase()===name&&b.exportTableStatus==='MEASURED'&&(!body.requireExtendedHashes||Object.keys(extendedBaseline).every(key=>b[key])))))return {ok:false,status:409,text:async()=>JSON.stringify({ok:false,error:'INTEGRITY_POLICY_BASELINE_MISSING'})};integrityPolicy={...integrityPolicy,...body,revision:integrityPolicy.revision+1,updatedAt:now,actor:'admin'};}data={ok:true,policy:policyView()};
 }
 else if(url==='/api/desktop/bootstrap/module-baselines')data={ok:true,items:moduleBaselines};
 else if(url.startsWith('/api/desktop/bootstrap/module-baselines?')){assert.equal(method,'POST');assert.ok(body instanceof w.File);assert.equal(options.headers['X-CSRF-Token'],'DOM_CSRF');const name=new URL(url,'https://fixture.invalid').searchParams.get('fileName');const baseline={name,fileSha256:binarySha256,fileCrc64:binaryCrc64,codeSha256:binarySha256,codeCrc64:binaryCrc64,exportTableStatus:'MEASURED',exportTableSha256:eatSha256,exportTableCrc64:eatCrc64,...extendedBaseline,createdAt:now,label:'fixture'},existing=moduleBaselines.find(b=>b.name===name&&b.fileSha256===baseline.fileSha256);if(existing)Object.assign(existing,baseline);else moduleBaselines.push(baseline);data={ok:true,baseline:{name}};}
 else if(url==='/api/desktop/machines')data={ok:true,items:rows.filter(row=>row.machineId).map(row=>({machineId:row.machineId,blocked:row.machineBlocked,source:row.machinePolicy?.source||'NONE',reason:row.machinePolicy?.reason||'',changedAt:now}))};
 else if(url==='/api/desktop/bootstrap/security-authority'){
   if(method==='POST'){assert.equal(body.expectedRevision,securityPolicy.revision);securityPolicy={...securityPolicy,...body,revision:securityPolicy.revision+1};delete securityPolicy.expectedRevision;delete securityPolicy.expectedOperationsRevision;securityOps.revision++;}
   data=securityView();
 }
 else if(url==='/api/desktop/bootstrap/security-operations/activation')data={ok:true,status:{allEnabled:false,serverEnabled:false,baselineEnabled:false}};
 else if(url==='/api/desktop/bootstrap/security-authority/preview')data={ok:true,preview:{readOnly:true,baseRevision:securityPolicy.revision,eligible:true,runtimeCompatibility:'RECENT_OBSERVATIONS_ONLY_NOT_OFFLINE_PC_PROOF'}};
 else if(url==='/api/desktop/bootstrap/security-operations/preview-pair')data={ok:true,preview:{...body,eligible:true,policyRevision:securityPolicy.revision,operationsRevision:securityOps.revision}};
 else if(url==='/api/desktop/bootstrap/security-operations/activate'){
   assert.equal(method,'POST');assert.equal(options.headers['X-CSRF-Token'],'DOM_CSRF');assert.equal(body.expectedRevision,securityOps.revision);assert.equal(body.expectedPolicyRevision,securityPolicy.revision);artifacts.A=candidates.find(x=>x.id===body.aId);artifacts.B=candidates.find(x=>x.id===body.bId);assert.ok(artifacts.A&&artifacts.B);securityOps.revision++;data={ok:true};
 }
 else if(url==='/api/desktop/bootstrap')data={ok:true,bootstrap:{artifacts:{...artifacts},launchers:[...launchers],sessions:bootstrapSessions.map(row=>({...row})),limits:{maxArtifactBytes:67108864},serverTime:now}};
 else if(url.startsWith('/api/desktop/bootstrap/artifacts?')){
   assert.equal(method,'POST');assert.ok(body instanceof w.File);assert.equal(options.headers['Content-Type'],'application/octet-stream');assert.equal(options.credentials,'same-origin');
   if(uploadFail){uploadFail=false;throw new TypeError('upload interrupted');}
   const params=new URL(url,'https://fixture.invalid').searchParams,component=params.get('component');assert.ok(['A','B'].includes(component));assert.equal(params.get('fileName'),component+'.exe');
   const artifact={id:'ART_'+component,component,version:params.get('version'),sha256:(component==='A'?'a':'b').repeat(64),crc64:binaryCrc64,size:body.size,createdAt:now};candidates.push(artifact);data={ok:true,artifact,disposition:'CANDIDATE',activeUnchanged:true};
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
 else if(url.startsWith('/api/desktop/licenses?')||url.startsWith('/api/desktop/workspace/licenses?')){
   const params=new URL(url,'https://fixture.invalid').searchParams,q=(params.get('q')||'').toLowerCase(),status=params.get('status');assert.ok(status===null||['AVAILABLE','USED','REVOKED','EXPIRED'].includes(status),'The API does not accept the UI-only ALL filter');
   const matching=rows.filter(x=>(!status||x.status===status)&&[x.id,x.label,x.deviceName].join(' ').toLowerCase().includes(q)),pageSize=Number(params.get('pageSize')||25),page=Math.min(Number(params.get('page')||0),Math.max(0,Math.ceil(matching.length/pageSize)-1));
   data={ok:true,items:url.startsWith('/api/desktop/workspace/')?matching.slice(page*pageSize,(page+1)*pageSize):matching,counts:Object.fromEntries(['AVAILABLE','USED','REVOKED','EXPIRED'].map(status=>[status,rows.filter(row=>row.status===status).length])),totalCount:rows.length,filteredCount:matching.length,page,pageSize,pages:Math.max(1,Math.ceil(matching.length/pageSize)),revision:1,serverTime:now};
 }
 else if(method==='GET'&&/^\/api\/desktop\/workspace\/licenses\/[^/]+$/.test(url)){
   const id=decodeURIComponent(url.split('/').at(-1)),row=rows.find(row=>row.id===id);assert.ok(row,'detail must use an existing raw ID');data={ok:true,license:{...row},metadata:{revision:0,note:'',tags:[]},timeline:[],flows:row.binarySha256?[{binarySha256:row.binarySha256}]:[]};
 }
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
async function settlePanels(){await waitFor(()=>vm.runInContext('[...desktopPanels.values()].every(item=>!item.pending)',dom.getInternalVMContext()),'asynchronous panel replies');await w.renderCurrent(true);}
async function closeModal(){w.document.querySelector('#modal-confirm').click();await waitFor(()=>modalClosed()&&actionIdle(),'modal close and action completion');await settlePanels();}
// Simulate a panel cache reaching its existing ten-second lifetime; fake server
// data changes below should be fetched before their DOM content is asserted.
async function refreshPanel(key){vm.runInContext(`if(desktopPanels.has(${JSON.stringify(key)}))desktopPanels.get(${JSON.stringify(key)}).at=0`,dom.getInternalVMContext());await w.renderCurrent(true);await settlePanels();}

function field(name,value){const input=w.document.querySelector(`[data-modal-field="${name}"]`);assert.ok(input,name);input.value=value;return input;}
(async()=>{try{
 await waitFor(()=>shown('#desktop-launcher-create')&&actionIdle(),'initial license page');
 assert.equal(w.document.querySelector('#app').classList.contains('hidden'),false);
 assert.equal(w.document.querySelector('#page-title').textContent,'Windows 라이선스');
 assert.equal(new URL(requests.find(r=>r.url.startsWith('/api/desktop/workspace/licenses?')).url,'https://fixture.invalid').searchParams.has('status'),false);
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
   assert.equal(w.document.querySelector('#desktop-launcher-create').disabled,true,'Candidates do not become active on upload');
 }
 w.document.querySelector('[data-desktop-action="security-operations"]').click();await waitFor(()=>shown('#desktop-security-root'),'security operations modal');
 const securityAction=name=>w.document.querySelector(`[data-security-action="${name}"]`).click();
 const beforePremature=requests.length;securityAction('save-policy');await waitFor(()=>w.document.querySelector('#security-status').textContent.includes('미리보기'),'policy preview required');assert.equal(requests.length,beforePremature);
 securityAction('preview-policy');await waitFor(()=>w.document.querySelector('#sec-policy-preview').textContent.includes('readOnly'),'read-only preview');
 w.document.querySelector('#sec-fresh').value='44000';const beforeChanged=requests.length;securityAction('save-policy');await waitFor(()=>w.document.querySelector('#security-status').textContent.includes('미리보기'),'changed policy requires new preview');assert.equal(requests.length,beforeChanged);
 securityAction('preview-policy');await waitFor(()=>w.document.querySelector('#security-status').textContent==='처리했습니다.','new policy preview');
 securityAction('save-policy');await waitFor(()=>w.document.querySelector('#security-status').textContent.includes('서버에 반영'),'server policy save');
 const beforePair=requests.length;securityAction('activate');await waitFor(()=>w.document.querySelector('#security-status').textContent.includes('먼저 검증'),'pair preview required');assert.equal(requests.length,beforePair);
 securityAction('preview-pair');await waitFor(()=>w.document.querySelector('#sec-pair-preview').textContent.includes('eligible'),'pair preview');
 securityAction('activate');await waitFor(()=>w.document.querySelector('#security-status').textContent.includes('서버에 반영'),'pair activate');
 await closeModal();await w.renderCurrent();assert.equal(w.document.querySelector('#desktop-security-root')?.childElementCount||0,0);
 console.log('PASS DOM model: candidates are not active; policy/pair preview requirements; server-only operation requests; close cleanup');
 await waitFor(()=>!w.document.querySelector('#desktop-launcher-create').disabled&&actionIdle(),'active pair panel refresh');
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
 await w.renderCurrent();assert.equal(w.document.querySelector('#desktop-license-search'),search);assert.equal(search.value,'아직 검색하지 않은 입력');assert.equal(w.document.activeElement,search);
 rows[1].status='AVAILABLE';await w.renderCurrent(true);
 // A change during an in-flight poll is queued instead of being dropped. The
 // same native selector survives both requests and keeps the latest selection.
 const beforeQueuedFetch=w.fetch;let finishPoll=null,heldPoll=false;
 w.fetch=(url,options)=>{if(!heldPoll&&url.startsWith('/api/desktop/workspace/licenses?')){heldPoll=true;return new Promise(resolve=>{finishPoll=()=>resolve(beforeQueuedFetch(url,options));});}return beforeQueuedFetch(url,options);};
 filter.focus();const inFlight=w.renderCurrent(true);await waitFor(()=>finishPoll!==null,'held license poll');
 filter.value='USED';filter.dispatchEvent(new w.Event('change',{bubbles:true}));finishPoll();await inFlight;await waitFor(()=>actionIdle()&&w.document.querySelectorAll('#desktop-license-records tbody tr').length===1,'queued filter after poll');w.fetch=beforeQueuedFetch;
 assert.equal(w.document.querySelector('#desktop-license-filter'),filter);assert.equal(w.document.activeElement,filter);assert.equal(filter.value,'USED');
 const selectedOption=filter.options[filter.selectedIndex];await w.renderCurrent(true);assert.equal(filter.options[filter.selectedIndex],selectedOption);assert.equal(filter.value,'USED');
 // An SSE outage starts a bounded polling fallback; reconnect clears it.
 const source=eventSources.at(-1),beforeDisconnect=requests.length;source.onerror();await waitFor(()=>requests.length>beforeDisconnect&&actionIdle(),'SSE fallback initial refresh');
 assert.match(w.document.querySelector('#live-state').textContent,/15초/);const poll=[...intervals.values()].find(timer=>timer.delay===15000);assert.ok(poll);const beforePoll=requests.length;poll.fn();await waitFor(()=>requests.length>beforePoll&&actionIdle(),'SSE fallback timer refresh');
 source.listeners.get('ready')();await waitFor(actionIdle,'SSE reconnect refresh');assert.equal([...intervals.values()].filter(timer=>timer.delay===15000).length,0);
 const beforeActivation=requests.length;source.listeners.get('relay-event')({data:JSON.stringify({type:'desktop_license_activated',time:now,detail:'safe fixture'})});await waitFor(()=>requests.length>beforeActivation&&actionIdle(),'activation event refresh');
 w.document.querySelector('#desktop-license-clear').click();await waitFor(()=>w.document.querySelectorAll('#desktop-license-records tbody tr').length===25&&actionIdle(),'clear license filter');
 // Details intentionally have no key re-read; one-use machine locks are automatic.
 const detailRequests=()=>requests.filter(r=>r.method==='GET'&&/^\/api\/desktop\/(?:workspace\/)?licenses\/[^/]+$/.test(r.url));
 assert.equal(detailRequests().length,0);assert.ok(!w.document.body.textContent.includes(key));
 // Integrity panels now load only when their tab is opened.
 w.document.querySelector('#desktop-tab-modules').click();
 await waitFor(()=>shown('#desktop-integrity-panel')&&actionIdle(),'lazy integrity panel');
 assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/불일치 · 거부/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/미등록 기준 · 검증 안 됨/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/하드웨어 인증은 아닙니다/);
 w.document.querySelector('#desktop-tab-licenses').click();
 w.document.querySelector('[data-desktop-action="detail"]').click();await waitFor(()=>!modalClosed()&&shown('#desktop-machine-security-title'),'license detail dialog');
 assert.equal(shown('#desktop-detail-key'),false);assert.ok(w.document.querySelector('#modal-body').textContent.includes(machineId));assert.ok(w.document.querySelector('#modal-body').textContent.includes(binarySha256));assert.ok(w.document.querySelector('#modal-body').textContent.includes(binaryCrc64));assert.match(w.document.querySelector('#modal-body').textContent,/현재 인증된 실행은 계속/);assert.equal(w.document.querySelector('#desktop-machine-action').textContent,'이 PC 차단 해제');
 assert.equal(detailRequests().at(-1).url,'/api/desktop/workspace/licenses/DL_000');assert.match(w.document.querySelector('#modal-body').textContent,/사용됨/);await closeModal();
 assert.ok(!w.document.body.textContent.includes(key));assert.ok(!Object.keys(w.localStorage).some(name=>String(w.localStorage.getItem(name)).includes(key)));
 const machineRequests=()=>requests.filter(r=>r.url.startsWith('/api/desktop/machines/'));
 w.document.querySelector('[data-desktop-action="detail"]').click();await waitFor(()=>shown('#desktop-machine-action')&&!modalClosed(),'machine detail for cancelled unblock');w.document.querySelector('#desktop-machine-action').click();await waitFor(()=>shown('[data-modal-field="reason"]')&&!modalClosed()&&w.document.querySelector('#modal-title').textContent==='이 PC 접근 차단 해제','machine unblock confirmation');w.document.querySelector('#modal-cancel').click();await waitFor(()=>modalClosed()&&actionIdle(),'cancel machine unblock');assert.equal(machineRequests().length,0);
 w.document.querySelector('[data-desktop-machine]').click();await waitFor(()=>shown('[data-modal-field="reason"]')&&!modalClosed(),'unblock from machine panel');assert.match(w.document.querySelector('#modal-body').textContent,/사용된 키는 복구되지 않습니다/);field('reason','관리자 확인 후 허용');await closeModal();assert.equal(machineRequests().length,1);assert.equal(machineRequests()[0].url,'/api/desktop/machines/'+machineId+'/unblock');assert.equal(rows[0].status,'USED');assert.equal(rows[0].machineBlocked,false);
 w.document.querySelector('[data-desktop-action="detail"]').click();await waitFor(()=>shown('#desktop-machine-security-title')&&!modalClosed(),'unblocked detail');assert.equal(shown('#desktop-machine-action'),false);await closeModal();
 w.document.querySelector('#desktop-tab-modules').click();assert.equal(w.document.querySelector('#desktop-tabpanel-modules').hidden,false);assert.equal(w.document.querySelector('#desktop-tabpanel-licenses').hidden,true);assert.equal(w.document.querySelector('#desktop-tab-modules').getAttribute('aria-selected'),'true');
 await waitFor(()=>shown('#desktop-module-baseline-add')&&actionIdle(),'module panel after machine update');
 // Baseline publication uses authenticated raw upload, never a client report.
 w.document.querySelector('#desktop-module-baseline-add').click();await waitFor(()=>shown('#desktop-baseline-file')&&!modalClosed(),'module baseline upload');const dllInput=w.document.querySelector('#desktop-baseline-file'),dllFile=new w.File(['MZ_DLL'],'ntdll.dll');Object.defineProperty(dllInput,'files',{value:[new w.File(['MZ_DLL'],'a'.repeat(61)+'.dll')],configurable:true});field('label','Windows test version');const beforeLongUpload=requests.length;w.document.querySelector('#modal-confirm').click();await waitFor(()=>w.document.querySelector('#desktop-baseline-status').textContent.includes('64자 이하'),'baseline DLL basename length limit');assert.equal(requests.length,beforeLongUpload);Object.defineProperty(dllInput,'files',{value:[dllFile],configurable:true});await closeModal();assert.ok(requests.some(r=>r.url.startsWith('/api/desktop/bootstrap/module-baselines?')&&r.csrf==='DOM_CSRF'));
 const longLegacyDll='a'.repeat(61)+'.dll';assert.match(w.desktopIntegrityPolicyMarkup({...policyView(),requiredModules:[longLegacyDll],unsupportedRequiredModules:[longLegacyDll]}),/지원하지 않는 이전 필수 DLL 이름/);
 const legacyEatMarkup=w.desktopExportTableMarkup({expectedExportTableSha256:eatSha256,expectedExportTableCrc64:eatCrc64});assert.match(legacyEatMarkup,/서버 EAT 확인 안 됨/);assert.doesNotMatch(legacyEatMarkup,/서버 EAT 기준 불일치/);
 // Strict checks are an explicit server policy, not enabled by initial rendering or DLL upload.
 moduleBaselines.push({name:'kernel32.dll',fileSha256:binarySha256,fileCrc64:binaryCrc64,createdAt:now},{name:'kernelbase.dll',fileSha256:binarySha256,fileCrc64:binaryCrc64,createdAt:now});await refreshPanel('baselines');
 assert.equal(integrityPolicy.enabled,false);
 const policyPosts=()=>requests.filter(r=>r.url==='/api/desktop/bootstrap/integrity-policy'&&r.method==='POST');
 assert.equal(policyPosts().length,0);assert.match(w.document.querySelector('.desktop-integrity-policy').textContent,/꺼짐/);assert.match(w.document.querySelector('.desktop-integrity-policy').textContent,/kernel32.dll/);
 assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/Kernel32.ReadFile/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/KernelBase/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/코드 내보내기 1,800/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/묶음 수신 중/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/측정 수신 시간 초과/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/필수 모듈 누락/);
 const eatRecord=[...w.document.querySelectorAll('.desktop-integrity-record')].find(record=>record.textContent.includes(changedEatSha256));assert.ok(eatRecord);assert.equal(eatRecord.classList.contains('desktop-integrity-rejected'),true);assert.match(eatRecord.textContent,/서버 EAT 기준 불일치/);assert.ok(eatRecord.textContent.includes(eatSha256));assert.ok(eatRecord.textContent.includes(eatCrc64));assert.ok(eatRecord.textContent.includes(changedEatCrc64));assert.match(w.document.querySelector('.desktop-integrity-policy').textContent,/내보내기 테이블\(EAT\) 기준이 없는 필수 DLL: kernel32.dll, kernelbase.dll/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/EAT 기준 미등록 · 원본 재등록 필요/);
 w.document.querySelector('#desktop-integrity-policy-edit').click();await waitFor(()=>shown('[data-modal-field="requiredModules"]')&&!modalClosed(),'policy dialog cancellation');assert.match(w.document.querySelector('#modal-body').textContent,/실행이 거부될 수/);assert.equal(w.document.querySelector('#desktop-policy-extended-hashes').checked,false);w.document.querySelector('#modal-cancel').click();await waitFor(()=>modalClosed()&&actionIdle(),'cancel policy');assert.equal(policyPosts().length,0);
 w.document.querySelector('#desktop-integrity-policy-edit').click();await waitFor(()=>shown('[data-modal-field="requiredModules"]')&&!modalClosed(),'policy dialog');field('enabled','true');field('requiredModules','../ntdll.dll');w.document.querySelector('#modal-confirm').click();await waitFor(()=>w.document.querySelector('#desktop-integrity-policy-status').textContent.includes('경로를 제외'),'invalid policy DLL name');assert.equal(policyPosts().length,0);
 field('requiredModules','a'.repeat(61)+'.dll');w.document.querySelector('#modal-confirm').click();await waitFor(()=>w.document.querySelector('#desktop-integrity-policy-status').textContent.includes('64자 이하'),'policy DLL basename length limit');assert.equal(policyPosts().length,0);
 field('requiredModules','ntdll.dll, kernel32.dll, kernelbase.dll');w.document.querySelector('#modal-confirm').click();await waitFor(()=>w.document.querySelector('#desktop-integrity-policy-status').textContent.includes('모듈 기준을 먼저'),'server denies missing trusted baseline');assert.equal(integrityPolicy.enabled,false);assert.equal(modalClosed(),false);assert.equal(policyPosts().length,1);
 for(const baseline of moduleBaselines)Object.assign(baseline,{exportTableStatus:'MEASURED',exportTableSha256:eatSha256,exportTableCrc64:eatCrc64});
 field('requiredModules','NTDLL.dll, kernel32.dll, kernelbase.dll, ntdll.dll');await closeModal();assert.equal(integrityPolicy.enabled,true);assert.deepEqual(policyPosts().at(-1).body,{enabled:true,requireExtendedHashes:false,requiredModules:['ntdll.dll','kernel32.dll','kernelbase.dll']});assert.equal(policyPosts().at(-1).csrf,'DOM_CSRF');assert.match(w.document.querySelector('.desktop-integrity-policy').textContent,/켜짐/);assert.match(w.document.querySelector('#desktop-integrity-panel').textContent,/현재 정책으로 재측정 필요/);
 w.document.querySelector('#desktop-integrity-policy-edit').click();await waitFor(()=>shown('[data-modal-field="enabled"]')&&!modalClosed(),'policy disabling');assert.equal(field('enabled','false').value,'false');await closeModal();assert.equal(integrityPolicy.enabled,false);assert.equal(policyPosts().at(-1).body.enabled,false);
 // Extended hashes stay opt-in; the same trusted file upgrades a baseline.
 assert.equal(integrityPolicy.requireExtendedHashes,false);assert.ok(w.document.querySelector('#desktop-integrity-panel').textContent.includes(xxh64));assert.ok(w.document.querySelector('#desktop-integrity-panel').textContent.includes(blake3));
 assert.equal(w.document.querySelectorAll('[data-desktop-key="report-audit2"] tbody tr').length,3);await w.renderCurrent(true);assert.equal(w.document.querySelectorAll('[data-desktop-key="report-audit2"] tbody tr').length,3);assert.equal(new Set([...w.document.querySelectorAll('[data-desktop-key="report-audit2"] tbody tr')].map(row=>row.dataset.desktopKey)).size,3);
 const legacyRecord=w.document.querySelector('[data-desktop-key="report-audit2"]');assert.match(legacyRecord.textContent,/미측정 · 검증 안 됨/);assert.doesNotMatch(legacyRecord.textContent,/서버 확장 해시 기준 일치/);
 const extendedRecord=w.document.querySelector('[data-desktop-key="report-audit4"]');assert.match(extendedRecord.textContent,/파일 확장 해시 · 서버 확장 해시 기준 일치/);assert.match(extendedRecord.textContent,/EAT 확장 해시 · 서버 기준 불일치/);assert.ok(extendedRecord.textContent.includes(otherXxh64));assert.ok(extendedRecord.textContent.includes(otherBlake3));
 assert.match(w.desktopExtendedHashMarkup('코드',xxh64,xxh64,blake3,blake3,false),/서버 검증 안 됨/);
 w.document.querySelector('#desktop-integrity-policy-edit').click();await waitFor(()=>shown('#desktop-policy-extended-hashes')&&!modalClosed(),'extended policy opt in');field('enabled','true');w.document.querySelector('#desktop-policy-extended-hashes').checked=true;w.document.querySelector('#modal-confirm').click();await waitFor(()=>w.document.querySelector('#desktop-integrity-policy-status').textContent.includes('모듈 기준을 먼저'),'extended policy needs upgraded baseline');assert.equal(integrityPolicy.requireExtendedHashes,false);w.document.querySelector('#modal-cancel').click();await waitFor(()=>modalClosed()&&actionIdle(),'cancel blocked extended policy');
 const countBeforeUpgrade=moduleBaselines.length;
 for(const name of ['ntdll.dll','kernel32.dll','kernelbase.dll']){
   w.document.querySelector('#desktop-module-baseline-add').click();await waitFor(()=>shown('#desktop-baseline-file')&&!modalClosed(),'same trusted DLL upgrade');const input=w.document.querySelector('#desktop-baseline-file');Object.defineProperty(input,'files',{value:[new w.File(['MZ_DLL'],name)]});await closeModal();
 }
 assert.equal(moduleBaselines.length,countBeforeUpgrade);assert.match(w.document.querySelector('#desktop-module-baselines').textContent,/XXH64/);assert.ok(moduleBaselines.every(b=>Object.keys(extendedBaseline).every(key=>b[key])));
 w.document.querySelector('#desktop-integrity-policy-edit').click();await waitFor(()=>shown('#desktop-policy-extended-hashes')&&!modalClosed(),'extended policy enable');field('enabled','true');w.document.querySelector('#desktop-policy-extended-hashes').checked=true;await closeModal();assert.equal(integrityPolicy.requireExtendedHashes,true);assert.equal(policyPosts().at(-1).body.requireExtendedHashes,true);
 // Actual DOM nodes and each scroller survive SSE, polling, and explicit refresh.
 const modulePanel=w.document.querySelector('#desktop-tabpanel-modules'),record=w.document.querySelector('[data-desktop-key="report-audit4"]'),baselineDetails=w.document.querySelector('#desktop-module-baselines'),integrityList=w.document.querySelector('.desktop-integrity-list'),reportTable=record.querySelector('.table-wrap'),mainPane=w.document.querySelector('.main'),contentPane=w.document.querySelector('#content');
 record.open=true;baselineDetails.open=true;integrityList.scrollTop=135;reportTable.scrollLeft=144;mainPane.scrollTop=543;contentPane.scrollTop=234;
 const assertWorkspaceState=()=>{assert.equal(w.document.querySelector('#desktop-tabpanel-modules'),modulePanel);assert.equal(modulePanel.hidden,false);assert.equal(w.document.querySelector('#desktop-tab-modules').getAttribute('aria-selected'),'true');assert.equal(w.document.querySelector('[data-desktop-key="report-audit4"]'),record);assert.equal(record.open,true);assert.equal(baselineDetails.open,true);assert.equal(integrityList.scrollTop,135);assert.equal(reportTable.scrollLeft,144);assert.equal(mainPane.scrollTop,543);assert.equal(contentPane.scrollTop,234);};
 rows[2].status='USED';const beforeModuleSse=requests.length;source.listeners.get('relay-event')({data:JSON.stringify({type:'desktop_integrity_report',time:now,detail:'module fixture'})});await waitFor(()=>requests.length>beforeModuleSse&&actionIdle(),'module SSE refresh');assertWorkspaceState();assert.equal(w.document.querySelector('[data-desktop-status="USED"] strong').textContent,'2');
 const beforeModulePoll=requests.length;poll.fn();await waitFor(()=>requests.length>beforeModulePoll&&actionIdle(),'module polling refresh');assertWorkspaceState();await w.renderCurrent();assertWorkspaceState();
 // Scrolling during the request is preserved at commit, not restored backwards.
 const scrollFetch=w.fetch;let releaseScroll=null;
 w.fetch=(url,options)=>url==='/api/desktop/bootstrap/integrity-reports'?new Promise(resolve=>{releaseScroll=()=>resolve(scrollFetch(url,options));}):scrollFetch(url,options);
 vm.runInContext("desktopPanels.get('integrity').at=0",dom.getInternalVMContext());
 const scrollingRefresh=w.renderCurrent(true);await waitFor(()=>releaseScroll!==null,'scroll during live request');mainPane.scrollTop=765;contentPane.scrollTop=345;integrityList.scrollTop=211;releaseScroll();await scrollingRefresh;await settlePanels();w.fetch=scrollFetch;assert.equal(mainPane.scrollTop,765);assert.equal(contentPane.scrollTop,345);assert.equal(integrityList.scrollTop,211);assert.equal(record.open,true);
 // JSDOM has no layout engine. Supply only geometry for the existing real DOM
 // scroller/record so prepending a live report tests the scroll anchor correction.
 const firstRecord=w.document.querySelector('[data-desktop-key="report-audit1"]');integrityList.scrollTop=0;
 integrityList.getBoundingClientRect=()=>({top:0,bottom:680,height:680});firstRecord.getBoundingClientRect=()=>{const top=[...integrityList.children].indexOf(firstRecord)*72-integrityList.scrollTop;return {top,bottom:top+72,height:72};};
 integrityReports.unshift({id:'audit-new',stage:'B',check:'MODULE_INVENTORY',status:'CLIENT_DIAGNOSTIC',at:now+1});await refreshPanel('integrity');assert.equal(integrityList.scrollTop,72);assert.equal(w.document.querySelector('[data-desktop-key="report-audit1"]'),firstRecord);assert.equal(record.open,true);delete integrityList.getBoundingClientRect;delete firstRecord.getBoundingClientRect;
 const moduleScroll=mainPane.scrollTop;w.document.querySelector('#desktop-tab-licenses').click();mainPane.scrollTop=99;w.document.querySelector('#desktop-tab-modules').click();assert.equal(mainPane.scrollTop,moduleScroll);assert.equal(record.open,true);
 w.document.querySelector('#desktop-tab-modules').focus();w.document.querySelector('#desktop-tab-modules').dispatchEvent(new w.KeyboardEvent('keydown',{key:'ArrowLeft',bubbles:true}));assert.equal(w.document.querySelector('#desktop-tabpanel-licenses').hidden,false);assert.equal(w.document.activeElement,w.document.querySelector('#desktop-tab-licenses'));assert.equal(mainPane.scrollTop,99);
 rows[2].status='AVAILABLE';
 w.document.querySelector('#desktop-tab-licenses').click();assert.equal(w.document.querySelector('#desktop-tabpanel-licenses').hidden,false);assert.equal(w.document.querySelector('#desktop-tabpanel-modules').hidden,true);
 // Pure one-use issuance has no duration/expiry controls or request fields.
 w.document.querySelector('#desktop-license-create').click();await waitFor(()=>shown('[data-modal-field="label"]')&&!modalClosed(),'issue form');assert.equal(shown('[data-modal-field="term"],[data-modal-field="days"],[data-modal-field="expiresAt"],[data-modal-field="validDays"]'),false);assert.equal(w.document.querySelectorAll('[data-modal-field]').length,1);field('label','실제 고객');w.document.querySelector('#modal-confirm').click();await waitFor(()=>shown('#desktop-issued-key'),'new license receipt');
 assert.equal(w.document.querySelector('#desktop-issued-key').value,key);assert.ok(!Object.keys(w.localStorage).some(name=>String(w.localStorage.getItem(name)).includes(key)));
 w.document.querySelector('#desktop-key-copy').click();await waitFor(()=>copied===key,'clipboard write');assert.equal(copied,key);
 assert.match(w.document.querySelector('#modal-body').textContent,/발급 화면에서만/);assert.doesNotMatch(w.document.querySelector('#modal-body').textContent,/KEY:|\*로/);assert.match(w.document.querySelector('#modal-body').textContent,/B 콘솔에서 KEY를 입력하고 Enter/);assert.match(key,/^[A-F0-9]{64}$/);
 await closeModal();assert.equal(w.document.querySelector('#desktop-issued-key'),null);assert.ok(!w.document.body.textContent.includes(key));
 // Newly issued key is also absent from its detail.
 const detailSearch=w.document.querySelector('#desktop-license-search');detailSearch.value=issuedId;w.document.querySelector('#desktop-license-search-form').dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await waitFor(()=>w.document.querySelectorAll('#desktop-license-records tbody tr').length===1&&actionIdle(),'issued row search');
 w.document.querySelector('[data-desktop-action="detail"]').click();await waitFor(()=>shown('#desktop-machine-security-title')&&!modalClosed(),'issued key detail');assert.equal(shown('#desktop-detail-key'),false);assert.equal(detailRequests().at(-1).url,'/api/desktop/workspace/licenses/'+issuedId);await closeModal();
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
 // Other retained admin views defer a live refresh until a native select
 // closes, then resume automatically; their main pane follows user scroll events.
 w.switchView('audit');await w.renderCurrent();const auditSelect=w.document.querySelector('#audit-type');auditSelect.focus();const beforeAuditRefresh=requests.length;
 source.listeners.get('service-state')({data:JSON.stringify({enabled:true})});await Promise.resolve();assert.equal(requests.length,beforeAuditRefresh);assert.equal(w.document.activeElement,auditSelect);assert.equal(w.document.querySelector('#audit-type'),auditSelect);
 auditSelect.blur();await waitFor(()=>requests.length>beforeAuditRefresh&&actionIdle(),'deferred audit live refresh after select blur');assert.match(w.document.querySelector('#content').textContent,/감사 기록 fixture/);
 // A select opened after the request starts also keeps its native popup:
 // the shared guard cancels only the pending DOM commit, then retries on blur.
 const pendingAuditSelect=w.document.querySelector('#audit-type'),pendingAuditOption=pendingAuditSelect.options[0],auditFetch=w.fetch,auditMain=w.document.querySelector('.main'),auditContent=w.document.querySelector('#content'),auditTable=w.document.querySelector('#content .table-wrap');let releaseAudit=null;
 w.fetch=(url,options)=>url.startsWith('/api/audit?')?new Promise(resolve=>{releaseAudit=()=>resolve(auditFetch(url,options));}):auditFetch(url,options);
 const pendingAudit=w.renderCurrent(true);await waitFor(()=>releaseAudit!==null,'audit request before dropdown focus');auditMain.scrollTop=807;auditContent.scrollTop=278;auditTable.scrollLeft=57;auditMain.dispatchEvent(new w.Event('scroll'));auditContent.dispatchEvent(new w.Event('scroll'));auditTable.dispatchEvent(new w.Event('scroll'));pendingAuditSelect.focus();releaseAudit();await pendingAudit;w.fetch=auditFetch;
 assert.equal(vm.runInContext('activeGenericRefresh===null',dom.getInternalVMContext()),true);assert.equal(w.document.querySelector('#audit-type'),pendingAuditSelect);assert.equal(pendingAuditSelect.options[0],pendingAuditOption);assert.equal(w.document.activeElement,pendingAuditSelect);assert.equal(auditMain.scrollTop,807);assert.equal(auditContent.scrollTop,278);assert.equal(auditTable.scrollLeft,57);
 const beforeAuditBlur=requests.length;pendingAuditSelect.blur();await waitFor(()=>requests.length>beforeAuditBlur&&actionIdle(),'audit focus-during-request resumes after blur');assert.equal(auditMain.scrollTop,807);assert.equal(auditContent.scrollTop,278);assert.equal(w.document.querySelector('#content .table-wrap').scrollLeft,57);
 w.switchView('system');await w.renderCurrent();const genericMain=w.document.querySelector('.main'),genericContent=w.document.querySelector('#content'),systemFetch=w.fetch;let releaseSystem=null;genericMain.scrollTop=401;genericContent.scrollTop=88;
 w.fetch=(url,options)=>url==='/api/system'?new Promise(resolve=>{releaseSystem=()=>resolve(systemFetch(url,options));}):systemFetch(url,options);
 const systemRefresh=w.renderCurrent(true);await waitFor(()=>releaseSystem!==null,'system request in flight');genericMain.scrollTop=702;genericContent.scrollTop=167;genericMain.dispatchEvent(new w.Event('scroll'));genericContent.dispatchEvent(new w.Event('scroll'));releaseSystem();await systemRefresh;w.fetch=systemFetch;assert.equal(genericMain.scrollTop,702);assert.equal(genericContent.scrollTop,167);assert.ok(w.document.querySelector('#version-protocol'));
 const beforeOwnerReplacement=w.document.querySelector('#version-protocol'),ownerFetch=w.fetch;let releaseOwner=null;
 w.fetch=(url,options)=>url==='/api/system'?new Promise(resolve=>{releaseOwner=()=>resolve(ownerFetch(url,options));}):ownerFetch(url,options);
 const obsoleteSystemRefresh=w.renderCurrent(true);await waitFor(()=>releaseOwner!==null,'generic request before session replacement');vm.runInContext("session={...session,csrf:'REPLACED_SESSION'}",dom.getInternalVMContext());releaseOwner();await obsoleteSystemRefresh;w.fetch=ownerFetch;assert.equal(w.document.querySelector('#version-protocol'),beforeOwnerReplacement);assert.equal(vm.runInContext('activeGenericRefresh===null',dom.getInternalVMContext()),true);vm.runInContext("session={...session,csrf:'DOM_CSRF'}",dom.getInternalVMContext());
 w.switchView('desktop-licenses');await w.renderCurrent();
 // A detail response arriving after logout/session replacement must not reveal
 // the key in a new session, even though the original request was authorized.
 const normalFetch=w.fetch;let finishDetail=null;
 w.fetch=(url,options)=>url==='/api/desktop/licenses/'+issuedId?new Promise(resolve=>{finishDetail=resolve;}):normalFetch(url,options);
 const abandonedDetail=w.showDesktopLicenseDetail(issuedId);await waitFor(()=>finishDetail!==null,'pending detail request');
 vm.runInContext("session={role:'viewer',csrf:'VIEWER'}",dom.getInternalVMContext());finishDetail({ok:true,status:200,text:async()=>JSON.stringify({ok:true,license:{id:issuedId,status:'AVAILABLE'},licenseKey:key})});await abandonedDetail;w.fetch=normalFetch;
 assert.equal(shown('#desktop-detail-key'),false);assert.ok(!w.document.body.textContent.includes(key));
 const beforeForbidden=requests.length;await assert.rejects(()=>w.downloadDesktopLauncher({launcherId,downloadUrl:'/api/desktop/bootstrap/launchers/'+launcherId+'/download'},'DOM_CSRF'),/관리자/);assert.equal(requests.length,beforeForbidden);
 await assert.rejects(()=>w.showDesktopLicenseDetail(issuedId),/관리자/);assert.equal(requests.length,beforeForbidden);await assert.rejects(()=>w.showDesktopIntegrityPolicy(),/관리자/);assert.equal(requests.length,beforeForbidden);assert.equal(shown('#desktop-detail-key'),false);
 assert.equal(errors.length,0,errors.join('\n'));
 console.log('DESKTOP ADMIN UI PASS: actual script shell, retired navigation, retained operations, escaped rows, paging/filters, USED status/counts, no detail key reveal, issuance-only copy/close scrub, raw legacy IDs preserved in API paths with prefix-free display, pure one-use issuance without expiry request fields, receipt scrub, stable request retry, revoke/reissue, CSRF, A/B binary File uploads with retry preservation, random-name provisioned A download with strict name/header checks, launcher idempotency, linked license state, session revoke, global counts under filters, PC fingerprint/CRC64/SHA256 evidence, automatic PC lock, admin-only CSRF unblock, visible KEY-input instructions, server integrity diagnostics and trusted module baseline upload, policy off by default, confirm/cancel and validation, missing baseline server rejection, normalized configurable mandatory DLLs, CSRF policy enable/disable, module export coverage advisory and complete/incomplete snapshot status, separate EAT expected/observed SHA256 and CRC64 rejection evidence with unchanged code hashes, old baseline EAT upgrade requirement, preserved drafts, native select/option identity, queued filter changes during in-flight requests, separate module tab and keyboard navigation, opt-in extended policy and same-file baseline upgrades, XXH64/BLAKE3 expected/observed and unmeasured states, retained disclosure nodes and main/nested scroll, in-flight user scrolling and prepended-record anchors through real SSE/poll/manual refresh, duplicate unknown module rows, deferred audit select refresh after blur (including focus after request start with native option identity and latest scroll), and current main-pane scroll through a system request.');
 }finally{w.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
