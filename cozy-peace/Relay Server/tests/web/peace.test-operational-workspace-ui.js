'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../..');
const escape=value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;');
function Harness(view,file,responses,admin=true){
 const dom=new JSDOM('<!doctype html><div id="content"></div>'),content=dom.window.document.getElementById('content'),calls=[];
 const ctx=vm.createContext({document:dom.window.document,window:dom.window,console,Map,Set,Date,Number,URLSearchParams,
  esc:escape,fmtTime:v=>'time:'+v,fmtDuration:v=>String(v),fmtBytes:v=>String(v),uiText:v=>String(v??''),
  badge:v=>'<span class="badge">'+escape(v)+'</span>',roleIsAdmin:()=>admin,roleCanOperate:()=>true,
  statsRange:'1H',desktopStatusLabels:{ACTIVE:'사용 중',AVAILABLE:'사용 전'},svgLineChart:()=>'<svg></svg>',
  traceQuery:'',recoveryQuery:'',traceRows:new Map(),adminEditedControls:new Set(),currentView:view,
  guardAdminViewCommit:v=>assert.equal(v,view),adminViewContent:{set html(value){content.innerHTML=value;}},
  api:async url=>{calls.push(url);assert.ok(Object.hasOwn(responses,url),'unexpected API: '+url);return structuredClone(responses[url]);}
 });
 vm.runInContext(fs.readFileSync(path.join(root,file),'utf8'),ctx,{filename:file});
 return {dom,content,calls,run:name=>vm.runInContext(name+'()',ctx)};
}
test('server inventory keeps each authorized action while grouping device data into readable columns',async()=>{
 const s={id:'SERVER-ONE',alias:'<script>bad</script>',status:'ONLINE',health:'GOOD',online:true,canAcceptClients:true,rttMs:23,appVersion:'1.2.3',lastIP:'192.0.2.1',lastSeen:10,reconnectCount:2,note:'<img src=x onerror=bad()>',drain:{active:false}};
 const h=Harness('servers','public/scripts/actions/peace.admin-pages-devices.js',{'/api/servers':{servers:[s]}});
 await h.run('renderServers');
 assert.equal(h.content.querySelectorAll('thead th').length,7);
 assert.equal(h.content.querySelectorAll('script,img').length,0);
 assert.match(h.content.textContent,/<script>bad<\/script>/);
 assert.match(h.content.textContent,/192\.0\.2\.1/);assert.match(h.content.textContent,/1\.2\.3/);assert.match(h.content.textContent,/23 ms/);
 assert.deepEqual([...h.content.querySelectorAll('[data-server-action]')].map(x=>x.dataset.serverAction),['detail','alias','note','kick','drain-on','disable','delete']);
 assert.equal(h.content.querySelector('.row-actions').open,false);
 const readonly=Harness('servers','public/scripts/actions/peace.admin-pages-devices.js',{'/api/servers':{servers:[s]}},false);await readonly.run('renderServers');
 assert.deepEqual([...readonly.content.querySelectorAll('[data-server-action]')].map(x=>x.dataset.serverAction),['detail','note']);
});
test('dashboard prioritizes four live metrics and retains all secondary values and destinations',async()=>{
 const d={servers:{online:2,total:3,disabled:0,draining:1},ack:{successRate:99,pending:1,timeout:2},notifications:{unread:4,critical:1,warning:2},serviceEnabled:true,maintenanceMode:false,uptimeMs:300,totalConnections:10,versions:{protocol:2,server:'7.0'},recovery:{queued:3,deadLetters:4,replayed:5},ha:{role:'PRIMARY',instanceId:'preview',acceptsTraffic:true},recentEvents:[]};
 const totals={connections:0,sends:0,ackOk:0,ackError:0,ackTimeout:0,ackSuccessRate:100};
 const h=Harness('dashboard','public/scripts/pages/peace.admin-pages-monitoring.js',{'/api/dashboard':{dashboard:d},'/api/statistics?range=1H':{statistics:{buckets:[],totals}},'/api/desktop/licenses':{items:[{status:'ACTIVE'}]}});
 await h.run('renderDashboard');
 assert.equal(h.content.querySelector('.overview-primary').children.length,4);
 assert.equal(h.content.querySelectorAll('#dashboard-additional-metrics .card').length,5);
 assert.equal(h.content.querySelector('#dashboard-additional-metrics').open,false);
 assert.equal(h.content.querySelector('[data-open-view="desktop-licenses"]').textContent,'회원 · 라이선스 열기');
 assert.equal(h.content.querySelectorAll('[data-stats-range]').length,4);
});
test('request explorer retains full request identity and replay authorization in the compact list',async()=>{
 const t={key:'trace-key',requestId:'REQ-ONE',source:'SERVER',clientId:'DEVICE-ONE',serverId:'SERVER-ONE',number:'9223372036854775807',status:'TIMEOUT',retries:2,completedAt:100,durationMs:18,forwardedAt:80};
 const h=Harness('trace','public/scripts/pages/peace.admin-pages-monitoring.js',{'/api/request-traces?query=':{traces:[t]}});await h.run('renderTrace');
 assert.equal(h.content.querySelectorAll('thead th').length,7);
 for(const text of ['REQ-ONE','DEVICE-ONE','SERVER-ONE','9223372036854775807','18 ms'])assert.ok(h.content.textContent.includes(text));
 assert.equal(h.content.querySelector('[data-trace-detail]').dataset.traceDetail,'trace-key');
 assert.equal(h.content.querySelector('[data-trace-replay]').dataset.traceReplay,'trace-key');
 assert.equal(h.content.querySelector('#trace-search').type,'search');
 const readonly=Harness('trace','public/scripts/pages/peace.admin-pages-monitoring.js',{'/api/request-traces?query=':{traces:[t]}},false);await readonly.run('renderTrace');assert.equal(readonly.content.querySelector('[data-trace-replay]'),null);
});
test('recovery puts unresolved work before configuration while keeping every policy control and exact ID',async()=>{
 const recovery={policy:{enabled:true,maxItemsPerClient:100,ttlSeconds:3600,maxDeliveryAttempts:5},summary:{queued:1,activeDeadLetters:1},clients:[],queue:[{queueId:'QUEUE-ONE',requestId:'REQ-ONE',clientId:'DEVICE-ONE',serverId:'SERVER-ONE',number:'42',attempts:1,reason:'OFFLINE',queuedAt:1,expiresAt:2}],deadLetters:[{deadLetterId:'DLQ-ONE',status:'ACTIVE',originalRequestId:'REQ-TWO',clientId:'DEVICE-TWO',serverId:'SERVER-TWO',number:'43',reason:'TIMEOUT',attempts:2,failedAt:1}]};
 const h=Harness('recovery','public/scripts/pages/peace.admin-pages-traffic.js',{'/api/request-recovery?query=':{recovery}});await h.run('renderRecovery');
 assert.ok(h.content.innerHTML.indexOf('전송 실패 보관함')<h.content.innerHTML.indexOf('id="recovery-settings"'));
 assert.equal(h.content.querySelector('[data-dlq-retry]').dataset.dlqRetry,'DLQ-ONE');
 assert.equal(h.content.querySelector('[data-dlq-discard]').dataset.dlqDiscard,'DLQ-ONE');
 assert.equal(h.content.querySelector('#recovery-settings').open,false);
 for(const id of ['queue-policy-enabled','queue-policy-max','queue-policy-ttl','queue-policy-attempts','queue-policy-save','recovery-search','recovery-search-btn'])assert.ok(h.content.querySelector('#'+id),id);
 assert.ok(h.content.textContent.includes('QUEUE-ONE'));
});
test('security inventory keeps current and trusted identities without turning an unverified network into a pass',async()=>{
 const security={score:90,label:'WARNING',verified:1,onlineHmacCapable:1,staleSecrets:0,unknownSecretAge:0,legacy:0,activeRotations:0,alerts:[],devices:[{type:'SERVER',id:'SERVER-ONE',hasSecret:true,secretAgeDays:2,capable:true,verified:true,online:true,enforced:true,authStatus:'VERIFIED',verifiedAt:10,rotationStatus:'DONE'}]};
 const network={summary:{changed:1,critical:0,warning:1},geo:{available:true,provider:'local'},devices:[{type:'SERVER',id:'SERVER-ONE',changed:true,status:'CHANGED',severity:'WARNING',current:{ip:'192.0.2.10',country:'KR',subnet:'192.0.2.0/24'},trusted:{ip:'192.0.2.11',country:'US',subnet:'192.0.2.0/25'},changeCount:3,lastChangeAt:2}]};
 const responses={'/api/security/dashboard':{security},'/api/security/network':network};
 const h=Harness('security','public/scripts/pages/peace.admin-pages-security.js',responses);await h.run('renderSecurityCenter');
 assert.deepEqual([...h.content.querySelectorAll('thead')].map(x=>x.children[0].children.length),[6,7]);
 for(const value of ['192.0.2.10','192.0.2.11','192.0.2.0/24','192.0.2.0/25','KR','US','CHANGED','WARNING'])assert.ok(h.content.textContent.includes(value),value);
 assert.equal(h.content.querySelector('[data-network-trust]').dataset.id,'SERVER-ONE');
 assert.equal(h.content.querySelector('[data-network-trust]').disabled,false);
 const readonly=Harness('security','public/scripts/pages/peace.admin-pages-security.js',responses,false);await readonly.run('renderSecurityCenter');assert.equal(readonly.content.querySelector('[data-network-trust]'),null);
});
test('protocol inventory keeps every sequence statistic, blocker and authorized operation in seven columns',async()=>{
 const responses={'/api/control/protocol-readiness':{readiness:{ready:0,total:1,candidateProtocol:3,devices:[{type:'SERVER',id:'SERVER-ONE',ready:false,profile:{current:2,candidate:3},blockers:['MISSING_CAPABILITY']}]}},'/api/control/security':{devices:[{type:'SERVER',id:'SERVER-ONE',online:true,hasSecret:true,verified:false,enforced:true}]},'/api/control/sequences':{devices:[{type:'SERVER',id:'SERVER-ONE',capable:true,enabled:true,stats:{rxLast:19,rxMissing:2,rxDuplicates:3,rxOutOfOrder:4}}]},'/api/control/security/rotations':{rotations:[{type:'SERVER',id:'SERVER-ONE',status:'PENDING'}]}};
 const h=Harness('protocol','public/scripts/pages/peace.admin-pages-security.js',responses);await h.run('renderProtocolSecurity');
 assert.equal(h.content.querySelectorAll('thead th').length,7);
 for(const text of ['SERVER-ONE','MISSING_CAPABILITY','최근 19','누락 2','중복 3','순서 어긋남 4','BLOCKED','UNVERIFIED','PENDING'])assert.ok(h.content.textContent.includes(text),text);
 for(const selector of ['[data-security-challenge]','[data-security-rotate]','[data-security-reset]'])assert.equal(h.content.querySelector(selector).dataset.id,'SERVER-ONE');
});
