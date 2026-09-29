'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix71-home-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),service=require('../services/member/service'),home=require('../services/member/home'),commerce=require('../services/member/commerce'),rewards=require('../services/member/rewards');let serial=0;
function client(n){const id=String(n).padStart(16,'0'),key='FIX71-HOME-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=require('../license/licenseManager').CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return c;}
const run=(c,action,body={})=>service.Execute(c,'FIX71-HOME-'+(++serial),action,body),snapshot=()=>JSON.stringify(s.DB());
try{
 commerce.EnsureCatalog();const ca=client(7001),cb=client(7002),cc=client(7003);for(const client of [ca,cb,cc]){
 s.Atomic(()=>require('./helpers/member-identity-fixture')(client));run(client,'me');
 }
 const a=s.Account(ca),b=s.Account(cb),c=s.Account(cc),now=Date.now()-100,today=rewards.Day(now),yesterday=rewards.Day(now-86400000),pubg=commerce.CatalogRows().find(g=>commerce.GameKey(g)==='PUBG');
 s.Atomic(()=>{
  a.balance=100000;a.points=123;a.eventSpins=2;a.attendance={day:today,at:now,count:5,streak:5,days:[today]};b.attendance={day:yesterday,at:now-86400000,count:10,streak:10,days:[yesterday]};c.attendance={day:rewards.Day(now-172800000),at:now-172800000,count:99,streak:99,days:[]};
  c.purchaseActivityVisible=false;c.profilePostsVisibility='PRIVATE';
  for(let i=0;i<8;i++){const id='POST-HOME-'+i;s.DB().posts[id]={id,accountId:b.id,title:'인기글 '+i,body:'본문 전체 '+i,at:now+i,revision:1,audience:'PUBLIC'};const comment='COMMENT-'+i;s.DB().comments[comment]={id:comment,postId:id,accountId:b.id,body:'최근 댓글 '+i,at:now+i,revision:1};}
  s.DB().reactions.RANK={postId:'POST-HOME-0',accountId:a.id,value:1};
  s.DB().posts.PRIVATE={id:'PRIVATE',accountId:c.id,title:'PRIVATE_POST',body:'HIDDEN_BODY',at:now,revision:1};
  s.DB().comments.PRIVATE={id:'COMMENT-PRIVATE',postId:'PRIVATE',accountId:c.id,body:'PRIVATE_COMMENT',at:now+99,revision:1};
  s.DB().comments.HIDDEN={id:'COMMENT-HIDDEN',postId:'POST-HOME-0',accountId:b.id,body:'HIDDEN_COMMENT',hidden:true,at:now+99,revision:1};
  s.DB().news.N={id:'N',title:'공개 소식',body:'내용 '.repeat(200),category:'ALERT',published:true,at:now,revision:1};
  s.DB().news.PRIVATE={id:'N-P',title:'PRIVATE_NEWS',body:'secret',category:'NOTICE',audience:b.id,published:true,at:now,revision:1};
  for(let i=0;i<4;i++){const id='ORDER-'+i;s.DB().orders[id]={id,accountId:a.id,productId:pubg.id,title:pubg.title,gameKey:'PUBG',at:now+i,days:0,singleUse:true,uses:1,amount:700,status:'PAID',preparedClientId:i===0?ca.clientId:'',activatedAt:0,expiresAt:0,accessType:'TYPE1',licenseKey:'SECRET_LICENSE'};const lid='LEDGER-'+i;s.DB().ledger[lid]={id:lid,accountId:a.id,productId:pubg.id,reference:id,title:pubg.title,days:0,uses:1,kind:'PURCHASE',amount:-700,at:now+i};const point='POINT-'+i;s.DB().pointLedger[point]={id:point,accountId:a.id,kind:'ATTENDANCE',amount:100,at:now+i};}
  a.activeOrderId='ORDER-0';a.recentHistory={products:[{id:pubg.id,at:now}],services:[{route:'news',at:now}]};
  s.DB().orders.PRIVATE={id:'PRIVATE-ORDER',accountId:c.id,productId:pubg.id,title:'PRIVATE_PURCHASE',at:now+99,days:0,singleUse:true,uses:1,amount:100,status:'PAID'};
 });
 const before=snapshot(),data=run(ca,'home');assert.equal(snapshot(),before,'home refresh stays read-only');
 assert.equal(data.feed.length,5);assert.equal(data.feed[0].id,'POST-HOME-0','same popularity order as canonical feed');assert.deepEqual(data.feed.map(row=>row.rank),[1,2,3,4,5]);
 for(const row of data.feed){assert.equal(row.body,s.DB().posts[row.id].body);assert.equal(row.author.id,b.id);assert.ok(Object.hasOwn(row,'myReaction'));assert.ok(Object.hasOwn(row,'mentionMembers'));}
 assert.ok(!Object.hasOwn(data,'recentComments'),'retired recent comments not serialized; daily count remains');
 assert.deepEqual(data.attendanceRanking.map(({rank,nickname,streak})=>({rank,nickname,streak})),[{rank:1,nickname:b.nickname,streak:10},{rank:2,nickname:a.nickname,streak:5}]);
 assert.equal(data.counts.todayPosts,8);assert.equal(data.counts.todayComments,8);assert.equal(data.counts.online,3);
 assert.equal(data.catalog.length,2);assert.ok(data.catalog.every(row=>['game.pubg','game.valorant'].includes(row.icon)));assert.equal(data.recentProducts[0].icon,'game.pubg');assert.equal(data.runningGames[0].icon,'game.pubg');
 for(const key of ['orders','payments','pointHistory','purchases','topGames'])assert.ok(data[key].length<=3,key+' bounded');assert.ok(data.purchases.every(row=>row.member.id===a.id&&row.at>0));assert.ok(data.topGames.every(row=>row.icon==='game.pubg'));
 assert.equal(data.wallet.balance,100000);assert.equal(data.wallet.points,123);assert.ok(!Object.hasOwn(data,'events'),'retired wheel never returns from home');
 assert.equal(data.orders[0].amount,700);assert.equal(data.orders[0].activatedAt,0);assert.equal(data.orders[0].expiresAt,0,'unused pass must not invent an expiry date');
 assert.equal(data.payments[0].reference,'ORDER-3');assert.equal(data.payments[0].paymentMethod,'WALLET');
 assert.ok(data.purchases.every(row=>row.icon==='game.pubg'),'purchase row game icon');
 const wire=JSON.stringify(data);for(const secret of ['PRIVATE_POST','PRIVATE_NEWS','PRIVATE_COMMENT','HIDDEN_COMMENT','PRIVATE_PURCHASE','SECRET_LICENSE','imageCover','imageThumb'])assert.ok(!wire.includes(secret),'must not expose '+secret);
 assert.throws(()=>run({...ca,biometricVerified:false},'home'),/MEMBER_AUTH_REQUIRED/);
 const countBefore=snapshot();state.clients.set('duplicate',{...ca});assert.equal(home.OnlineCount(),3,'same member counted once');cb.socket.destroyed=true;assert.equal(home.OnlineCount(),2,'disconnected socket excluded');assert.equal(snapshot(),countBefore,'presence count creates no account');
 const native=path.resolve(__dirname,'../../MoaPlayApp_Android64'),ui=fs.readFileSync(path.join(native,'MoaPlayApp.Member.Home.inc'),'utf8');
 assert.ok(ui.includes("StartCard('인기 글'"));assert.ok(ui.includes('HubFillPostCard(PostCard,Item,False,0,True)'),'expanded popular item reuses complete interactive post renderer');assert.ok(ui.includes('HubFillGameCard(Button,Item,16)'),'game summaries reuse discovery renderer');assert.ok(ui.includes('function TMoaPlayForm.HubHomeAction'));assert.ok(ui.includes('FHubLocalRender:=True;HubRender'));
 assert.ok(!ui.includes('HubDate('),'home summaries have relative clocks');for(const count of ['online','todayPosts','todayComments'])assert.ok(ui.includes("HubNumber(Counts,'"+count+"')"));
 for(const removed of ["StartCard('내 계정'","StartCard('모아의 놀이터'","StartCard('이벤트'","StartCard('돌림판'","StartCard('최근 댓글'"])assert.ok(!ui.includes(removed));
 const news=fs.readFileSync(path.join(native,'MoaPlayApp.Member.NewsShop.inc'),'utf8'),fill=news.slice(news.indexOf('function TMoaPlayForm.HubFillNewsCard'),news.indexOf('function HubGameIconKey'));assert.ok(fill.includes('C.OnClick:=HubActionClick;C.OnDblClick:=nil'),'news single-click no double-trigger');
 const history=fs.readFileSync(path.join(native,'MoaPlayApp.Member.History.inc'),'utf8'),wheel=fs.readFileSync(path.join(native,'MoaPlayApp.Member.Rewards.inc'),'utf8');
 assert.ok(ui.includes("StartCard('MY'"));assert.ok(!ui.includes("'points.exchange.open'"));assert.ok(!ui.includes("'activity.subscriptions'"));assert.ok(!ui.includes("'charge'"));
 assert.ok(ui.includes("'home.toggle|wallet'"));assert.ok(ui.includes("HubTextAction(WalletPanel,'','points'"));assert.ok(ui.includes('HubHomeBannerArt(Card'));
 assert.ok(!ui.includes("'wheel'"));assert.ok(!ui.includes('HubFillWheel'));assert.ok(!wheel.includes('function TMoaPlayForm.HubFillWheel'));
 for(const removed of ["Entry('거래 번호'","Entry('이용권 번호'","Entry('안내'","Entry('#'","Entry('이용 기간'","Entry('이용 종료'"])assert.ok(!history.includes(removed),removed+' retired from receipt');
 assert.ok(history.includes("Entry('이용권',MemberCaption('1회 이용권'))"));assert.ok(history.includes('Y:=Y+H+6'),'receipt rows use compact equal spacing');
 assert.ok(ui.includes("Key='pointHistory' then Row:=SummaryRow(RowKey,Name,Marker,GameIcon,HubNumber(Obj,'at'),Info,nil,0,True,False)"),'point rows have no dropdown action');
 assert.ok(ui.includes('PostCard.OnHold:=HubPostHold'),'expanded popular card supports direct long-press repost');
 assert.ok(history.includes("'pass.download|'"));assert.ok(history.includes("'receipt.toggle|'"));assert.ok(history.includes('HubFillReceipt'));assert.ok(!history.includes('displayExpiresAt'),'receipt never invents expiry');
 for(const color of ['FFF0CB67','FFCCD4E1','FFD6A080'])assert.ok(history.includes(color));
 const beforeRetired=snapshot();assert.throws(()=>run(ca,'event.spin',{revision:1}),/UNKNOWN_ACTION/);assert.equal(snapshot(),beforeRetired,'retired wheel cannot debit spins or award points');
 // A download/preparation never consumes a pass. Only a verified paired PC plus explicit Start can consume it.
 const prepared=home.Read(a).runningGames.find(row=>row.id==='ORDER-0');assert.equal(prepared.status,'PAID');assert.equal(prepared.connectionReady,false);assert.equal(prepared.remainingUses,1);
 assert.throws(()=>s.Atomic(()=>commerce.Start(a,ca,{orderId:'ORDER-0'})),/GAME_CONNECTION_REQUIRED/);
 const serverId='0000000000009999',sessionId='HOME-VERIFIED-SESSION';
 ca.buildCompleted=true;ca.buildSessionId=sessionId;
 state.servers.set(serverId,{serverId,registered:true,connected:true,deviceAuthVerified:true,buildClients:new Set([ca.clientId]),buildSessions:new Map([[ca.clientId,sessionId]]),socket:{destroyed:false,write(){return true;}}});
 state.clientIdentities.get(ca.installationDeviceKey).serverId=serverId;
 state.buildSessions.set(sessionId,{sessionId,clientId:ca.clientId,serverId,orderId:'ORDER-0',status:'AUTHORIZED',expiresAt:Date.now()+60000});
 const ready=home.Read(a).runningGames.find(row=>row.id==='ORDER-0');assert.equal(ready.connectionReady,true);assert.equal(ready.remainingUses,1);assert.equal(ready.status,'PAID','server proof alone never consumes');
 s.Atomic(()=>commerce.Start(a,ca,{orderId:'ORDER-0'}));const playing=home.Read(a).runningGames.find(row=>row.id==='ORDER-0');assert.equal(playing.status,'ACTIVE');assert.equal(playing.remainingUses,0);assert.equal(playing.expiresAt,0,'single-use pass has no purchase-period expiry');
 const endedOrder=s.DB().orders['ORDER-0'];state.buildSessions.delete(sessionId);const beforeEnded=snapshot(),ended=home.Read(a);assert.equal(snapshot(),beforeEnded,'home projection after session end remains read-only');assert.ok(!ended.runningGames.some(row=>row.id==='ORDER-0'));assert.equal(commerce.PublicOrder(endedOrder).status,'USED');
 assert.throws(()=>s.Atomic(()=>commerce.Start(a,ca,{orderId:'ORDER-0'})),/GAME_ALREADY_USED/);
 console.log('FIX76 HOME PASS: bounded private projections, retired recent comments, wallet dropdown, compact single-use receipts, retired wheel with historical balances untouched, verified PC preparation -> explicit one-time Start -> permanent used state, read-only home refresh.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
