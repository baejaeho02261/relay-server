'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix68-home-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),service=require('../services/member/service'),home=require('../services/member/home');let serial=0;
function client(n){const id=String(n).padStart(16,'0'),key='FIX68-HOME-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=require('../license/licenseManager').CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return c;}
const run=(c,action,body={})=>service.Execute(c,'FIX68-HOME-'+(++serial),action,body),snapshot=()=>JSON.stringify(s.DB());
try{
 const ca=client(6801),cb=client(6802),cc=client(6803);for(const c of [ca,cb,cc])run(c,'me');
 const a=s.Account(ca),b=s.Account(cb),c=s.Account(cc),now=Date.now()-100;
 s.Atomic(()=>{
  a.balance=543210;a.points=777;b.balance=999999;a.eventSpins=4;
  for(let i=0;i<7;i++){
   const id='NEWS-HOME-'+i;s.DB().news[id]={id,title:'소식 '+i,body:'실제 본문 '+i+' '.repeat(200),category:'NOTICE',published:true,at:now+i,revision:1};
   const game='GAME-HOME-'+i;s.DB().products[game]={id:game,title:'게임 '+i,description:'설명',genre:'액션',published:true,sort:i,updatedAt:now+i,image:'NEVER_SEND_FULL_IMAGE',imageCover:'NEVER_SEND_COVER',imageThumb:i===0?'data:image/jpeg;base64,'+'a'.repeat(25000):'',plans:[]};
   const order='ORDER-HOME-'+i;s.DB().orders[order]={id:order,accountId:a.id,productId:game,title:'이용권 '+i,at:now+i,days:1,amount:100,status:'PAID',accessType:'TYPE1',licenseKey:'SECRET-LICENSE'};
   s.DB().ledger['LEDGER-HOME-'+i]={id:'LEDGER-HOME-'+i,accountId:a.id,reference:order,kind:'PURCHASE',amount:-100,at:now+i};
   s.DB().pointLedger['POINT-HOME-'+i]={id:'POINT-HOME-'+i,accountId:a.id,kind:'ATTENDANCE',amount:100,at:now+i};
  }
  a.activeOrderId='ORDER-HOME-0';Object.assign(s.DB().orders[a.activeOrderId],{status:'ACTIVE',activatedAt:now,expiresAt:now+86400000});
  s.DB().news.HIDDEN={id:'HIDDEN',title:'다른 사람 소식',body:'PRIVATE_NEWS',category:'NOTICE',published:true,audience:b.id,at:now};s.DB().news.DRAFT={id:'DRAFT',title:'DRAFT_NEWS',published:false,at:now};
  s.DB().orders['PRIVATE-ORDER']={id:'PRIVATE-ORDER',accountId:b.id,productId:'GAME-HOME-0',title:'PRIVATE_ORDER',at:now,days:1,amount:100,status:'PAID'};
  s.DB().ledger['PRIVATE-LEDGER']={id:'PRIVATE-LEDGER',accountId:b.id,reference:'PRIVATE-ORDER',kind:'PURCHASE',amount:-100,at:now};s.DB().pointLedger['PRIVATE-POINT']={id:'PRIVATE-POINT',accountId:b.id,kind:'ATTENDANCE',amount:999,at:now};
  b.purchaseActivityVisible=false;b.profilePostsVisibility='PRIVATE';
  s.DB().posts['POST-PUBLIC']={id:'POST-PUBLIC',accountId:c.id,title:'공개 글',body:'본문',at:now,revision:1};s.DB().posts['POST-PRIVATE']={id:'POST-PRIVATE',accountId:b.id,title:'PRIVATE_POST',body:'secret',at:now+1,revision:1};
  const thread={id:'DM-AAAAAAAAAAAAAAAAAAAAAAAA',members:[a.id,c.id],received:{[a.id]:5,[c.id]:0},readReceived:{[a.id]:2,[c.id]:0},pendingTo:a.id,deletedAt:0};s.DB().directThreads[thread.id]=thread;s.DB().directThreads['DM-BBBBBBBBBBBBBBBBBBBBBBBB']={...thread,id:'DM-BBBBBBBBBBBBBBBBBBBBBBBB',deletedAt:now};
 });
 const before=snapshot(),result=run(ca,'home');assert.equal(snapshot(),before,'home must not award, mark read, view, merge, or write');
 assert.equal(result.wallet.balance,543210);assert.equal(result.wallet.points,777);assert.equal(result.events.spins,4);assert.equal(result.activeGame.id,a.activeOrderId);assert.deepEqual(result.activeGames.map(x=>x.id),[a.activeOrderId]);assert.deepEqual(result.runningGames,result.activeGames);assert.ok(result.activeGames.every(x=>!Object.hasOwn(x,'licenseKey')));
 for(const key of ['news','catalog','orders','payments','pointHistory','purchases','topGames','recentProducts','recentServices'])assert.ok(result[key].length<=3,key+' bounded');assert.ok(result.feed.length<=2);
 assert.equal(result.counts.news,7);assert.equal(result.counts.unreadNews,7);assert.equal(result.counts.orders,7);assert.equal(result.counts.payments,7);assert.equal(result.counts.pointHistory,7);assert.equal(result.counts.unreadMessages,3);assert.equal(result.counts.requests,1);assert.equal(result.counts.messages,0);
 const wire=JSON.stringify(result);for(const secret of ['PRIVATE_NEWS','DRAFT_NEWS','PRIVATE_ORDER','PRIVATE_POST','SECRET-LICENSE','NEVER_SEND_FULL_IMAGE','NEVER_SEND_COVER'])assert.ok(!wire.includes(secret),'must not expose '+secret);
 assert.ok(result.catalog.every(row=>row.imageThumb.length<=24000));assert.ok(result.feed.some(row=>row.id==='POST-PUBLIC'));assert.equal(result.orders[0].title,'이용권 6');
 run(ca,'home',{id:b.id});assert.equal(snapshot(),before,'caller-supplied ID cannot select another owner');assert.throws(()=>run({...ca,biometricVerified:false},'home'),/MEMBER_AUTH_REQUIRED/);
 const article=run(ca,'article',{id:'NEWS-HOME-0',countView:true});assert.equal(article.article.body.trim(),'실제 본문 0');assert.equal(article.article.unread,false);assert.equal(s.ViewCount('news','NEWS-HOME-0'),1);
 run(ca,'article',{id:'NEWS-HOME-0',countView:true});assert.equal(s.ViewCount('news','NEWS-HOME-0'),1,'same-day explicit re-open is idempotent');const readState=snapshot();assert.equal(home.Read(a).counts.unreadNews,6);assert.equal(snapshot(),readState,'refresh after explicit open stays pure');
 const native=path.resolve(__dirname,'../../MoaPlayApp_Android64'),news=fs.readFileSync(path.join(native,'MoaPlayApp.Member.NewsShop.inc'),'utf8'),dashboard=fs.readFileSync(path.join(native,'MoaPlayApp.Member.Home.inc'),'utf8');
 assert.ok(!news.includes('열람하려면 게시글을 눌러주세요'));assert.ok(news.includes('Card.Fill.Kind:=TBrushKind.None;Card.XRadius:=12'));assert.ok(news.includes('Card.Stroke.Kind:=TBrushKind.Solid'));
 const newsFill=news.slice(news.indexOf('function TMoaPlayForm.HubFillNewsCard'),news.indexOf('procedure HubGamePhoto'));assert.ok(!newsFill.includes("'next'"));assert.ok(!newsFill.includes('MemberFrostedCard'));assert.ok(newsFill.includes("HubText(Full,'body')"));assert.ok(news.includes("FMember.Request('article'"));
 const inlineList=news.slice(news.indexOf('procedure TMoaPlayForm.HubRenderNews'),news.indexOf('procedure TMoaPlayForm.HubCatalogSearchChanged'));assert.ok(inlineList.includes("Expanded:=HubCached('news.inline')"));assert.ok(inlineList.includes("not Found and (FHubNewsOpenID<>'')"));assert.ok(inlineList.includes('HubFillNewsCard(C,Expanded,18)'));assert.ok(inlineList.indexOf('HubFillNewsCard(C,Expanded,18)')<inlineList.indexOf('HubFillNewsCard(C,TJSONObject(V),18)'));assert.ok(inlineList.includes('HubPaging(Data)'),'selected out-of-page article preserves original paging');
 const icon=news.slice(news.indexOf('procedure HubContentIcon'),news.indexOf('function HubContentCategoryHeading'));assert.ok(!icon.includes('UiRect'),'category icons have no plate');assert.ok(news.includes('Y+(LineH-24)/2'),'icon aligns with the first title line');
 for(const route of ['baccarat','roulette','slots','blackjack','crash','dice','mines','plinko','limbo','hilo','tower','event.dino','event.flappy','event.whack','event.dodge','event.rhythm'])assert.ok(dashboard.includes("'"+route+"'"),'home route '+route);assert.ok(dashboard.includes('MenuRows:=HubActivityMenuRows'),'all canonical settings categories reachable');
 console.log('FIX68 HOME/NEWS PASS: bounded owner projection, privacy, read-only refresh, no media/secret leakage, counts, auth, inline article source guards and explicit read/view idempotency.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
