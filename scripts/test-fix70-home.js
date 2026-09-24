'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix70-home-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),service=require('../services/member/service'),home=require('../services/member/home'),commerce=require('../services/member/commerce'),rewards=require('../services/member/rewards');let serial=0;
function client(n){const id=String(n).padStart(16,'0'),key='FIX70-HOME-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=require('../license/licenseManager').CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return c;}
const run=(c,action,body={})=>service.Execute(c,'FIX70-HOME-'+(++serial),action,body),snapshot=()=>JSON.stringify(s.DB());
try{
 commerce.EnsureCatalog();const ca=client(7001),cb=client(7002),cc=client(7003);for(const c of [ca,cb,cc])run(c,'me');
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
  for(let i=0;i<4;i++){const id='ORDER-'+i;s.DB().orders[id]={id,accountId:a.id,productId:pubg.id,title:pubg.title,gameKey:'PUBG',at:now+i,days:7,amount:700,status:i===0?'ACTIVE':'PAID',activatedAt:i===0?now:0,expiresAt:i===0?now+604800000:0,accessType:'TYPE1',licenseKey:'SECRET_LICENSE'};const lid='LEDGER-'+i;s.DB().ledger[lid]={id:lid,accountId:a.id,productId:pubg.id,reference:id,title:pubg.title,days:7,kind:'PURCHASE',amount:-700,at:now+i};const point='POINT-'+i;s.DB().pointLedger[point]={id:point,accountId:a.id,kind:'ATTENDANCE',amount:100,at:now+i};}
  a.activeOrderId='ORDER-0';a.recentHistory={products:[{id:pubg.id,at:now}],services:[{route:'news',at:now}]};
  s.DB().orders.PRIVATE={id:'PRIVATE-ORDER',accountId:c.id,productId:pubg.id,title:'PRIVATE_PURCHASE',at:now+99,days:1,amount:100,status:'PAID'};
 });
 const before=snapshot(),data=run(ca,'home');assert.equal(snapshot(),before,'home refresh stays read-only');
 assert.equal(data.feed.length,5);assert.equal(data.feed[0].id,'POST-HOME-0','same popularity order as canonical feed');assert.deepEqual(data.feed.map(row=>row.rank),[1,2,3,4,5]);
 for(const row of data.feed){assert.equal(row.body,s.DB().posts[row.id].body);assert.equal(row.author.id,b.id);assert.ok(Object.hasOwn(row,'myReaction'));assert.ok(Object.hasOwn(row,'mentionMembers'));}
 assert.equal(data.recentComments.length,5);assert.deepEqual(data.recentComments.map(row=>row.id),['COMMENT-7','COMMENT-6','COMMENT-5','COMMENT-4','COMMENT-3']);
 assert.deepEqual(data.attendanceRanking,[{rank:1,nickname:b.nickname,streak:10},{rank:2,nickname:a.nickname,streak:5}]);
 assert.equal(data.counts.todayPosts,8);assert.equal(data.counts.todayComments,8);assert.equal(data.counts.online,3);
 assert.equal(data.catalog.length,2);assert.ok(data.catalog.every(row=>['game.pubg','game.valorant'].includes(row.icon)));assert.equal(data.recentProducts[0].icon,'game.pubg');assert.equal(data.runningGames[0].icon,'game.pubg');
 for(const key of ['orders','payments','pointHistory','purchases','topGames'])assert.ok(data[key].length<=3,key+' bounded');assert.ok(data.purchases.every(row=>row.member.id===a.id&&row.at>0));assert.ok(data.topGames.every(row=>row.icon==='game.pubg'));
 assert.equal(data.wallet.balance,100000);assert.equal(data.wallet.points,123);assert.equal(data.events.spins,2);
 const wire=JSON.stringify(data);for(const secret of ['PRIVATE_POST','PRIVATE_NEWS','PRIVATE_COMMENT','HIDDEN_COMMENT','PRIVATE_PURCHASE','SECRET_LICENSE','imageCover','imageThumb'])assert.ok(!wire.includes(secret),'must not expose '+secret);
 assert.throws(()=>run({...ca,biometricVerified:false},'home'),/MEMBER_AUTH_REQUIRED/);
 const countBefore=snapshot();state.clients.set('duplicate',{...ca});assert.equal(home.OnlineCount(),3,'same member counted once');cb.socket.destroyed=true;assert.equal(home.OnlineCount(),2,'disconnected socket excluded');assert.equal(snapshot(),countBefore,'presence count creates no account');
 const native=path.resolve(__dirname,'../../MoaPlayApp_Android64'),ui=fs.readFileSync(path.join(native,'MoaPlayApp.Member.Home.inc'),'utf8');
 assert.ok(ui.includes("StartCard('인기 글'"));assert.ok(ui.includes('HubFillPostCard(Inner,Item,True,0,True)'),'expanded popular item reuses complete interactive post renderer');assert.ok(ui.includes('HubFillGameCard(Button,Item,12)'),'game summaries reuse discovery renderer');assert.ok(ui.includes('function TMoaPlayForm.HubHomeAction'));assert.ok(ui.includes('FHubLocalRender:=True;HubRender'));
 assert.ok(!ui.includes('HubDate('),'home summaries have relative clocks');for(const count of ['online','todayPosts','todayComments'])assert.ok(ui.includes("HubNumber(Counts,'"+count+"')"));
 for(const removed of ["StartCard('내 계정'","StartCard('모아의 놀이터'","StartCard('이벤트'"])assert.ok(!ui.includes(removed));assert.ok(ui.includes("StartCard('돌림판'"));
 const news=fs.readFileSync(path.join(native,'MoaPlayApp.Member.NewsShop.inc'),'utf8'),fill=news.slice(news.indexOf('function TMoaPlayForm.HubFillNewsCard'),news.indexOf('function HubGameIconKey'));assert.ok(fill.includes('C.OnClick:=HubActionClick;C.OnDblClick:=nil'),'news single-click no double-trigger');
 console.log('FIX70 HOME PASS: five full canonical popular posts, private/hidden content filtered, five recent comments, honest streak ranking/presence/KST daily counts, two icon games, bounded owner receipts, no read writes or catalog media, relative clocks and shared inline renderers.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
