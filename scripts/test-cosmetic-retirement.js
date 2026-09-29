'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix75-cosmetics-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),service=require('../services/member/service'),database=require('../storage/database'),shop=require('../services/member/customization'),rewards=require('../services/member/rewards');
function client(n){const id=String(n).padStart(16,'0'),key='FIX75-COSMETICS-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=require('../license/licenseManager').CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;s.Atomic(()=>require('./helpers/member-identity-fixture')(c));return c;}
let serial=0;const run=(c,action,body={},requestId)=>service.Execute(c,requestId||'FIX75-COSMETICS-'+(++serial),action,body),snapshot=()=>JSON.stringify(s.DB());
function unchanged(fn,pattern){const before=snapshot();assert.throws(fn,pattern);assert.equal(snapshot(),before,'rejected retired request must not write a receipt, award or debit');}
try{
 require('../services/member/commerce').EnsureCatalog();const a=client(751),b=client(752);run(a,'me');run(b,'me');let p=s.Account(a);
 const now=Date.now()-100,oldPoint={id:'OLD-BADGE-POINT',accountId:p.id,kind:'BADGE_REWARD',reference:'POSTS_1',amount:50,balance:777,at:now},oldCash={id:'OLD-CASH',accountId:p.id,kind:'ADMIN_GRANT',reference:'OLD',amount:98765,balance:98765,at:now};
 const oldPurchase={id:'OLD-TITLE-PURCHASE',accountId:p.id,itemId:'TITLE_COLOR',title:'칭호 색상 세트',price:500,currency:'POINTS',at:now};
 const oldShopBody={itemId:'TITLE_COLOR',revision:1},oldSelectBody={id:'POSTS_1'},oldProfileBody={nickname:p.nickname,bio:'saved before retirement'};
 s.Atomic(()=>{
  Object.assign(p,{balance:98765,points:777,eventSpins:2,titleBadgeId:'POSTS_1',titleStyles:{POSTS_1:{name:'예전 칭호',color:'#123456'}},inventory:{nicknameTickets:1,nicknameColors:1,titleColors:3,titleNames:2},badgeProgress:{version:1,counts:{posts:999,attendance:999},seen:{},awards:{POSTS_1:{at:now,rewardPoints:50,rewardPaid:true},ALL_TITLES:{at:now,rewardPoints:10000,rewardPaid:false}}}});
  s.DB().pointLedger.OLD=oldPoint;s.DB().ledger.OLD=oldCash;s.DB().shopPurchases.OLD=oldPurchase;
  s.DB().settings.memberShop={revision:1,items:{NICKNAME_TICKET:{enabled:true,price:10},NICKNAME_COLOR:{enabled:true,price:20},TITLE_COLOR:{enabled:true,price:500},TITLE_NAME:{enabled:true,price:2000}}};
  p.recentHistory={products:[],services:[{route:'badges',at:now},{route:'title.color',at:now},{route:'title.name',at:now},{route:'points',at:now}]};
  const receipt=(id,action,body,result)=>{s.DB().operations[p.id+':'+id]={fingerprint:crypto.createHash('sha256').update(JSON.stringify({action,body})).digest('hex'),result,at:now};};
  receipt('FIX75-OLD-TITLE-BUY','shop.purchase',oldShopBody,{purchase:oldPurchase,profile:{...s.PublicProfile(p,true),titleBadge:{id:'POSTS_1',title:'예전 칭호'}}});
  receipt('FIX75-OLD-SELECT','badge.select',oldSelectBody,{selected:'POSTS_1'});
  receipt('FIX75-OLD-PROFILE','profile.save',oldProfileBody,{profile:{...s.PublicProfile(p,true),bio:oldProfileBody.bio,titleBadge:{id:'POSTS_1',title:'예전 칭호'},inventory:{...p.inventory}}});
 });
 const awards=structuredClone(p.badgeProgress),inventory=structuredClone(p.inventory),receipts=structuredClone(s.DB().operations),before=snapshot();
 for(let i=0;i<2;i++)for(const action of ['me','home','shop','rewards','feed','notifications','history'])run(a,action);
 assert.equal(snapshot(),before,'read routes neither claim pending awards nor backfill missions');
 assert.equal(p.balance,98765);assert.equal(p.points,777);assert.deepEqual(p.badgeProgress,awards);
 assert.equal(run(b,'member',{id:p.id}).profile.titleBadge,undefined);assert.equal(run(b,'live',{profiles:[p.id]}).profiles[0].titleBadge,undefined);
 assert.deepEqual(run(a,'shop').items.map(x=>x.id),shop.Items());assert.deepEqual(Object.keys(run(a,'shop').inventory),['nicknameTickets','nicknameColors','commentTickets','repostTickets','shareTickets']);
 assert.deepEqual(run(a,'history').recentServices.map(x=>x.route),['points']);
 assert.ok(!run(a,'notifications').items.some(x=>x.id==='points:'+oldPoint.id||x.target==='badges'),'old awards do not generate notifications or dead navigation');
 assert.deepEqual(run(a,'rewards').history.items.find(x=>x.id===oldPoint.id),oldPoint,'past points remain a read-only ledger entry');
 for(const action of ['badges','badge.select','badge.claim','title.color','title.name'])unchanged(()=>run(a,action,{id:'POSTS_1',color:'#123456',name:'new'}),/UNKNOWN_ACTION/);
 unchanged(()=>run(a,'badge.select',oldSelectBody,'FIX75-OLD-SELECT'),/UNKNOWN_ACTION/);
 unchanged(()=>run(a,'shop.purchase',oldShopBody,'FIX75-OLD-TITLE-BUY'),/SHOP_UNAVAILABLE/);
 for(const itemId of ['TITLE_COLOR','TITLE_NAME'])unchanged(()=>run(a,'shop.purchase',{itemId,revision:1}),/SHOP_UNAVAILABLE/);
 unchanged(()=>run(a,'history.record',{route:'badges'}),/INPUT_INVALID/);
 unchanged(()=>service.AdminWrite('shop.save',{revision:1,items:s.DB().settings.memberShop.items},'FIX75'),/INPUT_INVALID/);
 const replay=run(a,'profile.save',oldProfileBody,'FIX75-OLD-PROFILE');assert.equal(replay.profile.titleBadge,undefined);assert.equal(replay.profile.inventory.titleColors,undefined);assert.equal(replay.profile.bio,oldProfileBody.bio);assert.deepEqual(s.DB().operations,receipts,'receipt presentation never rewrites stored history');
 const post=run(a,'post.create',{body:'퇴역 이후의 첫 게시글'}).post;run(b,'react',{postId:post.id,value:1});run(a,'profile.save',{nickname:p.nickname,bio:'새 소개'});run(a,'follow.set',{id:s.Account(b).id,following:true});
 assert.equal(p.points,777);assert.equal(s.Account(b).points||0,0);assert.equal(s.Account(b).badgeProgress,undefined,'new members have no mission state');assert.deepEqual(p.badgeProgress,awards,'ordinary mutations never capture or claim awards');
 run(a,'nickname.color',{color:'#ABCDEF'});assert.equal(p.nicknameColor,'#ABCDEF');assert.equal(p.inventory.nicknameColors,0);assert.equal(p.inventory.titleColors,inventory.titleColors);assert.equal(p.inventory.titleNames,inventory.titleNames);
 const bought=run(a,'shop.purchase',{itemId:'NICKNAME_COLOR',revision:1});assert.equal(bought.profile.points,757);assert.equal(p.inventory.nicknameColors,1);assert.equal(p.inventory.titleColors,inventory.titleColors);
 const priorPoints=p.points;run(a,'attendance.check');assert.equal(p.points,priorPoints,'first attendance no longer includes a mission bonus');
 unchanged(()=>run(a,'event.spin',{revision:rewards.Rules().revision}),/UNKNOWN_ACTION/);assert.equal(p.points,priorPoints);assert.equal(p.eventSpins,2);assert.equal(p.balance,98765);
 assert.deepEqual(s.DB().pointLedger.OLD,oldPoint);assert.deepEqual(s.DB().ledger.OLD,oldCash);assert.deepEqual(s.DB().shopPurchases.OLD,oldPurchase);assert.deepEqual(p.badgeProgress,awards);assert.equal(Object.values(s.DB().pointLedger).filter(x=>x.kind==='BADGE_REWARD').length,1);
 const points=p.points;assert.equal(database.SaveDatabase(),true);database.LoadDatabase();p=s.Account(a);assert.equal(p.points,points);assert.equal(p.balance,98765);assert.deepEqual(s.DB().pointLedger.OLD,oldPoint);assert.deepEqual(p.badgeProgress,awards);assert.deepEqual(s.DB().operations[p.id+':FIX75-OLD-PROFILE'],receipts[p.id+':FIX75-OLD-PROFILE']);
 assert.ok(!fs.existsSync(path.resolve(__dirname,'../services/member','badges.js')),'award engine is deleted, not replaced with an empty facade');
 const web=fs.readFileSync(path.resolve(__dirname,'../public/admin-member-customization.js'),'utf8');assert.doesNotMatch(web,/TITLE_COLOR|TITLE_NAME|titleBadge|칭호|배지/);
 console.log('FIX75 cosmetic retirement PASS ('+process.env.STORAGE_ENGINE+'): no claims on reads/mutations/replay, removed actions and sales rejected, balances and immutable history retained, clean public/UI projections, nickname shop/attendance preserved and wheel retired, durable reload.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
