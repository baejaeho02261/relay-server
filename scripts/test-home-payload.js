'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix75-home-payload-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const s=require('../services/member/store'),commerce=require('../services/member/commerce'),home=require('../services/member/home'),rewards=require('../services/member/rewards'),wire=require('../services/member/wire');
// These are size sentinels for already-validated stored images. The gallery
// codec has separate pixel/validation tests; projection must not decode them.
const media=(bytes,char)=>'data:image/jpeg;base64,'+char.repeat(Math.ceil(bytes/3)*4);
try{
 commerce.EnsureCatalog();const p=s.Account({installationDeviceKey:'FIX75_HOME_PAYLOAD'}),now=Date.now(),games=commerce.CatalogRows();
 const original=media(420000,'A'),display=media(180000,'B'),thumb=media(12000,'C'),feedImage=media(70000,'D');
 s.Atomic(()=>{
  p.balance=50000;p.points=125;p.eventSpins=3;p.activeOrderId='PAYLOAD-ORDER-0';p.attendance={day:rewards.Day(now),streak:1,count:1,at:now,days:[rewards.Day(now)]};
  for(const game of games)game.gallery=Array.from({length:6},()=>({image:original,display,displayVersion:1,thumb}));
  p.recentHistory={products:games.map(game=>({id:game.id,at:now})),services:[{route:'news',at:now},{route:'points',at:now-1},{route:'attendance',at:now-2}]};
  for(let i=0;i<5;i++){
   const id='PAYLOAD-POST-'+i;s.DB().posts[id]={id,accountId:p.id,title:'Home feed '+i,body:'가'.repeat(2000),at:now-i,revision:1,audience:'PUBLIC',image:original,imageFeed:feedImage,imageFeedVersion:2};
   const comment='PAYLOAD-COMMENT-'+i;s.DB().comments[comment]={id:comment,postId:id,accountId:p.id,body:'Reply',at:now-i};
  }
  for(let i=0;i<3;i++){
   const game=games[i%games.length],id='PAYLOAD-ORDER-'+i;
   s.DB().news['PAYLOAD-NEWS-'+i]={id:'PAYLOAD-NEWS-'+i,title:'News '+i,body:'가'.repeat(5000),category:'NOTICE',published:true,at:now-i,revision:1};
   s.DB().orders[id]={id,accountId:p.id,productId:game.id,title:game.title,gameKey:game.gameKey,status:'PAID',singleUse:true,uses:1,days:0,amount:700,at:now-i,preparedClientId:i===0?'PAYLOAD-CLIENT':''};
   s.DB().ledger['PAYLOAD-LEDGER-'+i]={id:'PAYLOAD-LEDGER-'+i,accountId:p.id,productId:game.id,title:game.title,kind:'PURCHASE',reference:id,amount:-700,at:now-i};
   s.DB().pointLedger['PAYLOAD-POINT-'+i]={id:'PAYLOAD-POINT-'+i,accountId:p.id,kind:'ATTENDANCE',amount:100,at:now-i};
  }
 });
 const snapshot=JSON.stringify(s.DB()),data=home.Read(p),json=JSON.stringify(data),size=Buffer.byteLength(json);
 assert.equal(JSON.stringify(s.DB()),snapshot,'populated home remains read-only');
 assert.equal(data.catalog.length,2);assert.ok(data.catalog.every(row=>row.gallery.length===6));assert.ok(data.catalog.every(row=>row.gallery.every(photo=>photo.image===display)));
 assert.deepEqual(data.catalog,commerce.Catalog({summary:true},p).items,'home retains the complete display-quality discovery cards');
 assert.equal(data.recentProducts.length,2);
 for(const row of data.recentProducts){
  assert.deepEqual(Object.keys(row).sort(),['gameKey','genre','icon','id','title','viewedAt']);
  assert.ok(row.title&&row.icon&&row.genre&&row.viewedAt);assert.ok(games.some(game=>game.id===row.id));
 }
 assert.ok(!json.includes(original),'neither recent rows nor catalog send the original gallery');
 for(const [key,count] of [['news',3],['feed',5],['orders',3],['payments',3],['pointHistory',3],['purchases',3],['topGames',2],['recentServices',3]])assert.equal(data[key].length,count,key+' exercises its populated home limit');
 assert.ok(data.runningGames.length>0);assert.equal(data.attendanceRanking.length,1);assert.equal(data.counts.todayComments,5);
 assert.ok(size<8000000,'maximum-sized gallery displays plus populated home sections fit the wire budget');
 assert.doesNotThrow(()=>wire.Encode(data,false));assert.doesNotThrow(()=>wire.Encode(data,true));
 // Prove this fixture reproduces the removed duplicate-original bug.
 const duplicated={...data,recentProducts:games.map(game=>({...commerce.PublicGame(game),viewedAt:now}))};
 assert.ok(Buffer.byteLength(JSON.stringify(duplicated))>8000000);assert.throws(()=>wire.Encode(duplicated,false),/RESPONSE_LIMIT/);
 console.log(`FIX75 HOME PAYLOAD PASS: ${size} bytes with two six-photo galleries and populated home sections; recent rows retain navigation fields without duplicated originals; both wire modes encode successfully.`);
}finally{fs.rmSync(dir,{recursive:true,force:true});}
