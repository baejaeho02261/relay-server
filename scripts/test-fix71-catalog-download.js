'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{Readable}=require('node:stream'),{PNG}=require('pngjs');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix71-download-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';
require('../core/utils').EnsureDirs();const s=require('../services/member/store'),commerce=require('../services/member/commerce'),downloads=require('../services/member/game-downloads');
async function upload(bytes,key='PUBG',name='PubgClient.exe'){
 const req=new Readable({read(){this.push(bytes);this.push(null);}});return downloads.Upload(req,key,name);
}
(async()=>{try{
 const db=s.DB(),p={id:'USR-OWNER',subject:'OWNER',nickname:'이용자',balance:90000,points:0,createdAt:Date.now()};db.profiles.OWNER=p;commerce.EnsureCatalog();
 const file=Buffer.alloc(512);file.write('MZ');file.writeUInt32LE(128,60);file.write('PE\0\0',128);
 await assert.rejects(upload(Buffer.from('not an exe')),/GAME_EXE_INVALID/);
 await assert.rejects(upload(file,'PUBG','../evil.exe'),/GAME_FILENAME_INVALID/);
 await assert.rejects(upload(file,'OTHER'),/GAME_ARTIFACT_INVALID/);
 const artifact=await upload(file);assert.equal(artifact.bytes,512);assert.equal(downloads.Artifact(artifact.id).sha256,artifact.sha256);
 const png=new PNG({width:2,height:2});png.data.fill(255);const photo='data:image/png;base64,'+PNG.sync.write(png).toString('base64');
 const pubg=commerce.CatalogRows().find(x=>x.gameKey==='PUBG');
 let game=commerce.SaveProduct({...pubg,description:'배틀그라운드 게임',plans:[1,7,15,30].map(days=>({days,price:days*100})),artifactId:artifact.id,gallery:[photo,photo],published:true});
 assert.equal(game.gallery.length,2);assert.ok(game.gallery[0].image.startsWith('data:image/jpeg;'));assert.equal(game.artifact.id,artifact.id);
 assert.throws(()=>commerce.SaveProduct({...game,gallery:Array(7).fill(photo)}),/CONTENT_IMAGE_INVALID/);
 assert.throws(()=>commerce.SaveProduct({...game,gallery:['https://evil.invalid/x.png']}),/CONTENT_IMAGE_INVALID/);
 const valorant=commerce.CatalogRows().find(x=>x.gameKey==='VALORANT');assert.throws(()=>commerce.SaveProduct({...valorant,artifactId:artifact.id}),/GAME_ARTIFACT_UNAVAILABLE/);
 assert.deepEqual(commerce.Catalog().items.find(x=>x.id===game.id).gallery.map(x=>Object.keys(x)),[['thumb'],['thumb']]);
 assert.equal(commerce.Product({id:game.id},p).product.views,1);assert.equal(commerce.Catalog().items.find(x=>x.id===game.id).views,1);assert.equal(commerce.Product({id:game.id},p).product.views,1,'same-day opens do not inflate counters');
 const purchase=()=>s.Atomic(()=>commerce.Purchase(s.ProfileById(p.id),{productId:game.id,days:1,price:100,revision:game.revision}));
 const result=purchase(),order=result.order;purchase();assert.equal(commerce.PublicOrder(s.DB().orders[order.id]).purchases.length,2);assert.equal(commerce.PurchasePayments(p).length,2);
 const ticket=downloads.Issue(p,{}, {orderId:order.id}).download;assert.equal(ticket.status,'PAID');assert.equal(s.DB().orders[order.id].activatedAt,0,'saving an EXE does not activate an unused pass');
 assert.ok(ticket.url.startsWith('https://relay-server-production-5386.up.railway.app/game-download/'));const token=new URL(ticket.url).pathname.split('/').pop();
 assert.equal(downloads.Verify(token).id,artifact.id);await downloads.VerifyBytes(downloads.Verify(token));
 const http=require('node:http'),server=http.createServer((req,res)=>{const url=new URL(req.url,'http://localhost');downloads.Serve(req,res,url.pathname,url).then(handled=>{if(!handled){res.writeHead(404);res.end();}}).catch(()=>{res.writeHead(500);res.end();});});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{
  const local='http://127.0.0.1:'+server.address().port+'/game-download/'+token;
  let response=await fetch(local);assert.equal(response.status,200);assert.equal(response.headers.get('x-content-sha256'),artifact.sha256);assert.deepEqual(Buffer.from(await response.arrayBuffer()),file);
  response=await fetch(local,{headers:{Range:'bytes=128-131'}});assert.equal(response.status,206);assert.equal(response.headers.get('content-range'),'bytes 128-131/512');assert.deepEqual(Buffer.from(await response.arrayBuffer()),Buffer.from([80,69,0,0]));
  response=await fetch(local,{method:'HEAD'});assert.equal(response.status,200);assert.equal(response.headers.get('content-length'),'512');assert.equal((await response.arrayBuffer()).byteLength,0);
  response=await fetch(local,{headers:{Range:'bytes=600-700'}});assert.equal(response.status,416);await response.text();
  response=await fetch(local+'.invalid');assert.equal(response.status,403);await response.text();
 }finally{await new Promise(resolve=>server.close(resolve));}

 assert.throws(()=>downloads.Verify(token.slice(0,-1)+'x'),/GAME_DOWNLOAD_FORBIDDEN/);
 assert.throws(()=>downloads.Issue({id:'USR-OTHER'}, {},{orderId:order.id}),/GAME_DOWNLOAD_FORBIDDEN/);
 const now=Date.now;Date.now=()=>now()+121000;try{assert.throws(()=>downloads.Verify(token),/GAME_DOWNLOAD_FORBIDDEN/);}finally{Date.now=now;}
 const saved=s.DB().orders[order.id];saved.status='REFUNDED';assert.throws(()=>downloads.Verify(token),/GAME_DOWNLOAD_FORBIDDEN/);saved.status='PAID';
 saved.expiresAt=now()-1;assert.throws(()=>downloads.Verify(token),/GAME_DOWNLOAD_FORBIDDEN/);saved.expiresAt=0;
 p.blocked=true;assert.throws(()=>downloads.Verify(token),/GAME_DOWNLOAD_FORBIDDEN/);p.blocked=false;
 const meta=downloads.Artifact(artifact.id);const bad=Buffer.from(file);bad[400]=88;fs.writeFileSync(meta.file,bad);await assert.rejects(downloads.VerifyBytes(downloads.Verify(token)),/GAME_CHECKSUM_MISMATCH/);
 fs.writeFileSync(meta.file,file);
 const native=path.resolve(__dirname,'../../MoaPlayApp_Android64'),card=fs.readFileSync(path.join(native,'MoaPlayCatalogCard.pas'),'utf8'),ui=fs.readFileSync(path.join(native,'MoaPlayApp.Member.NewsShop.inc'),'utf8'),down=fs.readFileSync(path.join(native,'MoaPlayGameDownloads.pas'),'utf8');
 assert.match(card,/FHoldTimer.Interval:=560/);assert.match(card,/OnClick:=OpenNow;OnDblClick:=nil/);assert.doesNotMatch(card,/FSingleTimer/);
 assert.match(ui,/for Days in \[1,7,15,30\]/);assert.match(ui,/for Key in FHubCache.Keys/);assert.doesNotMatch(ui,/HubCatalogCardDoubleClick|product\.plan\|/);assert.match(ui,/Photos.Count-1/);
 assert.match(down,/setDestinationInExternalPublicDir/);assert.match(down,/if Code=8 then/);assert.match(down,/SHA-256/);assert.match(down,/Total<>ExpectedBytes/);assert.match(down,/Check.Complete\(1\)/);assert.match(down,/URI.getHost/);assert.match(down,/FTimer.OnTimer:=nil/);
 console.log('FIX71 catalog: duration cards, gallery validation, monotonic views, receipt preservation, secured EXE upload/ticket/checksum and native lifetime guards PASS');
 }finally{fs.rmSync(dir,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
