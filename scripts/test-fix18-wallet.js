'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'relay-fix17-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';
require('../core/utils').EnsureDirs();const state=require('../core/state'),s=require('../services/member/store'),hub=require('../services/member/service'),entry=require('../services/member/entryPass'),lm=require('../license/licenseManager'),db=require('../storage/database'),build=require('../services/buildGate');
let seq=0;const run=(c,action,body={},id)=>hub.Execute(c,id||'FIX17REQ'+String(++seq).padStart(8,'0'),action,body),admin=(action,body)=>hub.AdminWrite(action,body,'FIX17-ADMIN');
function client(id,key){const lines=[],c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(x){lines.push(x.trim());return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=lm.CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;return {c,lines};}
function screenshot(matrix,scale=6){const {PNG}=require('pngjs'),side=(matrix.size+16)*scale,png=new PNG({width:side,height:side});png.data.fill(255);for(let y=0;y<matrix.size;y++)for(let x=0;x<matrix.size;x++)if(matrix.bits[y*matrix.size+x]==='1')for(let dy=0;dy<scale;dy++)for(let dx=0;dx<scale;dx++){const i=(((y+8)*scale+dy)*side+(x+8)*scale+dx)*4;png.data[i]=png.data[i+1]=png.data[i+2]=0;}for(let y=Math.floor((side-9*scale)/2);y<(side+9*scale)/2;y++)for(let x=Math.floor((side-9*scale)/2);x<(side+9*scale)/2;x++){const i=(y*side+x)*4;png.data[i]=png.data[i+1]=png.data[i+2]=255;}return 'data:image/png;base64,'+PNG.sync.write(png).toString('base64');}
try{
 const {c:a,lines}=client('1111111111111111','FIX17-A'),{c:b}=client('2222222222222222','FIX17-B');const p=s.Account(a),q=s.Account(b);
 assert.equal(state.licenses.get(a.licenseKey).expiresAt,0);assert.equal(state.licenses.get(a.licenseKey).accessType,'');assert.equal(lm.GetLicenseStatus(state.licenses.get(a.licenseKey)),'BOUND');assert.ok(lm.GetUsableLicenseForConnection(a));assert.equal(entry.ForClient(a),null);assert.equal(build.Queue(a,'BUILD-NO-GAME').reason,'GAME_PASS_REQUIRED');
 const game=admin('product.save',{title:'테일즈런너',description:'게임 안내만 표시',accessType:'TYPE2',published:true,plans:[{days:1,price:1000},{days:7,price:6000},{days:15,price:12000},{days:30,price:20000}]});assert.equal(game.price,undefined);assert.equal(run(a,'catalog').items[0].days,undefined);assert.throws(()=>run(a,'purchase',{productId:game.id}),/GAME_PLAN_INVALID/);
 const save=db.SaveDatabase,body={accountId:p.id,confirmedAccountId:p.id,confirmed:true,amount:30000,reason:'구매 검증용 잔액',requestId:'FIX18-GRANT-ONE'};
 const before=JSON.stringify(s.DB());db.SaveDatabase=()=>false;assert.throws(()=>admin('wallet.grant',body),/STORAGE_SAVE_FAILED/);db.SaveDatabase=save;assert.equal(JSON.stringify(s.DB()),before);
 const approved=admin('wallet.grant',body);assert.deepEqual(admin('wallet.grant',body),approved);assert.equal(run(a,'me').profile.balance,30000);assert.equal(entry.ForClient(a),null,'a wallet balance does not unlock games');
 const purchase={productId:game.id,days:30,price:20000,revision:game.revision};
 assert.throws(()=>run(a,'purchase',{...purchase,days:2}),/GAME_PLAN_UNAVAILABLE/);
 assert.throws(()=>run(a,'purchase',{...purchase,price:1}),/PRICE_CHANGED/);
 assert.throws(()=>run(a,'purchase',{...purchase,revision:0}),/PRICE_CHANGED/);
 assert.throws(()=>run(b,'purchase',purchase),/INSUFFICIENT_BALANCE/);
 const beforePurchase=JSON.stringify(s.DB());db.SaveDatabase=()=>false;assert.throws(()=>run(a,'purchase',purchase,'BUY-ROLLBACK-17'),/STORAGE_SAVE_FAILED/);db.SaveDatabase=save;assert.equal(JSON.stringify(s.DB()),beforePurchase);
 const bought=run(a,'purchase',purchase,'BUY-ROLLBACK-17');assert.equal(bought.profile.balance,10000);assert.equal(bought.order.days,30);assert.equal(bought.order.activatedAt,0);assert.deepEqual(run(a,'purchase',purchase,'BUY-ROLLBACK-17'),bought);assert.equal(Object.keys(s.DB().orders).length,1);
 assert.throws(()=>run(a,'purchase',purchase),/INSUFFICIENT_BALANCE/);assert.equal(run(a,'me').profile.balance,10000);
 const orderId=bought.order.id;

 const event=lines.filter(x=>x.startsWith('HUB_EVENT|')).pop().split('|');assert.equal(event[2],require('../services/member/protocol').Sign(a,'HUB_EVENT',[event[1]]));assert.equal(require('../services/member/protocol').Verify(a,['x'],event[2]),false);
 assert.throws(()=>run(b,'order.activate',{orderId:orderId}),/ORDER_NOT_FOUND/);
 const active=run(a,'order.activate',{orderId:orderId},'ACTIVATE-FIX17');assert.equal(active.order.status,'ACTIVE');assert.deepEqual(run(a,'order.activate',{orderId:orderId},'ACTIVATE-FIX17'),active);assert.equal(entry.ForClient(a).accessType,'TYPE2');assert.equal(state.licenses.get(a.licenseKey).expiresAt,0);assert.equal(run(a,'me').profile.balance,10000);assert.throws(()=>admin('order.refund',{id:orderId,reason:'환불'}),/ACTIVATED_REFUND_REVIEW/);
 // A short game entitlement caps the independently renewable PC Build lease.
 const serverId='3333333333333333',saved=state.clientIdentities.get('FIX17-A');saved.serverId=serverId;a.serverId=serverId;const serverLines=[];state.servers.set(serverId,{type:'server',serverId,connected:true,registered:true,deviceAuthVerified:true,clients:new Set([a.clientId]),socket:{destroyed:false,write(x){serverLines.push(x);return true;}}});state.deviceAuthStatus.set('SERVER:'+serverId,{verified:true,verifiedAt:Date.now()});state.deviceCapabilities.set('SERVER:'+serverId,new Set(['BUILD_SESSION_LEASE']));state.deviceSecrets.set('SERVER:'+serverId,'TEST-'+crypto.randomBytes(32).toString('hex'));
 const entitlement=s.DB().orders[orderId];entitlement.expiresAt=Date.now()+60000;const queued=build.Queue(a,'FIX17-GAME-BUILD');assert.equal(queued.ok,true);assert.ok(queued.grant.sessionExpiresAt>0);assert.ok(queued.grant.sessionExpiresAt<=entitlement.expiresAt);assert.equal(queued.grant.accessType,'TYPE2');assert.equal(build.Complete(a.clientId,'FIX17-GAME-BUILD').ok,true);
 entitlement.expiresAt=Date.now()-1;build.Cleanup();assert.equal(entry.ForClient(a),null);assert.equal(build.ActiveSessionForClient(a.clientId),null);assert.ok(lm.GetUsableLicenseForConnection(a));const afterExpiry=run(a,'me');assert.equal(afterExpiry.profile.id,p.id,'entry survives game expiry');assert.equal(afterExpiry.orders.items.find(x=>x.id===orderId).status,'EXPIRED','expired passes are displayed as expired');
 for(const action of ['charge','charge.new','payment.start'])assert.throws(()=>run(a,action,{}),/UNKNOWN_ACTION|TOPUP_UNAVAILABLE/);
 const snapshot=db.BuildDatabaseObject();assert.equal(db.ImportDatabaseObject(snapshot),true);assert.equal(lm.FindLicense(a.licenseKey).entryPass,true);assert.equal(lm.FindLicense(a.licenseKey).expiresAt,0);
 // Wallet funds survive time; only the game's first-use term expires.
 const now=Date.now;Date.now=()=>now()+3650*86400000;
 try{assert.equal(run(a,'me').profile.balance,10000);assert.ok(lm.GetUsableLicenseForConnection(a));}finally{Date.now=now;}
 // Buy all four durations into one combined unused pass and refund it once.
 admin('wallet.grant',{accountId:q.id,confirmedAccountId:q.id,confirmed:true,amount:100000,reason:'환불 검증용 잔액',requestId:'FIX18-GRANT-TWO'});
 let combinedDays=0;for(const plan of game.plans){const result=run(b,'purchase',{productId:game.id,days:plan.days,price:plan.price,revision:game.revision});combinedDays+=plan.days;assert.equal(result.order.days,combinedDays);}
 assert.equal(run(b,'me').orders.total,1);assert.equal(run(b,'me',{purchasesOnly:true}).payments.total,4);
 assert.equal(run(b,'me').profile.balance,61000);
 const unused=run(b,'me').orders.items[0],refunded=admin('order.refund',{id:unused.id,reason:'미사용 취소'});assert.equal(refunded.status,'REFUNDED');const refundBalance=run(b,'me').profile.balance;admin('order.refund',{id:unused.id,reason:'미사용 취소'});assert.equal(run(b,'me').profile.balance,refundBalance);
 const disabled=admin('product.save',{title:'판매 준비',accessType:'TYPE1',published:true});assert.ok(disabled.plans.every(x=>!x.available));assert.throws(()=>run(b,'purchase',{productId:disabled.id,days:1,price:0,revision:disabled.revision}),/GAME_PLAN_UNAVAILABLE/);
 assert.throws(()=>admin('product.save',{title:'잘못된 가격',accessType:'TYPE1',plans:[{days:0,price:100}]}),/GAME_PLAN_INVALID/);
 // Retired legacy approvals cannot create any additional wallet credit.
 const legacyBefore=run(b,'me').profile.balance;assert.throws(()=>admin('charge.approve',{id:'CHG-111111111111111111111111',mode:'WALLET',amount:5000}),/TOPUP_UNAVAILABLE/);assert.equal(run(b,'me').profile.balance,legacyBefore);

 console.log('FIX18 WALLET/PURCHASE PASS: permanent entry, four-term games, administrator grants and retired charge rejection, atomic rollback, idempotency, ownership, signed refresh, wallet without expiry, signed purchase quotes, refunds, game lease cap and expiry, snapshot recovery');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
