'use strict';
const s=require('./store'),state=require('../../core/state'),plans=require('./gamePlans');
const media=require('./media');
function Gallery(value,previous=[]){
 if(value===undefined)return previous;
 if(!Array.isArray(value)||value.length>6)s.Fail('CONTENT_IMAGE_INVALID');
 return value.filter(x=>x!=='').map(value=>media.GalleryFields(value));
}
const GAMES=Object.freeze({PUBG:{title:'배틀그라운드',genre:'배틀로얄',accessType:'TYPE1'},VALORANT:{title:'발로란트',genre:'전술 슈팅',accessType:'TYPE2'}});
function GameKey(value){
 const candidates=typeof value==='string'?[value]:[value?.gameKey,value?.title];
 for(const value of candidates){
  const key=String(value||'').toUpperCase().replace(/[ _:'’–—-]/g,'');
  if(['PUBG','PUBGBATTLEGROUNDS','BATTLEGROUNDS','PLAYERUNKNOWNSBATTLEGROUNDS','배틀그라운드','PUBG배틀그라운드'].includes(key))return 'PUBG';
  if(key==='VALORANT'||key==='발로란트')return 'VALORANT';
 }
 return '';
}
function GameIcon(value){const key=GameKey(value);return key?'game.'+key.toLowerCase():'ticket';}
function DefaultGame(key){const info=GAMES[key];return {id:'PRD-'+key,gameKey:key,...info,description:info.title+' 이용권 안내',singleUse:true,price:0,plans:[{uses:1,price:0}],published:true,deleted:false,sort:key==='PUBG'?0:1,revision:1,updatedAt:0};}
function CatalogRows(includeHidden=false){
 const db=s.DB(),selected=db.settings.catalogGameIds||{};
 return Object.keys(GAMES).map(key=>{
  const configured=db.products[selected[key]];
  return configured&&GameKey(configured)===key?configured:Object.values(db.products).filter(p=>GameKey(p)===key&&!p.catalogRetired).sort((a,b)=>Number(!!a.deleted)-Number(!!b.deleted)||Number(!!b.published)-Number(!!a.published)||(a.sort||0)-(b.sort||0))[0]||DefaultGame(key);
 }).filter(p=>!p.catalogRetired&&(includeHidden||p.published&&!p.deleted));
}
function EnsureCatalog(){
 const db=s.DB();if(db.settings.catalogVersion===74)return;
 s.Atomic(()=>{
  const chosen=CatalogRows(true),ids=new Set(chosen.map(p=>p.id));db.settings.catalogGameIds={};
  for(const source of chosen){const key=GameKey(source),p={...source,gameKey:key,title:GAMES[key].title,genre:source.genre||GAMES[key].genre,catalogRetired:false,singleUse:true,price:plans.Price(source),plans:plans.Plans(source).map(({uses,price})=>({uses,price})),updatedAt:source.updatedAt||Date.now()};db.products[p.id]=p;db.settings.catalogGameIds[key]=p.id;}
  // Retire catalogue listings only: entitlements, receipts and refunds remain intact.
  for(const p of Object.values(db.products)){delete p.image;delete p.imageCover;delete p.imageThumb;if(!ids.has(p.id)){p.catalogRetired=true;p.published=false;}}
  db.settings.catalogVersion=74;
 });
}
function PublicGame(p){return {id:p.id,gameKey:GameKey(p),icon:GameIcon(p),title:p.title,description:p.description,genre:p.genre||p.details?.genre||'게임',accessType:p.accessType,singleUse:true,price:plans.Price(p),available:plans.Plans(p)[0].available,plans:plans.Plans(p),published:p.published,deleted:p.deleted,sort:p.sort,revision:p.revision,updatedAt:p.updatedAt,views:s.ViewCount('product',p.id),gallery:(p.gallery||[]).map(x=>({thumb:x.thumb||'',image:x.image||''})),artifact:require('./game-downloads').PublicArtifact(p.artifactId,GameKey(p)),artifactId:p.artifactId||''};}
function Catalog(body={},viewer){
 const page=s.Page(CatalogRows(),{...body,offset:0,limit:2});
 return {...page,q:'',items:page.items.map(p=>{
  const item={...PublicGame(p),gallery:(p.gallery||[]).map(x=>({image:media.GalleryDisplay(x),thumb:x.thumb||''})),unread:!!viewer&&(viewer.readProducts?.[p.id]||0)<(p.revision||1)};
  if(body.summary===true)item.description=String(p.description||'').replace(/\s+/g,' ').trim().slice(0,140);
  return item;
 })};
}
function Product(body,p){
 const row=CatalogRows().find(x=>x.id===body.id);if(!row)s.Fail('PRODUCT_UNAVAILABLE');
 if(p){if((p.readProducts?.[row.id]||0)<(row.revision||1))s.Atomic(()=>{p.readProducts||={};p.readProducts[row.id]=row.revision||1;});require('./views').Article(p,row,'product');require('./history').RecordProduct(p,body);}
 return {product:{...PublicGame(row),unread:false},...(p?{profile:s.PublicProfile(p,true)}:{})};
}
function SaveProduct(body){
 const key=GameKey(body.gameKey||body.title);if(!key)s.Fail('INPUT_INVALID');
 const current=CatalogRows(true).find(p=>GameKey(p)===key),id=body.id?s.Text(body.id,40):current.id,previous=s.DB().products[id];
 if(body.id&&id!==current.id)s.Fail('PRODUCT_NOT_FOUND');
 if(previous&&body.revision!==undefined&&body.revision!==(previous.revision||0))s.Fail('CONTENT_CHANGED');
 const accessType=s.Text(body.accessType||previous?.accessType||GAMES[key].accessType,16);if(!['TYPE1','TYPE2','TYPE3'].includes(accessType))s.Fail('ACCESS_TYPE_INVALID');
 const genre=s.Text(body.genre===undefined?(previous?.genre||GAMES[key].genre):body.genre,50,true);
 const row={...previous,id,gameKey:key,title:GAMES[key].title,description:s.Text(body.description,1500),genre,accessType,singleUse:true,price:body.price===undefined?plans.Price(previous):s.Money(body.price,0),plans:[{uses:1,price:body.price===undefined?plans.Price(previous):s.Money(body.price,0)}],published:body.published===true,deleted:previous?.deleted||false,catalogRetired:false,sort:key==='PUBG'?0:1,revision:(previous?.revision||0)+1,updatedAt:Date.now(),gallery:Gallery(body.gallery,previous?.gallery||[]),artifactId:require('./game-downloads').ResolveArtifact(body.artifactId,key,previous?.artifactId||'')};
 delete row.image;delete row.imageCover;delete row.imageThumb;
 return s.Atomic(()=>{s.DB().products[id]=row;s.DB().settings.catalogGameIds||={};s.DB().settings.catalogGameIds[key]=id;return PublicGame(row);});
}
function ResolveOrder(id){
 const db=s.DB(),seen=new Set();let order=db.orders[id];
 while(order?.mergedInto){if(seen.has(order.id))return null;seen.add(order.id);const parent=db.orders[order.mergedInto];if(!parent||parent.accountId!==order.accountId)return null;order=parent;}
 return order;
}
function SessionForOrder(row){
 if(!row||!row.preparedClientId)return null;
 const session=require('../buildGate').ActiveSessionForClient(row.preparedClientId);
 if(!session||session.orderId!==row.id||row.consumedAt&&session.sessionId!==row.sessionId)return null;
 const ids=require('../../identity/identityManager'),client=ids.GetOnlineClient(row.preparedClientId),server=ids.GetOnlineServer(session.serverId),saved=ids.GetSavedClientByID(row.preparedClientId);
 if(!client?.connected||!server?.connected||!client.biometricVerified||!client.licenseAuthorized||saved?.serverId!==session.serverId)return null;
 if(client.buildCompleted!==true||client.buildSessionId!==session.sessionId||!(server.buildClients instanceof Set)||!server.buildClients.has(client.clientId)||!(server.buildSessions instanceof Map)||server.buildSessions.get(client.clientId)!==session.sessionId)return null;
 if(!require('../deviceAuth').Verified('CLIENT',client.clientId)||!require('../deviceAuth').Verified('SERVER',session.serverId))return null;
 try{if(s.Subject(client)!==s.ProfileById(row.accountId)?.subject)return null;}catch(_){return null;}
 return session;
}
function PublicOrder(row){
 const {licenseKey,preparedClientId,sessionId,...result}=row,session=SessionForOrder(row);
 const legacyUsed=row.singleUse!==true&&(row.activatedAt||row.status==='ACTIVE');
 const status=legacyUsed?'USED':row.consumedAt?(session?'ACTIVE':'USED'):row.status;
 return {...result,status,gameKey:GameKey(s.DB().products[row.productId]||row),icon:GameIcon(s.DB().products[row.productId]||row),singleUse:true,uses:1,days:0,expiresAt:0,displayExpiresAt:0,remainingUses:row.consumedAt||['USED','REFUNDED','EXPIRED','MERGED'].includes(status)?0:1,connectionReady:!!session,sessionExpiresAt:session?.expiresAt||0,paymentMethod:row.source==='WALLET_PURCHASE'?'WALLET':row.source,purchases:Object.values(s.DB().ledger).filter(x=>x.kind==='PURCHASE'&&x.accountId===row.accountId&&x.reference===row.id).map(x=>({id:x.id,at:x.at,uses:1,days:0,amount:x.amount,paymentMethod:'WALLET'}))};
}
function NormalizeOrders(p,atomic=true){
 const db=s.DB(),legacy=Object.values(db.orders).filter(row=>row.accountId===p.id&&row.productId&&row.singleUse!==true),stale=Object.values(db.orders).filter(row=>row.accountId===p.id&&row.singleUse&&row.status==='ACTIVE'&&row.consumedAt&&!SessionForOrder(row));
 if(!legacy.length&&!stale.length)return;
 const apply=()=>{
  const roots=legacy.filter(row=>!row.mergedInto);
  for(const row of roots){
   const linked=legacy.filter(x=>ResolveOrder(x.id)?.id===row.id),receipts=Object.values(db.ledger).filter(x=>x.kind==='PURCHASE'&&x.accountId===p.id&&linked.some(o=>o.id===x.reference)).sort((a,b)=>a.at-b.at||a.id.localeCompare(b.id));
   const used=!!row.activatedAt||row.status==='ACTIVE',dead=['REFUNDED','EXPIRED'].includes(row.status);
   const original={days:row.days||0,expiresAt:row.expiresAt||0,amount:row.amount};
   Object.assign(row,{singleUse:true,uses:1,days:0,expiresAt:0,legacy:original,status:dead?row.status:used?'USED':'PAID',consumedAt:used?(row.activatedAt||Date.now()):0});
   // A previously merged, unused entitlement is split by its original paid receipts.
   // No wallet entry is recreated and an already started legacy pass gains no new use.
   if(!used&&!dead&&receipts.length){
    receipts.forEach((receipt,index)=>{
     let target=row;
     if(index){const id=s.Id('ORD');target={...row,id,activatedAt:0,consumedAt:0,legacy:{...original},at:receipt.at};delete target.mergedInto;db.orders[id]=target;}
     target.amount=-receipt.amount;target.at=receipt.at;receipt.legacyOrderId=receipt.reference;receipt.reference=target.id;receipt.uses=1;
    });
   }
   for(const child of linked)if(child!==row)Object.assign(child,{singleUse:true,uses:1,days:0,expiresAt:0});
  }
  for(const row of legacy)if(!row.singleUse)Object.assign(row,{singleUse:true,uses:1,days:0,expiresAt:0,status:'USED',consumedAt:row.activatedAt||Date.now()});
  for(const row of stale){row.status='USED';row.endedAt=Date.now();}
 };
 if(atomic)s.Atomic(apply);else apply();
}
function OwnOrders(p){NormalizeOrders(p);return Object.values(s.DB().orders).filter(x=>x.accountId===p.id&&!x.mergedInto).sort((a,b)=>b.at-a.at||b.id.localeCompare(a.id)).map(PublicOrder);}
function ActiveGames(p){
 if(p.blocked)return [];
 return Object.values(s.DB().orders).filter(row=>row.accountId===p.id&&!row.mergedInto&&((row.consumedAt&&SessionForOrder(row))||(!row.consumedAt&&row.status==='PAID'&&p.activeOrderId===row.id&&row.preparedClientId)))
 .sort((a,b)=>(a.activatedAt||a.at)-(b.activatedAt||b.at)).map(row=>({...PublicOrder(row),genre:s.DB().products[row.productId]?.genre||'게임'}));
}
function ActiveGame(p){return ActiveGames(p).find(row=>row.id===p.activeOrderId)||null;}
function Purchase(p,body){
 const game=Product({id:body.productId}).product,plan=game.plans[0];
 if(body.days!==undefined&&body.days!==0)s.Fail('GAME_PLAN_INVALID');
 if(!plan?.available)s.Fail('GAME_PLAN_UNAVAILABLE');
 if(body.price!==plan.price||body.revision!==game.revision)s.Fail('PRICE_CHANGED');
 if(p.balance<plan.price)s.Fail('INSUFFICIENT_BALANCE');
 NormalizeOrders(p,false);
 const now=Date.now(),id=s.Id('ORD'),row={id,accountId:p.id,productId:game.id,title:game.title,accessType:game.accessType,singleUse:true,uses:1,days:0,amount:plan.price,status:'PAID',at:now,activatedAt:0,consumedAt:0,expiresAt:0,licenseKey:'',source:'WALLET_PURCHASE'};
 s.DB().orders[id]=row;
 Object.assign(s.Ledger(p,-plan.price,'PURCHASE',row.id),{uses:1,days:0,title:game.title,productId:game.id,displayExpiresAt:0});
 return {accountId:p.id,order:PublicOrder(row),profile:s.PublicProfile(p,true),activeGame:ActiveGame(p),activeGames:ActiveGames(p)};
}
function Activate(p,c,body){
 NormalizeOrders(p,false);const order=s.DB().orders[body.orderId];
 if(!order||order.accountId!==p.id||order.mergedInto||order.singleUse!==true)s.Fail('ORDER_NOT_FOUND');
 if(order.status==='REFUNDED')s.Fail('ORDER_REFUNDED');
 if(order.consumedAt||!['PAID','ACTIVE'].includes(order.status))s.Fail('GAME_ALREADY_USED');
 const bound=require('../../license/licenseManager').GetBoundLicenseEntry(c.clientId);if(!bound)s.Fail('MEMBER_AUTH_REQUIRED');
 const ready=SessionForOrder(order);
 if(ready&&order.preparedClientId===c.clientId)return {accountId:p.id,requestedOrderId:order.id,order:PublicOrder(order),activeGame:ActiveGame(p),activeGames:ActiveGames(p),requiresBiometric:false,connectionReady:true};
 p.activeOrderId=order.id;order.preparedClientId=c.clientId;order.preparedAt=Date.now();
 require('./entryPass').Convert(bound.license);state.licenseRevision++;
 return {accountId:p.id,requestedOrderId:order.id,order:PublicOrder(order),activeGame:ActiveGame(p),activeGames:ActiveGames(p),requiresBiometric:true,connectionReady:false};
}
function AfterActivation(c,data){
 // A repeated durable preparation response cannot invalidate a proof already completed.
 const order=s.DB().orders[data?.requestedOrderId],p=order&&s.ProfileById(order.accountId);if(!order||!data?.requiresBiometric||p?.activeOrderId!==order.id||order.consumedAt||SessionForOrder(order))return;
 const stamp=order.id+':'+order.preparedAt;if(c.memberPreparation===stamp)return;c.memberPreparation=stamp;
 require('../buildGate').RevokeForClient(c.clientId,'PURCHASE_SWITCH');
 c.biometricVerified=false;c.buildCompleted=false;c.buildSessionId='';
 require('../../license/licenseManager').AuthorizeBoundClientByQr(c,'PURCHASE');
}
function Start(p,c,body){
 NormalizeOrders(p,false);const order=s.DB().orders[body.orderId];
 if(!order||order.accountId!==p.id||order.mergedInto||order.singleUse!==true)s.Fail('ORDER_NOT_FOUND');
 if(order.status==='REFUNDED')s.Fail('ORDER_REFUNDED');
 const session=SessionForOrder(order);
 if(order.preparedClientId!==c.clientId||!session){if(order.consumedAt||order.status==='USED')s.Fail('GAME_ALREADY_USED');s.Fail('GAME_CONNECTION_REQUIRED');}
 if(order.consumedAt&&order.sessionId!==session.sessionId)s.Fail('GAME_ALREADY_USED');
 if(!order.consumedAt){if(order.status!=='PAID')s.Fail('GAME_ALREADY_USED');order.consumedAt=Date.now();order.activatedAt=order.consumedAt;order.sessionId=session.sessionId;order.status='ACTIVE';}
 p.activeOrderId=order.id;
 return {accountId:p.id,requestedOrderId:order.id,order:PublicOrder(order),activeGame:ActiveGame(p),activeGames:ActiveGames(p),started:true};
}
function StartReply(p,c,receipt){
 const row=s.DB().orders[receipt.requestedOrderId],session=SessionForOrder(row);
 if(!row||row.accountId!==p.id||row.preparedClientId!==c.clientId||!row.consumedAt||!session||session.sessionId!==row.sessionId)s.Fail('GAME_ALREADY_USED');
 return {accountId:p.id,requestedOrderId:row.id,order:PublicOrder(row),activeGame:ActiveGame(p),activeGames:ActiveGames(p),started:true};
}
function SessionEnded(session,reason){
 const row=s.DB().orders[session.orderId];if(!row||!row.consumedAt||row.sessionId!==session.sessionId||row.status!=='ACTIVE')return;
 s.Atomic(()=>{row.status='USED';row.endedAt=Date.now();row.endedReason=String(reason||'SESSION_ENDED');});
}
function Refund(body,actor){
 const requested=s.DB().orders[body.id];if(!requested)s.Fail('ORDER_NOT_FOUND');
 return s.Atomic(()=>{
  const p=s.ProfileById(requested.accountId);NormalizeOrders(p,false);const order=s.DB().orders[body.id];
  if(order.mergedInto)s.Fail('ORDER_NOT_FOUND');if(order.status==='REFUNDED')return PublicOrder(order);
  if(order.consumedAt||order.status==='USED'||order.source==='QR_CHARGE')s.Fail('ACTIVATED_REFUND_REVIEW');
  const reason=s.Text(body.reason,200,true);s.Ledger(p,order.amount,'REFUND',order.id);
  Object.assign(order,{status:'REFUNDED',refundedAt:Date.now(),refundedBy:actor,refundReason:reason});
  return PublicOrder(order);
 });
}
function PurchasePayments(p,normalize=true){
 if(normalize)NormalizeOrders(p);const db=s.DB();
 return Object.values(db.ledger).filter(x=>x.accountId===p.id&&x.kind==='PURCHASE').sort((a,b)=>b.at-a.at).map(x=>{
  const order=ResolveOrder(x.reference),owned=order?.accountId===p.id;
  return {...x,gameKey:GameKey(db.products[x.productId||order?.productId]||x),icon:GameIcon(db.products[x.productId||order?.productId]||x),title:x.title||(owned?order.title:'게임 이용권'),singleUse:true,uses:1,days:0,displayExpiresAt:0,orderId:owned?order.id:'',paymentMethod:'WALLET',source:'WALLET_PURCHASE',order:owned?PublicOrder(order):null,refunded:owned&&order.status==='REFUNDED'};
 });
}
function OwnPostRows(p){return require('./readScope').By('posts','accountId',p.id).filter(x=>!x.deleted&&!x.hidden&&!x.archived).sort((a,b)=>b.at-a.at||b.id.localeCompare(a.id));}
function PublicLedger(row){if(row.kind!=='ADMIN_GRANT')return row;const {actor,reason,requestId,memberHandle,reference,...publicRow}=row;return publicRow;}
function Mine(p,body){
 const orders=OwnOrders(p),db=s.DB(),content=require('./profile-activity').Read(p,p,body);
 return {profile:s.PublicProfile(p,true),...content,activeGame:ActiveGame(p),activeGames:ActiveGames(p),orders:s.Page(orders,body,20),payments:s.Page(body.purchasesOnly===true?PurchasePayments(p):Object.values(db.ledger).filter(x=>x.accountId===p.id).sort((a,b)=>b.at-a.at).map(PublicLedger),body,20)};
}
module.exports={GAMES,GameKey,GameIcon,CatalogRows,EnsureCatalog,PublicGame,Product,Catalog,SaveProduct,Purchase,Activate,AfterActivation,Start,StartReply,SessionEnded,SessionForOrder,NormalizeOrders,Refund,Mine,OwnPostRows,PurchasePayments,PublicOrder,OwnOrders,ActiveGame,ActiveGames};
