'use strict';
// Home is a bounded projection of existing services. Opening or refreshing it
// must not read articles, create views, normalize passes, or award a badge.
const s=require('./store'),social=require('./social'),extra=require('./socialActions');
const LIMIT=3;
const short=(value,max=120)=>[...String(value||'').replace(/\s+/gu,' ').trim()].slice(0,max).join('');
const latest=rows=>rows.sort((a,b)=>(b.at||b.updatedAt||0)-(a.at||a.updatedAt||0)||String(b.id).localeCompare(String(a.id)));
function SmallPhoto(row){
 const image=row?.imageThumb||'';
 return typeof image==='string'&&image.length<=24000&&/^data:image\/(png|jpeg);base64,/.test(image)?image:'';
}
function Read(p){
 const db=s.DB(),commerce=require('./commerce'),rewards=require('./rewards'),history=require('./history'),prefs=require('./preferences');
 const visibleNews=social.NewsRows(p),visiblePosts=social.FeedRows(p,{sort:'latest'});
 const products=Object.values(db.products).filter(x=>x.published&&!x.deleted).sort((a,b)=>(a.sort||0)-(b.sort||0)||(b.updatedAt||0)-(a.updatedAt||0));
 // Do not call Mine/OwnOrders: those functions intentionally merge legacy
 // passes. A dashboard refresh is not an authorization to modify entitlements.
 const orders=latest(Object.values(db.orders).filter(x=>x.accountId===p.id&&!x.mergedInto));
 const payments=commerce.PurchasePayments(p),points=latest(Object.values(db.pointLedger).filter(x=>x.accountId===p.id));
 const recent=history.Read(p);
 const recentProducts=recent.recentProducts.slice(0,LIMIT).map(row=>({id:row.id,title:short(row.title,70),genre:short(row.genre,50),at:row.at,imageThumb:SmallPhoto(db.products[row.id])}));
 const recentServices=recent.recentServices.slice(0,LIMIT);
 const conversations=Object.values(db.directThreads).filter(row=>!row.deletedAt&&row.members.includes(p.id)&&row.members.every(id=>{const peer=s.ProfileById(id);return peer&&!peer.blocked&&!extra.Blocked(p.id,id);}));
 const messageCount=conversations.filter(row=>row.pendingTo!==p.id).length,requestCount=conversations.filter(row=>row.pendingTo===p.id).length;
 const unreadCount=conversations.reduce((sum,row)=>sum+Math.max(0,(row.received?.[p.id]||0)-(row.readReceived?.[p.id]||0)),0);
 const purchases=latest(Object.values(db.orders).filter(row=>{const owner=s.ProfileById(row.accountId),game=db.products[row.productId];return row.source!=='QR_CHARGE'&&row.status!=='REFUNDED'&&!row.mergedInto&&row.amount>0&&game?.published&&!game.deleted&&owner&&!owner.blocked&&!extra.Blocked(p.id,owner.id)&&prefs.Read(owner).purchaseActivityVisible;}));
 const notifications=require('./notifications').Read(p,{limit:1});
 const activeGames=commerce.ActiveGames(p);
 return {
  wallet:require('./arcade').Wallet(p),attendance:rewards.Attendance(p),
  counts:{news:visibleNews.length,unreadNews:social.UnreadNewsCount(p),catalog:products.length,feed:visiblePosts.length,orders:orders.length,payments:payments.length,pointHistory:points.length,notifications:notifications.total,messages:messageCount,requests:requestCount,unreadMessages:unreadCount,...require('./follows').Counts(p.id)},
  news:visibleNews.slice(0,LIMIT).map(row=>({...social.PublicNews(row,true),views:s.ViewCount('news',row.id),unread:(p.readNews?.[row.id]||((p.readNewsAt||0)>=row.at?(row.revision||1):0))<(row.revision||1)})),
  catalog:products.slice(0,LIMIT).map(row=>({id:row.id,title:short(row.title,70),genre:short(row.genre||row.details?.genre||'게임',50),imageThumb:SmallPhoto(row)})),
  orders:orders.slice(0,LIMIT).map(row=>{const item=commerce.PublicOrder(row);return {id:item.id,title:short(item.title,70),days:item.days,status:item.status,at:item.at,displayExpiresAt:item.displayExpiresAt};}),
  payments:payments.slice(0,LIMIT).map(row=>({id:row.id,title:short(row.title,70),days:row.days,amount:row.amount,at:row.at,displayExpiresAt:row.displayExpiresAt,refunded:row.refunded})),
  pointHistory:points.slice(0,LIMIT).map(row=>({id:row.id,kind:row.kind,amount:row.amount,at:row.at})),
  feed:visiblePosts.slice(0,2).map(row=>({id:row.id,title:short(row.title||row.body||'사진 · 투표 게시글',90),summary:short(row.title?row.body:'',120),at:row.at,authorName:short(s.ProfileById(row.accountId)?.nickname||'회원',24)})),
  recentProducts,recentServices,
  purchases:purchases.slice(0,LIMIT).map(row=>({title:short(row.title||db.products[row.productId]?.title,70),memberName:short(s.ProfileById(row.accountId)?.nickname,24),at:row.at,productId:row.productId})),
  topGames:require('./topGames').RankedPurchases().slice(0,LIMIT).map((row,index)=>({id:row.id,title:short(row.title,70),rank:index+1,imageThumb:SmallPhoto(db.products[row.id])})),
  activeGame:commerce.ActiveGame(p),activeGames,runningGames:activeGames.slice(0,12),
  events:{spins:p.eventSpins||0,wheelEnabled:rewards.Rules().enabled},
 };
}
module.exports={Read,LIMIT};
