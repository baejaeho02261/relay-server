'use strict';
// Home is a bounded, viewer-authorized projection. Refreshing it does not
// mark content read, count a view, normalize passes, or award a reward.
const s=require('./store'),social=require('./social'),extra=require('./socialActions');
const LIMIT=3,POPULAR_LIMIT=5,COMMENT_LIMIT=5,RANKING_LIMIT=5;
const short=(value,max=120)=>[...String(value||'').replace(/\s+/gu,' ').trim()].slice(0,max).join('');
const latest=rows=>rows.sort((a,b)=>(b.at||b.updatedAt||0)-(a.at||a.updatedAt||0)||String(b.id).localeCompare(String(a.id)));
function OnlineCount(){
 const ids=new Set(),state=require('../../core/state');
 for(const client of state.clients.values()){
  if(!client.connected||!client.deviceAuthVerified||!client.socket||client.socket.destroyed)continue;
  // Never call Account here: displaying a count must not create a member.
  let subject;try{subject=s.Subject(client);}catch(_){continue;}
  const profile=s.DB().profiles[subject];if(profile&&!profile.blocked)ids.add(profile.id);
 }
 return ids.size;
}
function Read(p){
 const db=s.DB(),commerce=require('./commerce'),rewards=require('./rewards'),history=require('./history'),prefs=require('./preferences');
 const visibleNews=social.NewsRows(p),visiblePosts=social.FeedRows(p,{sort:'popular'}),visiblePostIds=new Set(visiblePosts.map(row=>row.id));
 const products=commerce.CatalogRows(),productIds=new Set(products.map(row=>row.id));
 const product=(id)=>products.find(row=>row.id===id)||db.products[id];
 const gameIdentity=row=>({gameKey:commerce.GameKey(product(row.productId||row.id)||row),icon:commerce.GameIcon(product(row.productId||row.id)||row)});
 // Do not call Mine/OwnOrders: these intentionally merge legacy passes.
 const orders=latest(Object.values(db.orders).filter(x=>x.accountId===p.id&&!x.mergedInto));
 const payments=commerce.PurchasePayments(p),points=latest(Object.values(db.pointLedger).filter(x=>x.accountId===p.id));
 const recent=history.Read(p),today=rewards.Day(Date.now());
 const recentProducts=recent.recentProducts.filter(row=>productIds.has(row.id)).slice(0,LIMIT).map(row=>({...commerce.PublicGame(product(row.id)),viewedAt:row.at}));
 const recentServices=recent.recentServices.slice(0,LIMIT);
 const conversations=Object.values(db.directThreads).filter(row=>!row.deletedAt&&row.members.includes(p.id)&&row.members.every(id=>{const peer=s.ProfileById(id);return peer&&!peer.blocked&&!extra.Blocked(p.id,id);}));
 const messageCount=conversations.filter(row=>row.pendingTo!==p.id).length,requestCount=conversations.filter(row=>row.pendingTo===p.id).length;
 const unreadCount=conversations.reduce((sum,row)=>sum+Math.max(0,(row.received?.[p.id]||0)-(row.readReceived?.[p.id]||0)),0);
 const purchases=latest(Object.values(db.orders).filter(row=>{const owner=s.ProfileById(row.accountId);return row.source!=='QR_CHARGE'&&row.status!=='REFUNDED'&&!row.mergedInto&&row.amount>0&&productIds.has(row.productId)&&owner&&!owner.blocked&&!extra.Blocked(p.id,owner.id)&&prefs.Read(owner).purchaseActivityVisible;}));
 const visibleComments=latest(Object.values(db.comments).filter(row=>!row.deleted&&!row.hidden&&visiblePostIds.has(row.postId)&&!extra.Blocked(p.id,row.accountId)&&!s.ProfileById(row.accountId)?.blocked&&require('./activity-settings').CommentVisible(p,row)));
 const attendanceRanking=Object.values(db.profiles).filter(row=>!row.blocked&&!extra.Blocked(p.id,row.id)).map(row=>({nickname:short(row.nickname,24),streak:rewards.Attendance(row).streak,at:row.attendance?.at||0,id:row.id})).filter(row=>row.streak>0).sort((a,b)=>b.streak-a.streak||a.at-b.at||a.id.localeCompare(b.id)).slice(0,RANKING_LIMIT).map((row,index)=>({rank:index+1,nickname:row.nickname,streak:row.streak}));
 const notifications=require('./notifications').Read(p,{limit:1}),activeGames=commerce.ActiveGames(p);
 return {
  wallet:require('./wallet').Read(p),attendance:rewards.Attendance(p),attendanceRanking,
  counts:{online:OnlineCount(),todayPosts:visiblePosts.filter(row=>rewards.Day(row.at)===today).length,todayComments:visibleComments.filter(row=>rewards.Day(row.at)===today).length,news:visibleNews.length,unreadNews:social.UnreadNewsCount(p),catalog:products.length,feed:visiblePosts.length,orders:orders.length,payments:payments.length,pointHistory:points.length,notifications:notifications.total,messages:messageCount,requests:requestCount,unreadMessages:unreadCount,...require('./follows').Counts(p.id)},
  news:visibleNews.slice(0,LIMIT).map(row=>({...social.PublicNews(row,true),views:s.ViewCount('news',row.id),unread:(p.readNews?.[row.id]||((p.readNewsAt||0)>=row.at?(row.revision||1):0))<(row.revision||1)})),
  catalog:products.slice(0,LIMIT).map(row=>commerce.PublicGame(row)),
  orders:orders.slice(0,LIMIT).map(row=>{const item=commerce.PublicOrder(row);return {id:item.id,productId:item.productId,title:short(item.title,70),days:item.days,status:item.status,at:item.at,...gameIdentity(row)};}),
  payments:payments.slice(0,LIMIT).map(row=>({id:row.id,productId:row.productId,title:short(row.title,70),days:row.days,amount:row.amount,at:row.at,refunded:row.refunded,...gameIdentity(row)})),
  pointHistory:points.slice(0,LIMIT).map(row=>({id:row.id,kind:row.kind,amount:row.amount,at:row.at})),
  // The expanded row uses the actual feed renderer and the exact same privacy
  // projection, including polls/media/mentions/reposts and action counts.
  feed:visiblePosts.slice(0,POPULAR_LIMIT).map((row,index)=>({...social.PublicPost(row,p,false,true),rank:index+1})),
  recentComments:visibleComments.slice(0,COMMENT_LIMIT).map(row=>extra.PublicComment(row,p)),recentProducts,recentServices,
  purchases:purchases.slice(0,LIMIT).map(row=>({id:row.id,title:short(row.title||product(row.productId)?.title,70),member:s.PublicProfile(s.ProfileById(row.accountId),false,p),at:row.at,productId:row.productId})),
  topGames:require('./topGames').RankedPurchases().filter(row=>productIds.has(row.id)).slice(0,LIMIT).map((row,index)=>({id:row.id,title:short(row.title,70),rank:index+1,...gameIdentity(row)})),
  activeGame:commerce.ActiveGame(p),activeGames,runningGames:activeGames.slice(0,12),
  events:{spins:p.eventSpins||0,wheelEnabled:rewards.Rules().enabled},
 };
}
module.exports={Read,LIMIT,POPULAR_LIMIT,COMMENT_LIMIT,RANKING_LIMIT,OnlineCount};
