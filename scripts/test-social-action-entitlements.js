'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-social-shop-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),api=require('../services/member/service'),shop=require('../services/member/customization'),db=require('../storage/database');
const ids=['COMMENT_TICKET','REPOST_TICKET','SHARE_TICKET'],keys=['commentTickets','repostTickets','shareTickets'];
function client(n){const id=String(n).padStart(16,'0'),key='SOCIAL-SHOP-'+n,c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:true,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-'+id,socket:{destroyed:false,write(){return true;}}};state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));c.licenseKey=require('../license/licenseManager').CreateLicense(900,'출입증',['QR'],'QR').key;state.licenses.get(c.licenseKey).boundClient=id;s.Atomic(()=>require('./helpers/member-identity-fixture')(c,n%2?'kakao':'google'));return c;}
let serial=0;const run=(c,action,body={},requestId)=>api.Execute(c,requestId||'SOCIAL-SHOP-'+(++serial),action,body),p=c=>s.Account(c);
const snapshot=()=>JSON.stringify(s.DB());
function rejects(c,action,body,reason){const before=snapshot();assert.throws(()=>run(c,action,body),reason);assert.equal(snapshot(),before,'rejection must roll back inventory, content, receipts, rate state and ledger');}
function resetRates(c){s.Atomic(()=>{p(c).last_post=0;p(c).last_comment=0;});}
function buy(c,id,requestId){return run(c,'shop.purchase',{itemId:id,revision:shop.Rules().revision},requestId);}
try{
 require('../services/member/commerce').EnsureCatalog();const a=client(761),b=client(762),third=client(763);run(a,'me');run(b,'me');run(third,'me');
 s.Atomic(()=>{p(a).points=10000;p(b).points=10000;p(third).points=10000;});
 const mine=run(a,'post.create',{body:'내 게시글'}).post,peer=run(b,'post.create',{body:'다른 회원 게시글'}).post;
 const inventory=run(a,'shop');for(let i=0;i<3;i++){assert.equal(inventory.inventory[keys[i]],0);assert.equal(inventory.items.find(x=>x.id===ids[i]).enabled,false);rejects(a,'shop.purchase',{itemId:ids[i],revision:1},/SHOP_UNAVAILABLE/);}
 const offers=Object.fromEntries(shop.Items().map(id=>[id,{enabled:true,price:id==='COMMENT_TICKET'?11:id==='REPOST_TICKET'?13:id==='SHARE_TICKET'?17:19}]));
 api.AdminWrite('shop.save',{revision:shop.Rules().revision,items:offers},'TEST');
 rejects(a,'comment.create',{postId:peer.id,body:'안녕'},/COMMENT_TICKET_REQUIRED/);
 rejects(a,'repost.set',{postId:peer.id,value:true},/REPOST_TICKET_REQUIRED/);
 rejects(a,'post.share',{id:mine.id,memberId:p(b).id},/SHARE_TICKET_REQUIRED/);
 resetRates(a);rejects(a,'post.create',{quotePostId:peer.id,body:'인용'},/REPOST_TICKET_REQUIRED/);
 rejects(a,'post.edit',{id:mine.id,revision:mine.revision,body:'인용 변경',quotePostId:peer.id},/REPOST_TICKET_REQUIRED/);
 // Server products determine the count and debit; clients cannot multiply inventory.
 const start=p(a).points,first=buy(a,'COMMENT_TICKET','SOCIAL-PURCHASE-RETRY');assert.equal(first.inventory.commentTickets,1);assert.equal(first.inventoryAccountId,p(a).id);assert.equal(first.inventoryRevision,s.DB().revision);assert.equal(p(a).points,start-11);
 assert.equal(buy(a,'COMMENT_TICKET','SOCIAL-PURCHASE-RETRY').purchase.id,first.purchase.id);assert.equal(p(a).points,start-11);assert.equal(p(a).inventory.commentTickets,1);
 const commentBody={postId:peer.id,body:'구매한 첫 댓글'},comment=run(a,'comment.create',commentBody,'SOCIAL-COMMENT-RETRY');assert.equal(comment.inventory.commentTickets,0);assert.equal(comment.comment.body,commentBody.body);
 assert.equal(run(a,'comment.create',commentBody,'SOCIAL-COMMENT-RETRY').comment.id,comment.comment.id);assert.equal(Object.values(s.DB().comments).length,1);
 buy(a,'COMMENT_TICKET');assert.equal(run(a,'comment.create',commentBody,'SOCIAL-COMMENT-RETRY').inventory.commentTickets,1,'receipt projection uses current inventory without consuming another ticket');
 resetRates(a);const ownComment=run(a,'comment.create',{postId:mine.id,body:'내 글 댓글'});assert.equal(ownComment.comment.own,true);assert.equal(ownComment.inventory.commentTickets,0);
 assert.equal(run(a,'thread',{postId:peer.id,countView:false}).comments.items.length,1,'comments remain readable without a ticket');
 buy(a,'COMMENT_TICKET');resetRates(a);run(b,'post.settings',{id:peer.id,revision:s.DB().posts[peer.id].revision||0,commentsDisabled:true});rejects(a,'comment.create',{postId:peer.id,body:'금지'},/COMMENTS_DISABLED/);assert.equal(p(a).inventory.commentTickets,1);
 run(b,'post.settings',{id:peer.id,revision:s.DB().posts[peer.id].revision,commentsDisabled:false});
 rejects(a,'comment.create',{postId:peer.id,body:' ',quantity:999},/INPUT_INVALID/);assert.equal(p(a).inventory.commentTickets,1);
 buy(a,'REPOST_TICKET');const repost=run(a,'repost.set',{postId:peer.id,value:true},'SOCIAL-REPOST-RETRY'),at=s.DB().reposts[p(a).id+':'+peer.id].at;assert.equal(repost.inventory.repostTickets,0);assert.equal(run(a,'feed').items[0].id,peer.id);
 assert.equal(run(a,'repost.set',{postId:peer.id,value:true},'SOCIAL-REPOST-RETRY').post.id,peer.id);assert.equal(s.DB().reposts[p(a).id+':'+peer.id].at,at);assert.equal(Object.values(s.DB().repostEvents).length,1);
 rejects(a,'repost.set',{postId:peer.id,value:true},/REPOST_TICKET_REQUIRED/);
 run(a,'repost.set',{postId:peer.id,value:false});assert.equal(p(a).inventory.repostTickets,0,'withdrawing a repost never mints a refund');
 buy(a,'REPOST_TICKET');run(a,'repost.set',{postId:mine.id,value:true});assert.equal(p(a).inventory.repostTickets,0,'own repost also consumes one');
 buy(a,'REPOST_TICKET');resetRates(a);const quote=run(a,'post.create',{quotePostId:peer.id,body:'정상 인용'}).post;assert.equal(p(a).inventory.repostTickets,0);
 run(a,'post.edit',{id:quote.id,revision:quote.revision,quotePostId:peer.id,body:'같은 인용 글 수정'});assert.equal(p(a).inventory.repostTickets,0,'editing unchanged quote does not charge again');
 buy(a,'SHARE_TICKET');const shareBody={id:mine.id,memberId:p(b).id},shared=run(a,'post.share',shareBody,'SOCIAL-SHARE-RETRY');assert.equal(shared.inventory.shareTickets,0);assert.equal(shared.messages.at(-1).sharedPost.id,mine.id);
 assert.equal(run(a,'post.share',shareBody,'SOCIAL-SHARE-RETRY').messages.length,1);assert.equal(Object.values(s.DB().postShares).length,1);
 rejects(a,'post.share',shareBody,/SHARE_TICKET_REQUIRED/);
 buy(a,'SHARE_TICKET');run(a,'post.share',{id:peer.id,memberId:p(third).id});assert.equal(p(a).inventory.shareTickets,0,'peer post can be delivered to another permitted reader');
 // Privacy remains authoritative despite ownership of a ticket.
 buy(a,'REPOST_TICKET');buy(a,'SHARE_TICKET');run(b,'activity.settings.save',{allowRepost:false});rejects(a,'repost.set',{postId:peer.id,value:true},/REPOST_UNAVAILABLE/);rejects(a,'post.share',{id:peer.id,memberId:p(third).id},/REPOST_UNAVAILABLE/);
 run(b,'activity.settings.save',{allowRepost:true});run(b,'block.set',{id:p(a).id,blocked:true});rejects(a,'comment.create',{postId:peer.id,body:'차단'},/POST_NOT_FOUND/);rejects(a,'post.share',{id:mine.id,memberId:p(b).id},/POST_SHARE_UNAVAILABLE/);run(b,'block.set',{id:p(a).id,blocked:false});
 resetRates(b);const privatePost=run(b,'post.create',{audience:'PRIVATE',body:'비밀'}).post;rejects(a,'repost.set',{postId:privatePost.id,value:true},/POST_NOT_FOUND/);
 // Failed storage cannot debit a use or create a comment/message/repost/purchase.
 for(const [action,body]of [['comment.create',{postId:peer.id,body:'롤백'}],['repost.set',{postId:peer.id,value:true}],['post.share',{id:mine.id,memberId:p(b).id}],['shop.purchase',{itemId:'COMMENT_TICKET',revision:shop.Rules().revision}]]){
  resetRates(a);const before=snapshot(),save=db.SaveDatabase;db.SaveDatabase=()=>false;try{assert.throws(()=>run(a,action,body),/STORAGE_SAVE_FAILED/);}finally{db.SaveDatabase=save;}assert.equal(snapshot(),before,action+' rollback');
 }
 const savedPoints=p(a).points,savedInventory=structuredClone(p(a).inventory),savedUses=structuredClone(s.DB().socialUses);assert.equal(db.SaveDatabase(),true);db.LoadDatabase();assert.equal(p(a).points,savedPoints);assert.deepEqual(p(a).inventory,savedInventory);assert.deepEqual(s.DB().socialUses,savedUses);
 const author=run(b,'feed').items.find(x=>x.id===mine.id).author;assert.equal(author.accountProvider,'kakao');assert.equal(author.accountLinked,true);assert.equal(author.accountVerified,true);assert.equal(author.accountEmail,undefined);
 assert.equal(run(b,'live',{profiles:[p(a).id]}).profiles[0].accountVerified,true);
 const oauth=require('../services/member/oauthIdentity'),realNow=Date.now;Date.now=()=>realNow()+16*60*1000;try{assert.equal(oauth.Public(p(a)).accountVerified,false,'stale provider proof is not a verified badge');assert.equal(oauth.Public(p(a)).accountLinked,true);}finally{Date.now=realNow;}
 oauth.RevokeAccount(p(a).id);const revoked=run(b,'member',{id:p(a).id}).profile;assert.equal(revoked.accountVerified,false);assert.equal(revoked.accountLinked,false);assert.equal(revoked.accountEmail,undefined);
 assert.equal(run(b,'live',{profiles:[p(a).id]}).profiles[0].accountVerified,false,'linked-provider markers refresh after unlink');
 assert.ok(Object.values(s.DB().socialUses).every(row=>['COMMENT','REPOST','SHARE'].includes(row.kind)&&row.postId&&row.reference));
 console.log('Social action entitlements PASS ('+process.env.STORAGE_ENGINE+'): administrator prices, real actions on own/peer posts, quote paths, exact use/purchase retry, live inventory, privacy checks, atomic rollback, durable balances/audit, provider proof and public-email privacy.');
}finally{require('../services/member/oauthIdentity').StopMonitor();fs.rmSync(dir,{recursive:true,force:true});}
