'use strict';
const s=require('./store');
const audiences=['PUBLIC','CLOSE_FRIENDS','FOLLOWERS','PRIVATE'];
const booleans=['hideLikeCounts','hideShareCounts','commentsDisabled','archived','pinned'];
function Audience(value){if(!audiences.includes(value))s.Fail('INPUT_INVALID');return value;}
function CanRead(post,viewer){
 const owner=s.ProfileById(post.accountId);if(!owner||owner.blocked)return false;
 if(viewer?.id===owner.id)return true;
 if(post.archived||!viewer||!require('./preferences').CanReadPosts(viewer,owner))return false;
 const audience=post.audience||'PUBLIC';
 return audience==='PUBLIC'||audience==='CLOSE_FRIENDS'&&require('./activity-settings').Has(owner,'closeFriends',viewer.id)||audience==='FOLLOWERS'&&require('./follows').IsFollowing(viewer.id,owner.id);
}
function Counts(post,p){const settings=require('./activity-settings').Values(p);return {hideLikeCounts:settings.hideLikeCounts||post.hideLikeCounts===true,hideShareCounts:settings.hideShareCounts||post.hideShareCounts===true};}
function AudienceLabel(post,p){
 const audience=post.audience||'PUBLIC',profile=['PUBLIC','FOLLOWING','PRIVATE','CLOSE_FRIENDS'].includes(p.profilePostsVisibility)?p.profilePostsVisibility:p.profilePostsPrivate===true?'PRIVATE':'PUBLIC';
 if(audience==='PRIVATE'||profile==='PRIVATE')return '나만 보기';
 if(audience!=='PUBLIC'&&profile!=='PUBLIC'&&audience!==profile)return '제한된 공개';
 return ({PUBLIC:'전체 공개',CLOSE_FRIENDS:'친한 친구만',FOLLOWERS:'팔로워만',FOLLOWING:'내가 팔로우하는 회원'})[audience==='PUBLIC'?profile:audience]||'제한된 공개';
}
function Public(post,p){
 const own=post.accountId===p.id;
 return {...Counts(post,p),commentsDisabled:post.commentsDisabled===true,archived:post.archived===true,pinned:!!post.pinnedAt,previewPosition:['top','center','bottom'].includes(post.previewPosition)?post.previewPosition:'center',...(own?{audience:post.audience||'PUBLIC',audienceLabel:AudienceLabel(post,p),ownHideLikeCounts:post.hideLikeCounts===true,ownHideShareCounts:post.hideShareCounts===true}:{}),shares:Counts(post,p).hideShareCounts?null:ShareCount(post)};
}
function Owned(p,id){const post=s.DB().posts[id];if(!post||post.deleted||post.hidden)s.Fail('POST_NOT_FOUND');if(post.accountId!==p.id)s.Fail('NOT_OWNER');return post;}
function Settings(p,body={}){
 const post=Owned(p,body.id),keys=Object.keys(body).filter(key=>!key.startsWith('_')&&!['id','revision'].includes(key));
 if(!keys.length||keys.some(key=>![...booleans,'audience','previewPosition'].includes(key)))s.Fail('INPUT_INVALID');
 if(!Number.isSafeInteger(body.revision)||body.revision!==(post.revision||0))s.Fail('CONTENT_CHANGED');
 for(const key of booleans)if(Object.hasOwn(body,key)&&typeof body[key]!=='boolean')s.Fail('INPUT_INVALID');
 if(Object.hasOwn(body,'audience'))Audience(body.audience);
 if(Object.hasOwn(body,'previewPosition')&&(!['top','center','bottom'].includes(body.previewPosition)||!(post.image||post.gifId||post.gifMedia)))s.Fail('INPUT_INVALID');
 if(body.pinned===true){if(body.archived===true||post.archived&&body.archived!==false)s.Fail('POST_ARCHIVED');const pins=Object.values(s.DB().posts).filter(row=>row.accountId===p.id&&!row.deleted&&!row.hidden&&!row.archived&&row.pinnedAt&&row.id!==post.id);if(pins.length>=3)s.Fail('POST_PIN_LIMIT');}
 for(const key of keys)if(key!=='pinned')post[key]=body[key];
 if(Object.hasOwn(body,'pinned'))post.pinnedAt=body.pinned?(post.pinnedAt||Date.now()):0;
 if(post.archived)post.pinnedAt=0;
 post.revision=(post.revision||0)+1;post.updatedAt=Date.now();
 return {post:require('./social').PublicPost(post,p,false,body._wire==='zlib')};
}
function Archives(p,body={}){const page=require('./people').Page(Object.values(s.DB().posts).filter(post=>post.accountId===p.id&&post.archived&&!post.deleted&&!post.hidden).sort((a,b)=>b.updatedAt-a.updatedAt||b.at-a.at||b.id.localeCompare(a.id)),body);return {...page,items:page.items.map(post=>require('./social').PublicPost(post,p,false,body._wire==='zlib'))};}
function ShareCount(post){return Object.values(s.DB().postShares||{}).filter(row=>row.postId===post.id).length;}
function Insights(p,body={}){
 const post=Owned(p,body.id),db=s.DB(),active=id=>{const member=s.ProfileById(id);return member&&!member.blocked;};
 return {insights:{id:post.id,views:s.ViewCount('post',post.id),likes:Object.values(db.reactions).filter(row=>row.postId===post.id&&row.value===1&&active(row.accountId)).length,comments:Object.values(db.comments).filter(row=>row.postId===post.id&&!row.deleted&&!row.hidden&&active(row.accountId)).length,reposts:Object.values(db.reposts).filter(row=>row.postId===post.id&&active(row.accountId)).length+Object.values(db.posts).filter(row=>row.quotePostId===post.id&&!row.deleted&&!row.hidden&&!row.archived&&active(row.accountId)).length,shares:ShareCount(post)}};
}
function MayShare(p,post,target){return require('./activity-settings').Eligible(p,target)&&require('./socialActions').Visible(post,target)&&require('./activity-settings').CanInteract(target,p,'message','게시글을 공유했습니다.');}
function Shareable(p,id){const post=require('./socialActions').Post(p,id);if(post.archived)s.Fail('POST_ARCHIVED');if(post.accountId!==p.id&&!require('./activity-settings').Values(s.ProfileById(post.accountId)).allowRepost)s.Fail('REPOST_UNAVAILABLE');return post;}
function Recipients(p,body={}){
 const post=Shareable(p,body.id),people=require('./people'),q=people.Query(body.q),rows=Object.values(s.DB().profiles).filter(target=>MayShare(p,post,target)&&people.Matches(target,q));
 rows.sort((a,b)=>Number(require('./follows').IsFollowing(p.id,b.id))-Number(require('./follows').IsFollowing(p.id,a.id))||s.Handle(a).localeCompare(s.Handle(b)));
 const page=people.Page(rows,body);return {...page,postId:post.id,q,query:String(body.q||'').trim(),limit:body.limit||12,hasMore:page.nextOffset!==null,items:page.items.map(target=>people.Public(p,target))};
}
function Share(p,body={}){
 const post=Shareable(p,body.id),target=s.Resolve(body.memberId);if(!MayShare(p,post,target))s.Fail('POST_SHARE_UNAVAILABLE');
 const dm=require('./direct-messages'),opened=dm.Open(p,{memberId:target.id}),receipt=dm.Send(p,{id:opened.id,text:'게시글을 공유했습니다.'}),row=s.DB().directThreads[opened.id].messages.at(-1);
 row.sharedPostId=post.id;row.text='게시글을 공유했습니다.';row.mentions=[];
 s.DB().postShares[receipt.sentMessageId]={id:receipt.sentMessageId,postId:post.id,accountId:p.id,at:row.at};
 // Receipts contain no recipient, title, body, image or conversation snapshot.
 return {...receipt,postId:post.id};
}
function Shared(postId,p,compact=false,sharp=false){
 const post=s.DB().posts[postId];if(!require('./socialActions').Visible(post,p)||post.archived)return {id:postId,unavailable:true};
 // Inbox rows only need a safe identifier. The opened thread receives the
 // complete canonical feed projection, with fresh audience/block checks for
 // this viewer (including quoted posts, mentions, counters, polls and media).
 if(compact)return {id:post.id};
 return require('./social').PublicPost(post,p,false,sharp);
}
function ProjectShare(p,receipt){const result=require('./direct-messages').Project(p,'post.share',receipt),post=s.DB().posts[receipt.postId];return {...result,...(require('./socialActions').Visible(post,p)?{post:require('./social').PublicPost(post,p,false,false,true)}:{postUnavailable:true})};}
function FilterProjection(value,viewer){
 if(!value||typeof value!=='object')return value;
 if(Array.isArray(value))return value.map(row=>FilterProjection(row,viewer));
 const post=s.DB().posts[value.id],comment=s.DB().comments[value.id];
 if(post&&['body','title','own','myReaction','comments'].some(key=>Object.hasOwn(value,key))&&!require('./socialActions').Visible(post,viewer))return {id:post.id,unavailable:true};
 if(comment&&Object.hasOwn(value,'body')&&(!require('./socialActions').Visible(s.DB().posts[comment.postId],viewer)||!require('./commentThreads').Visible(comment,viewer)))return {id:comment.id,postId:comment.postId,unavailable:true};
 const copy=Object.fromEntries(Object.entries(value).map(([key,item])=>[key,FilterProjection(item,viewer)]));
 if(post&&Object.hasOwn(copy,'likes')){const visibility=Counts(post,viewer);if(visibility.hideLikeCounts){copy.hideLikeCounts=true;copy.likes=null;}if(visibility.hideShareCounts){copy.hideShareCounts=true;if(Object.hasOwn(copy,'shares'))copy.shares=null;if(Object.hasOwn(copy,'reposts'))copy.reposts=null;}}
 return copy;
}
module.exports={FilterProjection,Audience,CanRead,Counts,Public,Settings,Archives,Insights,Recipients,Share,Shared,ProjectShare};
