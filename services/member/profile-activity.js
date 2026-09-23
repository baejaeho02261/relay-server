'use strict';
const s=require('./store');
function Mode(body={}){const mode=body.activity||(body.commentsOnly===true?'comments':'posts');if(!['posts','comments','reposts','tagged'].includes(mode))s.Fail('INPUT_INVALID');return mode;}
function CanRead(viewer,target){return !!target&&!target.blocked&&!require('./socialActions').Blocked(viewer.id,target.id)&&require('./preferences').CanReadPosts(viewer,target);}
function Visible(viewer,post){const author=post&&s.ProfileById(post.accountId);return !!post&&!post.archived&&require('./socialActions').Visible(post,viewer)&&!!author&&CanRead(viewer,author)&&require('./activity-settings').FeedVisible(viewer,post);}
function HasMedia(post){return !!(post.image||post.gifId||post.gifMedia);}
function Tags(p,body,post,previous=[]){
 if(Object.hasOwn(body,'taggedMemberIds')&&Object.hasOwn(body,'taggedHandles'))s.Fail('PROFILE_TAG_INVALID');
 const input=Object.hasOwn(body,'taggedMemberIds')?body.taggedMemberIds:body.taggedHandles;
 let manual=Array.isArray(post.manualTaggedMemberIds)?post.manualTaggedMemberIds:previous;
 if(input!==undefined){
  if(!Array.isArray(input)||input.length>10||input.some(id=>typeof id!=='string'||id.length>80)||input.length&&!HasMedia(post))s.Fail('PROFILE_TAG_INVALID');
  manual=input.map(id=>{
   const target=s.Resolve(id);if(!require('./mentions').Eligible(p,target)||!require('./preferences').CanReadPosts(target,p))s.Fail('PROFILE_TAG_INVALID');
   return target.id;
  });
  if(new Set(manual).size!==manual.length)s.Fail('PROFILE_TAG_INVALID');
 }
 // Keep old explicit tags separate from inferred inline tags: editing away an
 // @mention must also remove its tagged-gallery entry, without losing manual tags.
 post.manualTaggedMemberIds=HasMedia(post)?[...manual]:[];
 if(!HasMedia(post))return [];
 const inline=require('./mentions').Members(post,p).map(row=>row.id).filter(id=>require('./preferences').CanReadPosts(s.ProfileById(id),p));
 return [...new Set([...post.manualTaggedMemberIds,...inline])].slice(0,10);
}
function PublicTags(post,p){
 const ids=(post.taggedMemberIds||[]).filter(id=>{const target=s.ProfileById(id);return !!target&&!target.blocked&&!require('./socialActions').Blocked(p.id,id)&&!require('./socialActions').Blocked(post.accountId,id);});
 return {taggedMemberIds:ids,taggedMembers:ids.map(id=>{const row=s.ProfileById(id);return {id:row.id,handle:s.Handle(row),nickname:row.nickname,avatar:row.avatarThumb||''};})};
}
function Rows(viewer,target,body={}){
 const mode=Mode(body);if(!CanRead(viewer,target))return [];
 if(mode==='comments')return require('./profiles').CommentRows(viewer,target);
 const db=s.DB(),own=require('./commerce').OwnPostRows(target).filter(post=>Visible(viewer,post));
 if(mode==='posts'){
  const positions=new Map((target.gridOrder||[]).map((id,index)=>[id,index]));
  return own.sort((a,b)=>Number(!!b.pinnedAt)-Number(!!a.pinnedAt)||(b.pinnedAt||0)-(a.pinnedAt||0)||(positions.get(a.id)??Number.MAX_SAFE_INTEGER)-(positions.get(b.id)??Number.MAX_SAFE_INTEGER)||b.at-a.at||b.id.localeCompare(a.id)).map(post=>({post,eventId:post.id,activityKind:post.quotePostId?'quote':'post',activityAt:post.at}));
 }
 if(mode==='tagged')return Object.values(db.posts).filter(post=>!post.archived&&HasMedia(post)&&post.taggedMemberIds?.includes(target.id)&&Visible(viewer,post)&&!require('./socialActions').Blocked(post.accountId,target.id)).sort((a,b)=>b.at-a.at||b.id.localeCompare(a.id)).map(post=>({post,eventId:post.id,activityKind:'tagged',activityAt:post.at}));
 const rows=own.map(post=>({post,eventId:post.id,activityKind:post.quotePostId?'quote':'post',activityAt:post.at}));
 const events=Object.values(db.repostEvents||{}).filter(row=>row.accountId===target.id),recorded=new Set(events.map(row=>row.postId));
 // Existing direct relationships predate the event log. Project one legacy
 // record without rewriting storage on a read; subsequent actions keep history.
 for(const row of Object.values(db.reposts))if(row.accountId===target.id&&!recorded.has(row.postId))events.push(row);
 for(const event of events){const post=db.posts[event.postId];if(Visible(viewer,post))rows.push({post,eventId:event.id,activityKind:'repost',activityAt:event.at});}
 return rows.sort((a,b)=>b.activityAt-a.activityAt||b.eventId.localeCompare(a.eventId));
}
function ProtectQuote(viewer,value){
 if(!value?.quote||value.quote.unavailable)return;
 const source=s.DB().posts[value.quote.id];
 if(!Visible(viewer,source))value.quote={id:value.quote.id,unavailable:true};else ProtectQuote(viewer,value.quote);
}
function Projection(viewer,row,body,small=false){
 const post=row.post,thumb=(!small?require('./media').FeedImage(post):'')||post.imageThumb||post.gifMedia?.frames?.[0]||require('./gifs').Get(post.gifId)?.frames?.[0]||'';
 const value=body.postCards===true?require('./social').PublicPost(post,viewer,false,body._wire==='zlib'):{id:post.id,title:post.title||'',body:(post.title||post.body||'사진 · GIF · 투표').slice(0,140),at:post.at,revision:post.revision||0};
 ProtectQuote(viewer,value);
 return {...value,previewPosition:post.previewPosition||'center',pinned:!!post.pinnedAt,mentionMembers:require('./mentions').Members(post,viewer),imageThumb:thumb,mediaKind:post.gifId||post.gifMedia?'gif':post.image?'photo':'text',quotePostId:post.quotePostId||'',eventId:row.eventId,activityKind:row.activityKind,activityAt:row.activityAt};
}
function Page(viewer,target,body={},max=12){
 const mode=Mode(body);
 if(mode==='comments')return require('./profiles').Comments(viewer,target,body);
 const page=s.Page(Rows(viewer,target,body),body,max);return {...page,items:page.items.map(row=>Projection(viewer,row,body,max>12))};
}
function Read(viewer,target,body={}){
 const mode=Mode(body),page=Page(viewer,target,body),empty={items:[],total:0,nextOffset:null};
 return {activity:mode,posts:mode==='comments'?empty:page,...(mode==='comments'?{comments:page}:{}),...(mode==='reposts'?{reposts:page}:{}),...(mode==='tagged'?{tagged:page}:{})};
}
function Scope(viewer,target,body={}){const mode=Mode(body);return s.Page(Rows(viewer,target,body),body,12).items.map(row=>mode==='comments'?row.id+'/'+(row.revision||0):row.eventId+'/'+(row.post.revision||0));}
module.exports={Mode,Rows,Page,Read,Scope,Tags,PublicTags,CanRead,Visible};
