'use strict';
const s=require('./store'),crypto=require('node:crypto');
const MODES=['followers','following','subscriptions','flagged'];
const SORTS=['default','newest','oldest'],CATEGORIES=['all','low_interaction','frequent_feed'];
function IsFollowing(viewer,target){return !!s.DB().follows[viewer+':'+target];}
function Counts(id){
 let followers=0,following=0;
 for(const row of Object.values(s.DB().follows)){
  if(row.follower!==id&&row.following!==id)continue;
  const from=s.ProfileById(row.follower),to=s.ProfileById(row.following);
  if(!from||!to||from.blocked||to.blocked||require('./socialActions').Blocked(from.id,to.id))continue;
  if(row.following===id)followers++;if(row.follower===id)following++;
 }
 return {followers,following};
}
function Target(p,body){
 const target=(body.handle||body.id)?s.Resolve(body.handle||body.id):p;
 if(!target||target.blocked||require('./socialActions').Blocked(p.id,target.id))s.Fail('MEMBER_NOT_FOUND');
 return target;
}
function Set(p,body){
 const target=s.Resolve(body.handle||body.id);if(!target||target.blocked||require('./socialActions').Blocked(p.id,target.id))s.Fail('MEMBER_NOT_FOUND');
 if(target.id===p.id||typeof body.following!=='boolean')s.Fail('INPUT_INVALID');
 const key=p.id+':'+target.id;
 if(body.following){if(!s.DB().follows[key])s.DB().follows[key]={follower:p.id,following:target.id,at:Date.now()};}
 else delete s.DB().follows[key];
 return {id:target.id,following:IsFollowing(p.id,target.id),counts:Counts(target.id)};
}
function Remove(p,body){
 // Ownership is always the authenticated recipient, never a submitted owner.
 if(Object.keys(body).some(key=>!['id','_wire','_delta'].includes(key))||typeof body.id!=='string')s.Fail('INPUT_INVALID');
 const target=Target(p,body);if(target.id===p.id)s.Fail('INPUT_INVALID');
 const key=target.id+':'+p.id,removed=!!s.DB().follows[key];delete s.DB().follows[key];
 return {id:target.id,removed,following:IsFollowing(p.id,target.id),followsYou:false,counts:Counts(p.id)};
}
function Query(body){
 const mode=body.mode===undefined?'following':body.mode,sort=body.sort===undefined?'default':body.sort,category=body.category===undefined?'all':body.category;
 if(!MODES.includes(mode)||!SORTS.includes(sort)||!CATEGORIES.includes(category))s.Fail('INPUT_INVALID');
 if(category!=='all'&&mode!=='following')s.Fail('INPUT_INVALID');
 const q=require('./people').Query(body.q??body.query),page=require('./people').Page([],body);
 return {mode,q,sort,category,offset:page.offset,limit:body.limit===undefined?12:body.limit};
}
function Edges(p,target,mode){
 const followers=mode==='followers',rows=new Map(),extra=require('./socialActions');
 for(const edge of Object.values(s.DB().follows)){
  if(followers?edge.following!==target.id:edge.follower!==target.id)continue;
  const peer=s.ProfileById(followers?edge.follower:edge.following);
  if(!peer||peer.blocked||extra.Blocked(p.id,peer.id)||extra.Blocked(target.id,peer.id))continue;
  const row={profile:peer,at:Number(edge.at)||0};if(!rows.has(peer.id)||rows.get(peer.id).at<row.at)rows.set(peer.id,row);
 }
 return [...rows.values()];
}
function DateOrder(a,b,sort){return (sort==='oldest'?a.at-b.at:b.at-a.at)||a.profile.id.localeCompare(b.profile.id);}
function CategoryRows(p,following){
 const db=s.DB(),extra=require('./socialActions'),settings=require('./activity-settings'),preferences=require('./preferences');
 const scores=new Map(following.map(row=>[row.profile.id,{interactions:0,posts:0}])),posts=new Map();
 // These rankings use current, readable posts and the viewer's own actions.
 // We do not manufacture impression history or inspect other members' activity.
 for(const post of Object.values(db.posts))if(scores.has(post.accountId)&&extra.Visible(post,p)&&settings.FeedVisible(p,post)&&preferences.CanReadPosts(p,s.ProfileById(post.accountId))){posts.set(post.id,post.accountId);scores.get(post.accountId).posts++;}
 for(const row of Object.values(db.reactions))if(row.accountId===p.id&&row.value===1&&posts.has(row.postId))scores.get(posts.get(row.postId)).interactions++;
 for(const row of Object.values(db.comments))if(row.accountId===p.id&&!row.deleted&&!row.hidden&&posts.has(row.postId))scores.get(posts.get(row.postId)).interactions++;
 const low=[...following].sort((a,b)=>scores.get(a.profile.id).interactions-scores.get(b.profile.id).interactions||DateOrder(a,b,'oldest')).slice(0,50);
 const frequent=following.filter(row=>scores.get(row.profile.id).posts>0).sort((a,b)=>scores.get(b.profile.id).posts-scores.get(a.profile.id).posts||DateOrder(a,b,'newest')).slice(0,50);
 return [
  {id:'low_interaction',title:'교류가 가장 적은 계정',basis:'own_likes_comments',rows:low},
  {id:'frequent_feed',title:'피드에 가장 많이 표시된 계정',basis:'visible_posts',rows:frequent}
 ];
}
function Suggestions(p,followers){
 const seen=new globalThis.Set(followers.map(row=>row.profile.id)),dismissed=new globalThis.Set(p.dismissedPeople||[]),settings=require('./activity-settings');
 return Object.values(s.DB().profiles).filter(peer=>settings.Eligible(p,peer)&&!seen.has(peer.id)&&!dismissed.has(peer.id)&&!IsFollowing(p.id,peer.id)&&!settings.Has(p,'muted',peer.id)&&!settings.Has(p,'restricted',peer.id)).sort((a,b)=>s.Handle(a).localeCompare(s.Handle(b))||a.id.localeCompare(b.id)).slice(0,6);
}
function Stamp(p){return [p.id,s.Handle(p),p.nickname,p.avatarRevision||0,p.profileRevision||0,p.nicknameColor||'',p.titleBadgeId||'',p.titleStyles||null];}
function Snapshot(p,body){
 const query=Query(body),target=Target(p,body),own=target.id===p.id;
 const followers=Edges(p,target,'followers'),following=Edges(p,target,'following');
 const counts={followers:followers.length,following:following.length,subscriptions:0,flagged:0};
 // Member subscriptions and follow-request moderation do not exist yet.
 // Product/game purchases must never be presented as profile subscriptions.
 const categories=own&&query.mode==='following'?CategoryRows(p,following):[];
 let rows=query.mode==='followers'?followers:query.mode==='following'?following:[];
 if(query.category!=='all')rows=categories.find(row=>row.id===query.category)?.rows||[];
 rows=rows.filter(row=>require('./people').Matches(row.profile,query.q));
 if(query.category==='all'||query.sort!=='default')rows.sort((a,b)=>DateOrder(a,b,query.sort));
 const page=require('./people').Page(rows,query),suggestions=own&&query.mode==='followers'&&!query.q&&query.offset===0?Suggestions(p,followers):[];
 const signature={query,target:Stamp(target),own,counts,total:page.total,nextOffset:page.nextOffset,
  rows:page.items.map(row=>[Stamp(row.profile),row.at,IsFollowing(p.id,row.profile.id),IsFollowing(row.profile.id,p.id)]),
  suggestions:suggestions.map(Stamp),categories:categories.map(row=>[row.id,row.rows.map(item=>[Stamp(item.profile),item.at])])};
 const followsTag=crypto.createHash('sha256').update(JSON.stringify(signature)).digest('hex');
 return {query,target,own,counts,page,suggestions,categories,followsTag};
}
function Public(p,target){return {...s.PublicProfile(target,false,p),own:target.id===p.id,isFollowing:target.id!==p.id&&IsFollowing(p.id,target.id),followsYou:target.id!==p.id&&IsFollowing(target.id,p.id)};}
function Project(p,state){
 const {query,target,own,counts,page,suggestions,categories,followsTag}=state;
 return {...page,...query,profile:Public(p,target),own,counts,followsTag,
  items:page.items.map(row=>({...Public(p,row.profile),followedAt:row.at})),suggestions:suggestions.map(peer=>Public(p,peer)),
  categories:categories.map(row=>({id:row.id,title:row.title,basis:row.basis,count:row.rows.length,
   description:row.rows.length?s.Handle(row.rows[0].profile)+'님'+(row.rows.length>1?' 외 '+(row.rows.length-1)+'명':''):'',
   items:row.rows.slice(0,2).map(item=>Public(p,item.profile))}))};
}
function List(p,body={}){return Project(p,Snapshot(p,body));}
function Live(p,body={}){
 if(body.knownFollowsTag!==undefined&&(typeof body.knownFollowsTag!=='string'||body.knownFollowsTag.length>64))s.Fail('INPUT_INVALID');
 const state=Snapshot(p,body.query||{});
 return {followsTag:state.followsTag,...(body.knownFollowsTag===state.followsTag?{}:{followsPage:Project(p,state)})};
}
module.exports={IsFollowing,Counts,Set,Remove,List,Live};
