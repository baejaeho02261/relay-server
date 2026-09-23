'use strict';
// Native/server query and lifetime checks. This is not a Delphi compilation.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(root,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const flow=read('MoaPlayApp.Member.Flow.inc'),live=read('MoaPlayApp.Member.Live.inc'),dashboard=read('MoaPlayApp.Dashboard.inc');
const extract=(s,re)=>{const m=s.match(re);assert.ok(m,String(re));return m[1];};
const HubText=(o,k,f='')=>typeof o?.[k]==='string'?o[k]:f,HubNumber=(o,k)=>Number(o?.[k])||0,HubObject=(o,k)=>o?.[k]||null;
function expr(source,vars){
 const js=source.replace(/<>/g,'!==').replace(/(?<![!<>=])=(?!=)/g,'===').replace(/\bor\b/g,'||').replace(/\band\b/g,'&&').replace(/\bnot\b/g,'!').replace(/\.StartsWith\(/g,'.startsWith(');
 return Function(...Object.keys(vars),'HubText','HubNumber','HubObject',`return (${js});`)(...Object.values(vars),HubText,HubNumber,HubObject);
}
function staleContract(source){
 const guard=extract(source,/if (\(HubText\(Data,'mode'\)[\s\S]+?) then Exit;/);
 const base={mode:'followers',q:'moa',sort:'default',category:'all',offset:0,profile:{id:'USR-OWN'}};
 const vars={FHubCategory:'followers',FollowQuery:'moa',FHubFollowSort:'default',FHubFollowFilter:'all',FHubOffset:0,FollowTarget:'USR-OWN'};
 assert.equal(expr(guard,{...vars,Data:base}),false,'matching response renders');
 for(const [key,value] of [['mode','following'],['q','different'],['sort','oldest'],['category','low_interaction'],['offset',12],['profile',{id:'USR-PEER'}]]){
  assert.equal(expr(guard,{...vars,Data:{...base,[key]:value}}),true,'old '+key+' response must be discarded');
 }
 for(const mode of ['followers','following','subscriptions','flagged'])assert.equal(expr(guard,{...vars,FHubCategory:mode,Data:{...base,mode}}),false);
}
staleContract(flow);
assert.throws(()=>staleContract(flow.replace("(HubNumber(Data,'offset')<>FHubOffset)","(HubNumber(Data,'offset')<0)")));
assert.throws(()=>staleContract(flow.replace("(HubText(HubObject(Data,'profile'),'id')<>FollowTarget)","(FollowTarget='')")));
for(const [key,field,fallback] of [['followSort','FHubFollowSort','default'],['followFilter','FHubFollowFilter','all']]){
 assert.ok(flow.includes(`Snapshot.AddPair('${key}',${field});`));
 assert.ok(flow.includes(`${field}:=HubText(Snapshot,'${key}','${fallback}');`));
}
for(const key of ['mode','q','sort','category'])assert.ok(flow.includes(`Body.AddPair('${key}',FHub${{mode:'Category',q:'SearchText',sort:'FollowSort',category:'FollowFilter'}[key]})`));
const hide=extract(dashboard,/if (FHubActivityScope or [^\n]+) then BottomHeight:=0;/);
for(const [view,scope,want] of [['follows',false,true],['me',false,false],['chats',false,false],['people',true,true],['settings.notifications',false,true]])assert.equal(expr(hide,{FHubActivityScope:scope,FHubView:view}),want);
assert.match(live,/if FHubView<>'follows' then Collect\(HubCached\(HubReadAction\)\)/,'relationship peers do not trigger duplicate per-profile polling');
assert.match(live,/Body.AddPair\('knownFollowsTag',HubText\(HubCached\('follows'\),'followsTag'\)\)/);
const page=live.slice(live.indexOf("    RelationshipsPage:=HubObject(Data,'followsPage');"));
assert.match(page,/\(FHubView='follows'\) and \(FHubLiveScope='follows'\)/);
assert.match(page,/QueryText=FHubLiveQuery/,'late live response belongs to current query');
assert.match(page,/HubReply\('follows',RelationshipsReply.ToJSON\)/,'live page uses existing held-row/focus deferral');
assert.match(flow,/HubInputFocused and not \(\(Action='thread'\)/);
assert.match(flow,/else if \(Action='follow.set'\) or \(Action='follow.remove'\) then begin/);
assert.match(flow,/if Action='follow.set' then HubApplyFollow\(Data\)/,'removing incoming follower must not overwrite outgoing-follow state/counts');
assert.match(read('MoaPlayApp.Member.PeopleSync.inc'),/if FHubView='follows' then begin[\s\S]*FMember.CancelReads[\s\S]*FHubCache.Remove\('follows'\)/);
const ui=read('MoaPlayApp.Member.Relationships.inc');
assert.match(ui,/Query:=LowerCase\(Trim\(FHubSearchText\)\)/);
assert.match(ui,/if Query.StartsWith\('@'\) then Delete\(Query,1,1\)/);
const rendererGuard=extract(ui,/if Assigned\(Data\) and (\(\(HubText\(Data,'mode'\)[\s\S]+?) then Exit;/);
for(const raw of ['moa','@moa','MOA','  @MoA  ']){
 const Query=raw.trim().toLowerCase().replace(/^@/,'');
 assert.equal(expr(rendererGuard,{Data:{mode:'followers',q:'moa',sort:'default',category:'all'},Mode:'followers',Query,FHubSearchText:raw,FHubFollowSort:'default',FHubFollowFilter:'all'}),false,'typed @ and case never hide the matching rows');
}
assert.match(ui,/if not Suggested then begin LabelText.TagString:='member-name\|'/,'live updates preserve recommendation copy');
assert.match(live,/Child.Name='MoaPlayRelationshipNickname' then TLabel\(Child\).TextSettings.FontColor:=MemberMuted/);
assert.match(read('MoaPlayApp.pas'),/\{\$I MoaPlayApp.Member.Relationships.inc\}/);
console.log('FIX67 relationships native contracts PASS: stale query/target/page rejection, back restoration, tab visibility, deferred live refresh and independent follower removal.');
