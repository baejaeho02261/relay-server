'use strict';
// Execute narrow translations/extractions of shipped Pascal/JS expressions.
// This checks native/server contracts without pretending to compile Delphi.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const native=path.resolve(__dirname,'../../MoaPlayApp_Android64'),server=path.resolve(__dirname,'../services/member');
const read=(name,base=native)=>fs.readFileSync(path.join(base,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const part=(s,a,b)=>{const from=s.indexOf(a),to=s.indexOf(b,from+a.length);assert.ok(from>=0&&to>from,a);return s.slice(from,to);};
const match=(s,re,label)=>{const m=s.match(re);assert.ok(m,label||String(re));return m;};
const HubText=(obj,key,fallback='')=>typeof obj?.[key]==='string'?obj[key]:fallback;
const HubNumber=(obj,key)=>Number(obj?.[key])||0,HubBool=(obj,key)=>obj?.[key]===true;
const Assigned=value=>value!=null,IntToStr=String;
function expression(s,variables={}){
 // The tested predicates contain no assignment or quoted operators.
 const code=s.replace(/<>/g,'!==').replace(/(?<![!<>=])=(?!=)/g,'===').replace(/\bor\b/g,'||').replace(/\band\b/g,'&&').replace(/\bnot\b/g,'!');
 return Function(...Object.keys(variables),'HubText','HubNumber','HubBool','Assigned','IntToStr',`return (${code});`)(...Object.values(variables),HubText,HubNumber,HubBool,Assigned,IntToStr);
}
const flow=read('MoaPlayApp.Member.Flow.inc'),live=read('MoaPlayApp.Member.Live.inc');
function navigationContract(source){
 const navigate=part(source,'procedure TMoaPlayForm.HubNavigate','procedure TMoaPlayForm.HubGoBack');
 const back=part(source,'procedure TMoaPlayForm.HubGoBack','function TMoaPlayForm.HubReadAction');
 const save=match(navigate,/Snapshot.AddPair\('searchText',([^;]+)\);/,'snapshot owns query')[1];
 const restore=match(back,/FHubSearchText:=([^;]+);/,'back restores query')[1];
 const reset=match(navigate,/if (\(\(NewView='all'\)[^\n]+?) then FHubSearchText:='';/,'search-root reset predicate')[1];
 function visit(from,to,query){const snapshot={};snapshot.searchText=expression(save,{FHubSearchText:query});return {snapshot,query:expression(reset,{NewView:to,FHubView:from})?'':query};}
 for(const [route,query,detail] of [['catalog','퍼즐 우주','game'],['people','@moa.friend','member'],['all','개인정보','activity.account']]){
  const next=visit(route,detail,query);assert.equal(expression(restore,{Snapshot:next.snapshot}),query);
  for(const other of ['catalog','people','all']){
   const switched=visit(route,other,query);assert.equal(switched.query,route===other?query:'','only a fresh search route resets');
   assert.equal(expression(restore,{Snapshot:switched.snapshot}),query,'back across search roots restores the earlier query');
  }
 }
 const first=visit('catalog','people','arcade'),second=visit('people','all','@친구');
 assert.equal(expression(restore,{Snapshot:second.snapshot}),'@친구');assert.equal(expression(restore,{Snapshot:first.snapshot}),'arcade');
 assert.ok(back.indexOf("FHubSearchText:=")<back.indexOf('HubFetch;HubRecordVisit(FHubView)'),'query restored before issuing read');
}
navigationContract(flow);
assert.throws(()=>navigationContract(flow.replace("Snapshot.AddPair('searchText',FHubSearchText);",'')),'lost query snapshot is detected');
assert.throws(()=>navigationContract(flow.replace("FHubSearchText:=HubText(Snapshot,'searchText');","FHubSearchText:='';")),'empty-on-back regression is detected');

const news=read('MoaPlayApp.Member.NewsShop.inc');
function catalogContract(source){
 const catalog=part(source,'procedure TMoaPlayForm.HubRenderCatalog','procedure TMoaPlayForm.HubRenderArticle');
 const guard=match(catalog,/if (Assigned\(Data\) and \(HubText\(Data,'q'\)[^\n]+?\)) then begin/,'cached query guard')[1];
 const wait=part(catalog,'  if Assigned(Data) and','  Items:=HubArray');
 assert.match(wait,/Exit;/,'old tiles cannot fall through below the loading/error state');
 assert.ok(catalog.indexOf('FHubSearchEdit.ApplyStyleLookup')<catalog.indexOf('  if Assigned(Data) and'),'search remains available during a pending query');
 for(const [oldQuery,newQuery] of [['racing','퍼즐'],['','우주'],['@친구',''],['title','title'],['genre',' genre ']]){
  assert.equal(expression(guard,{Data:{q:oldQuery},FHubSearchText:newQuery,Trim:s=>s.trim()}),oldQuery!==newQuery.trim());
 }
 assert.match(wait,/FHubLoading/,'failure and pending states do not claim an empty result');
}
catalogContract(news);
assert.throws(()=>catalogContract(news.replace("HubText(Data,'q')<>Trim(FHubSearchText)","HubText(Data,'q')=Trim(FHubSearchText)")),'wrong-query cards cannot flash under the new search');

const activity=read('profile-activity.js',server);
const scopeFunction=activity.slice(activity.indexOf('function Scope('),activity.indexOf('\nmodule.exports'));
const Mode=Function('s','return ('+part(activity,'function Mode(','function CanRead')+');')({Fail:reason=>{throw Error(reason);}});
function nativeSignatures(source,items){
 const body=part(source,'  procedure Signature(Obj:TJSONObject);','begin\n  Updates:=');
 const expr=match(body,/Expected.Add\((.+)\);end;/,'native event signature')[1];
 return items.map(Obj=>expression(expr,{Obj}));
}
function signatureContract(source){
 for(const offset of [0,1,2]){
  const rows=[{post:{id:'POST-A',revision:4},eventId:'REPOST-3'},{post:{id:'POST-A',revision:4},eventId:'REPOST-2'},{post:{id:'POST-B',revision:1},eventId:'POST-B'}];
  const Scope=Function('Mode','Rows','s','return ('+scopeFunction+');')(Mode,()=>rows,{Page:(all,body,max)=>({items:all.slice(body.offset||0,(body.offset||0)+(body.limit||max))})});
  const body={activity:'reposts',offset,limit:2};
  const expected=Scope({}, {},body),selected=rows.slice(offset,offset+2).map(row=>({...row.post,eventId:row.eventId}));
  assert.deepEqual(nativeSignatures(source,selected),expected,'native signatures exactly match server event identities');
 }
 assert.deepEqual(nativeSignatures(source,[{id:'CMT-1',revision:2},{id:'POST-OLD',revision:0}]),['CMT-1/2','POST-OLD/0'],'comments/legacy cache fallback');
}
signatureContract(live);
assert.throws(()=>signatureContract(live.replace("HubText(Obj,'eventId',HubText(Obj,'id'))","HubText(Obj,'id')")),'same-post repost events cannot cause endless scope mismatch/refetch');

const gallery=read('MoaPlayApp.Member.ProfileGallery.inc');
const mediaExpr=match(activity,/mediaKind:([^,]+),quotePostId:/,'compact media discriminator')[1];
function galleryContract(source){
 const skip=match(source,/ID:=HubText\(Item,'id'\);if (.+?) then Continue;/)[1];
 const markers=match(source,/Icon:='';\s*if (.+?) then Icon:='([^']+)'\s*else if (.+?) then Icon:='([^']+)'\s*else if (.+?) then Icon:='([^']+)';/);
 const markerFor=vars=>expression(markers[1],vars)?markers[2]:expression(markers[3],vars)?markers[4]:expression(markers[5],vars)?markers[6]:'';
 const fixtures=[{id:'HIDDEN',unavailable:true},{id:''},{id:'TEXT',post:{}},{id:'PHOTO',post:{image:'data:photo'}},{id:'GIF',post:{gifId:'GIF1'}},{id:'ORIGINALGIF',post:{gifMedia:{frames:['frame']}}}];
 const shown=[];
 for(const Item of fixtures){
  const ID=Item.id;if(expression(skip,{ID,Item}))continue;
  Item.mediaKind=Function('post',`return (${mediaExpr});`)(Item.post);
  const vars={Item,Gif:null,ActivityKind:''};
  const icon=markerFor(vars);
  shown.push([ID,icon]);
 }
 assert.deepEqual(shown,[['TEXT',''],['PHOTO',''],['GIF','play'],['ORIGINALGIF','play']]);
 assert.equal(markerFor({Item:{quotePostId:'POST',mediaKind:'gif'},Gif:{},ActivityKind:'repost'}),'repost','repost attribution takes priority over media marker');
 assert.equal(markerFor({Item:{pinned:true,quotePostId:'POST',mediaKind:'gif'},Gif:{},ActivityKind:'repost'}),'pin','profile pin takes priority without removing repost/GIF fallbacks');
}
galleryContract(gallery);
assert.throws(()=>galleryContract(gallery.replace("(ID='') or HubBool(Item,'unavailable')","(ID='')")),'removed post cannot remain clickable');
assert.throws(()=>galleryContract(gallery.replace("Assigned(Gif) or (HubText(Item,'mediaKind')='gif')","Assigned(Gif)")),'compact GIF marker must not rely on omitted full GIF payload');

// FIX66 removes the extra tag field: mentions travel in the same draft/body
// as ordinary typed text. Server parsing/authorization has its own real-service
// suite; these checks preserve native serialization and registration boundaries.
const compose=read('MoaPlayApp.Member.Compose.inc'),actions=read('MoaPlayApp.Member.Actions.inc');
function inlineComposeContract(source){
 assert.doesNotMatch(source,/HubPostTaggedText|FHubEdits\[2\]|사람 태그|taggedMemberIds/,'no separate people-tag field or payload remains');
 assert.match(source,/PromptText:=MemberCaption\('서로를 존중하는 글을 남겨주세요\. 개인정보, 욕설, 도배 및 무단 광고는 삼가주세요\.'\)/);
 assert.match(source,/FHubMemo\.OnEnter:=HubInputEnter;FHubMemo\.OnExit:=HubInputExit;HubRestoreDraft/);
 assert.match(actions,/Body.AddPair\('body',FHubMemo.Text\)/,'post creation/edit sends original inline mention text');
 assert.match(actions,/Body.AddPair\('body',Trim\(FHubCommentEdit.Text\)\)/,'comment creation/edit uses its single composer');
}
inlineComposeContract(compose);
assert.throws(()=>inlineComposeContract(compose+"\nFHubEdits[2]:=EditAt(Tail,Value,'사람 태그',0,400);"),'a second tagging UI cannot silently return');
function draftContract(source){
 const save=part(source,'procedure TMoaPlayForm.HubSaveDraft','procedure TMoaPlayForm.HubRestoreDraft');
 const restore=part(source,'procedure TMoaPlayForm.HubRestoreDraft','procedure TMoaPlayForm.HubNavigate');
 const saving=match(save,/for I:=0 to (\d+) do if Assigned\(FHubEdits\[I\]\) then Obj.AddPair\(('field'\+IntToStr\(I\)),FHubEdits\[I\].Text\)/);
 const restoring=match(restore,/for I:=0 to (\d+) do if Assigned\(FHubEdits\[I\]\) then FHubEdits\[I\].Text := (HubText\(Obj,'field'\+IntToStr\(I\),FHubEdits\[I\].Text\))/);
 const memoSaving=match(save,/if Assigned\(FHubMemo\) then Obj.AddPair\('memo',([^;]+)\);/)[1];
 const memoRestoring=match(restore,/if Assigned\(FHubMemo\) then FHubMemo.Text := ([^;]+);/)[1];
 const edits=[{Text:'제목'},{Text:'투표 질문'},{Text:'프로필 입력'}],draft={};
 for(let I=0;I<=Number(saving[1]);I++)draft[expression(saving[2],{I})]=edits[I].Text;
 const memo='안녕 @Amy 😀\n@moa.friend 같이 이야기해요';
 draft.memo=expression(memoSaving,{FHubMemo:{Text:memo}});
 const rebuilt=[{Text:''},{Text:''},{Text:''}];
 for(let I=0;I<=Number(restoring[1]);I++)rebuilt[I].Text=expression(restoring[2],{I,Obj:JSON.parse(JSON.stringify(draft)),FHubEdits:rebuilt});
 assert.deepEqual(rebuilt,edits,'existing title/poll/profile slots retain their values');
 assert.equal(expression(memoRestoring,{Obj:JSON.parse(JSON.stringify(draft))}),memo,'inline mentions, emoji and line breaks survive the real memo draft path');
}
draftContract(flow);
assert.throws(()=>draftContract(flow.replace("Obj.AddPair('memo',FHubMemo.Text)","Obj.AddPair('memo','')")),'lost inline body draft is detected');
const social=read('social.js',server),service=read('service.js',server);
assert.equal((social.match(/post.mentions=require\('\.\/mentions'\).CaptureContent\(p,post\)/g)||[]).length,2,'both create and edit derive mentions on the server');
assert.match(social,/comment.mentions=require\('\.\/mentions'\).Capture\(p,comment.body\)/);
assert.match(social,/mentionMembers:require\('\.\/mentions'\).Members\(post,p\)/,'only authorized mention metadata is projected');
assert.match(social,/PublicTags\(post,p\)/,'existing media-tag projections remain compatible');
const app=read('MoaPlayApp.pas'),methods=read('MoaPlayApp.Methods.inc'),dpr=read('MoaPlay.dpr'),project=read('MoaPlay.dproj');
for(const unit of ['MoaPlayGlassCard','MoaPlayMentionLinks','MoaPlayDiscoverCard']){
 assert.ok(app.includes(unit));assert.ok(dpr.includes(`${unit} in '${unit}.pas'`));assert.ok(project.includes(`DCCReference Include="${unit}.pas"`));
}
for(const file of ['MoaPlayApp.Member.ProfileDetails.inc','MoaPlayApp.Member.ProfileGallery.inc'])assert.ok(app.includes('{$I '+file+'}'));
for(const name of ['HubRenderProfileDetails','HubProfileDetailsAction','HubProfileDetailsReply','HubRenderProfileGallery','HubMentionBody'])assert.ok(methods.includes(name));
assert.match(flow,/if HubProfileDetailsReply\(Action,Payload\) then Exit/);
assert.match(flow,/HubProfileDetailsTitle\(FHubView\)<>'' then Result:='profile.details'/);
assert.match(flow,/HubRenderProfileDetails\(HubCached\('profile.details'\)\)/);
assert.match(service,/'profile.details':\(\)=>require\('\.\/profile-details'\).Read\(p,body\)/);
assert.match(service,/'profile.details.save':\(\)=>require\('\.\/profile-details'\).Save\(p,body\)/);
const widgets=read('MoaPlayApp.Member.Widgets.inc');
const helper=part(widgets,'function TMoaPlayForm.HubMentionBody','function HubNicknameColor');
assert.match(helper,/if not Assigned\(Members\) or \(Members.Count=0\) then begin\s+Result:=HubLabel[\s\S]*?Exit;\s+end;/,'no metadata remains ordinary text');
assert.match(helper,/Text.Configure\(Value,Members,Size,FHubTouch,HubActionClick(?:,Bold)?\)/);
const feed=read('MoaPlayApp.Member.Feed.inc');
assert.match(feed,/HubMentionBody\(C,Body,HubArray\(Post,'mentionMembers'\)/);
assert.match(feed,/HubMentionBody\(C,Text,HubArray\(Item,'mentionMembers'\)/);
const links=read('MoaPlayMentionLinks.pas');
assert.match(links,/if not Assigned\(Parent\) or not Assigned\(Layout\) or not Assigned\(Members\)/);
assert.match(links,/if not Lookup.TryGetValue\(Token.Handle,ID\) then Continue/,'typed handles alone cannot invent member destinations');
assert.match(links,/Tap.TouchScope:=Scope/);assert.match(links,/Tap.OnClick:=Handler/);
require('./test-fix65-profile-note');
console.log('FIX65/FIX66 INTEGRATION PASS: executed search back-stack, catalog query isolation, native/server repost signatures, unavailable/GIF gallery guards, inline memo drafts, mention authorization wiring and unit/routes; negative mutations rejected.');
