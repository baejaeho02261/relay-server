'use strict';
// Native integration gates, not Delphi/device compilation.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const dir=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(dir,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const flow=read('MoaPlayApp.Member.Flow.inc'),delta=read('MoaPlayApp.Member.Delta.inc'),live=read('MoaPlayApp.Member.Live.inc');
// FIX69: the client follows the native viewport, never a centered 480-unit root.
const ui=read('MoaPlayApp.Ui.inc');
assert.match(ui,/FRoot\.Align := TAlignLayout\.Client/);
assert.doesNotMatch(ui,/FRoot\.SetBounds|RootWidth\s*:?=\s*Min\(480/);
assert.match(ui,/RootWidth := Max\(1, Trunc\(FRoot\.Width\)\)/);

const routine=(s,name)=>{const rows=[...s.matchAll(/^(?:procedure|function)\s+([\w.]+)/gm)],i=rows.findIndex(x=>x[1]===name);assert.ok(i>=0,name);return s.slice(rows[i].index,rows[i+1]?.index??s.length);};
const reply=routine(flow,'TMoaPlayForm.HubReply'),poll=routine(flow,'TMoaPlayForm.HubPollTimerTimer'),fetch=routine(flow,'TMoaPlayForm.HubFetch');
assert.match(flow,/FHubView='home' then Result:='home'/);assert.match(flow,/FHubView='archives'\) then Result:=FHubView/);
assert.match(flow,/FHubView='home' then HubRenderHome\(HubCached\('home'\)\)/);assert.match(flow,/FHubView='archives' then HubRenderFeed\(HubCached\('archives'\)\)/);
assert.match(fetch,/'_ifNoneMatch',HubText\(HubCached\(Action\),'contentTag'\)/);
assert.ok(reply.indexOf('if HubNewsReply(Action,Data) then Exit')<reply.indexOf("((Action='article') and (FHubView<>'article'))"));
assert.ok(reply.indexOf('HubPostToolsReply(Action,Data)')<reply.indexOf("((Action='home') and (FHubView<>'home'))"));
assert.ok(reply.indexOf('HubRefreshSticker(Data)')<reply.indexOf('HubRefreshPhoto(Data)'));
const expr=reply.match(/Mutation:=([^;]+);/)[1].replace(/<>/g,'!==').replace(/(?<![<>!=])=(?!=)/g,'===').replace(/\band\b/g,'&&').replace(/\bor\b/g,'||').replace(/Pos\('\.',Action\)>0/g,"Action.includes('.')");
const mutation=Function('Action','return '+expr);
for(const name of ['post.insights','post.recipients','home','archives','photo','article'])assert.equal(mutation(name),false,name);
for(const name of ['post.settings','post.share','post.create','react','bookmark.set','purchase'])assert.equal(mutation(name),true,name);
// Execute the idle-home refresh predicate, including all actual input guards.
const predicate=poll.match(/if \(FHubView='home'\) and ([\s\S]*?) then begin HubFetch;Exit;end;/)[0].slice(3).split(' then begin')[0]
 .replace(/<>/g,'!==').replace(/(?<![<>!=])=(?!=)/g,'===').replace(/\band\b/g,'&&').replace(/\bor\b/g,'||').replace(/\bnot\b/g,'!');
const due=Function('s','with(s){return '+predicate+';}');
const ctx={FHubView:'home',FHubLoading:false,FMember:{HasPending:false},HubInputFocused:false,FHubTouch:{Busy:false},HubScrollDragging:false,FHubOverlay:null,TStopwatch:{GetTimeStamp:3000,Frequency:1000},FHubRequestedAt:0,Assigned:x=>x!=null};
assert.equal(due(ctx),true);
for(const patch of [{FHubView:'feed'},{FHubLoading:true},{FMember:{HasPending:true}},{HubInputFocused:true},{FHubTouch:{Busy:true}},{HubScrollDragging:true},{FHubOverlay:{Visible:true}},{FHubRequestedAt:1500}])assert.equal(due({...ctx,...patch}),false,JSON.stringify(patch));
assert.match(routine(live,'TMoaPlayForm.HubLiveTick'),/if FHubView='home' then Exit/,'home must not duplicate its projection poll with a second live poll');
const settings=reply.slice(reply.indexOf("else if Action='post.settings'"),reply.indexOf("else if Action='post.share'"));
assert.match(settings,/HubRender/);assert.match(settings,/HubFetch/);assert.doesNotMatch(settings,/HubCloseOverlay/,'an older receipt cannot close a newer menu');
assert.match(reply,/Action='post.settings'[\s\S]*FMember.CancelReads/,'pre-mutation reads cannot resurrect archived cards');
const patch=routine(delta,'TMoaPlayForm.HubApplyDelta');
for(const key of ['shares','commentsDisabled','archived','pinned','previewPosition','audience','audienceLabel','ownHideLikeCounts','ownHideShareCounts'])assert.ok(patch.includes("'"+key+"'"),key);
assert.match(patch,/for Cache in FHubCache.Values do PatchPost\(Cache\)/);
const names=patch.match(/Names:=\[([\s\S]*?)\];/)[1];assert.doesNotMatch(names,/'image'|'imageThumb'|'gif'/,'lean metadata acknowledgements retain already-loaded media');
assert.match(patch,/Upsert\(HubCached\('archives'\),Post,True\)/);assert.match(patch,/Upsert\(HubCached\('archives'\),Post,False,True\)/);assert.match(patch,/RemoveHomePost/);
const queue=routine(delta,'TMoaPlayForm.HubDrainSocial');assert.match(queue,/Action='post.settings'[\s\S]*HubSocialItem\('post',HubText\(Body,'id'\)\)[\s\S]*HubSetJSON\(Body,'revision'/);assert.match(queue,/HubBool\(Item,'own'\)/);
for(const key of ['shares','commentsDisabled','audienceLabel','pinned','previewPosition'])assert.ok(live.includes("'"+key+"'"));
assert.match(live,/if NeedRender then begin[\s\S]*HubUpdateCommentComposer;ResizeDashboardUI/);
for(const name of ['MoaPlayApp.Member.Flow.inc','MoaPlayApp.Member.Delta.inc','MoaPlayApp.Member.Live.inc']){
 const b=fs.readFileSync(path.join(dir,name));assert.equal(b.subarray(0,3).toString('hex'),'efbbbf');assert.doesNotMatch(b.toString('utf8'),/(?<!\r)\n/);
}
console.log('FIX68 native integration PASS: read/mutation classification, actual idle-home poll predicate, inline news/photo dispatch, archive/metadata delta, queue revision rebasing and structural live refresh. Delphi/device execution not performed.');
