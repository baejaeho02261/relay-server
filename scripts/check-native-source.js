'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../..'),apk=path.join(root,'MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(apk,name),'utf8');
for(const folder of ['MoaPlayApp_Android64','MoaPlayConnect_Win64']){
 const base=path.join(root,folder);
 for(const name of fs.readdirSync(base).filter(x=>/\.(pas|inc)$/.test(x))){
  const bytes=fs.readFileSync(path.join(base,name));assert.deepEqual([...bytes.subarray(0,3)],[239,187,191],name+' BOM');
  const text=new TextDecoder('utf8',{fatal:true}).decode(bytes);
  for(const match of text.matchAll(/\{\$I\s+([^}]+)\}/gi))assert.ok(fs.existsSync(path.join(base,match[1].trim())),match[1]);
  // FMX brush enum references need their defining unit in this unit's uses.
  // This catches the reported E2003 before shipping an amount-control edit.
  if(name.endsWith('.pas')&&/\bTBrushKind\b/.test(text)){
   const imports=[...text.matchAll(/\buses\s+([^;]+);/gi)].map(m=>m[1]).join(',');
   assert.match(imports,/\bFMX\.Graphics\b/i,name+' requires FMX.Graphics for TBrushKind');
  }
 }
}
// Include files declare fields in the same form class: grouped names can
// redeclare an older standalone field even when all methods are valid.
const fieldNames=[];
for(const m of read('MoaPlayApp.Fields.inc').matchAll(/^\s*(F\w+(?:\s*,\s*F\w+)*)\s*:/gm))
 fieldNames.push(...m[1].split(',').map(n=>n.trim().toLowerCase()));
assert.equal(new Set(fieldNames).size,fieldNames.length,'Duplicate form fields');
// A missing SVG returns an empty string at runtime, silently hiding an action.
const iconNames=new Set([...read('MoaPlayMemberSvg.pas').matchAll(/Name\s*=\s*'([^']+)'/g)].map(m=>m[1]));
for(const file of fs.readdirSync(apk).filter(n=>/\.(pas|inc)$/.test(n)))
 for(const m of read(file).matchAll(/MemberSvg\(\s*'([^']+)'/g))
  assert.ok(iconNames.has(m[1]),file+' missing SVG '+m[1]);
const declared=[...read('MoaPlayApp.Methods.inc').matchAll(/\b(?:procedure|function)\s+(\w+)/gi)].map(x=>x[1].toLowerCase());
const units=fs.readdirSync(apk).filter(x=>/\.(pas|inc)$/.test(x)).map(read).join('\n');
// Deleted form fields must not leave a callback reference that only DCC would find.
const formUnits=fs.readdirSync(apk).filter(x=>/^MoaPlayApp\..*\.inc$/.test(x)).map(read).join('\n');
const declaredFields=new Set(fieldNames);
for(const m of formUnits.matchAll(/\bF(?:Hub|Support|Auth|MemberEntry|Biometric)\w*/g))
 assert.ok(declaredFields.has(m[0].toLowerCase()),'Undeclared form field '+m[0]);
const implemented=[...units.matchAll(/\b(?:procedure|function)\s+TMoaPlayForm\.(\w+)/gi)].map(x=>x[1].toLowerCase());
assert.equal(new Set(implemented).size,implemented.length,'Duplicate form methods');
for(const name of declared)assert.ok(implemented.includes(name),'Missing '+name);
for(const name of implemented)assert.ok(declared.includes(name),'Undeclared '+name);
for(const [name,type] of [['MoaPlayMemberClient.pas','TMoaPlayMemberClient'],['MoaPlayMemberSwitch.pas','TMoaPlayMemberSwitch'],['MoaPlayMemberMemo.pas','TMoaPlayMemberMemo'],['MoaPlayIconPulse.pas','TMoaPlayIconPulse'],['MoaPlayFeedCard.pas','TMoaPlayFeedTap'],['MoaPlayCatalogCard.pas','TMoaPlayCatalogTap']])
 assert.deepEqual(require('./native-declarations').Check(read(name),type),[],name);
// Cross-layer invariants for the lifecycle bugs: no editor exit saves a partially destroyed form.
const flow=read('MoaPlayApp.Member.Flow.inc'),motion=read('MoaPlayApp.Member.Motion.inc'),compose=read('MoaPlayApp.Member.Compose.inc'),social=read('MoaPlayApp.Member.Social.inc');
assert.match(flow,/if FHubRendering or not Assigned\(FHubDrafts\)/);
assert.match(flow,/HubSaveDraft;\s*FHubRendering:=True;\s*try/);
assert.match(flow,/finally FHubRendering:=False;end;/);
assert.match(motion,/if FClosing or FHubRendering/);
assert.match(compose,/Draft\.AddPair\('imageChanged'/);assert.match(compose,/HubSaveComposeMedia;HubRenderComposeChange/);
assert.match(compose,/for I:=0 to 1 do/);assert.doesNotMatch(compose,/for I:=0 to 3 do/);
assert.match(compose,/제목을 작성하세요/);assert.match(compose,/서로를 존중하는 글을 남겨주세요/);assert.doesNotMatch(compose,/투표 질문을 작성하세요/);
assert.match(read('MoaPlayGifPicker.pas'),/ACTION_GET_CONTENT/);assert.match(read('MoaPlayGifPicker.pas'),/image\/gif/);
assert.match(read('MoaPlayMemberGif.pas'),/FAnimated\.LoadFromStream\(Stream\)/);
assert.doesNotMatch(social,/Row\('닫기'/);assert.doesNotMatch(read('MoaPlayApp.Member.MyPage.inc'),/fsUnderline/);
assert.doesNotMatch(read('MoaPlayApp.Member.Feed.inc'),/'reply','reply\|'/);
const feed=read('MoaPlayApp.Member.Feed.inc');
assert.match(feed,/'bubble',HubCount\(HubNumber\(Item,'replies'\)\),ReplyAction/);
assert.match(feed,/ReplyAction:='reply\|'\+ID/);
assert.match(feed,/if ShowPostLink then ReplyAction:='comment.thread\|'\+ID\+'\|'\+HubText\(Item,'postId'\)/);
assert.match(social,/Action='comment.thread'[\s\S]*HubText\(Item,'postId'\)=Parts\[2\]/,'profile reply navigation validates its thread identity');
assert.match(feed,/HubFillCommentCard\(C,Item,False\)/);
// Restored owner activity uses the same validated post/comment renderers as public profiles.
const profile=read('MoaPlayApp.Member.MyPage.inc');
const me=profile.split('procedure TMoaPlayForm.HubRenderMe')[1].split('procedure TMoaPlayForm.HubRenderMember')[0];
assert.match(me,/HubProfileStat\(/);assert.match(me,/HubProfileTabs\(/);
assert.match(me,/HubRenderOwnComments\(/);assert.match(me,/HubRenderProfileGallery\(/);
assert.match(me,/HubProfileButtons\(C,Profile,True,False,Y\)/);
assert.match(profile,/Captions:array\[0\.\.3\] of string=\('게시글','댓글','리포스트함','태그한 게시글'\)/);
assert.match(profile,/HubFillCommentCard\(C,Item,True\)/,'public comment history retains safe thread rendering');
const postBody=feed.split('function TMoaPlayForm.HubFillPostCard')[1].split('function TMoaPlayForm.HubQuoteCard')[0];
assert.doesNotMatch(postBody,/HubReaction\(|post\.menu|more\|post\|/,'retired feed toolbar and menu stay absent');
assert.doesNotMatch(postBody,/chevron\.down|feed\.expanded|if not Expanded/,'feed content remains fully visible');
assert.doesNotMatch(feed,/feed\.channel|feed\.sort/);
const hold=read('MoaPlayFeedCard.pas');
assert.match(hold,/procedure TMoaPlayFeedTap.CancelTouch;[\s\S]*?FHoldTimer.Enabled:=False;inherited/,'scroll/page cancellation stops a hold timer');
assert.match(hold,/if FWasHeld then Exit/,'hold release must not also dispatch a tap');
assert.match(hold,/FWasHeld:=True;FDown:=False;Handler:=FHold;CancelTouch/,'one hold cannot dispatch twice');
assert.match(hold,/not TControl\(Node\).Visible then Exit/,'hidden pages cannot repost');
assert.match(hold,/FHoldTimer.OnTimer:=nil/,'destroyed posts release timer callbacks');
assert.match(social,/GifView\.LoadFrames\(GifData\)/);
// FIX70: retired game classes and endpoints must not remain linked.
for(const name of ['MoaPlayCasinoBoard.pas','MoaPlayCasinoAmount.pas','MoaPlayCasinoIndicators.pas','MoaPlaySkillGames.pas'])
 assert.ok(!fs.existsSync(path.join(apk,name)),name+' is retired');
assert.doesNotMatch(read('MoaPlayApp.pas'),/MoaPlayCasino|MoaPlaySkillGames/);
assert.ok(!fs.existsSync(path.join(apk,'MoaPlayRewardWheel.pas')));
assert.doesNotMatch(read('MoaPlayApp.Member.Rewards.inc'),/HubWheel|HubRenderWheel|HubFillWheel/);
require('./check-native-theme').Check(apk);
require('./check-native-touch-glass').Check(apk);
require('./check-native-messaging').Check(apk);
require('./test-native-updates').Check();
assert.match(flow,/if not FHubPageChanged and FHubTouch\.Busy then Exit;/,'local updates keep held cards alive');
console.log('Native source checks passed (encoding, includes, declarations and lifecycle invariants; Delphi compilation not run).');
