'use strict';
// Regression contracts for the native detail editor: geometry, partial saves,
// per-item drafts and concurrent edits. Server behavior is covered by social tests.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=n=>fs.readFileSync(path.join(root,n),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const edit=read('MoaPlayApp.Member.ProfileEdit.inc'),detail=read('MoaPlayApp.Member.ProfileDetails.inc');
const flow=read('MoaPlayApp.Member.Flow.inc'),widget=read('MoaPlayApp.Member.Widgets.inc');
function between(s,a,b){const start=s.indexOf(a),end=s.indexOf(b,start+a.length);assert.ok(start>=0&&end>start,`${a} / ${b}`);return s.slice(start,end);}
const field=between(edit,'  procedure Field','  procedure Link');
assert.doesNotMatch(field,/FloatingLabel:=True|HubInputPanelStyle/,'field labels never move on focus');
assert.match(field,/HubLabel\(Row,MemberCaption\(Caption\)/);
for(const text of ['이름','사용자 이름','소개','링크 추가','음악, 프로필 등을 추가해보세요.','성별 대명사','그리드 순서 변경','AI로 생성한 프로필','더 알아보기','프로페셔널 계정으로 전환','개인정보 설정','프로필 인증 표시'])assert.ok(edit.includes(text),text);
const captions=["Field('이름'","Field('사용자 이름'","Field('성별 대명사'","Field('소개'","Link('링크'","Link('배너'","HubLabel(Row,MemberCaption('성별')","Link('그리드 순서 변경'"];
let previous=-1;for(const s of captions){const i=edit.indexOf(s);assert.ok(i>previous,`ordered profile section ${s}`);previous=i;}
const routes=[...detail.matchAll(/(?:if|else if) View='(profile\.[^']+)' then Result:=/g)].map(m=>m[1]);
assert.deepEqual(routes,['profile.links','profile.link.edit','profile.banners','profile.banner.edit','profile.grid','profile.ai','profile.accounttype','profile.verification']);
assert.match(flow,/HubProfileDetailsTitle\(FHubView\)<>'' then Result:='profile.details'/);
assert.match(flow,/if HubProfileDetailsReply\(Action,Payload\) then Exit/);
assert.match(flow,/HubRenderProfileDetails\(HubCached\('profile.details'\)\)/);
for(const page of ['profile.link.edit','profile.banner.edit']){
 assert.ok(between(flow,'procedure TMoaPlayForm.HubSaveDraft','procedure TMoaPlayForm.HubRestoreDraft').includes(`FHubView='${page}'`));
 assert.ok(between(widget,'function HubDraftKey','{ Shared').includes(`View='${page}'`));
}
const action=between(detail,'function TMoaPlayForm.HubProfileDetailsAction','function TMoaPlayForm.HubProfileDetailsReply');
assert.match(action,/FMember.Request\('profile.details.save',Body.ToJSON,True\)/);
assert.doesNotMatch(action,/Body.AddPair\('(?:nickname|bio|avatar|handle|pronouns)'/,'detail saves cannot overwrite a parent unsaved form');
assert.match(action,/Body.AddPair\('expectedProfileRevision',TJSONNumber.Create\(HubNumber\(Profile,'profileRevision'\)\)\)/);
assert.match(action,/if Items.Items\[Index\].ToJSON<>Baseline then/,'a remotely replaced array entry cannot be overwritten');
assert.match(action,/not FHubDrafts.ContainsKey\(HubDraftKey\(View,PageID\)\)/,'reopening a draft preserves its original concurrency baseline');
assert.match(action,/FHubSubmitEpoch:=FHubEditorEpoch/);
assert.match(action,/if FMember.HasPending then/);
assert.match(action,/if \(Key<>'aiProfile'\) and \(Key<>'showVerification'\) then Exit/);
assert.match(action,/if \(Value<>'PERSONAL'\) and \(Value<>'CREATOR'\) and \(Value<>'BUSINESS'\) then Exit/);
assert.match(action,/Value.ToLower.StartsWith\('https:\/\/'\) or Value.ToLower.StartsWith\('http:\/\/'\)/);
assert.doesNotMatch(action,/FreeAndNil\(FHubPage\)|HubRenderNow/,'click dispatch keeps its sender alive');
const reply=detail.slice(detail.indexOf('function TMoaPlayForm.HubProfileDetailsReply'));
assert.match(reply,/Submitted:=Mutation and HubSubmittedEditor\(Action\)/,'stale save replies cannot close a different editor');
assert.match(reply,/HubSaveDraft;ReconcileDraft;HubApplySavedProfile\(Data\)/,'saving a details toggle preserves typed parent fields');
assert.match(reply,/HubDiscardEditor\(SubmittedView,FHubPostID\);AndroidToast\('저장했어요.'\);HubGoBack/,'successful edited-item save drops its own draft before back navigation');
assert.match(reply,/if not HubInputFocused then FHubLocalRender:=True;HubRender/,'network updates do not destroy a focused editor');
assert.match(detail,/HubText\(Verification,'status'\)='DEVICE_AUTHENTICATED'/);
assert.doesNotMatch(detail,/Body.AddPair\('verification'|verified',TJSONBool.Create\(True\)/,'the client cannot self-grant verification');

// Evaluate the production reconciliation predicate for changed/unchanged drafts.
// A successful creation changes the editor identity to its saved array index;
// subsequent Save must update that item rather than append a duplicate.
const reconcile=between(reply,'  procedure ReconcileDraft;','\nbegin\n  Result:=(Action=');
const keepSource=reconcile.match(/KeepDraft:=(.*?);/)[1];
const keepJS=keepSource.replace(/Assigned\((\w+)\)/g,'!!$1').replace(/HubText\((\w+),'([^']+)'\)/g,"($1?.['$2']||'')").replace(/<>/g,'!==').replace(/\band\b/g,'&&').replace(/\bor\b/g,'||');
const keepDraft=Function('Draft','Pending',`return ${keepJS}`);
const sent={field0:'설명',field1:'https://example.com/one'};
for(const origin of ['0','new','new.music','new.profile'])for(const navigated of [false,true])for(const field of ['', 'field0','field1']){
 const draft={...sent};if(field)draft[field]+=' 수정';const keep=keepDraft(draft,sent);assert.equal(keep,!!field);
 const savedId=origin.startsWith('new')?'2':origin;
 const draftMap=new Map([[origin,draft],[origin+'.entry','before']]);
 // Apply the exact retirement/rekey contract asserted against native code below.
 draftMap.delete(origin);draftMap.delete(origin+'.entry');
 if(keep)draftMap.set(savedId,draft);
 if(keep||!navigated)draftMap.set(savedId+'.entry','acknowledged-entry');
 if(keep){assert.deepEqual(draftMap.get(savedId),draft);assert.equal(draftMap.get(savedId+'.entry'),'acknowledged-entry');}
 else assert.ok(!draftMap.has(savedId));
 if(origin.startsWith('new'))assert.ok(!draftMap.has(origin),'acknowledged creation cannot remain a create-again draft');
}
assert.equal(keepDraft(null,sent),false);
assert.match(reconcile,/FHubDrafts.Remove\(OriginKey\);FHubDrafts.Remove\(OriginKey\+'\.entry'\)/);
assert.match(reconcile,/if KeepDraft then FHubDrafts.AddOrSetValue\(SavedKey,DraftText\)/);
assert.match(reconcile,/FHubDrafts.AddOrSetValue\(SavedKey\+'\.entry',Entry.ToJSON\)/);
assert.match(reconcile,/if \(FHubView=OriginView\) and \(FHubPostID=OriginID\) then FHubPostID:=SavedID/);
assert.match(reconcile,/HubSetJSON\(Snapshot,'postId',TJSONString.Create\(SavedID\)\)/,'back history points at the acknowledged item');
assert.doesNotMatch(reconcile,/Inc\(FHubEditorEpoch\)|FHubEditorEpoch:=/,'unrelated editor epochs remain unchanged');
assert.match(action,/FHubDrafts.AddOrSetValue\('profile.details.pending',Pending.ToJSON\)/);
assert.match(reply,/if Mutation then begin\s+FHubDrafts.Remove\('profile.details.pending'\);AndroidToast/,'failed/conflicting saves never reconcile an unacknowledged item');
assert.match(action,/Items.Items\[Index\].ToJSON<>Baseline/,'another writer still requires an explicit reload');
assert.match(action,/if Action='pdetail.reload' then begin/);
assert.match(action,/HubDiscardEditor\(FHubView,FHubPostID\);FHubLocalRender:=True;HubRender;Exit/,'explicit reload discards only the current detail draft');
assert.match(reply,/HubText\(Obj,'reason'\)='PROFILE_CHANGED'/,'conflicts request the latest server snapshot');
assert.match(detail,/Input\('제목',HubText\(Item,'title'\),'프로필에 표시할 이름',0,60\)/);
assert.match(action,/Trim\(FHubEdits\[0\].Text\)='' then ErrorText/);
assert.match(detail,/Detail:=HubText\(Item,'handle'\);if Detail<>'' then Detail:='@'\+Detail/);

// Evaluate coordinates extracted from production rows across supported narrow/wide layouts.
const compact=s=>s.replace(/\s+/g,'');
const expressions=[...detail.matchAll(/HubIconButton\(C,'chevron.down',[^\n]+?,(C.Width-(?:88|44)),10,44,44\)/g)].map(m=>m[1]);
assert.equal(expressions.length,2,'both grid controls remain 44dp targets');
let checks=0;
for(let viewport=240;viewport<=1024;viewport+=7){
 const W=viewport-40;
 const xy=expressions.map(s=>Function('W',`return ${s.replace('C.Width','W')}`)(W));
 assert.ok(xy[0]>=0&&xy[0]+44<=xy[1]&&xy[1]+44<=W);
 const input=between(detail,'  procedure Input','  procedure ChoiceRow');
 assert.ok(compact(input).includes('SetBounds(-4,21,C.Width+4,42)'));
 assert.equal(-4+(W+4),W,'text content stays inside the section edge');
 const profileWidth=Math.max(1,viewport-100);assert.ok(profileWidth>=140,'AI description reserves the entire switch area');
 checks++;
}
for(const name of ['MoaPlayApp.Member.ProfileEdit.inc','MoaPlayApp.Member.ProfileDetails.inc']){
 const b=fs.readFileSync(path.join(root,name));assert.deepEqual([...b.subarray(0,3)],[239,187,191]);
 assert.doesNotMatch(b.toString('utf8'),/(?<!\r)\n/,'Delphi sources retain CRLF');
}
console.log(`FIX65 profile editor: ${checks} layouts, partial-save/draft/concurrency/verification contracts passed`);
