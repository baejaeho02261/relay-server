'use strict';
// Preserve the FIX64 public-profile/share/recommendation contracts while the
// FIX65/FIX66 suites cover the four-tab layout and the requested note removal.
require('./test-fix65-profile-layout');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(root,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const profile=read('MoaPlayApp.Member.MyPage.inc'),people=read('MoaPlayApp.Member.People.inc'),share=read('MoaPlayMemberShare.pas');
function section(source,from,to){const start=source.indexOf(from),end=source.indexOf(to,start+from.length);assert.ok(start>=0&&end>start);return source.slice(start,end);}
function authSurface(source){
 const member=section(source,'procedure TMoaPlayForm.HubRenderMember','procedure TMoaPlayForm.HubRenderInfo');
 assert.match(member,/if HubBool\(Data,'profilePostsHidden'\) then HubEmpty/);
 assert.match(member,/HubProfileButtons\(C,Profile,Own,HubBool\(Data,'isFollowing'\),Y\)/);
 assert.doesNotMatch(source,/'member.badges\|'/,'peer badge action moved from card to header');
 assert.match(source,/HubNicknameColor\(Profile\)/,'purchased name colors stay visible');
}
authSurface(profile);
assert.throws(()=>authSurface(profile.replace("if HubBool(Data,'profilePostsHidden') then HubEmpty","if False then HubEmpty")));
function suggestions(source){
 const rows=section(source,'function TMoaPlayForm.HubProfileSuggestions','procedure TMoaPlayForm.HubRenderPeople');
 assert.match(rows,/THorzScrollBox.Create/);assert.match(rows,/Count>=12 then Break/,'bounded carousel avoids building all members');
 assert.match(rows,/ID=HubText\(FHubOwnProfile,'id'\)/,'own profile is never recommended');
 const realCards=section(rows,'if Assigned(Items) then for V in Items do','{ The final card');
 const finalCard=rows.slice(rows.indexOf('{ The final card'));
 assert.match(realCards,/HubIconButton\(C,'close','people.dismiss\|'\+ID/,'real suggestions retain dismiss actions');
 assert.doesNotMatch(finalCard,/people.dismiss\|/,'the final discovery prompt is permanent');assert.match(rows,/HubFollowButton/);
 assert.match(rows,/C.TagString:='profile.people'/,'final finder card opens the complete list');
 assert.doesNotMatch(rows,/FMember.Request|HubFetch/,'rendering cannot trigger a network loop');
}
suggestions(people);
assert.throws(()=>suggestions(people.replace('Count>=12 then Break','Count>=12000 then Break')));
assert.throws(()=>suggestions(people.replace("if Count>=12 then Break;","if Count>=12 then Break;HubFetch;")));
const render=section(people,'procedure TMoaPlayForm.HubRenderPeople','procedure TMoaPlayForm.HubPeopleSearchKeyDown');
assert.match(render,/if ChatMode then Action:='dm.open\|'/);
assert.match(render,/FHubSearchEdit.OnKeyDown:=HubPeopleSearchKeyDown/);
assert.match(people,/FHubOffset:=0;FHubFullDirty:=True;FHubSearchEdit.ResetFocus;HubFetch/,'search resets pagination and releases the native input before repaint');
assert.match(people,/Body.AddPair\('memberId',ID\)/);
assert.match(people,/if \(ID=''\) or \(ID=HubText\(FHubOwnProfile,'id'\)\) then Exit/,'follow and dismiss mutations reject missing/self IDs');
assert.match(people,/FMember.HasPending/,'mutations preserve the pending-request discipline');
assert.match(people,/FMember.Request\(Value,Body.ToJSON,True\)/,'follow and dismiss use durable authenticated transport');
function publicShare(source){
 assert.match(source,/ACTION_SEND/);assert.match(source,/createChooser/);assert.match(source,/text\/plain/);
 assert.doesNotMatch(source,/ClientID|AuthID|Security|Balance|IMEI|https?:/i,'share exports the public handle, no device/auth data or nonexistent URL');
}
publicShare(share);assert.throws(()=>publicShare(share+'\n// export ClientID'));
for(const name of ['MoaPlayApp.Member.MyPage.inc','MoaPlayApp.Member.People.inc','MoaPlayMemberShare.pas']){
 const raw=fs.readFileSync(path.join(root,name));assert.deepEqual([...raw.subarray(0,3)],[239,187,191]);
 assert.equal(raw.toString().replace(/\r\n/g,'').includes('\n'),false,'Delphi source uses BOM/CRLF');
}
console.log('FIX64 profile contracts PASS on FIX70: public-only native share, read-only peer badges, purchased colors, profile privacy, bounded server suggestions, safe search and durable non-self mutations.');
