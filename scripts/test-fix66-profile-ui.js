'use strict';
// Evaluate positions from the production Pascal source rather than a separate UI mock.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=n=>fs.readFileSync(path.join(root,n),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
const profile=read('MoaPlayApp.Member.MyPage.inc'),edit=read('MoaPlayApp.Member.ProfileEdit.inc');
function part(s,a,b){const i=s.indexOf(a),j=s.indexOf(b,i+a.length);assert.ok(i>=0&&j>i,`missing ${a}`);return s.slice(i,j);}
function calc(s,values){const js=s.replace(/\bMax\b/g,'Math.max').replace(/\bMin\b/g,'Math.min').replace(/C.Width/g,'Width').replace(/Row.Width/g,'RowWidth');assert.match(js,/^[\w\s.()+*/,-]+$/);return Function(...Object.keys(values),`return (${js})`)(...Object.values(values));}
const stats=part(profile,'procedure TMoaPlayForm.HubProfileStat','function TMoaPlayForm.HubProfileDetails');
function align(source){
 const number=source.match(/HubCount\(Value\),18,MemberText,TTextAlign\.(\w+)\);L.SetBounds\((\d+),(\d+),(Max\(1,W-\d+\)),(\d+)\)/);
 const caption=source.match(/MemberCaption\(Caption\),12,MemberText,TTextAlign\.(\w+)\);L.SetBounds\((\d+),(\d+),(Max\(1,W-\d+\)),(\d+)\)/);
 assert.ok(number&&caption);assert.equal(number[1],'Leading');assert.equal(caption[1],'Leading');
 for(let Width=240;Width<=1024;Width+=7){
  const W=Math.min(72,Math.max(1,(Width-124)/3)),StatX=Width-16-3*W;
  const left=m=>Number(m[2]);assert.equal(left(number),left(caption),'number and caption share an exact left edge');
  assert.ok(calc(number[4],{W})>0&&calc(caption[4],{W})>0,'both text boxes remain measurable');
  assert.ok(Number(number[3])+Number(number[5])<=Number(caption[3]),'number and caption cannot overlap vertically');
  // Nickname, number and caption start on the exact same first-stat axis.
  const nickname=profile.match(/nickname[^\n]+\),(StatX\+\d+),(\d+),(Max\(1,W-\d+\)),(\d+),(\d+),HubNicknameColor/);assert.ok(nickname);
  assert.equal(calc(nickname[1],{StatX}),StatX+left(number));
  const nameLines=profile.split('\n').filter(line=>line.includes("L.TagString:='member-name|'"));
  assert.equal(nameLines.length,2);for(const line of nameLines)assert.match(line,/HorzAlign:=TTextAlign.Leading/);
  assert.equal(Number(nickname[5]),11);assert.ok(Number(nickname[2])+Number(nickname[4])<35+Number(number[3]));
 }
}
align(stats);assert.throws(()=>align(stats.replace('TTextAlign.Leading','TTextAlign.Trailing')));assert.throws(()=>align(stats.replace('SetBounds(3,1','SetBounds(5,1')));
assert.doesNotMatch(profile,/HubProfileNoteBubble|profile\.note|메모 남기기/);
const frame=part(edit,'  procedure FieldFrame','  procedure Field('),field=part(edit,'  procedure Field(','  procedure Link(');
assert.match(frame,/UiRect\(C,C,MemberTransparent,12\)/);assert.match(frame,/Row.HitTest:=False;Row.AutoCapture:=False/);
assert.match(frame,/Row.Fill.Kind:=TBrushKind.None/);assert.match(frame,/Row.Stroke.Kind:=TBrushKind.Solid/);
assert.match(field,/FloatingLabel:=False/);assert.doesNotMatch(field,/FloatingLabel:=True|OnClick|SetFocus/,'native editors remain the sole input owners');
const frameBox=frame.match(/Row.SetBounds\((\d+),Y,([^,]+),H\)/);
const label=field.match(/HubLabel\(Row,MemberCaption\(Caption\),(\d+),(\d+),([^,]+),(\d+),12/);
const single=field.match(/FHubEdits\[Index\].SetBounds\((\d+),(\d+),([^,]+),(\d+)\)/);
const memo=field.match(/FHubMemo.SetBounds\((\d+),(\d+),([^,]+),([^\)]+)\)/);
assert.ok(frameBox&&label&&single&&memo);
let checks=0;
for(let Width=240;Width<=1024;Width+=7){
 const RowWidth=calc(frameBox[2],{Width});assert.equal(Number(frameBox[1])+RowWidth,Width-16);
 for(const H of [56,76]){
  const input=H===56?single:memo;const x=Number(input[1]),y=Number(input[2]),w=calc(input[3],{RowWidth}),h=calc(input[4],{H});
  assert.ok(x>=0&&x+w<=RowWidth);assert.ok(y>=Number(label[2])+Number(label[4]));assert.ok(y+h<=H);
 }
 const textWidth=calc(edit.match(/TextW:=(Max\(1,C.Width-100\));TextH:=/)[1],{Width});
 assert.ok(16+textWidth<=Width-68-16,'description and switch reserve separate horizontal columns');
 assert.ok(Width-68+52<=Width-16);checks++;
}
const link=part(edit,'  procedure Link(','\nbegin\n  Profile:=');
assert.match(link,/HubTextAction\(C,'',Action,0,Y,C.Width/);assert.match(link,/B.XRadius:=0;B.YRadius:=0/);
assert.doesNotMatch(link,/AddMemberSvg/,'reference rows have no trailing arrow');
assert.match(edit,/if Count=0 then Link\('링크','','pdetail.link.new',MemberCaption\('링크 추가'\)\)/);
assert.match(edit,/Link\('배너','음악, 프로필 등을 추가해보세요.','pdetail.open\|banners',IntToStr\(Count\)\)/);
for(const action of ['pdetail.open|accounttype','pdetail.privacy','pdetail.open|verification'])assert.ok(edit.includes(action));
assert.match(edit,/Link\('개인정보 설정'[^\n]+;Rule;/);assert.match(edit,/Link\('프로필 인증 표시'[^\n]+;Rule;/);
const preview=edit.slice(edit.indexOf('procedure TMoaPlayForm.HubUpdateProfilePreview'));
assert.doesNotMatch(preview,/Initial|nickname|SetFocus|\.Free/);assert.match(preview,/TagString='avatar-placeholder'/);
assert.match(preview,/TControl\(Child\).Visible:=not Loaded/);assert.match(preview,/if not Loaded and not HasDefault then/);
assert.match(preview,/AddMemberSvg\([^\n]+'user'[^\n]+True\).TagString:='avatar-placeholder'/);
assert.match(preview,/FHubProfilePhotoRemove.Visible:=Encoded<>''/);
for(const name of ['MoaPlayApp.Member.MyPage.inc','MoaPlayApp.Member.ProfileEdit.inc']){
 const bytes=fs.readFileSync(path.join(root,name));assert.deepEqual([...bytes.subarray(0,3)],[239,187,191]);assert.doesNotMatch(bytes.toString(),/(?<!\r)\n/);
}
console.log(`FIX66 profile UI PASS on FIX68: ${checks} responsive layouts, aligned numbers/name, removed notes, bordered static fields, reference order/full-width actions, real saved details and reusable person-avatar fallback.`);
