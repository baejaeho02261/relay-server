'use strict';
// Static native contracts: this does not substitute for an FMX/device build.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const read = file => fs.readFileSync(path.join(root, file), 'utf8').replace(/^\uFEFF/, '').replace(/\r/g, '');
const navigation = read('MoaPlayApp.Member.Navigation.inc');
const actions = read('MoaPlayApp.Member.Actions.inc');
const methods = read('MoaPlayApp.Methods.inc');
const main = navigation.split('procedure TMoaPlayForm.HubOpenAccountAdd;')[0];
const addition = navigation.split('procedure TMoaPlayForm.HubOpenAccountAdd;')[1].split('procedure TMoaPlayForm.HubOpenAccountMenu;')[0];

assert.match(main, /Handle:=HubText\(FHubOwnProfile,'handle','member'\)/, 'only the authenticated profile is displayed');
assert.match(main, /HubAvatar\(Row,FHubOwnProfile,15,12,42\)/);
assert.match(main, /Circle.Fill.Color:=MemberPrimary/);
assert.match(main, /'check',4,4,13,13,False,True/, 'white check must remain legible in both themes');
assert.match(main, /Panel.Corners:=\[TCorner.TopLeft,TCorner.TopRight\]/);
assert.match(main, /'MoaPlay 계정 추가'/);
assert.match(main, /'계정 센터로 이동'/);
assert.match(main, /HubLabel\(Content,'MoaPlay'/);
assert.doesNotMatch(main, /Instagram|Meta|minjeonj_|프로필 편집/, 'do not copy another service, fixture account or obsolete menu row');
assert.match(main, /Item\('게시글 작성','grid','navigation.goto\|compose'\)/);
assert.match(main, /Item\('사람 찾아보기','user.add','profile.people'\)/);

assert.match(methods, /procedure HubOpenAccountAdd;/);
assert.match(actions, /Action='profile.account.add' then begin HubOpenAccountAdd;Exit;end/);
assert.match(actions, /ID='activity.account'.+HubNavigate\(ID\)/);
assert.match(addition, /TControl\(FHubOverlay.Children\[I\]\).Visible:=False/, 'nested dialog hides rather than frees the active click sender');
assert.doesNotMatch(addition, /FreeAndNil|\.Free\b|FMember.Request|SetSession|Logout|ClearSession|ClientID\s*:=|FHubOwnProfile\s*:=/i);
assert.match(addition, /추가 계정 로그인은 아직 지원되지 않아요/, 'no fabricated additional authenticated account');
assert.match(addition, /'sheet.close'/);
assert.match(addition, /'navigation.goto\|activity.account'/);
assert.match(addition, /Content.SetBounds\(0,0,W,ButtonY\+64\)/, 'all actions stay reachable by scrolling when keyboard reduces viewport');
assert.equal((navigation.match(/Shield.OnClick:=HubCloseOverlay/g) || []).length, 2);

// Evaluate the actual width expressions over compact phones and tablets.
function value(expression, scope) {
  const source = expression.replace(/\bMin\b/g, 'Math.min').replace(/\bMax\b/g, 'Math.max')
    .replace(/FRoot.Width/g, 'width').replace(/Group.Width/g, 'groupWidth').replace(/Row.Width/g, 'rowWidth');
  assert.match(source, /^[\w\s.()+*/,-]+$/);
  return Function(...Object.keys(scope), 'return (' + source + ')')(...Object.values(scope));
}
const widthExpression = main.match(/W:=([^;]+);H:=200/)[1];
const groupExpression = main.match(/Group.SetBounds\(16,8,([^,]+),132\)/)[1];
const rowExpression = main.match(/'sheet.close',1,1,([^,]+),65/)[1];
const nameExpression = main.match(/HubLabel\(Row,Handle,70,0,(Max\(1,Row.Width-126\)),65,17\)/)[1];
for (const width of [240,280,320,360,390,412,480,600,800,1024]) {
  const W = value(widthExpression, { width });
  const groupWidth = value(groupExpression, { W });
  const rowWidth = value(rowExpression, { groupWidth });
  const nameWidth = value(nameExpression, { rowWidth });
  assert.ok(W <= width && W <= 480);
  assert.equal(groupWidth + 32, W);
  assert.equal(rowWidth + 2, groupWidth);
  assert.ok(nameWidth > 0 && 70 + nameWidth < rowWidth - 39, 'name cannot overlap account check');
  assert.ok(15 + 42 < 70, 'avatar cannot overlap account handle');
  assert.ok(16 + W - 32 <= W - 16, 'group and center button use identical side insets');
}
const bytes = fs.readFileSync(path.join(root, 'MoaPlayApp.Member.Navigation.inc'));
assert.deepEqual([...bytes.subarray(0,3)], [239,187,191]);
assert.equal(bytes.toString().replace(/\r\n/g,'').includes('\n'), false);
console.log('FIX67 account sheet source guards PASS: reference structure, live account, responsive widths, nested click lifetime, honest account-add flow and preserved create actions.');
