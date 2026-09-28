'use strict';
// These contracts evaluate the native layout expressions. Device typography and
// rendering still require RAD Studio / FMX; this is not a screenshot test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const bytes = fs.readFileSync(path.join(base, 'MoaPlayApp.Member.MyPage.inc'));
const source = bytes.toString('utf8').replace(/^\uFEFF/, '').replace(/\r/g, '');
const own = source.slice(source.indexOf('procedure TMoaPlayForm.HubRenderMe'), source.indexOf('procedure TMoaPlayForm.HubRenderMember'));
const peer = source.slice(source.indexOf('procedure TMoaPlayForm.HubRenderMember'), source.indexOf('procedure TMoaPlayForm.HubRenderInfo'));
const actions = fs.readFileSync(path.join(base, 'MoaPlayApp.Member.Actions.inc'), 'utf8');
const navigation = fs.readFileSync(path.join(base, 'MoaPlayApp.Member.Navigation.inc'), 'utf8');
assert.doesNotMatch(own, /HubProfileStat\(|HubProfileSuggestions\(|HubProfileTabs\(|HubRenderOwnComments\(|HubRenderProfileGallery\(/);
assert.doesNotMatch(source, /HubTitleBadge(?:Width)?\(/, 'retired titles have no profile render path');
assert.match(peer, /if Own then begin HubRenderMe\(Data\);Exit;end;/);
assert.match(peer, /HubBool\(Data,'profilePostsHidden'\)/);
assert.match(peer, /HubProfileTabs\(FHubPage,False,ID,FHubY\)/);
assert.doesNotMatch(peer, /accountEmail|providerAccountEmail/);
assert.match(own, /Email:=Trim\(HubText\(Profile,'accountEmail'\)\)/);
assert.match(own, /if Email<>'' then begin\s+L:=HubLabel\(AccountPanel,Email,/);
assert.match(own, /ProfileAction\('edit','profile','프로필 편집'/);
assert.match(own, /ProfileAction\('share','profile.share','프로필 공유'/);
assert.match(own, /HubIconButton\(Hero,Icon,Action,X,Y,44,44\)/);
assert.match(own, /HubTextAction\(C,'','profile.account',16,AccountTop,C.Width-32,AccountH\)/);
assert.match(actions, /Action='profile.account' then begin HubOpenAccountMenu;Exit;end;/);
assert.match(navigation, /HubTextAction\(Group,'','profile.account.add'/, 'addition remains available in the account menu');
assert.match(own, /Provider='kakao'/);
assert.match(own, /Provider='google'/);
assert.match(own, /BrandFill:=\$FFFEE500/);
assert.match(own, /BrandFill:=\$FFE8F0FE/);
assert.match(own, /Badge.SetBounds\(AccountPanel.Width-ProviderW-16,12,ProviderW,24\)/);
assert.doesNotMatch(own, /Arc|OrbitAction|TSkSvg.Create|TPath.Create|profile\.create|profile\.people/);

function expression(name, occurrence = 0) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const matches = [...own.matchAll(new RegExp('\\b' + escaped + ':=([^;]+);', 'g'))];
  assert.ok(matches[occurrence], `missing native ${name} expression ${occurrence}`);
  return matches[occurrence][1];
}
function evaluate(expr, scope) {
  const js = expr.replace(/\bMin\b/g, 'Math.min').replace(/\bMax\b/g, 'Math.max').replace(/\bTrue\b/g, 'true');
  assert.match(js, /^[\w\s.()+*/,-]+$/, 'native geometry contains only whitelisted arithmetic');
  return Function(...Object.keys(scope), `return (${js})`)(...Object.values(scope));
}
function set(name, scope, occurrence = 0) {
  const value = evaluate(expression(name, occurrence), scope);
  const parts = name.split('.');
  if (parts.length === 1) scope[name] = value;
  else scope[parts[0]][parts[1]] = value;
}
function box(x, y, w, h) { return {x, y, w, h}; }
function inside(b, w, h, message) {
  assert.ok(b.w > 0 && b.h > 0 && b.x >= -1e-6 && b.y >= -1e-6 && b.x + b.w <= w + 1e-6 && b.y + b.h <= h + 1e-6, message);
}
function separated(a, b, message) {
  assert.ok(a.x + a.w <= b.x + 1e-6 || b.x + b.w <= a.x + 1e-6 || a.y + a.h <= b.y + 1e-6 || b.y + b.h <= a.y + 1e-6, message);
}
let checked = 0;
for (const width of [240, 280, 320, 360, 390, 412, 480, 600, 800, 1024]) {
  for (const providerW of [0, 54, 60]) {
    // Deliberately large measured heights exercise wrapped Korean names, long
    // provider names, and long email addresses without relying on JS fonts.
    for (const measuredName of [28, 58, 90]) for (const measuredAccount of [20, 44, 86]) for (const measuredEmail of [0, 18, 38, 112]) {
      const scope = {
        FHubPage: {Width: width}, C: {}, Hero: {Position: {Y: 0}},
        Nickname: 'nickname', Account: 'account', Email: 'email',
        HubBodyHeight: text => text === 'nickname' ? measuredName : text === 'account' ? measuredAccount : measuredEmail
      };
      set('C.Width', scope);
      scope.Hero.Width = scope.C.Width - 32;
      for (const key of ['AvatarSize', 'AvatarX', 'AvatarY', 'GroupW', 'LeftActionX', 'RightActionX', 'ActionY', 'NameY', 'NameSize', 'NameH', 'Hero.Height', 'AccountTop', 'AccountTextW', 'AccountNameY', 'AccountNameH', 'EmailY', 'EmailH', 'AccountH']) set(key, scope);
      if (measuredEmail) { set('EmailH', scope, 1); set('AccountH', scope, 1); }
      const s = scope;
      const portrait = box(s.AvatarX, s.AvatarY, s.AvatarSize, s.AvatarSize);
      const edit = box(s.LeftActionX, s.ActionY, 44, 44);
      const share = box(s.RightActionX, s.ActionY, 44, 44);
      const name = box(8, s.NameY, s.Hero.Width - 16, s.NameH);
      assert.equal(s.AvatarX + s.AvatarSize / 2, s.Hero.Width / 2);
      assert.equal((edit.x + share.x + share.w) / 2, s.Hero.Width / 2);
      assert.ok(s.AvatarSize >= 64);
      for (const b of [portrait, edit, share, name]) inside(b, s.Hero.Width, s.Hero.Height, 'identity or action is clipped');
      for (const [a, b] of [[portrait, edit], [portrait, share], [edit, share], [name, portrait], [name, edit], [name, share]]) separated(a, b, 'identity and actions must not overlap');
      assert.ok(portrait.x - (edit.x + edit.w) >= 16 && share.x - (portrait.x + portrait.w) >= 16);
      assert.ok(s.AccountTop >= s.Hero.Height + 16, 'account begins after the complete wrapped nickname');
      const panelW = s.C.Width - 32;
      const heading = box(16, 14, panelW - providerW - 48, 20);
      const account = box(16, s.AccountNameY, s.AccountTextW, s.AccountNameH);
      const chevron = box(panelW - 34, (s.AccountH - 18) / 2, 18, 18);
      assert.ok(s.AccountTextW >= 144, 'small phones preserve full-width account text');
      for (const b of [heading, account, chevron]) inside(b, panelW, s.AccountH, 'account content is clipped');
      separated(heading, account, 'account name clears the header');
      separated(account, chevron, 'account name clears the menu affordance');
      if (providerW) {
        const badge = box(panelW - providerW - 16, 12, providerW, 24);
        inside(badge, panelW, s.AccountH, 'provider badge is clipped');
        separated(badge, heading, 'provider badge clears the account heading');
        separated(badge, account, 'provider badge clears the account name');
      }
      if (measuredEmail) {
        const email = box(16, s.EmailY, s.AccountTextW, s.EmailH);
        inside(email, panelW, s.AccountH, 'full measured owner email fits');
        separated(email, account, 'email clears the complete wrapped account name');
        separated(email, chevron, 'email clears the menu affordance');
        assert.equal(s.AccountH - (email.y + email.h), 16);
      } else assert.equal(s.AccountH - (account.y + account.h), 16);
      checked++;
    }
  }
}
assert.deepEqual([...bytes.subarray(0, 3)], [239, 187, 191]);
assert.equal(bytes.toString().replace(/\r\n/g, '').includes('\n'), false);
console.log(`FIX75 profile PASS: ${checked} native geometry scenarios; separated 44dp actions, measured identity/email, provider menu, retired titles, preserved peer privacy.`);
