'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const native = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const read = name => fs.readFileSync(path.join(native, name), 'utf8').replace(/^\uFEFF/, '');
const actions = read('MoaPlayApp.Member.Actions.inc'), activity = read('MoaPlayApp.Member.ActivitySettings.inc');
const guard = actions.match(/if Action='comment.create' then\s*begin([\s\S]*?)Body.AddPair\('body'/)?.[1];
assert.ok(guard, 'production comment submission guards');
function compileGuard(value) {
  let js = value.replace(/:=/g, 'ASSIGN').replace(/<>/g, '!==').replace(/(?<![<>!=])=(?!=)/g, '===').replace(/ASSIGN/g, '=')
    .replace(/\bnot /g, '!').replace(/\band\b/g, '&&').replace(/\bor\b/g, '||')
    .replace(/if ([\s\S]+?) then Exit;/g, 'if ($1) return false;');
  assert.doesNotMatch(js, /\b(?:then|begin|end|Exit)\b/);
  return new Function('ctx', 'with(ctx){let Item; ' + js + ';return true;}');
}
const canSubmit = compileGuard(guard);
function state(changes = {}, post = { id: 'postA' }) {
  return { FHubView: 'comments', FHubCommentEdit: { Text: '댓글' }, FHubCommentContext: 'postA', FHubPostID: 'postA',
    FMember: { HasPending: false }, Assigned: v => v != null, Trim: v => v.trim(),
    HubCached: () => ({ post }), HubObject: (o, k) => o?.[k] ?? null, HubText: (o, k) => o?.[k] ?? '', HubBool: (o, k) => o?.[k] === true, ...changes };
}
assert.equal(canSubmit(state()), true);
let blocked = 0;
for (const changes of [{ FHubView: 'feed' }, { FHubCommentEdit: null }, { FHubCommentEdit: { Text: ' \n ' } },
  { FHubCommentContext: 'postB' }, { FMember: { HasPending: true } }]) { assert.equal(canSubmit(state(changes)), false); blocked++; }
for (const post of [null, { id: 'postB' }, { id: 'postA', unavailable: true }, { id: 'postA', commentsDisabled: true }, { id: 'postA', archived: true }]) {
  assert.equal(canSubmit(state({}, post)), false); blocked++;
}
const broken = compileGuard(guard.replace(" or HubBool(Item,'archived')", ''));
assert.equal(broken(state({}, { id: 'postA', archived: true })), true, 'mutation verifies that the archive guard changes behavior');
assert.ok(actions.indexOf('HubNewsAction(Action,ID)') < actions.indexOf('HubSocialAction(Action,ID'), 'news card dispatch reaches inline read first');
assert.doesNotMatch(actions, /HubNavigate\('article'\)/, 'article opens no separate detail screen');
assert.match(actions, /if ReturnView='news' then begin HubNavigate\('news'\);Exit;end;\s*if ReturnView='home' then FDashboardActiveTab:=0/, 'legacy news link exits before root-tab history clearing');
assert.match(activity, /Action='activity.archive' then begin HubNavigate\('archives'\);Exit;end/);
assert.doesNotMatch(activity, /게시글 보관 기능은 아직 제공되지 않습니다/);
assert.match(activity, /Leaf\('archive','보관한 게시물',.*'archives'/);
assert.match(activity, /Leaf\('youractivity','소식',.*'news'/);
for (const file of ['MoaPlayApp.Member.Actions.inc', 'MoaPlayApp.Member.ActivitySettings.inc']) {
  const bytes = fs.readFileSync(path.join(native, file)); assert.equal(bytes.subarray(0, 3).toString('hex'), 'efbbbf');
  assert.ok(!bytes.toString('utf8').replace(/\r\n/g, '').includes('\n'));
}
console.log(`FIX68 ACTIONS PASS: executed ${blocked} invalid/stale/disabled comment submission cases, valid submission, inline news and preserved settings/archive routes. Native compiler not executed.`);
