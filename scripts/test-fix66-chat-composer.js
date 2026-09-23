'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const native = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const read = name => fs.readFileSync(path.join(native, name), 'utf8').replace(/^\uFEFF/, '');
const dm = read('MoaPlayDirectMessages.pas'), dashboard = read('MoaPlayApp.Dashboard.inc');
function routine(text, name) {
  const starts = [...text.matchAll(/^(?:constructor|destructor|procedure|function)\s+([\w.]+)/gm)];
  const i = starts.findIndex(m => m[1] === name); assert.ok(i >= 0, name);
  return text.slice(starts[i].index, starts[i + 1]?.index ?? text.length).replace(/\{[\s\S]*?\}/g, '');
}
const translate = body => body.replace(/:=/g, 'ASSIGN').replace(/<>/g, '!==').replace(/(?<![<>!=])=(?!=)/g, '===').replace(/ASSIGN/g, '=')
  .replace(/\bnot\b/g, '!').replace(/\band\b/g, '&&').replace(/\bor\b/g, '||').replace(/\bFalse\b/g, 'false').replace(/\bTrue\b/g, 'true')
  .replace(/\bExit\b/g, 'return').replace(/\bif ([\s\S]*?) then /g, 'if ($1) ');
function execute(text, name, state) {
  let body = routine(text, name).split('\nbegin')[1].replace(/\bend;\s*$/, '');
  body = translate(body).replace(/\bHubUpdateCommentComposer;/g, 'HubUpdateCommentComposer();').replace(/\belse\b/g, ';else');
  assert.doesNotMatch(body, /\b(?:begin|end|then|Exit)\b/);
  return new Function('ctx', 'with(ctx){' + body + '}')(state);
}
const update = state => execute(dashboard, 'TMoaPlayForm.HubUpdateCommentComposer', state);
const submit = state => execute(dashboard, 'TMoaPlayForm.HubCommentSendClick', state);
let sends = 0;
function context(overrides = {}) {
  const state = { Ready: false, FHubCommentSend: { Enabled: false, Opacity: 0 }, FHubCommentEdit: { Text: '댓글 내용' }, FMember: { HasPending: false }, FClosing: false,
    FHubView: 'comments', FHubCommentContext: 'postA', FHubPostID: 'postA', Assigned: value => value != null, Trim: value => value.trim(),
    HubUpdateCommentComposer() { update(state); },
    HubActionClick(sender) { assert.equal(sender, state.FHubCommentEdit); sends++; state.FMember.HasPending = true; }, ...overrides };
  return state;
}
let state = context(); submit(state); assert.equal(sends, 1); assert.equal(state.FHubCommentSend.Enabled, false); assert.equal(state.FHubCommentSend.Opacity, 0.35);
submit(state); assert.equal(sends, 1, 'repeated button taps cannot enqueue another pending comment');
state.FMember.HasPending = false; update(state); assert.equal(state.FHubCommentSend.Enabled, true, 'failed acknowledgement preserves retry and text'); assert.equal(state.FHubCommentEdit.Text, '댓글 내용');
state.FHubCommentEdit.Text = ''; update(state); assert.equal(state.FHubCommentSend.Enabled, false, 'successful acknowledgement clears and disables input action');
for (const changes of [{ FClosing: true }, { FHubView: 'feed' }, { FHubPostID: 'postB' }, { FHubCommentEdit: { Text: ' \n ' } }, { FMember: null }, { FMember: { HasPending: true } }]) {
  const blocked = context(changes), before = sends; submit(blocked); assert.equal(sends, before); assert.equal(blocked.FHubCommentSend.Enabled, false);
}
const key = routine(dashboard, 'TMoaPlayForm.HubCommentKeyDown');
assert.match(key, /Key:=0;KeyChar:=#0;/); assert.match(key, /HubCommentSendClick\(FHubCommentSend\)/, 'IME and visible send share the same guard and mutation route');
assert.doesNotMatch(routine(dashboard, 'TMoaPlayForm.HubCommentChanged'), /HubActionClick|HubCommentSendClick/, 'typing never sends');
const dmBuild = routine(dm, 'TMoaPlayDirectMessages.Build'), dashBuild = routine(dashboard, 'TMoaPlayForm.BuildDashboardUI');
assert.match(dmBuild, /FInputBox:=DMRect\(FFooter,12,4,240,48,MemberSoft,12\)/);
assert.match(dmBuild, /FSend.XRadius:=9;FSend.YRadius:=9/);
assert.match(dashBuild, /FHubCommentSend.XRadius:=9;FHubCommentSend.YRadius:=9/);
assert.match(dashBuild, /FHubCommentEdit\)\.FloatingLabel:=False/);
assert.match(dashBuild, /FHubCommentSend:=HubIconButton\(FHubCommentBox,'send'/);
assert.doesNotMatch(dashboard, /댓글을 남겨보세요|HubResizeProfileNote/);
assert.doesNotMatch(dm, /RenderNotes|DMObj\(Item,'note'\)/);
assert.doesNotMatch(routine(dm, 'TMoaPlayDirectMessages.RenderList'), /'more'|'menu\|'/);
assert.doesNotMatch(dmBuild, /'threadmenu'|FThreadMore/); assert.match(routine(dm, 'TMoaPlayDirectMessages.ThreadHold'), /ShowMenu/, 'FIX68 moves deletion to a row hold');
assert.match(routine(dm, 'TMoaPlayDirectMessages.ShowMenu'), /'delete\|'/);
assert.match(routine(dm, 'DMAvatar'), /AddMemberSvg\(Circle,Circle,'user'/);
assert.doesNotMatch(routine(dm, 'DMAvatar'), /Initial|Copy\(|nickname/);
assert.match(dashBuild, /FHubHeaderAccount,'',14,MemberText/);
assert.match(routine(dashboard, 'TMoaPlayForm.HubUpdateHeader'), /HubTextWidth\(Title,14\)/);
// Execute the production bounds, rather than fixed copies, over narrow phones,
// tablets, keyboard heights and the optional reply/edit strip.
const layout = routine(dashboard, 'TMoaPlayForm.ResizeDashboardUI');
const expr = name => new RegExp(name.replaceAll('.', '\\.') + '\\.SetBounds\\(([^;]+)\\);').exec(layout)?.[1];
function bounds(name, ctx) { const source = expr(name); assert.ok(source, name); return new Function('ctx', 'with(ctx){return [' + source.replace(/\bMax\(/g, 'Math.max(') + ']}')(ctx); }
let geometries = 0;
for (const W of [240, 280, 320, 360, 412, 600, 840, 1024]) for (const H of [160, 240, 640, 960]) for (const ReplyH of [0, 32]) {
  const ctx = { W, H, ReplyH, FHubCommentBox: { Width: 0 } };
  const box = bounds('FHubCommentBox', ctx); ctx.FHubCommentBox.Width = box[2];
  const text = bounds('FHubCommentEdit', ctx), send = bounds('FHubCommentSend', ctx);
  assert.equal(box[0], 12); assert.equal(box[0] + box[2], W - 12); assert.equal(box[3], 48);
  assert.ok(text[0] + text[2] <= send[0], 'editor text does not overlap the send target');
  assert.ok(send[0] + send[2] <= box[2] && send[1] + send[3] <= box[3]);
  assert.ok(text[1] + text[3] <= box[3]); geometries++;
}
// Source-sensitivity: missing context or pending guards must trip scenarios.
const stateGuard = routine(dashboard, 'TMoaPlayForm.HubUpdateCommentComposer');
assert.match(stateGuard, /FHubCommentContext=FHubPostID/); assert.match(stateGuard, /not FMember.HasPending/);
for (const name of ['MoaPlayDirectMessages.pas', 'MoaPlayApp.Dashboard.inc']) {
  const bytes = fs.readFileSync(path.join(native, name)); assert.equal(bytes.subarray(0, 3).toString('hex'), 'efbbbf');
  assert.ok(!bytes.toString('utf8').replace(/\r\n/g, '').includes('\n'));
}
console.log(`FIX66 chat/comment UI PASS: ${geometries} production composer bounds, executed send-state guards, IME/button parity, note-free/menu-free inbox, real person fallback and compact account headers. Delphi/device runtime not executed.`);
