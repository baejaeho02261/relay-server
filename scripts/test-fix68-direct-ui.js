'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const native = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const source = fs.readFileSync(path.join(native, 'MoaPlayDirectMessages.pas'), 'utf8');
const bridge = fs.readFileSync(path.join(native, 'MoaPlayApp.Member.DirectMessages.inc'), 'utf8');
function routine(name, text = source) {
  const starts = [...text.matchAll(/^(?:constructor|destructor|procedure|function)\s+([\w.]+)/gm)];
  const i = starts.findIndex(m => m[1] === name); assert.ok(i >= 0, name);
  return text.slice(starts[i].index, starts[i + 1]?.index ?? text.length).replace(/\{[\s\S]*?\}/g, '');
}
function json(value = {}) {
  const result = structuredClone(value);
  Object.defineProperties(result, {
    AddPair: { value(key, item) { this[key] = item; } },
    RemovePair: { value(key) { delete this[key]; return { Free() {} }; } }
  });
  return result;
}
function compileCopy(text = source) {
  let body = routine('DMCopyMessage', text).split('\nbegin')[1].replace(/\bend;\s*$/, '');
  body = body.replace(/:=/g, '=').replace(/\bnot /g, '!').replace(/\band\b/g, '&&').replace(/\bTrue\b/g, 'true');
  body = body.replace(/if ([^\n]+) then begin/g, 'if ($1) {').replace(/\bend;/g, '}');
  body = body.replace(/TJSONObject.Create;/g, 'json();').replace(/TJSONBool.Create\(true\)/g, 'true').replace(/\.Free;/g, '.Free();');
  assert.doesNotMatch(body, /\b(?:then|begin|end|True)\b/);
  return new Function('Value', 'CurrentProjection', 'DMCopy', 'DMObj', 'DMTxt', 'Assigned', 'json',
    'let Result, Shared, Redacted; ' + body + ';return Result;');
}
const copy = compileCopy();
function project(fn, message, current) {
  return fn(message, current, v => json(v), (v, key) => v[key] ?? null, (v, key) => v[key] ?? '', v => v != null, json);
}
let projections = 0;
for (const privateValue of ['private text', '비공개 본문', '숨겨진 닉네임', 'data:image/png;base64,PRIVATE']) {
  const message = { id: 'messageA', seq: 1, own: true, text: '게시글을 공유했습니다.',
    sharedPost: { id: 'postA', title: privateValue, body: privateValue, imageThumb: privateValue, author: { nickname: privateValue } } };
  const retained = project(copy, message, false), fresh = project(copy, message, true);
  assert.deepEqual(retained.sharedPost, { id: 'postA', needsRefresh: true });
  assert.ok(!JSON.stringify(retained).includes(privateValue), 'off-page private metadata is not retained');
  assert.deepEqual(fresh.sharedPost, message.sharedPost, 'fresh authorized server projection remains available');
  assert.equal(message.sharedPost.title, privateValue, 'projection never mutates the old snapshot'); projections += 3;
}
const denied = { id: 'm2', sharedPost: { id: 'postA', unavailable: true } };
assert.deepEqual(project(copy, denied, true).sharedPost, denied.sharedPost);
assert.deepEqual(project(copy, { id: 'plain', text: '일반 대화' }, false), json({ id: 'plain', text: '일반 대화' }));
assert.match(routine('TMoaPlayDirectMessages.MergeThread'), /DMCopyMessage\(Item,SeqA>=SeqB\)/);
const brokenCopy = compileCopy(source.replace('if not CurrentProjection and Assigned(Shared) then begin', 'if CurrentProjection and Assigned(Shared) then begin'));
assert.notDeepEqual(project(brokenCopy, { id: 'm', sharedPost: { id: 'p', title: 'private' } }, false).sharedPost, { id: 'p', needsRefresh: true });
function compileHold(text = source) {
  let body = routine('TDirectThreadRow.HoldTick', text).split('\nbegin')[1].replace(/\bend;\s*$/, '');
  body = body.replace(/:=/g, '=').replace(/\bnot /g, '!').replace(/\band\b/g, '&&').replace(/\bor\b/g, '||').replace(/\bFalse\b/g, 'false');
  body = body.replace(/if ([\s\S]+?) then Exit;/g, 'if ($1) return;').replace(/CancelTouch;/g, 'CancelTouch();');
  assert.doesNotMatch(body, /\b(?:then|begin|end|Exit)\b/);
  return new Function('ctx', 'with(ctx){' + body + '}');
}
const hold = compileHold(); let held = 0;
function holdState(extra = {}) {
  const state = { FHoldTimer: { Enabled: true }, AbsoluteEnabled: true, Visible: true, TouchScope: { Enabled: true }, Self: {},
    Assigned: value => value != null, cancelled: false, CancelTouch() { this.cancelled = true; },
    FOnHold() { assert.equal(state.cancelled, true, 'the ordinary click must be cancelled first'); held++; }, ...extra };
  return state;
}
let state = holdState(); hold(state); assert.equal(held, 1); assert.equal(state.FHoldTimer.Enabled, false);
for (const disabled of [{ AbsoluteEnabled: false }, { Visible: false }, { TouchScope: { Enabled: false } }, { FOnHold: null }]) {
  state = holdState(disabled); hold(state); assert.equal(held, 1); assert.equal(state.FHoldTimer.Enabled, false);
}
assert.match(routine('TDirectThreadRow.CancelTouch'), /FHoldTimer.Enabled:=False;inherited/);
assert.match(routine('TDirectThreadRow.MouseUp'), /FHoldTimer.Enabled:=False;inherited/);
assert.match(routine('TDirectThreadRow.Click'), /FHoldTimer.Enabled:=False;inherited/, 'native Click-only delivery cannot leave a delayed hold active');
assert.match(routine('TMoaPlayDirectMessages.RenderList'), /Row.SetBounds\(0,Y,W,82\)/);
assert.match(routine('TMoaPlayDirectMessages.RenderList'), /Row.Highlight:=True/);
assert.doesNotMatch(routine('TMoaPlayDirectMessages.Build'), /FThreadMore|threadmenu/);
const render = routine('TMoaPlayDirectMessages.RenderThread');
assert.match(render, /CanOpen:=not DMBool\(Shared,'unavailable'\)/);
assert.match(render, /SharedCard.Enabled:=CanOpen;SharedCard.HitTest:=CanOpen/);
assert.match(render, /FOnPostCard\(SharedCard,Shared\)/, 'shared media uses the complete feed card renderer');
assert.match(routine('TMoaPlayForm.HubDirectMessagesPostCard', bridge), /HubFillPostCard\(Card,Snapshot,True,0,True\)/);
assert.match(routine('TMoaPlayForm.HubDirectMessagesRoute', bridge), /'post.open' then begin HubNavigate\('comments','',ID\)/);
for (const name of ['AndroidManifest.template.xml', 'AndroidManifest.full.xml']) {
  const manifest = fs.readFileSync(path.join(native, name), 'utf8');
  assert.match(manifest, /android:anyDensity="true"/); assert.doesNotMatch(manifest, /android:(?:anyDensity|largeScreens|xlargeScreens)="false"/);
}
console.log(`FIX68 DM PASS: ${projections + 2} executed share projection checks, cancelled/hidden/background long-hold checks, full-width inbox and safe server-checked shared-post routing. Native compiler/device not executed.`);
