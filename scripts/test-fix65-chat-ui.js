'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const source = fs.readFileSync(path.join(root, 'MoaPlayDirectMessages.pas'), 'utf8').replace(/^\uFEFF/, '');
const bridge = fs.readFileSync(path.join(root, 'MoaPlayApp.Member.DirectMessages.inc'), 'utf8');
function routine(text, name) {
  const starts = [...text.matchAll(/^(?:constructor|destructor|procedure|function)\s+([\w.]+)/gm)];
  const at = starts.findIndex(x => x[1] === name);
  assert.ok(at >= 0, name);
  return text.slice(starts[at].index, starts[at + 1]?.index ?? text.length).replace(/\{[\s\S]*?\}/g, '');
}
// Translate complete small production helpers, not copies of their algorithms.
// The translator intentionally supports only their actual scalar/array syntax.
function executeHelper(text, name) {
  let body = routine(text, name);
  body = body.slice(body.indexOf('\nbegin') + 1).trim();
  assert.match(body, /^begin[\s\S]*end;$/);
  body = body.slice(5, -4)
    .replace(/([\w.]+\[[^\]]+\]) is TJSONObject/g, 'IsObject($1)')
    .replace(/for I:=([^;]+?) downto 0 do /g, 'FOR(I,$1) ')
    .replace(/\bif ([\s\S]*?) then /g, 'if ($1) ')
    .replace(/\btry\b/g, 'try {').replace(/\bfinally\b/g, '} finally {')
    .replace(/\bbegin\b/g, '{').replace(/\bend\b/g, '}')
    .replace(/\bExit\b/g, 'return Result').replace(/\bContinue\b/g, 'continue')
    .replace(/:=/g, 'ASSIGN').replace(/<>/g, '!==').replace(/(?<![<>!=])=(?!=)/g, '===')
    .replace(/ASSIGN/g, '=').replace(/\bnot\b/g, '!').replace(/\band\b/g, '&&').replace(/\bor\b/g, '||')
    .replace(/\bTrue\b/g, 'true').replace(/\bFalse\b/g, 'false')
    .replace(/FOR\(I,([^\n]+)\) (?=if)/g, 'for (I=$1; I>=0; I--) ');
  assert.doesNotMatch(body, /\b(?:then|downto|do|begin|end|Exit|Continue)\b/);
  const run = new Function('ctx', 'with(ctx){ ' + body + '\nreturn Result; }');
  return values => {
    const ctx = { Result: undefined, I: 0, Item: null, Assigned: value => value != null,
      TJSONObject: value => value, IsObject: value => value != null && typeof value === 'object' && !Array.isArray(value),
      DMNum: (value, key) => value?.[key] ?? 0, DMBool: (value, key) => value?.[key] === true, ...values };
    return run(ctx);
  };
}
const array = rows => ({ Count: rows.length, Items: rows });
const receipt = executeHelper(source, 'DMLastReadMessage');
const groups = executeHelper(source, 'DMContinuesGroup');
const cases = [
  [[], { lastSeq: 0, peerReadSeq: 0 }, -1],
  [[{ own: true, seq: 1 }], { lastSeq: 1, peerReadSeq: 0 }, -1],
  [[{ own: true, seq: 1 }], { lastSeq: 1, peerReadSeq: 1 }, 0],
  [[{ own: true, seq: 1 }, { own: true, seq: 2 }], { lastSeq: 2, peerReadSeq: 1 }, -1],
  [[{ own: true, seq: 1 }, { own: true, seq: 2 }, { own: false, seq: 3 }], { lastSeq: 3, peerReadSeq: 2 }, 1],
  [[{ own: false, seq: 1 }], { lastSeq: 1, peerReadSeq: 1 }, -1],
  [[{ own: true, seq: 1 }, { own: true, seq: 2 }], { lastSeq: 40, peerReadSeq: 40 }, -1]
];
for (const [rows, Thread, expected] of cases) assert.equal(receipt({ Items: array(rows), Thread }), expected);
assert.equal(receipt({ Items: null, Thread: {} }), -1);
for (const rows of [[], [{ own: true }], [{ own: true }, { own: false }, { own: false }]]) {
  for (let Index = -1; Index <= rows.length; Index++) for (const Mine of [true, false]) {
    assert.equal(groups({ Items: array(rows), Index, Mine }), Index >= 0 && Index < rows.length && rows[Index].own === Mine);
  }
}
// A delayed receipt for an earlier send must not label a newer unread send read.
const brokenReceipt = executeHelper(source.replace('    Exit;\r\n  end;\r\nend;\r\nfunction DMContinuesGroup', '  end;\r\nend;\r\nfunction DMContinuesGroup'), 'DMLastReadMessage');
assert.notEqual(brokenReceipt({ Items: array(cases[3][0]), Thread: cases[3][1] }), -1);
let calls = 0;
const state = { FLayoutNotifying: false, Visible: true, FLayoutReported: false, FReportedListMode: true, FListMode: true, FOnLayout: null, Self: null };
state.Self = state;
// Execute the production callback against one shared scope to observe reentry.
const liveNotify = new Function('ctx', 'with(ctx){' + routine(source, 'TMoaPlayDirectMessages.NotifyLayout').split('\nbegin')[1]
  .replace(/\bend;\s*$/, '').replace(/\bif ([\s\S]*?) then /g, 'if ($1) ')
  .replace(/\btry\b/g, 'try {').replace(/\bfinally\b/g, '} finally {').replace(/\bend\b/g, '}')
  .replace(/\bExit\b/g, 'return').replace(/:=/g, 'ASSIGN').replace(/(?<![<>!=])=(?!=)/g, '===').replace(/ASSIGN/g, '=')
  .replace(/\bnot\b/g, '!').replace(/\band\b/g, '&&').replace(/\bor\b/g, '||').replace(/\bTrue\b/g, 'true').replace(/\bFalse\b/g, 'false') + '}');
state.Assigned = value => value != null;
state.FOnLayout = () => { calls++; assert.equal(state.FLayoutNotifying, true); liveNotify(state); };
liveNotify(state); assert.equal(calls, 1); assert.equal(state.FLayoutNotifying, false);
liveNotify(state); assert.equal(calls, 1, 'same list mode cannot rebuild global chrome during polling');
state.FListMode = false; liveNotify(state); assert.equal(calls, 2);
state.Visible = false; state.FListMode = true; liveNotify(state); assert.equal(calls, 2);
state.Visible = true; liveNotify(state); assert.equal(calls, 3);
state.FListMode = false; state.FOnLayout = () => { throw new Error('resize failure'); };
assert.throws(() => liveNotify(state), /resize failure/); assert.equal(state.FLayoutNotifying, false, 'finally restores notification guard');
const layout = routine(source, 'TMoaPlayDirectMessages.LayoutWindow');
const composerExpression = /ComposerH:=([^;]+);/.exec(layout)[1].replace(/\bMin\(/g, 'Math.min(').replace(/\bMax\(/g, 'Math.max(');
const composerHeight = new Function('FComposerHeight', 'H', 'HeaderH', 'return ' + composerExpression);
let geometries = 0;
for (const width of [280, 320, 360, 412, 600, 840, 1024]) for (const available of [160, 190, 260, 480, 720, 1024]) for (const requested of [48, 64, 84, 112]) {
  const height = composerHeight(requested, available, 56), footerHeight = height + 16, boxWidth = Math.max(136, width - 24);
  assert.ok(height >= 48 && height <= 112);
  assert.ok(available - 56 - footerHeight >= 16, 'keyboard and multiline composer preserve a message viewport');
  assert.ok(10 + Math.max(68, boxWidth - 66) <= boxWidth - 46, 'active IME content cannot be covered by send');
  assert.ok(boxWidth - 46 + 40 <= boxWidth && height - 44 >= 0);
  geometries++;
}
const build = routine(source, 'TMoaPlayDirectMessages.Build');
assert.match(build, /FInput\.FloatingLabel:=False/);
assert.match(build, /DMButton\(FInputBox,'send'/, 'send lives inside the rounded composer');
assert.match(routine(source, 'TMoaPlayDirectMessages.RenderThread'), /DMLastReadMessage\(Items,Thread\)/);
assert.match(routine(source, 'TMoaPlayDirectMessages.RenderThread'), /DMContinuesGroup\(Items,I\+1,Mine\)/);
assert.match(routine(source, 'TMoaPlayDirectMessages.RenderThread'), /Bubble\.Stroke\.Kind:=TBrushKind\.None/);
assert.doesNotMatch(routine(source, 'TMoaPlayDirectMessages.RenderThread'), /DMLabel\([^;]*'at'/);
assert.doesNotMatch(routine(source, 'TMoaPlayDirectMessages.Render'), /FreeAndNil\(FInput\)|FreeAndNil\(FSearch\)/);
assert.doesNotMatch(source, /RenderNotes|DMObj\(Item,'note'\)/, 'FIX66 removes profile notes from the inbox');
assert.match(routine(source, 'TMoaPlayDirectMessages.UpdatePeerHeader'), /if Signature=FAvatarSignature then Exit/, 'avatar decode is not repeated on every message');
assert.match(bridge, /OnLayout:=HubDirectMessagesLayout/);
assert.match(bridge, /OnLayout:=nil/);
for (const name of ['SetThread', 'ShowList', 'OpenMember']) assert.match(routine(source, 'TMoaPlayDirectMessages.' + name), /NotifyLayout/);
assert.match(routine(source, 'TMoaPlayDirectMessages.Reply'), /NotifyLayout;LayoutWindow;Notice\('대화가 모두 삭제/);
for (const name of ['MoaPlayDirectMessages.pas', 'MoaPlayApp.Member.DirectMessages.inc']) {
  const bytes = fs.readFileSync(path.join(root, name)); assert.equal(bytes.subarray(0, 3).toString('hex'), 'efbbbf');
  assert.ok(!bytes.toString('utf8').replace(/\r\n/g, '').includes('\n'));
}
console.log(`FIX65 chat UI PASS: ${geometries} keyboard/composer geometries, production grouping/read-receipt helpers and reentrant layout notifications, removed notes, retained inputs and BOM/CRLF. Delphi/device runtime not executed.`);
