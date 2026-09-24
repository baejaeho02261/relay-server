'use strict';
// Focused source guards for the new retained FMX controls and the regressions
// they could reintroduce. These checks do not substitute for a Delphi build.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const declarations = require('./native-declarations');

function WithoutComments(source) {
 return source.replace(/\(\*[\s\S]*?\*\)|\{[\s\S]*?\}|\/\/[^\r\n]*|'(?:[^']|'')*'/g,
  token => token.startsWith("'") ? token : ' ');
}
function Routines(source) {
 const starts = [...source.matchAll(/^(?:constructor|destructor|procedure|function)\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\b/gmi)];
 return starts.map((entry, index) => ({name: entry[1].toLowerCase(),
  text: source.slice(entry.index, starts[index + 1]?.index ?? source.length)}));
}
function Routine(source, name) {
 const matches = Routines(source).filter(row => row.name === name.toLowerCase());
 assert.equal(matches.length, 1, 'Exactly one routine required: ' + name);
 return WithoutComments(matches[0].text);
}
function ClassProjection(source, className) {
 // native-declarations scans every F-prefixed identifier in its input. Isolate
 // each class, rather than treating the text-render helper's FLayout as a field
 // of the surrounding message controller (or hiding real undeclared fields).
 const declaration = new RegExp('\\b' + className + '\\s*=\\s*class\\b[\\s\\S]*?^\\s*end\\s*;', 'mi').exec(source);
 assert.ok(declaration, className + ' declaration');
 const methods = Routines(source).filter(row => row.name.startsWith(className.toLowerCase() + '.'));
 assert.ok(methods.length, className + ' implementations');
 assert.equal(new Set(methods.map(row => row.name)).size, methods.length, className + ' duplicate methods');
 return declaration[0] + '\n' + methods.map(row => row.text).join('\n');
}
function Before(source, first, second, message) {
 const a = source.search(first), b = source.search(second);
 assert.ok(a >= 0 && b >= 0 && a < b, message);
}
function Check(apk) {
 const read = name => fs.readFileSync(path.join(apk, name), 'utf8');
 const dm = read('MoaPlayDirectMessages.pas');
 for (const name of ['TMoaPlayDirectMessages', 'TDirectMessageText'])
  assert.deepEqual(declarations.Check(ClassProjection(dm, name), name), [], name);
 for (const [file, name] of [['MoaPlayPassWindow.pas', 'TMoaPlayPassWindow']])
  assert.deepEqual(declarations.Check(read(file), name), [], file);

 const flow = read('MoaPlayApp.Member.Flow.inc');
 const reply = Routine(flow, 'TMoaPlayForm.HubReply');
 Before(reply, /\bHubDirectMessagesReply\s*\(/i, /\bMutation\s*:=/i,
  'Private replies must exit before generic page-mutation handling');
 assert.doesNotMatch(reply, /\bHubEventGameReply\b/,'retired game callbacks are absent');
 const wheel = read('MoaPlayApp.Member.Rewards.inc');
 assert.match(Routine(wheel, 'TMoaPlayForm.HubWheelStop'), /CancelAnimation/,'retained reward wheel still stops on navigation/background');
 const timer = Routine(flow, 'TMoaPlayForm.HubRenderTimerTimer');
 Before(timer, /if\s+not\s+FHubPageChanged\s+and\s+FHubTouch\.Busy\s+then\s+Exit/i, /\bHubRenderNow\s*;/i,
  'Local renders must retain a held card until release');
 assert.match(timer, /\bHubInputFocused\b[\s\S]*?then\s+Exit/i,
  'Late page refreshes must preserve active editors');
 for (const [file, type] of [['MoaPlayMemberInput.pas', 'TMoaPlayMemberEdit'], ['MoaPlayMemberMemo.pas', 'TMoaPlayMemberMemo']]) {
  const refresh = Routine(read(file), type + '.RefreshPrompt');
  const caption = /if\s+FFloatingLabel\s+then\s+begin([\s\S]*?)end\s+else\s+begin/i.exec(refresh);
  assert.ok(caption, file + ' caption branch');
  assert.doesNotMatch(caption[1], /\bIsFocused\b|\bText\s*=\s*''/i,
   file + ' caption position must not depend on focus or entered text');
 }
 const messagesRender = Routine(dm, 'TMoaPlayDirectMessages.Render');
 assert.doesNotMatch(messagesRender, /\bFreeAndNil\s*\(\s*FInput\s*\)|\bFInput\s*:=/i,
  'Message refreshes retain the live IME composer');
 const markRead = Routine(dm, 'TMoaPlayDirectMessages.RequestRead');
 assert.match(markRead, /\bFDirty\b[\s\S]*?then\s+Exit/i, 'Read receipts wait for rendered messages');
 assert.match(markRead, /\bFConfirm\.Visible\b[\s\S]*?then\s+Exit/i, 'Covered messages remain unread');

}
module.exports = {Check};
if (require.main === module) {
 Check(path.resolve(__dirname, '../../MoaPlayApp_Android64'));
 console.log('FIX59 native lifecycle/source checks passed (Delphi compilation not run).');
}
