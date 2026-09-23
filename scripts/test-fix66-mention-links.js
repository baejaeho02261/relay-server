'use strict';
// Differential lexical/UTF-16 contract checks, plus execution of the native
// rectangle clipping expressions. Delphi FMX rendering still needs a device.
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const native = fs.readFileSync(path.resolve(__dirname, '../../MoaPlayApp_Android64/MoaPlayMentionLinks.pas'), 'utf8');
const { Tokens } = require('../services/member/mentions');
function section(first, last) { return native.slice(native.indexOf(first), native.indexOf(last, native.indexOf(first))); }
function chars(source) {
  const values = new Set();
  for (const match of source.matchAll(/'((?:[^']|'')*)'(?:\.\.'((?:[^']|'')*)')?/g)) {
    const start = match[1].replaceAll("''", "'");
    if (match[2] !== undefined) for (let c = start.charCodeAt(0); c <= match[2].charCodeAt(0); c++) values.add(String.fromCharCode(c));
    else values.add(start);
  }
  return values;
}
const firstChars = chars(section('function MentionFirstChar', 'function MentionHandleChar').match(/CharInSet\(C,\[([^\n]+?)\]\)/)[1]);
const blocked = chars(section('function MentionBlockedPrefix', 'function MentionTokens').match(/CharInSet\(Value\[P\],\[([^\n]+?)\]\)/)[1]);
const delimiters = chars(section('function MentionURLStop', 'function MentionBlockedPrefix').match(/CharInSet\(C,\[([^\n]+?)\]\)/)[1]);
const white = new Set();
for (const match of section('function MentionURLStop', 'function MentionBlockedPrefix').matchAll(/\$([\dA-F]+)(?:\.\.\$([\dA-F]+))?/g)) {
  for (let c = parseInt(match[1], 16); c <= parseInt(match[2] || match[1], 16); c++) white.add(String.fromCharCode(c));
}
const prefix = native.match(/MentionURLPrefix = '([^'\r\n]+)'/)[1];
function nativeTokens(value) {
  const spans = []; let after = 0;
  for (const found of value.matchAll(new RegExp(prefix, 'g'))) {
    if (found.index < after) continue;
    let to = found.index + found[0].length;
    while (to < value.length && !white.has(value[to]) && !delimiters.has(value[to])) to++;
    if (to === found.index + found[0].length) continue;
    spans.push([found.index, to]); after = to;
  }
  const result = []; let i = 0, span = 0;
  while (i < value.length) {
    if (value[i] !== '@' || !firstChars.has(value[i + 1])) { i++; continue; }
    const start = i++;
    while (i < value.length && (firstChars.has(value[i]) || value[i] === '.')) i++;
    const length = i - start;
    if (length < 4 || length > 25 || value[i] === '@') continue;
    let before = value[start - 1] || '';
    if (start >= 2 && /[\uDC00-\uDFFF]/.test(before) && /[\uD800-\uDBFF]/.test(value[start - 2])) before = value.slice(start - 2, start);
    if (blocked.has(before) || /[\p{L}\p{N}]/u.test(before)) continue;
    while (span < spans.length && spans[span][1] <= start) span++;
    if (span < spans.length && spans[span][0] <= start) continue;
    result.push({ handle: value.slice(start + 1, i).toLowerCase(), start, length });
  }
  return result;
}
const samples = [
  '@bob', '안녕 @BOB, (@carol)!', 'abc@bob.example user+name@bob.example',
  'https://example.com/@bob https://example.com/#(@carol) mailto:@bob www.example.com/@carol',
  '@@bob @bob@carol @' + 'b'.repeat(25), '@ab @b._ @bob.', '🙂 @bob\n@carol',
  '한글@bob x_@carol 𝒜@bob 𐐀@carol Ⅶ@bob ²@carol', '🙂@bob',
  '@bob\r\n@carol @ALICE @ab.cd @abc_def @.invalid @-invalid',
  'www.@bob (www.x/@carol) x.HTTPS://example.x/@bob [@alice]',
  'https:// @bob <mailto:> @carol', 'a'.repeat(1000) + '@bob @carol'
];
// Distinct scripts, punctuation, supplementary Unicode and every JS whitespace
// before and after a URL guard against index and regular-expression drift.
for (const before of ['',' ','\n','🙂','𝒜','𐐀','Ⅶ','²','中','한','_', '.', '%', '+','-','@','/','\\',':','?','=','&','(', '[', '<','"',"'"])
  for (const handle of ['bob','BOB','ab','b._','bob.','a'.repeat(24),'a'.repeat(25)])
    for (const after of ['', '@carol', ',', ')', '/suffix']) samples.push(before + '@' + handle + after);
for (const space of white) samples.push('https://example.test/' + space + '@bob www.example.test/@carol' + space + '@alice');
for (const sample of samples) {
  const actual = nativeTokens(sample);
  assert.deepEqual(actual, Tokens(sample), JSON.stringify(sample));
  for (const token of actual) assert.equal(sample.slice(token.start, token.start + token.length).toLowerCase(), '@' + token.handle);
}
assert.match(native, /Range.Pos:=Token.First-1;Range.Length:=Token.Count/);
assert.match(native, /Regions:=Layout.RegionForRange\(Range\)/);
assert.match(native, /TCharacter.IsLetter\(Code\) or TCharacter.IsNumber\(Code\)/);
assert.match(native, /Code:=\$10000\+\(Ord\(Value\[P-1\]\)-\$D800\)\*\$400\+\(Code-\$DC00\)/);
assert.match(native, /for Region in Regions do begin/);
assert.match(native, /MentionMaxMatches = 40/);assert.match(native, /MentionMaxRectangles = 80/);
assert.match(native, /Matches>=MentionMaxMatches/);assert.match(native, /Rectangles>=MentionMaxRectangles/);
assert.match(native, /Lookup.TryGetValue\(Token.Handle,ID\)/, 'only server-authorized aliases are linked');
assert.doesNotMatch(native, /MentionText\(Member,'handle'\)/, 'a rename cannot redirect old text through the current handle');
assert.match(native, /Tap.TouchScope:=Scope;Tap.TagString:=ActionPrefix\+ID/);
assert.match(native, /Tap.OnClick:=Handler/);assert.doesNotMatch(native, /Underline|fsUnderline/);
assert.match(native, /FPaintLayout.Color:=MemberLink/);assert.match(native, /Canvas.IntersectClipRect\(LocalRect\)/);
assert.match(native, /Tap:=TMentionLinkOverlay.Create\(Parent\);Tap.Parent:=Host/);
assert.doesNotMatch(native, /Layout.Free|Members.Free|Parent.Free|Sender.Free/);
const clipping = native.match(/Bounds:=RectF\((Max\(0,Region.Left\)),(Max\(0,Region.Top\)),\s*(Min\(Parent.Width,Region.Right\)),(Min\(Parent.Height,Region.Bottom\))\)/);
assert.ok(clipping, 'all wrapped line regions are clipped to the visible text body');
const runClip = clipping.slice(1).map(expression => Function('Region', 'Parent', 'return ' + expression.replace(/Max/g, 'Math.max').replace(/Min/g, 'Math.min')));
let geometry = 0;
for (const Parent of [{Width:48,Height:20},{Width:240,Height:90},{Width:640,Height:480}])
  for (const Region of [{Left:-3,Top:-2,Right:45,Bottom:19},{Left:30,Top:5,Right:300,Bottom:24},{Left:0,Top:40,Right:200,Bottom:65},{Left:0,Top:500,Right:50,Bottom:524}]) {
    const [left,top,right,bottom] = runClip.map(fn => fn(Region, Parent));
    if (right-left>0.1 && bottom-top>0.1) {
      assert.ok(left>=0&&top>=0&&right<=Parent.Width&&bottom<=Parent.Height);
      assert.ok(right-left<=Parent.Width&&bottom-top<=Parent.Height);
    }
    geometry++;
  }
console.log('FIX66 mention links: '+samples.length+' native/server lexical cases, UTF-16 offsets, authorized aliases, '+geometry+' clipped regions and bounded touch targets PASS');
