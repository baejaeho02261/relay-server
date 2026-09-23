'use strict';
// Resolve the actual tab arrays as well as literal icon calls. FIX68's missing
// home glyph was invisible to a checker that only inspected MemberSvg('...').
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { JSDOM } = require('jsdom');
const native = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const read = name => fs.readFileSync(path.join(native, name), 'utf8');
const svgSource = read('MoaPlayMemberSvg.pas'), dashboard = read('MoaPlayApp.Dashboard.inc');
const media = read('MoaPlayApp.Member.Media.inc');
function routine(source, name) {
  const starts = [...source.matchAll(/^(?:procedure|function)\s+([\w.]+)/gm)];
  const i = starts.findIndex(m => m[1] === name); assert.ok(i >= 0, name);
  return source.slice(starts[i].index, starts[i + 1]?.index ?? source.length).replace(/\{[\s\S]*?\}/g, '');
}
function names(name) {
  const list = /Names\s*:=\s*\[([^\]]+)\]/.exec(routine(dashboard, name)); assert.ok(list, name);
  return [...list[1].matchAll(/'([^']+)'/g)].map(m => m[1]);
}
const tabs = names('TMoaPlayForm.BuildDashboardUI');
assert.deepEqual(tabs, ['home', 'discover', 'feed', 'paperplane', 'user']);
assert.deepEqual(names('TMoaPlayForm.HubApplyTheme'), tabs, 'creation and live theme refresh resolve the same five glyphs');
function icon(name, filled, color, source = svgSource) {
  const rows = source.split(/\r?\n/).filter(line => line.includes("Name = '" + name + "'") &&
    (!line.includes('Filled =') || line.includes('Filled = ' + (filled ? 'True' : 'False'))));
  assert.equal(rows.length, 1, `${name}/${filled}: exactly one native source branch`);
  const literal = /Exit\('((?:''|[^'])+)'\);/.exec(rows[0]); assert.ok(literal, name);
  const payload = literal[1].replaceAll("''", "'").replaceAll('%COLOR%', color);
  const document = new JSDOM(payload, { contentType: 'image/svg+xml' }).window.document;
  assert.equal(document.documentElement.localName, 'svg');
  assert.equal(document.documentElement.getAttribute('viewBox'), '0 0 24 24');
  assert.equal(document.querySelectorAll('parsererror').length, 0);
  assert.ok(document.querySelector('path,circle,rect,ellipse,polygon'), `${name}: visible geometry`);
  assert.ok(!payload.includes('%COLOR%')); assert.ok(payload.includes(color));
  for (const reference of document.querySelectorAll('[mask],[clip-path]')) {
    const ref = reference.getAttribute('mask') || reference.getAttribute('clip-path');
    assert.match(ref, /^url\(#[\w-]+\)$/); assert.ok(document.getElementById(ref.slice(5, -1)));
  }
  return { payload, document };
}
let states = 0;
for (const color of ['#F5F5F5', '#0C0F14']) for (const name of tabs) {
  const off = icon(name, false, color), on = icon(name, true, color);
  assert.notEqual(on.payload, off.payload, `${name}: selected and ordinary states differ`); states += 2;
}
// Demonstrate that deleting either dynamically named home state is caught.
for (const active of [false, true]) {
  const broken = svgSource.split(/\r?\n/).filter(line => !(line.includes("Name = 'home'") && line.includes('Filled = ' + (active ? 'True' : 'False')))).join('\n');
  assert.throws(() => icon('home', active, '#FFFFFF', broken));
}
const off = icon('paperplane', false, '#FFFFFF').document, on = icon('paperplane', true, '#FFFFFF').document;
const outline = off.documentElement.querySelector(':scope > path'), solid = on.documentElement.querySelector(':scope > path');
assert.equal(outline.getAttribute('d'), solid.getAttribute('d'), 'selection keeps the complete curved airplane silhouette');
assert.ok((outline.getAttribute('d').match(/C/g) || []).length >= 4);
const fold = on.getElementById('plane-fold').querySelector('path');
const ends = fold.getAttribute('d').match(/-?\d+(?:\.\d+)?/g).map(Number);
assert.ok(ends[2] >= 22 && ends[3] <= 2, 'the selected fold reaches the tip, beyond the old middle-only cutout');
for (const active of [false, true]) {
  const doc = icon('discover', active, '#FFFFFF').document;
  const back = doc.documentElement.querySelector(':scope > path');
  assert.equal(back.getAttribute('mask'), 'url(#planet-outside)');
  assert.equal(doc.getElementById('planet-outside').querySelector('circle').getAttribute('r'), '8.2');
  assert.equal(doc.documentElement.querySelectorAll(':scope > path').length, 2, 'only front/back orbit, no upper/lower accent bars');
}
const avatar = icon('avatar.person', false, '#FFFFFF').document;
assert.ok(avatar.getElementById('avatar-circle')); assert.equal(avatar.querySelectorAll('text').length, 0);
const torso = /C([^C]+)Z$/.exec(avatar.querySelector('g > path').getAttribute('d')); assert.ok(torso, 'torso closes along a curve rather than a straight baseline');
const curve = torso[1].match(/-?\d+(?:\.\d+)?/g).map(Number);
assert.ok(curve[1] > 24 && curve[3] > 24 && curve[5] < 24, 'rounded torso continues below the circular crop');
const layout = routine(dashboard, 'TMoaPlayForm.ResizeDashboardUI');
const header = routine(dashboard, 'TMoaPlayForm.HubUpdateHeader');
const js = s => s.replace(/\bMax\(/g, 'Math.max(').replace(/\bMin\(/g, 'Math.min(').replace(/\bCeil\(/g, 'Math.ceil(');
function bounds(text, name, ctx) {
  const match = new RegExp(name.replaceAll('[', '\\[').replaceAll(']', '\\]') + '\\.SetBounds\\(([^;]+)\\);').exec(text); assert.ok(match, name);
  return new Function('ctx', 'with(ctx){return [' + js(match[1]) + ']}')(ctx);
}
let geometries = 0;
for (const W of [240, 280, 320, 360, 412, 480, 600, 840, 1024]) {
  const TabW = W / 5, BarH = 60;
  for (let I = 0; I < 5; I++) {
    const ctx = { W, TabW, BarH, I }, target = bounds(layout, 'FDashboardTabs[I]', ctx), glyph = bounds(layout, 'FDashboardIcons[I]', ctx);
    assert.equal(target[0], I * TabW); assert.equal(target[2], TabW);
    assert.equal(glyph[0] + glyph[2] / 2, TabW / 2); assert.equal(glyph[1] + glyph[3] / 2, BarH / 2);
    assert.ok(glyph[0] >= 0 && glyph[0] + glyph[2] <= TabW); assert.deepEqual(glyph.slice(2), [28, 28]); geometries++;
  }
  for (const measured of [28, 60, 140, 320, 1000]) {
    const FHubTitleBar = { Width: W }, AccountLayout = { TextWidth: measured };
    const expression = /AccountW:=([^;]+);/.exec(header)[1];
    const AccountW = new Function('FHubTitleBar', 'AccountLayout', 'return ' + js(expression))(FHubTitleBar, AccountLayout);
    const ctx = { FHubTitleBar, AccountW }, account = bounds(header, 'FHubHeaderAccount', ctx), label = bounds(header, 'FHubHeaderAccountLabel', ctx), chevron = bounds(header, 'FHubHeaderAccountChevron', ctx);
    assert.ok(account[0] >= 52 && account[0] + account[2] <= W - 52, 'centered chat account avoids side actions');
    assert.equal(chevron[0] - label[2], 2); assert.equal(chevron[1] + chevron[3] / 2, label[3] / 2);
    assert.ok(chevron[0] + chevron[2] <= AccountW); geometries++;
  }
}
assert.match(media, /FHubTabAvatar\.Stroke\.Kind:=TBrushKind\.Solid/);
assert.match(media, /FHubTabAvatar\.Stroke\.Thickness:=Max\(0\.35,0\.75\/MemberDisplayScale\(FHubTabAvatar\)\)/);
assert.match(dashboard, /FDashboardIcons\[I\]\.Svg\.Source:=MemberSvg\(Names\[I\],False\)/);
assert.match(dashboard, /FHubFilledIcons\[I\]\.Svg\.Source:=MemberSvg\(Names\[I\],True\)/);
console.log(`FIX69 navigation PASS: ${states} real dynamic tab SVG/theme states, deleted-home detection, plane fold/orbit/avatar geometry and ${geometries} production layout cases. Native compiler/device not executed.`);
