'use strict';
// Parse the actual native SVG payloads, including separate active states.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const native = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const source = fs.readFileSync(path.join(native, 'MoaPlayMemberSvg.pas'), 'utf8');
const dashboard = fs.readFileSync(path.join(native, 'MoaPlayApp.Dashboard.inc'), 'utf8');
const palette = fs.readFileSync(path.join(native, 'MoaPlayMemberTheme.pas'), 'utf8');

function svg(name, filled, color) {
  const rows = source.split(/\r?\n/).filter(line => line.includes("Name = '" + name + "'") &&
    (!line.includes('Filled =') || line.includes('Filled = ' + (filled ? 'True' : 'False'))));
  assert.equal(rows.length, 1, name + ' has one unambiguous state');
  const payload = rows[0].match(/Exit\('(.+)'\);/)[1].replaceAll('%COLOR%', color);
  const document = new JSDOM(payload, { contentType: 'image/svg+xml' }).window.document;
  assert.equal(document.documentElement.getAttribute('viewBox'), '0 0 24 24');
  assert.equal(document.querySelectorAll('parsererror').length, 0);
  assert.ok(!payload.includes('%COLOR%'));
  return { payload, document };
}

for (const color of ['#F5F5F5', '#0C0F14', '#FFFFFF']) {
  const off = svg('discover', false, color), on = svg('discover', true, color);
  assert.notEqual(off.payload, on.payload, 'active discovery must visibly fill');
  assert.equal(off.document.querySelectorAll('circle').length, 1);
  assert.equal(off.document.querySelectorAll('ellipse').length, 0, 'the previous open orbit replaces FIX66 full ellipse');
  assert.equal(off.document.querySelectorAll('path').length, 1);
  const planet = off.document.querySelector('circle'), orbit = off.document.querySelector('path');
  const radius = +planet.getAttribute('r');
  assert.equal(radius, 8.2, 'restore the old design without shrinking the current planet');
  const oldOrbit = 'M7 6.5c-3 .3-5 1.2-5 2.6 0 2.3 5 4.9 11.1 5.9 5 .8 8.9.2 8.9-1.7 0-1.1-1.5-2.6-4-3.8';
  const oldAccents = 'M5 17.7l1.3-1.1M18 5l.8-.8';
  assert.equal(orbit.getAttribute('d'), oldOrbit + oldAccents, 'the precise previous open orbit and accents are restored');
  assert.equal(on.document.querySelector('circle').getAttribute('r'), planet.getAttribute('r'));
  assert.equal(on.document.querySelector('circle').getAttribute('fill'), color);
  assert.equal(on.document.querySelector('circle').getAttribute('mask'), 'url(#orbit-cut)');
  const mask = on.document.querySelector('mask#orbit-cut');
  assert.ok(mask, 'orbit gap is transparent and never paints a theme-colored patch');
  assert.equal(mask.querySelector('path').getAttribute('d'), oldOrbit, 'only the orbit cuts the active planet');
  assert.equal(on.document.documentElement.lastElementChild.getAttribute('d'), orbit.getAttribute('d'), 'selection keeps the same orbital silhouette');
  assert.equal(off.document.querySelector('g').getAttribute('stroke-width'), '1.8');
  // Sample the restored cubic orbit in its actual native coordinate system.
  const curves = [[7,6.5,4,6.8,2,7.7,2,9.1], [2,9.1,2,11.4,7,14,13.1,15],
    [13.1,15,18.1,15.8,22,15.2,22,13.3], [22,13.3,22,12.2,20.5,10.7,18,9.5]];
  for (const points of curves) for (let step=0;step<=100;step++) {
    const t=step/100,u=1-t;
    const x=u**3*points[0]+3*u*u*t*points[2]+3*u*t*t*points[4]+t**3*points[6];
    const y=u**3*points[1]+3*u*u*t*points[3]+3*u*t*t*points[5]+t**3*points[7];
    assert.ok(x-0.9>=0&&x+0.9<=24&&y-0.9>=0&&y+0.9<=24,'orbit strokes cannot clip at any display scale');
  }
  assert.ok(12-radius-0.9>=0&&12+radius+0.9<=24,'current planet footprint stays within the unchanged 24px viewBox');

  const paperOff = svg('paperplane', false, color), paperOn = svg('paperplane', true, color);
  assert.notEqual(paperOff.payload, paperOn.payload);
  const outline = paperOff.document.querySelector('path').getAttribute('d');
  assert.ok((outline.match(/C/g) || []).length >= 4, 'all three tips and the inner corner have curved joins');
  assert.equal(paperOff.document.querySelector('g').getAttribute('stroke-linejoin'), 'round');
  const solid = paperOn.document.querySelector('path');
  assert.equal(solid.getAttribute('fill'), color);
  assert.equal(solid.getAttribute('fill-rule'), 'evenodd', 'the diagonal fold remains a transparent cutout');
  assert.ok(solid.getAttribute('d').startsWith(outline), 'selection preserves the same outer silhouette');
  const avatar = svg('avatar.person', false, color);
  assert.equal(avatar.document.querySelectorAll('text').length, 0, 'avatar cannot expose nickname initials');
  assert.equal(avatar.document.querySelector('g').getAttribute('fill'), color);
  assert.equal(avatar.document.querySelectorAll('circle,path').length, 2);
}

assert.match(source, /StringReplace\(SvgSource\(Name,Filled\),'%COLOR%',Color,\[rfReplaceAll\]\)/);
assert.match(source, /else Color:='#'\+IntToHex\(Cardinal\(MemberText\)/, 'theme is resolved on every SVG call');
assert.match(palette, /function MemberText:TAlphaColor;\s*begin if DarkValue then Result:=\$FFF5F5F5 else Result:=\$FF0C0F14/);
assert.match(dashboard, /FDashboardIcons\[I\]\.Svg\.Source:=MemberSvg\(Names\[I\],False\)/);
assert.match(dashboard, /FHubFilledIcons\[I\]\.Svg\.Source:=MemberSvg\(Names\[I\],True\)/, 'theme refresh regenerates both animation layers');
console.log('FIX66 icons PASS on FIX67: SVG parsing, restored open orbit/current footprint, filled states, rounded plane and theme refresh');
