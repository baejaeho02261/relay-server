'use strict';
// Packaging guard for the reported IDE main-source and missing-unit failures.
// This does not replace a Delphi Win64 compiler run.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../MoaPlayConnect_Win64');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const project = read('MoaPlayConnect.dproj');
const entries = [...project.matchAll(/<DelphiCompile\s+Include="([^"]+)"\s*>([\s\S]*?)<\/DelphiCompile>/g)];
assert.equal(entries.length, 1, 'Exactly one primary Delphi compile item');
assert.equal(entries[0][1], 'MoaPlayConnect.dpr');
assert.match(entries[0][2], /<MainSource>MainSource<\/MainSource>/);
assert.match(project, /<MainSource>MoaPlayConnect\.dpr<\/MainSource>/);
assert.match(project, /<FrameworkType>VCL<\/FrameworkType>/);
assert.match(project, /<Platform value="Win64">True<\/Platform>/);
for (const [, name] of project.matchAll(/(?:DCCReference|None)\s+Include="([^"]+)"/g)) {
  assert.ok(fs.existsSync(path.join(root, name)), 'Missing project resource: ' + name);
}
for (const name of fs.readdirSync(root)) {
  if (!/\.(?:pas|dpr|dproj|bat|inc)$/.test(name)) continue;
  const source = read(name);
  assert.ok(!source.includes('%MainSource%'), 'Unresolved source macro in ' + name);
  assert.ok(!/\bBS_TYPEMASK\b/.test(source), 'Undeclared SDK mask in ' + name);
  if (!name.endsWith('.dproj')) assert.ok(!/https?:\/\//i.test(source), 'Embedded HTTP endpoint in native source: ' + name);
  if (/\.(?:pas|dpr)$/.test(name)) {
    assert.ok(source.startsWith('\uFEFF'), 'Missing UTF-8 BOM: ' + name);
    assert.ok(!source.replace(/\r\n/g, '').includes('\n'), 'Mixed source line endings: ' + name);
  }
}
assert.ok(!fs.existsSync(path.join(root, 'MoaPlay.dproj')), 'No duplicate native project');
console.log('CONNECT PROJECT SOURCE CHECK PASS (actual Delphi compilation still required)');
