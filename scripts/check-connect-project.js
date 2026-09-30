'use strict';
// Packaging checks for the previously reported IDE source/resource errors.
// They do not replace compiling and running both programs with Delphi Win64.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../MoaPlayConnect_Win64');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
for (const [name, role] of [['MoaPlayConnect', 'client'], ['MoaPlayLauncher', 'launcher']]) {
  const project = read(name + '.dproj');
  const entries = [...project.matchAll(/<DelphiCompile\s+Include="([^"]+)"\s*>([\s\S]*?)<\/DelphiCompile>/g)];
  assert.equal(entries.length, 1, 'Exactly one primary Delphi compile item');
  assert.equal(entries[0][1], name + '.dpr');
  assert.match(entries[0][2], /<MainSource>MainSource<\/MainSource>/);
  assert.ok(project.includes('<MainSource>' + name + '.dpr</MainSource>'));
  assert.match(project, /<FrameworkType>None<\/FrameworkType>/);
  assert.ok(project.includes('<DCC_ConsoleTarget>false</DCC_ConsoleTarget>'));
  assert.match(project, /<Platform value="Win64">True<\/Platform>/);
  assert.match(project, /<Target Name="PublishRandomExecutable" AfterTargets="Build;Rebuild">/);
  assert.ok(project.includes("$([System.Guid]::NewGuid().ToString('N')).exe"));
  assert.ok(project.includes('\\$(Platform)\\$(Config)\\' + role));
  assert.match(project, /<Move SourceFiles="\$\(CompiledArtifact\)"/);
  assert.match(project, /<Icon_MainIcon\s*\/>/);
  assert.ok(!/\.ico\b/i.test(project));
  for (const [, file] of project.matchAll(/(?:DCCReference|None)\s+Include="([^"]+)"/g)) {
    assert.ok(fs.existsSync(path.join(root, file)), 'Missing project resource: ' + file);
  }
  const dpr = read(name + '.dpr');
  assert.ok(dpr.includes('{$APPTYPE GUI}'));
  for (const [, res] of dpr.matchAll(/\{\$R\s+'([^']+)'\}/g)) {
    const bytes = fs.readFileSync(path.join(root, res));
    assert.ok(bytes.length > 32, 'Missing compiled resource: ' + res);
    assert.equal(bytes.readUInt32LE(4), 32, 'Expected Windows RES header: ' + res);
    const types = [];
    for (let at = 0; at < bytes.length;) {
      assert.ok(at + 8 <= bytes.length, 'Truncated resource header');
      const size = bytes.readUInt32LE(at), header = bytes.readUInt32LE(at + 4);
      assert.ok(header >= 16 && at + header + size <= bytes.length, 'Truncated resource data');
      if (bytes.readUInt16LE(at + 8) === 0xffff) types.push(bytes.readUInt16LE(at + 10));
      at += (header + size + 3) & ~3;
    }
    assert.ok(!types.includes(3) && !types.includes(14), 'Custom icon remains: ' + res);
    assert.ok(types.includes(24), 'Missing application manifest: ' + res);
  }
}
assert.ok(!fs.existsSync(path.join(root, 'MoaPlayConnect.ico')));
const consoleSource = read('MoaPlay.Console.pas');
const entry = consoleSource.slice(consoleSource.indexOf('function RunMoaPlayConsole: Integer;', consoleSource.indexOf('implementation')));
assert.ok(entry.indexOf('Context.CompleteClaimAndCleanup;') < entry.indexOf('if not AllocConsole'), 'Console must be created only after authenticated handoff and cleanup');
assert.ok(entry.includes('if not AllocConsole'));
assert.ok(!/\b(?:WriteLn|ShowMessage|MessageBox)\s*\(/i.test(consoleSource), 'User diagnostics must remain silent');
for (const name of fs.readdirSync(root)) {
  if (!/\.(?:pas|dpr|dproj|bat|inc)$/.test(name)) continue;
  const source = read(name);
  assert.ok(!source.includes('%MainSource%'), 'Unresolved source macro in ' + name);
  assert.ok(!/\bBS_TYPEMASK\b/.test(source), 'Undeclared SDK mask in ' + name);
  if (!name.endsWith('.dproj')) assert.ok(!/https?:\/\//i.test(source), 'Embedded HTTP endpoint: ' + name);
  if (/\.(?:pas|dpr)$/.test(name)) {
    assert.ok(source.startsWith('\uFEFF'), 'Missing UTF-8 BOM: ' + name);
    assert.ok(!source.replace(/\r\n/g, '').includes('\n'), 'Mixed source line endings: ' + name);
    assert.ok(!/\b(?:Vcl|FMX)\./i.test(source), 'Retired GUI dependency: ' + name);
    assert.ok(!/\b(?:CryptProtectData|CryptUnprotectData|RegSetValueEx|TRegistry)\b/.test(source), 'Persistent client credentials: ' + name);
    for (const [, block] of source.matchAll(/constructor\s+[\w.]+[^;]*;([\s\S]*?)(?=\n(?:constructor|destructor|procedure|function|class\s+function)|$)/gi)) {
      assert.ok(!/^\s*Start\s*;/m.test(block), 'Thread started inside constructor: ' + name);
    }
  }
}
for (const retired of ['MoaPlay.dproj', 'MoaPlay.Main.pas', 'MoaPlay.UI.pas']) {
  assert.ok(!fs.existsSync(path.join(root, retired)), 'Retired GUI source: ' + retired);
}
console.log('A/B PROJECT SOURCE CHECK PASS (actual Delphi compilation still required)');
