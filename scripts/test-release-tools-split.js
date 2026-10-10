'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const tools = require('../tools/release-tools');
const sourceTools = path.resolve(__dirname, '../tools');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'game-release-tools-'));
const home = path.join(root, 'Game Web ! & (test)', 'tools');
function json(file, value) { fs.writeFileSync(file, JSON.stringify(value)); }
function rejects(fn, message) { assert.throws(fn, message); }
try {
  fs.mkdirSync(home, { recursive: true });
  const p = tools.locations(home);
  fs.mkdirSync(path.dirname(p.canonicalSource), { recursive: true });
  fs.mkdirSync(path.dirname(p.example), { recursive: true });
  const sourceCopy = path.join(root, 'completed-spec.json');
  const spec = { version: 1, releaseName: 'test release ! &', securityVersion: 97, protocol: 'GAME-CONNECT-4', hashVersion: 3, handoffVersion: 3, toolchain: { delphi: 'test-delphi', cpp: 'test-cpp', windowsSdk: 'test-sdk', imgui: 'test-imgui' } };
  const files = ['A', 'B', 'O'].map((role, index) => {
    const file = path.join(root, role + " random ! & ' (한글).exe");
    fs.writeFileSync(file, Buffer.alloc(1024, index + 1));
    return file;
  });
  json(sourceCopy, spec);
  rejects(() => tools.makeManifest(home, files), /spec.json is missing/);
  assert.equal(tools.createSpecFrom(home, sourceCopy), p.spec);
  assert.deepEqual(JSON.parse(fs.readFileSync(p.spec)), spec);
  rejects(() => tools.createSpecFrom(home, sourceCopy), /preserved/);
  rejects(() => tools.makeManifest(home, files), /deployment-policy.json is missing/);
  json(p.policy, { testPolicy: 1 });
  rejects(() => tools.makeManifest(home, files), /source-manifest.json is missing/);
  json(p.canonicalSource, { fixtureOnly: true });
  rejects(() => tools.makeManifest(home, [files[0], files[0], files[2]]), /different files/);
  rejects(() => tools.makeManifest(home, files.slice(0, 2)), /all three/);
  const created = tools.makeManifest(home, files);
  assert.deepEqual(fs.readFileSync(p.source), fs.readFileSync(p.canonicalSource));
  assert.equal(created.file, p.manifest);
  assert.match(created.manifestId, /^[a-f0-9]{128}$/);
  assert.equal(tools.checkManifest(home, files).manifestId, created.manifestId);
  const original = fs.readFileSync(p.manifest);
  rejects(() => tools.makeManifest(home, files), /preserved/);
  assert.deepEqual(fs.readFileSync(p.manifest), original);
  for (let i = 0; i < files.length; i++) {
    fs.appendFileSync(files[i], 'changed');
    rejects(() => tools.checkManifest(home, files), new RegExp(['A', 'B', 'O'][i] + ' EXE'));
    fs.writeFileSync(files[i], Buffer.alloc(1024, i + 1));
  }
  json(p.policy, { testPolicy: 2 });
  rejects(() => tools.checkManifest(home, files), /deployment-policy.json/);
  json(p.policy, { testPolicy: 1 });
  json(p.source, { fixtureOnly: false });
  rejects(() => tools.checkManifest(home, files), /snapshot was not overwritten/);
  const staleOutput = path.join(home, 'must-not-be-created.json');
  rejects(() => tools.makeManifest(home, files, staleOutput), /snapshot was not overwritten/);
  assert.equal(fs.existsSync(staleOutput), false);
  assert.deepEqual(JSON.parse(fs.readFileSync(p.source)), { fixtureOnly: false });
  json(p.canonicalSource, { fixtureOnly: false });
  rejects(() => tools.checkManifest(home, files), /source-manifest.json/);
  json(p.canonicalSource, { fixtureOnly: true });
  json(p.source, { fixtureOnly: true });
  fs.unlinkSync(p.source);
  rejects(() => tools.checkManifest(home, files), /source-manifest.json is missing beside the BAT/);
  json(p.source, { fixtureOnly: true });
  json(p.spec, { ...spec, securityVersion: 98 });
  rejects(() => tools.checkManifest(home, files), /spec.json/);
  json(p.spec, spec);
  const tampered = JSON.parse(original); tampered.manifestId = 'f'.repeat(128);
  json(p.manifest, tampered);
  rejects(() => tools.checkManifest(home, files), /PROVENANCE_MANIFEST_INVALID/);
  fs.writeFileSync(p.manifest, original);
  rejects(() => tools.validateSpec({ ...spec, toolchain: { ...spec.toolchain, imgui: '' } }));
  rejects(() => tools.validateSpec({ ...spec, handoffVersion: 2 }));

  // Exercise queued stdin and quoted Explorer paths without passing them to a shell.
  const example = { ...spec, releaseName: '', toolchain: { delphi: '', cpp: '', windowsSdk: '', imgui: '' } };
  json(p.example, example);
  fs.unlinkSync(p.spec);
  const invoke = action => spawnSync(process.execPath, ['-e', 'require(process.argv[1]).main([process.argv[2]], process.argv[3]).catch(e=>{console.error(e.message);process.exitCode=1})', path.join(sourceTools, 'release-tools.js'), action, home], { input: action === 'spec' ? 'Release ! &\n97\ncompiler\ncompiler\nsdk\nimgui\nYES\n' : files.map(f => '"' + f + '"').join('\n') + '\nYES\n', encoding: 'utf8', timeout: 10000 });
  const specRun = invoke('spec');
  assert.equal(specRun.status, 0, specRun.stderr);
  assert.equal(JSON.parse(fs.readFileSync(p.spec)).releaseName, 'Release ! &');
  fs.unlinkSync(p.manifest);
  const manifestRun = invoke('manifest');
  assert.equal(manifestRun.status, 0, manifestRun.stderr);
  assert.match(manifestRun.stdout, /Manifest ID:\n[a-f0-9]{128}/);
  assert.equal(invoke('check').status, 0);
  assert.deepEqual(fs.readdirSync(home).sort(), ['deployment-policy.json', 'release-manifest.json', 'source-manifest.json', 'spec.json']);

  for (const file of ['Prepare_ImGui.bat', 'Create_Spec.bat', 'Create_Release_Manifest.bat', 'Check_Release_Manifest.bat']) {
    const bytes = fs.readFileSync(path.join(sourceTools, file));
    assert(!bytes.toString('ascii').replace(/\r\n/g, '').includes('\n'), file + ': CRLF required');
    assert(bytes.includes(Buffer.from('DisableDelayedExpansion')));
    const content = bytes.toString('ascii'), labels = new Set([...content.matchAll(/^:([a-z_]+)\r?$/gm)].map(m => m[1]));
    for (const match of content.matchAll(/\bgoto ([a-z_]+)/g)) assert(labels.has(match[1]), file + ': unresolved label ' + match[1]);
  }
  console.log('PASS: split release tools, literal paths, spec validation, manifest identity, no-overwrite and local JSON placement (Windows BAT execution NOT_RUN).');
} finally { fs.rmSync(root, { recursive: true, force: true }); }
