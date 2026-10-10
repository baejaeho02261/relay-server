'use strict';
// Local workflow helpers. Never builds EXEs, registers releases or invents CI evidence.
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const provenance = require('./release-provenance');
const schema = require('../services/desktopReleaseProvenance');
const ROLES = ['A', 'B', 'O'];
const FOLDERS = ['launcher', 'client', 'overlay'];

function fail(message) { throw new Error(message); }
function readBounded(file, maximum) {
  const fd = fs.openSync(file, 'r');
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size < 1 || before.size > maximum) fail('Input must be a nonempty regular file within its size limit: ' + file);
    const bytes = fs.readFileSync(fd), after = fs.fstatSync(fd);
    if (bytes.length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) fail('Input changed while reading: ' + file);
    return bytes;
  } finally { fs.closeSync(fd); }
}
function readJson(file) { return JSON.parse(readBounded(file, 65536).toString('utf8').replace(/^\uFEFF/, '')); }
function writeNewBytes(file, bytes) {
  let fd, created = false;
  try {
    fd = fs.openSync(file, 'wx', 0o600); created = true;
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
  } catch (error) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch (_) {} }
    if (created) { try { fs.unlinkSync(file); } catch (_) {} }
    throw error;
  }
}
function writeNew(file, value) { writeNewBytes(file, Buffer.from(JSON.stringify(value, null, 2) + '\n', 'utf8')); }
function validateSpec(spec) {
  if (!spec || Object.keys(spec).sort().join(',') !== 'handoffVersion,hashVersion,protocol,releaseName,securityVersion,toolchain,version') fail('Invalid spec fields.');
  const placeholder = '0'.repeat(128);
  schema.ValidateManifest({ ...spec, artifacts: { A: placeholder, B: placeholder, O: placeholder }, sourceManifestSha512: placeholder, policySha512: placeholder });
  return spec;
}
function locations(home) {
  return {
    spec: path.join(home, 'spec.json'),
    policy: path.join(home, 'deployment-policy.json'),
    manifest: path.join(home, 'release-manifest.json'),
    source: path.join(home, 'source-manifest.json'),
    canonicalSource: path.resolve(home, '..', 'maintenance', 'source-manifest.json'),
    example: path.resolve(home, '..', 'setup', 'release-manifest-spec.example.json'),
    native: path.resolve(home, '..', '..', 'GameConnect_Win64')
  };
}
function requireInputs(home) {
  const p = locations(home);
  if (!fs.existsSync(p.spec)) fail('spec.json is missing beside the BAT. Run Create_Spec.bat first.');
  if (!fs.existsSync(p.policy)) fail('deployment-policy.json is missing beside the BAT. Export the CURRENT policy from admin Security / Deployment and save it in GameWeb\\tools.');
  if (!fs.existsSync(p.canonicalSource)) fail('Internal maintenance/source-manifest.json is missing. Use the complete matching source package.');
  return p;
}
function sourceSnapshot(p, create) {
  const canonical = readBounded(p.canonicalSource, 8 * 1024 * 1024);
  if (!fs.existsSync(p.source)) {
    if (!create) fail('source-manifest.json is missing beside the BAT. Generate a new manifest with Create_Release_Manifest.bat using the matching complete source package.');
    writeNewBytes(p.source, canonical);
  }
  const snapshot = readBounded(p.source, 8 * 1024 * 1024);
  if (!snapshot.equals(canonical)) fail('source-manifest.json beside the BAT differs from the matching package metadata. Preserve the old release files separately, then remove the old snapshot and create a NEW manifest. The snapshot was not overwritten.');
}
function verifySourceStillCurrent(p, manifest) {
  if (provenance.FileHash(p.canonicalSource, 8 * 1024 * 1024) !== manifest.sourceManifestSha512) fail('Package source metadata changed during processing. No release should be uploaded; retry with one matching source package.');
}
function finalFiles(files) {
  if (files.length !== 3) fail('Supply all three FINAL approved EXE paths: A, B, O.');
  const seen = new Set();
  return files.map((file, index) => {
    const resolved = path.resolve(file);
    let stat;
    try { stat = fs.statSync(resolved); } catch (_) { fail(ROLES[index] + ' EXE was not found: ' + resolved); }
    if (/\x00/.test(file) || path.extname(resolved).toLowerCase() !== '.exe' || !stat.isFile() || stat.size < 512 || stat.size > 64 * 1024 * 1024) fail(ROLES[index] + ' must be a final .exe file of 512 bytes to 64 MiB.');
    const real = fs.realpathSync(resolved), key = process.platform === 'win32' ? real.toLowerCase() : real;
    if (seen.has(key)) fail('A, B and O must refer to different files.');
    seen.add(key);
    return resolved;
  });
}
function createSpecFrom(home, file) {
  const target = locations(home).spec;
  if (fs.existsSync(target)) fail('spec.json already exists beside the BAT and was preserved. Edit it directly, or archive it before creating a new one.');
  const spec = validateSpec(readJson(file));
  writeNew(target, spec);
  return target;
}
function makeManifest(home, files, output) {
  const p = requireInputs(home), destination = output ? path.resolve(output) : p.manifest;
  if (fs.existsSync(destination)) fail('Output already exists and was preserved: ' + destination + '. Archive it or specify a new output path.');
  const selected = finalFiles(files);
  sourceSnapshot(p, true);
  const result = provenance.MakeManifest(p.spec, ...selected, p.source, p.policy);
  verifySourceStillCurrent(p, result.manifest);
  writeNew(destination, result);
  const checked = provenance.LoadManifest(destination);
  return { file: destination, manifestId: checked.manifestId };
}
function checkManifest(home, files, manifestFile) {
  const p = requireInputs(home), source = manifestFile ? path.resolve(manifestFile) : p.manifest;
  if (!fs.existsSync(source)) fail('release-manifest.json is missing beside the BAT. Run Create_Release_Manifest.bat first.');
  sourceSnapshot(p, false);
  const actual = provenance.MakeManifest(p.spec, ...finalFiles(files), p.source, p.policy);
  verifySourceStillCurrent(p, actual.manifest);
  const saved = provenance.LoadManifest(source);
  if (saved.manifestId !== actual.manifestId) {
    const differences = [];
    for (const role of ROLES) if (saved.manifest.artifacts[role] !== actual.manifest.artifacts[role]) differences.push(role + ' EXE');
    if (saved.manifest.policySha512 !== actual.manifest.policySha512) differences.push('deployment-policy.json');
    if (saved.manifest.sourceManifestSha512 !== actual.manifest.sourceManifestSha512) differences.push('source-manifest.json');
    const spec = m => { const { artifacts, policySha512, sourceManifestSha512, ...rest } = m; return schema.Stable(rest); };
    if (spec(saved.manifest) !== spec(actual.manifest)) differences.push('spec.json');
    fail('Manifest no longer matches: ' + differences.join(', ') + '. Finish approvals, export current policy, then create a NEW manifest.');
  }
  return { file: source, manifestId: saved.manifestId };
}
function questions() {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const lines = rl[Symbol.asyncIterator]();
  rl.on('SIGINT', () => rl.close());
  return {
    async ask(label, validate = () => true, hint = 'Invalid value.') {
      while (true) {
        process.stdout.write(label + ': ');
        const answer = await lines.next();
        if (answer.done) fail('Input ended or cancelled. No new output was saved.');
        const value = answer.value.trim();
        if (validate(value)) return value;
        console.log(hint);
      }
    },
    close() { rl.close(); }
  };
}
async function promptSpec(home) {
  const p = locations(home);
  if (fs.existsSync(p.spec)) fail('spec.json already exists beside the BAT and was preserved. Edit it directly, or archive it before creating a new one.');
  const example = readJson(p.example);
  if (example.version !== 1 || example.protocol !== 'GAME-CONNECT-4' || example.hashVersion !== 3 || ![1, 3].includes(example.handoffVersion)) fail('Unsupported spec example. Use the matching full source package.');
  console.log('Enter ACTUAL final-build versions. These are operator records, not CI evidence.');
  console.log('Check the admin minimum security version; it is separate from the exported deployment policy.');
  const q = questions(), text = s => s.length > 0 && s.length <= 160 && !/[\x00-\x1f\x7f]/.test(s);
  try {
    const releaseName = await q.ask('Release name', text, 'Enter 1-160 characters without control characters.');
    const securityVersion = Number(await q.ask('Security version (at least the admin minimum)', s => /^\d+$/.test(s) && Number.isSafeInteger(Number(s)) && Number(s) >= 1, 'Enter a positive safe integer.'));
    const toolchain = {};
    for (const [field, label] of [['delphi', 'Delphi compiler'], ['cpp', 'C++ compiler'], ['windowsSdk', 'Windows SDK used'], ['imgui', 'ImGui version or commit']]) toolchain[field] = await q.ask(label, text, 'Enter the actual version (1-160 characters).');
    const spec = validateSpec({ version: 1, releaseName, securityVersion, protocol: example.protocol, hashVersion: example.hashVersion, handoffVersion: example.handoffVersion, toolchain });
    console.log(JSON.stringify(spec, null, 2));
    const answer = await q.ask('Save? YES / NO', s => /^(yes|no)$/i.test(s), 'Type YES or NO.');
    if (answer.toUpperCase() !== 'YES') fail('Cancelled. No spec was saved.');
    writeNew(p.spec, spec);
    return p.spec;
  } finally { q.close(); }
}
async function promptFiles(home) {
  const p = locations(home), files = [], q = questions();
  console.log('Select the same FINAL EXEs used by Create_Approval and Check_Approval.');
  console.log('Random filenames are normal. Paste Explorer Copy as path; do not rename EXEs.');
  try {
    for (let i = 0; i < ROLES.length; i++) {
      console.log(ROLES[i] + ' output folder hint: ' + path.join(p.native, 'Win64', 'Release', FOLDERS[i]));
      let value = await q.ask(ROLES[i] + ' full EXE path', s => s.length > 0);
      if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
      files.push(value);
    }
    const selected = finalFiles(files);
    for (let i = 0; i < selected.length; i++) console.log(ROLES[i] + ': ' + selected[i]);
    const answer = await q.ask('Use these final files? YES / NO', s => /^(yes|no)$/i.test(s), 'Type YES or NO.');
    if (answer.toUpperCase() !== 'YES') fail('Cancelled. No output was saved.');
    return selected;
  } finally { q.close(); }
}
async function main(args, home = __dirname) {
  const [action, ...params] = args;
  if (action === 'spec') {
    let file;
    if (!params.length) file = await promptSpec(home);
    else if (params.length === 2 && params[0] === '--from') file = createSpecFrom(home, path.resolve(params[1]));
    else fail('Usage: Create_Spec.bat [--from COMPLETED_SPEC.json]');
    console.log('SUCCESS: ' + file);
    console.log('Save the current admin deployment-policy.json beside this BAT, then use Create_Release_Manifest.bat.');
    return;
  }
  if (!['manifest', 'check'].includes(action) || ![0, 3, 4].includes(params.length)) fail('Usage: Create_Release_Manifest.bat [A.exe B.exe O.exe [NEW_OUTPUT.json]] or Check_Release_Manifest.bat [A.exe B.exe O.exe [MANIFEST.json]]');
  const p = requireInputs(home);
  if (action === 'manifest' && fs.existsSync(params[3] ? path.resolve(params[3]) : p.manifest)) fail('Manifest output already exists and was preserved. Archive it or specify a new output path.');
  if (action === 'check' && !fs.existsSync(params[3] ? path.resolve(params[3]) : p.manifest)) fail('Manifest file was not found. Run Create_Release_Manifest.bat first.');
  const files = params.length ? params.slice(0, 3) : await promptFiles(home);
  const result = action === 'manifest' ? makeManifest(home, files, params[3]) : checkManifest(home, files, params[3]);
  console.log('SUCCESS: ' + result.file + '\nManifest ID:\n' + result.manifestId);
  console.log(action === 'manifest' ? 'Register this JSON as a plan, upload FINAL A/B/O with this SAME ID, then complete manifest registration before combination validation.' : 'Local files match. Server registration, trusted approval keys and deployment policy are still checked by the server.');
  console.log('No server registration or CI PASS evidence was created.');
}
if (require.main === module) main(process.argv.slice(2)).catch(error => {
  const message = error.code === 'EEXIST' ? 'Output already exists and was preserved.' : error.code === 'ENOENT' ? 'Required file was not found: ' + (error.path || '') : error.message;
  console.error('ERROR: ' + message); process.exitCode = 1;
});
module.exports = { locations, validateSpec, finalFiles, createSpecFrom, makeManifest, checkManifest, main };
