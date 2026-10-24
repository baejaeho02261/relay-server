'use strict';
// Repository consistency check only. Never loads application modules or EXEs.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const MANIFEST = 'maintenance/relay-source-manifest.json';
const MAX_FILE = 64 * 1024 * 1024, MAX_MANIFEST = 16 * 1024 * 1024;
const IGNORED = new Set(['node_modules', '.git']);
const C = fs.constants;
function Fail(code, file) {
  const error = Error(code); error.checkCode = code;
  if (typeof file === 'string' && Safe(file)) error.checkPath = file;
  throw error;
}
function Safe(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 &&
    !/[\\:\x00-\x1f\x7f]/.test(value) && !path.posix.isAbsolute(value) &&
    path.posix.normalize(value) === value && value.normalize('NFC') === value &&
    value.split('/').every(part => part && part !== '.' && part !== '..' && !IGNORED.has(part));
}
function Keys(value, names, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) Fail(code);
}
function StrictJson(bytes, file) {
  const source = bytes.toString('utf8');
  if (!Buffer.from(source, 'utf8').equals(bytes)) Fail('JSON_UTF8_INVALID', file);
  let parsed;
  try { parsed = JSON.parse(source); } catch (_) { Fail('JSON_INVALID', file); }
  // JSON.parse accepts duplicate keys. Detect decoded duplicates before using it.
  let at = 0, nodes = 0;
  function space() { while (/\s/.test(source[at] || '') && at < source.length) at++; }
  function string() {
    const start = at++;
    while (at < source.length) {
      const char = source[at++];
      if (char === '\\') at++;
      else if (char === '"') return JSON.parse(source.slice(start, at));
    }
    Fail('JSON_INVALID', file);
  }
  function value(depth) {
    if (++nodes > 250000 || depth > 64) Fail('JSON_COMPLEXITY_LIMIT', file);
    space();
    if (source[at] === '{') {
      at++; space(); const keys = new Set();
      if (source[at] === '}') { at++; return; }
      while (at < source.length) {
        const key = string();
        if (keys.has(key)) Fail('JSON_DUPLICATE_KEY', file);
        keys.add(key); space(); at++; value(depth + 1); space();
        if (source[at++] === '}') return;
        space();
      }
    } else if (source[at] === '[') {
      at++; space();
      if (source[at] === ']') { at++; return; }
      while (at < source.length) {
        value(depth + 1); space();
        if (source[at++] === ']') return;
      }
    } else if (source[at] === '"') { string(); return; }
    else { while (at < source.length && !/[\s,}\]]/.test(source[at])) at++; return; }
    Fail('JSON_INVALID', file);
  }
  value(0); space();
  if (at !== source.length) Fail('JSON_INVALID', file);
  return parsed;
}
function Root(input) {
  const root = path.resolve(input), parts = root.slice(path.parse(root).root.length).split(path.sep).filter(Boolean);
  let cursor = path.parse(root).root;
  for (const part of parts) {
    cursor = path.join(cursor, part);
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink() || !stat.isDirectory()) Fail('ROOT_DIRECTORY_UNSAFE');
  }
  return fs.realpathSync(root);
}
function Inspect(root, relative) {
  if (!Safe(relative)) Fail('PATH_INVALID');
  let cursor = root;
  const parts = relative.split('/');
  for (let index = 0; index < parts.length; index++) {
    cursor = path.join(cursor, parts[index]);
    let stat;
    try { stat = fs.lstatSync(cursor); }
    catch (error) { if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return null; throw error; }
    if (stat.isSymbolicLink()) Fail('SYMLINK_FORBIDDEN', relative);
    if (index < parts.length - 1 && !stat.isDirectory()) return null;
    if (index === parts.length - 1) return stat;
  }
}
function Open(root, relative) {
  if (!Safe(relative)) Fail('PATH_INVALID');
  // On Linux the directory FDs anchor every lookup against parent replacement.
  if (process.platform === 'linux' && C.O_DIRECTORY && C.O_NOFOLLOW) {
    let directory;
    try {
      directory = fs.openSync(root, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
      const parts = relative.split('/');
      for (const part of parts.slice(0, -1)) {
        const next = fs.openSync('/proc/self/fd/' + directory + '/' + part,
          C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
        fs.closeSync(directory); directory = next;
      }
      return fs.openSync('/proc/self/fd/' + directory + '/' + parts.at(-1),
        C.O_RDONLY | C.O_NOFOLLOW | (C.O_NONBLOCK || 0));
    } finally { if (directory !== undefined) fs.closeSync(directory); }
  }
  const before = Inspect(root, relative);
  if (!before || !before.isFile()) Fail('FILE_MISSING_OR_INVALID', relative);
  const descriptor = fs.openSync(path.join(root, relative), C.O_RDONLY | (C.O_NOFOLLOW || 0));
  const opened = fs.fstatSync(descriptor);
  if (opened.ino !== before.ino || opened.dev !== before.dev) {
    fs.closeSync(descriptor); Fail('FILE_CHANGED_DURING_READ', relative);
  }
  return descriptor;
}
function Read(root, relative, limit = MAX_FILE, digest) {
  let descriptor;
  try {
    descriptor = Open(root, relative);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || before.size > limit) Fail('FILE_TYPE_OR_SIZE_INVALID', relative);
    const hash = crypto.createHash('sha512'), chunks = digest ? null : [];
    const buffer = Buffer.alloc(65536); let total = 0, count;
    while ((count = fs.readSync(descriptor, buffer, 0, buffer.length, null)) !== 0) {
      total += count;
      if (total > limit || total > before.size) Fail('FILE_CHANGED_DURING_READ', relative);
      hash.update(buffer.subarray(0, count));
      if (chunks) chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    const after = fs.fstatSync(descriptor);
    if (total !== before.size || after.size !== before.size || after.ino !== before.ino ||
        after.dev !== before.dev || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || after.nlink !== 1)
      Fail('FILE_CHANGED_DURING_READ', relative);
    const actual = hash.digest('hex');
    if (digest && actual !== digest) Fail('HASH_MISMATCH', relative);
    // Recheck the path as well as the stable open FD before accepting this file.
    const current = Inspect(root, relative);
    if (!current || current.ino !== before.ino || current.dev !== before.dev || current.size !== before.size ||
        current.mtimeMs !== before.mtimeMs || current.ctimeMs !== before.ctimeMs) Fail('FILE_CHANGED_DURING_READ', relative);
    return chunks ? Buffer.concat(chunks, total) : total;
  } catch (error) {
    if (error.checkCode) throw error;
    const code = ['ENOENT', 'ENOTDIR', 'ELOOP', 'EACCES', 'EPERM'].includes(error.code) ? error.code : 'FILE_READ_FAILED';
    Fail(code, relative);
  } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}
function Unexpected(root, expected) {
  const found = new Set(); let count = 0;
  function visit(relative) {
    for (const name of fs.readdirSync(path.join(root, relative)).sort()) {
      if (++count > 20000) Fail('SOURCE_ENTRY_LIMIT');
      const file = relative ? relative + '/' + name : name;
      const stat = fs.lstatSync(path.join(root, file));
      if (stat.isSymbolicLink()) Fail('SYMLINK_FORBIDDEN', file);
      if (IGNORED.has(name) && stat.isDirectory()) continue;
      if (!Safe(file)) Fail('PATH_INVALID');
      if (stat.isDirectory()) visit(file);
      else if (!stat.isFile()) Fail('FILE_TYPE_INVALID', file);
      else {
        if (!expected.has(file) && file !== MANIFEST) Fail('UNEXPECTED_SOURCE_FILE', file);
        found.add(file);
      }
    }
  }
  visit('');
  for (const file of expected) if (!found.has(file)) Fail('EXPECTED_SOURCE_MISSING', file);
}
function Resolve(root, files, source, request) {
  if (typeof request !== 'string' || request.length > 4096 || /[\\:\x00-\x1f\x7f]/.test(request) ||
      !/^\.{1,2}(?:\/|$)/.test(request)) Fail('LOCAL_MODULE_REQUEST_INVALID', source);
  const target = path.posix.normalize(path.posix.join(path.posix.dirname(source), request));
  if (target !== '.' && !Safe(target)) Fail('LOCAL_MODULE_ESCAPE', source);
  function file(candidate) {
    if (!Safe(candidate)) return null;
    const stat = Inspect(root, candidate);
    if (!stat || !stat.isFile()) return null;
    if (!files.has(candidate)) Fail('MODULE_TARGET_NOT_INDEXED', candidate);
    if (!['', '.js', '.json'].includes(path.posix.extname(candidate))) Fail('MODULE_TYPE_UNSUPPORTED', candidate);
    return candidate;
  }
  function asFile(candidate) {
    return file(candidate) || file(candidate + '.js') || file(candidate + '.json');
  }
  function index(directory) {
    return file(path.posix.join(directory, 'index.js')) || file(path.posix.join(directory, 'index.json'));
  }
  const direct = target === '.' ? null : asFile(target);
  if (direct) return direct;
  const stat = target === '.' ? fs.statSync(root) : Inspect(root, target);
  if (!stat || !stat.isDirectory()) Fail('LOCAL_MODULE_NOT_FOUND', source);
  const packageName = path.posix.join(target, 'package.json'), packageStat = Inspect(root, packageName);
  if (packageStat && packageStat.isFile()) {
    if (!files.has(packageName)) Fail('MODULE_TARGET_NOT_INDEXED', packageName);
    const pkg = StrictJson(Read(root, packageName, 2 * 1024 * 1024), packageName);
    if (Object.hasOwn(pkg, 'main') && pkg.main) {
      if (typeof pkg.main !== 'string' || /[\\:\x00-\x1f\x7f]/.test(pkg.main) || path.posix.isAbsolute(pkg.main))
        Fail('PACKAGE_MAIN_INVALID', packageName);
      const main = path.posix.normalize(path.posix.join(target, pkg.main));
      if (main !== '.' && !Safe(main)) Fail('LOCAL_MODULE_ESCAPE', packageName);
      const resolved = main === '.' ? index(main) : asFile(main) || index(main);
      if (resolved) return resolved;
    }
  }
  const fallback = index(target);
  if (!fallback) Fail('LOCAL_MODULE_NOT_FOUND', source);
  return fallback;
}
function Run(inputRoot) {
  const root = Root(inputRoot), manifest = StrictJson(Read(root, MANIFEST, MAX_MANIFEST), MANIFEST);
  Keys(manifest, ['version', 'algorithm', 'scope', 'files', 'localModuleReferences'], 'MANIFEST_SCHEMA_INVALID');
  if (manifest.version !== 1 || manifest.algorithm !== 'sha512' || manifest.scope !== 'relay-repository' ||
      !manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files) ||
      !Array.isArray(manifest.localModuleReferences)) Fail('MANIFEST_SCHEMA_INVALID');
  const entries = Object.entries(manifest.files);
  if (!entries.length || entries.length > 8192 || manifest.localModuleReferences.length > 65536) Fail('MANIFEST_LIMIT');
  const names = new Set(), folded = new Set();
  for (const [name, digest] of entries) {
    if (!Safe(name) || name === MANIFEST) Fail('MANIFEST_PATH_INVALID');
    if (typeof digest !== 'string' || !/^[a-f0-9]{128}$/.test(digest)) Fail('MANIFEST_DIGEST_INVALID', name);
    if (names.has(name) || folded.has(name.toLowerCase())) Fail('MANIFEST_DUPLICATE_PATH', name);
    names.add(name); folded.add(name.toLowerCase());
  }
  if (!names.has('package.json') || !names.has('peace.relay-server.js')) Fail('MANIFEST_REQUIRED_SOURCE_MISSING');
  let total = 0;
  for (const [name, digest] of entries) {
    total += Read(root, name, MAX_FILE, digest);
    if (total > 512 * 1024 * 1024) Fail('SOURCE_TOTAL_SIZE_LIMIT');
  }
  Unexpected(root, names);
  const pkg = StrictJson(Read(root, 'package.json', 2 * 1024 * 1024), 'package.json');
  if (!/^\d+\.\d+\.\d+$/.test(pkg.engines?.node || '') || pkg.engines.node !== '24.22.1' ||
      process.version !== 'v' + pkg.engines.node) Fail('NODE_RUNTIME_MISMATCH', 'package.json');
  const references = new Set();
  for (const ref of manifest.localModuleReferences) {
    Keys(ref, ['file', 'line', 'request'], 'MODULE_REFERENCE_SCHEMA_INVALID');
    if (!Safe(ref.file) || !names.has(ref.file) || !ref.file.endsWith('.js') ||
        !Number.isSafeInteger(ref.line) || ref.line < 1 || ref.line > 10000000) Fail('MODULE_REFERENCE_SCHEMA_INVALID');
    const key = JSON.stringify([ref.file, ref.line, ref.request]);
    if (references.has(key)) Fail('MODULE_REFERENCE_DUPLICATE', ref.file);
    references.add(key); Resolve(root, names, ref.file, ref.request);
  }
  return {files: entries.length, localModuleReferences: references.size, bytes: total};
}
if (require.main === module) {
  try {
    const args = process.argv.slice(2);
    if (args.length && !(args.length === 2 && args[0] === '--root')) Fail('ARGUMENTS_INVALID');
    const result = Run(args.length ? args[1] : path.resolve(__dirname, '../..'));
    console.log('RELAY SOURCE CHECK PASS: ' + result.files + ' SHA-512 files; ' +
      result.localModuleReferences + ' local module references; Node ' + process.version);
    console.log('Scope: relay-repository consistency only; no Windows/native-source execution or publisher-trust claim.');
  } catch (error) {
    const code = error.checkCode || 'CHECK_FAILED';
    console.error('RELAY SOURCE CHECK FAIL: ' + code + (error.checkPath ? ' ' + JSON.stringify(error.checkPath) : ''));
    process.exitCode = 1;
  }
}
module.exports = {Run};
