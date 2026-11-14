'use strict';
// Public build data only. This helper does not issue, execute or sign an EXE.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { TextDecoder } = require('node:util');

const PREFIX = 'COZY_LAUNCHER_RESOURCE_';
const SETUP_REQUIRED = 'COZY_ISSUED_A_PUBLIC_KEY_SETUP_REQUIRED';
const MAX_RESOURCE = 128 * 1024;
const MAGIC = Buffer.from('COZYAISSUERKEY1!', 'ascii');
const SAME_FILE = ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'nlink'];

function Fail(code) { throw Error(PREFIX + code); }
function Absolute(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || /[\0\r\n]/.test(value)) Fail('ABSOLUTE_SOURCE_ROOT_REQUIRED');
  const resolved = path.resolve(value);
  if (resolved === path.parse(resolved).root) Fail('SOURCE_ROOT_INVALID');
  return resolved;
}
function NoLinks(file, optional = false) {
  const absolute = path.resolve(file), parts = [];
  let cursor = absolute;
  while (true) {
    parts.push(cursor);
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  const directories = [];
  for (const entry of parts.reverse()) {
    let stat;
    try { stat = fs.lstatSync(entry, { bigint: true }); }
    catch (error) {
      if (error.code === 'ENOENT' && entry === absolute && optional) return { stat: null, directories };
      Fail(error.code === 'ENOENT' ? 'INPUT_MISSING' : 'PATH_UNAVAILABLE');
    }
    if (stat.isSymbolicLink()) Fail('SYMLINK_REJECTED');
    if (entry !== absolute && !stat.isDirectory()) Fail('PATH_INVALID');
    if (stat.isDirectory()) directories.push({ file: entry, dev: stat.dev, ino: stat.ino });
    if (entry === absolute) return { stat, directories };
  }
  Fail('PATH_INVALID');
}
function Same(left, right) { return SAME_FILE.every(key => left[key] === right[key]); }
function Read(file, maximum, snapshots) {
  const checked = NoLinks(file), before = checked.stat;
  if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximum)) Fail('INPUT_FILE_INVALID');
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!Same(before, opened)) Fail('INPUT_CHANGED');
    const bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!count) Fail('INPUT_CHANGED');
      offset += count;
    }
    if (!Same(opened, fs.fstatSync(fd, { bigint: true }))) Fail('INPUT_CHANGED');
    snapshots.push({ file, stat: opened });
    return bytes;
  } catch (error) {
    if (error.message.startsWith(PREFIX)) throw error;
    Fail('INPUT_UNAVAILABLE');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function Text(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch (_) { Fail('UTF8_INVALID'); }
}
function PublicAnchor(include, binary) {
  let source = Text(include);
  if (source.includes(SETUP_REQUIRED)) Fail('PUBLIC_KEY_SETUP_REQUIRED');
  source = source.replace(/\(\*[\s\S]*?\*\)|\{[^}]*\}|\/\/[^\r\n]*/g, '');
  const match = /^\s*const\s+CozyIssuedATrustAnchor\s*:\s*array\s*\[0\.\.330\]\s+of\s+Byte\s*=\s*\(([^)]*)\)\s*;\s*$/i.exec(source);
  if (!match || !/^\s*\$[a-f0-9]{2}(?:\s*,\s*\$[a-f0-9]{2})*\s*$/i.test(match[1])) Fail('PUBLIC_INCLUDE_INVALID');
  const anchor = Buffer.from(match[1].match(/\$[a-f0-9]{2}/ig).map(value => parseInt(value.slice(1), 16)));
  if (anchor.length !== 331 || binary.length !== 331 || !anchor.equals(binary)) Fail('PUBLIC_BINARY_MISMATCH');
  if (!anchor.subarray(0, 16).equals(MAGIC) ||
      [0x31415352, 2048, 3, 256, 0, 0].some((value, index) => anchor.readUInt32LE(48 + index * 4) !== value) ||
      !anchor.subarray(72, 75).equals(Buffer.from([1, 0, 1])) || !(anchor[75] & 128) || !(anchor[330] & 1)) Fail('PUBLIC_RSA_INVALID');
  const digest = crypto.createHash('sha256').update(anchor.subarray(48)).digest();
  if (!crypto.timingSafeEqual(digest, anchor.subarray(16, 48))) Fail('PUBLIC_KEY_ID_INVALID');
  return { anchor, keyId: digest.toString('hex') };
}
function Exact(value, fields) {
  return value && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}
function Metadata(bytes) {
  const source = Text(bytes);
  let value;
  try {
    // This bounded schema uses distinct property names at every level. Reject
    // duplicate decoded names, including escaped spellings, before use.
    const names = [...source.matchAll(/"(?:\\.|[^"\\])*"\s*:/g)].map(match => JSON.parse(match[0].replace(/\s*:$/, '')));
    if (new Set(names).size !== names.length) Fail('METADATA_INVALID');
    value = JSON.parse(source);
  } catch (_) { Fail('METADATA_INVALID'); }
  if (!Exact(value, ['schemaVersion', 'version', 'companyName', 'productName', 'descriptions']) || value.schemaVersion !== 1 ||
      typeof value.version !== 'string' || !/^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){3}$/.test(value.version) ||
      !Exact(value.descriptions, ['A', 'B', 'O'])) Fail('METADATA_INVALID');
  const parts = value.version.split('.').map(Number);
  if (parts.some(part => part > 65535)) Fail('METADATA_VERSION_INVALID');
  for (const text of [value.companyName, value.productName, ...Object.values(value.descriptions)]) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(text)) Fail('METADATA_TEXT_INVALID');
  }
  return { ...value, parts };
}
function Manifest(bytes, version) {
  const source = Text(bytes);
  if (/<!DOCTYPE|<!ENTITY/i.test(source)) Fail('MANIFEST_INVALID');
  const identities = [...source.matchAll(/<assemblyIdentity\b([^<>]*)\/?\s*>/g)];
  if (identities.length !== 1) Fail('MANIFEST_INVALID');
  const versions = [...identities[0][1].matchAll(/(?:^|\s)version\s*=\s*(["'])([^"']*)\1/g)];
  if (versions.length !== 1 || versions[0][2] !== version) Fail('MANIFEST_VERSION_MISMATCH');
  return bytes;
}
function Pad(bytes) { return Buffer.concat([bytes, Buffer.alloc((-bytes.length) & 3)]); }
function Wide(value) { return Buffer.from(value + '\0', 'utf16le'); }
function VersionBlock(key, value, valueLength, type, children = []) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(valueLength, 2); header.writeUInt16LE(type, 4);
  let bytes = Buffer.concat([Pad(Buffer.concat([header, Wide(key)])), value]);
  for (const child of children) bytes = Buffer.concat([Pad(bytes), child]);
  if (bytes.length > 65535) Fail('VERSION_RESOURCE_TOO_LARGE');
  bytes.writeUInt16LE(bytes.length, 0);
  return bytes;
}
function VersionResource(metadata) {
  const [major, minor, patch, build] = metadata.parts;
  const high = major * 65536 + minor, low = patch * 65536 + build;
  const fixed = Buffer.alloc(52);
  [0xfeef04bd, 0x10000, high, low, high, low, 0x3f, 0, 0x40004, 1, 0, 0, 0]
    .forEach((value, index) => fixed.writeUInt32LE(value, index * 4));
  const values = { CompanyName: metadata.companyName, FileDescription: metadata.descriptions.A,
    FileVersion: metadata.version, ProductName: metadata.productName, ProductVersion: metadata.version };
  const strings = Object.entries(values).map(([key, value]) => VersionBlock(key, Wide(value), value.length + 1, 1));
  const table = VersionBlock('040904E4', Buffer.alloc(0), 0, 1, strings);
  const stringInfo = VersionBlock('StringFileInfo', Buffer.alloc(0), 0, 1, [table]);
  const translation = Buffer.alloc(4); translation.writeUInt16LE(0x0409); translation.writeUInt16LE(1252, 2);
  const variable = VersionBlock('Translation', translation, translation.length, 0);
  const variableInfo = VersionBlock('VarFileInfo', Buffer.alloc(0), 0, 1, [variable]);
  return VersionBlock('VS_VERSION_INFO', fixed, fixed.length, 0, [stringInfo, variableInfo]);
}
function Record(type, name, bytes, language = 0x0409, flags = 0x30) {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(bytes.length); header.writeUInt32LE(header.length, 4);
  header.writeUInt16LE(0xffff, 8); header.writeUInt16LE(type, 10);
  header.writeUInt16LE(0xffff, 12); header.writeUInt16LE(name, 14);
  header.writeUInt16LE(flags, 20); header.writeUInt16LE(language, 22);
  return Pad(Buffer.concat([header, bytes]));
}
function Recheck(snapshots, directories) {
  for (const entry of directories) {
    const checked = NoLinks(entry.file);
    if (!checked.stat.isDirectory() || checked.stat.dev !== entry.dev || checked.stat.ino !== entry.ino) Fail('DIRECTORY_CHANGED');
  }
  for (const entry of snapshots) {
    const checked = NoLinks(entry.file);
    if (!checked.stat.isFile() || !Same(checked.stat, entry.stat)) Fail('INPUT_CHANGED');
  }
}
function Prepare(sourceRoot) {
  const root = Absolute(sourceRoot), rootInfo = NoLinks(root);
  if (!rootInfo.stat.isDirectory()) Fail('SOURCE_ROOT_INVALID');
  const configuration = path.join(root, 'Cozy.Source', 'Cozy.Configuration');
  const project = path.join(root, 'Cozy.Projects', 'Cozy.Launcher');
  const output = path.join(project, 'Cozy.LauncherResources.res'), snapshots = [];
  const include = Read(path.join(configuration, 'Cozy.IssuedA.Trust.inc'), 16384, snapshots);
  // Report missing public setup before a missing generated .bin can mask it.
  if (Text(include).includes(SETUP_REQUIRED)) Fail('PUBLIC_KEY_SETUP_REQUIRED');
  const binary = Read(path.join(configuration, 'Cozy.IssuedA.Trust.bin'), 331, snapshots);
  const identity = PublicAnchor(include, binary);
  const metadata = Metadata(Read(path.join(configuration, 'Cozy.ReleaseMetadata.json'), 16384, snapshots));
  const manifest = Manifest(Read(path.join(project, 'Cozy.Launcher.manifest'), 65536, snapshots), metadata.version);
  const resource = Buffer.concat([Record(0, 0, Buffer.alloc(0), 0, 0), Record(10, 311, identity.anchor),
    Record(24, 1, manifest), Record(16, 1, VersionResource(metadata))]);
  if (resource.length > MAX_RESOURCE) Fail('RESOURCE_TOO_LARGE');
  const existing = NoLinks(output, true), directories = existing.directories;
  let old;
  if (existing.stat) old = Read(output, MAX_RESOURCE, snapshots);
  Recheck(snapshots, directories);
  const result = { ok: true, keyId: identity.keyId, resourceBytes: resource.length, publicOnly: true };
  if (old?.equals(resource)) return result;
  let pending, pendingIdentity;
  try {
    pending = path.join(project, '.Cozy.LauncherResources.' + crypto.randomBytes(16).toString('hex') + '.pending.res');
    const fd = fs.openSync(pending, 'wx', 0o600);
    try {
      pendingIdentity = fs.fstatSync(fd, { bigint: true });
      fs.writeFileSync(fd, resource); fs.fsyncSync(fd);
      pendingIdentity = fs.fstatSync(fd, { bigint: true });
    } finally { fs.closeSync(fd); }
    Recheck(snapshots, directories);
    if (!existing.stat && NoLinks(output, true).stat) Fail('OUTPUT_CHANGED');
    const currentPending = NoLinks(pending).stat;
    if (!currentPending.isFile() || currentPending.nlink !== 1n || currentPending.size !== BigInt(resource.length) || !Same(currentPending, pendingIdentity)) Fail('OUTPUT_CHANGED');
    fs.renameSync(pending, output); // Same-directory atomic commit; no fallible work follows it.
    pending = null;
    return result;
  } catch (error) {
    if (error.message.startsWith(PREFIX)) throw error;
    Fail('WRITE_FAILED');
  } finally {
    if (pending && pendingIdentity) {
      try {
        const current = fs.lstatSync(pending, { bigint: true });
        if (current.isFile() && current.dev === pendingIdentity.dev && current.ino === pendingIdentity.ino && current.nlink === 1n) fs.unlinkSync(pending);
      } catch (_) { /* Preserve anything this invocation did not create. */ }
    }
  }
}
function Main(argv) {
  if (argv.length !== 2 || argv[0] !== '--source-root') Fail('ARGUMENTS_INVALID');
  return Prepare(argv[1]);
}
if (require.main === module) {
  try { process.stdout.write(JSON.stringify(Main(process.argv.slice(2))) + '\n'); }
  catch (error) {
    const code = typeof error?.message === 'string' && /^COZY_LAUNCHER_RESOURCE_[A-Z0-9_]+$/.test(error.message) ? error.message : PREFIX + 'FAILED';
    process.stderr.write(code + '\n'); process.exitCode = 1;
  }
}
module.exports = { Prepare, Main };
