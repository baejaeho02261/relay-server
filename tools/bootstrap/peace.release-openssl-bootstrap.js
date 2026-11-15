/* Local test launcher only. No downloads, installs, registry writes, TLS bypass,
 * manifest regeneration, QA results, or production access are performed here. */
'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');

function envValue(env, name) {
  const key = Object.keys(env).find(k => k.toLowerCase() === name.toLowerCase());
  return key ? env[key] : '';
}
function uniquePaths(values, windows = true) {
  const seen = new Set();
  return values.filter(v => {
    if (typeof v !== 'string' || !v || v.includes('\0')) return false;
    const key = windows ? path.win32.normalize(v).toLowerCase() : path.normalize(v);
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });
}
function expandRegistryPath(value, env) {
  return String(value || '').replace(/%([^%]+)%/g, (all, name) => envValue(env, name) || all);
}
function windowsCandidates(env, registryRoots = [], gitPaths = []) {
  const w = path.win32;
  const roots = [...registryRoots];
  for (const key of ['ProgramW6432', 'ProgramFiles', 'ProgramFiles(x86)']) {
    const v = envValue(env, key); if (v) roots.push(w.join(v, 'Git'));
  }
  const local = envValue(env, 'LOCALAPPDATA');
  if (local) roots.push(w.join(local, 'Programs', 'Git'));
  for (const file of gitPaths) {
    if (!w.isAbsolute(file) || w.basename(file).toLowerCase() !== 'git.exe') continue;
    let d = w.dirname(file);
    for (let i = 0; i < 3; i++) { roots.push(d); d = w.dirname(d); }
  }
  const out = [];
  for (const raw of uniquePaths(roots)) {
    const root = expandRegistryPath(raw, env);
    if (!w.isAbsolute(root) || root.includes('%')) continue;
    for (const rel of ['mingw64\\bin\\openssl.exe', 'usr\\bin\\openssl.exe', 'mingw32\\bin\\openssl.exe']) {
      out.push(w.join(root, rel));
    }
  }
  // Deliberately ignore relative PATH entries and current-directory lookup.
  for (let dir of String(envValue(env, 'PATH') || '').split(';')) {
    dir = dir.trim().replace(/^"(.*)"$/, '$1');
    if (w.isAbsolute(dir)) out.push(w.join(dir, 'openssl.exe'));
  }
  return uniquePaths(out);
}
function prependPath(env, directory, windows = process.platform === 'win32') {
  const current = String(envValue(env, 'PATH') || '');
  const out = { ...env };
  for (const key of Object.keys(out)) if (key.toLowerCase() === 'path') delete out[key];
  out[windows ? 'Path' : 'PATH'] = directory + (current ? (windows ? ';' : ':') + current : '');
  return out;
}
function isFile(file) { try { return fs.statSync(file).isFile(); } catch { return false; } }
function textCommand(exe, args, env) {
  return cp.spawnSync(exe, args, {
    encoding: 'utf8', env, shell: false, windowsHide: true,
    timeout: 10000, maxBuffer: 256 * 1024
  });
}
function registryRoots(env) {
  const system = envValue(env, 'SystemRoot');
  if (!system) return [];
  const reg = path.win32.join(system, 'System32', 'reg.exe');
  if (!isFile(reg)) return [];
  const roots = [];
  for (const hive of ['HKCU', 'HKLM']) for (const view of ['64', '32']) {
    const r = textCommand(reg, ['query', hive + '\\SOFTWARE\\GitForWindows', '/v', 'InstallPath', '/reg:' + view], env);
    if (r.error || r.status !== 0) continue;
    for (const line of String(r.stdout || '').split(/\r?\n/)) {
      const m = /^\s*InstallPath\s+REG_(?:EXPAND_)?SZ\s+(.+?)\s*$/i.exec(line);
      if (m) roots.push(expandRegistryPath(m[1], env));
    }
  }
  return roots;
}
function gitPaths(env) {
  const system = envValue(env, 'SystemRoot');
  if (!system) return [];
  const where = path.win32.join(system, 'System32', 'where.exe');
  if (!isFile(where)) return [];
  const r = textCommand(where, ['git.exe'], env);
  if (r.error || r.status !== 0) return [];
  return String(r.stdout || '').split(/\r?\n/).filter(x => path.win32.isAbsolute(x));
}
function locateOpenSSL(env = process.env, explicit = '') {
  const windows = process.platform === 'win32';
  let candidates;
  if (explicit) {
    if (!path.isAbsolute(explicit) || path.basename(explicit).toLowerCase() !== (windows ? 'openssl.exe' : 'openssl')) {
      throw Error('OPENSSL_ABSOLUTE_EXECUTABLE_PATH_REQUIRED');
    }
    candidates = [explicit];
  } else if (windows) {
    candidates = windowsCandidates(env, registryRoots(env), gitPaths(env));
  } else {
    candidates = uniquePaths(String(envValue(env, 'PATH') || '').split(':')
      .filter(p => path.isAbsolute(p)).map(p => path.join(p, 'openssl')), false);
  }
  const tried = [];
  for (const file of candidates) {
    if (!isFile(file)) continue;
    const childEnv = prependPath(env, path.dirname(file), windows);
    const result = textCommand(file, ['version'], childEnv);
    const version = String(result.stdout || '').trim();
    if (!result.error && result.status === 0 && /^OpenSSL\s+\d+\./.test(version)) {
      return { file, version, env: childEnv };
    }
    tried.push(file + ' : ' + (result.error?.code || 'EXIT_' + result.status));
  }
  const error = Error('OPENSSL_NOT_FOUND_OR_NOT_EXECUTABLE');
  error.tried = tried; throw error;
}
function parseArgs(args) {
  let checkOnly = false, explicit = '', preflight = '', preflightAuto = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--check' && !checkOnly) checkOnly = true;
    else if (args[i] === '--preflight-auto' && !preflightAuto && !preflight) preflightAuto = true;
    else if (args[i] === '--preflight' && !preflightAuto && !preflight && args[i+1]) preflight = args[++i];
    else if (args[i] === '--openssl' && !explicit && args[i + 1]) explicit = args[++i];
    else throw Error('Usage: peace.release-openssl-bootstrap.js [--check] [--openssl ABSOLUTE_OPENSSL_PATH] [--preflight NEW_DIRECTORY | --preflight-auto]');
  }
  if(checkOnly&&(preflight||preflightAuto)) throw Error('CHECK_AND_PREFLIGHT_ARE_EXCLUSIVE');
  return { checkOnly, explicit, ...(preflight?{preflight}:{}), ...(preflightAuto?{preflightAuto}: {}) };
}
function nextEvidenceDirectory(env=process.env){
  const profile=envValue(env,'USERPROFILE')||envValue(env,'HOME');
  if(!profile||!path.isAbsolute(profile))throw Error('USER_PROFILE_DIRECTORY_REQUIRED');
  const parent=path.join(profile,'Documents','ReleaseEvidence');
  fs.mkdirSync(parent,{recursive:true});
  for(let n=4;n<=9999;n++){
    const candidate=path.join(parent,'preflight-'+String(n).padStart(2,'0'));
    if(!fs.existsSync(candidate))return candidate;
  }
  throw Error('NEW_EVIDENCE_DIRECTORY_EXHAUSTED');
}
function main(args = process.argv.slice(2)) {
  const { checkOnly, explicit, preflight, preflightAuto } = parseArgs(args);
  const web = path.resolve(MODULE_RESOURCE_ROOT, '..');
  const runner = path.join(MODULE_RESOURCE_ROOT, "artifacts/peace.release-preflight.js");
  if (!isFile(runner) || !isFile(path.join(web, 'package.json'))) throw Error('PUT_HELPER_IN_GAMEWEB_TOOLS');
  const found = locateOpenSSL(process.env, explicit);
  console.log('[OK] OpenSSL: ' + found.file);
  console.log('[OK] ' + found.version);
  console.log('[INFO] PATH applies only to this launcher and its child tests. System PATH is unchanged.');
  if (checkOnly) return 0;
  let output=preflight,command=[];
  if(preflightAuto || !output) output=nextEvidenceDirectory(process.env);
  if(output){
    output=path.resolve(output);
    if(fs.existsSync(output))throw Error('NEW_EVIDENCE_DIRECTORY_ALREADY_EXISTS');
    command=[path.join(MODULE_RESOURCE_ROOT,"artifacts/peace.release-preflight.js"),output];
    console.log('[INFO] Running optional source/server checks. No publication report is required.');
    console.log('[EVIDENCE] '+output);
  }
  const child = cp.spawnSync(process.execPath, command, {
    cwd: web, env: found.env, stdio: 'inherit', shell: false, windowsHide: false
  });
  if (child.error) throw child.error;
  if(output)console.log('[RESULT FILE] '+path.join(output,'preflight-result.json'));
  return Number.isInteger(child.status) ? child.status : 1;
}
if (require.main === module) {
  try { process.exitCode = main(); }
  catch (error) {
    console.error('[ERROR] ' + (error.code || error.message));
    for (const item of error.tried || []) console.error('[TRIED] ' + item);
    console.error('Git may be installed outside standard paths. No software was installed or downloaded.');
    console.error("Use: node tools\\bootstrap\\peace.release-openssl-bootstrap.js --openssl \"C:\\actual\\Git\\usr\\bin\\openssl.exe\"");
    process.exitCode = 1;
  }
}
module.exports = { envValue, uniquePaths, expandRegistryPath, windowsCandidates, prependPath, parseArgs, locateOpenSSL, nextEvidenceDirectory, main };
