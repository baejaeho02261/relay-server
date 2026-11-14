/* Read-only package check. Uses Node built-ins only. Never executes application modules or EXEs. */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {createRequire}=require('node:module');
const INDEX_SHA512='059fb30c1a461e82e9a8756ed163b698e5cfbe4c6b5d7c273eba0090f0cfb4f8441a9933be5040d8f4042ce582dd487535658c109101ae7839fc74167728ded9';
function digest(bytes,algorithm){return crypto.createHash(algorithm).update(bytes).digest('hex');}
function safeRelative(value){return typeof value==='string'&&value!==''&&!value.includes('\\')&&!value.includes(':')&&!value.includes('\0')&&!path.posix.isAbsolute(value)&&value.split('/').every(p=>p&&p!=='.'&&p!=='..');}
function inside(root,file){const rel=path.relative(root,file);return rel!==''&&!path.isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+path.sep);}
function regular(root,rel){
  if(!safeRelative(rel))throw Error('INVALID_INDEX_PATH');
  const parts=rel.split('/');let p=root;
  for(let i=0;i<parts.length;i++){
    p=path.join(p,parts[i]);const stat=fs.lstatSync(p);
    if(stat.isSymbolicLink())throw Error('SYMLINK_OR_JUNCTION');
    if(i<parts.length-1&&!stat.isDirectory())throw Error('PARENT_NOT_DIRECTORY');
    if(i===parts.length-1&&!stat.isFile())throw Error('NOT_REGULAR_FILE');
  }
  if(!inside(root,fs.realpathSync(p)))throw Error('OUTSIDE_ROOT');
  return p;
}
function stableHash(file,expected){
  const fd=fs.openSync(file,'r');try{
    const before=fs.fstatSync(fd);
    if(!before.isFile()||before.size!==expected.bytes)throw Error('SIZE_MISMATCH');
    const hash=crypto.createHash('sha512'),buffer=Buffer.alloc(65536);let total=0,n;
    while((n=fs.readSync(fd,buffer,0,buffer.length,null))!==0){total+=n;if(total>expected.bytes)throw Error('FILE_CHANGED_DURING_READ');hash.update(buffer.subarray(0,n));}
    const after=fs.fstatSync(fd);
    if(total!==expected.bytes||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs||after.ino!==before.ino||after.dev!==before.dev)throw Error('FILE_CHANGED_DURING_READ');
    if(hash.digest('hex')!==expected.sha512)throw Error('HASH_MISMATCH');
  }finally{fs.closeSync(fd);}
}
function VerifyApiSlotContract(batchBytes,contractBytes){
  const fail=code=>{throw Error('API_SLOT_CONTRACT_'+code);};
  if(!Buffer.isBuffer(batchBytes)||batchBytes.length>2*1024*1024||!Buffer.isBuffer(contractBytes)||contractBytes.length>1024*1024)fail('SIZE');
  const text=batchBytes.toString('utf8').replace(/\r\n/g,'\n');
  const one=expression=>{const found=[...text.matchAll(expression)];if(found.length!==1)fail('DECLARATION');return found[0][1];};
  const payload=one(/\$contractBase64 = @'\n([\s\S]*?)\n'@/g).replace(/\s/g,'');
  if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(payload))fail('BASE64');
  if(!Buffer.from(payload,'base64').equals(contractBytes))fail('PAYLOAD_MISMATCH');
  const pinned=one(/\(\$digest -ceq '([a-f0-9]{128})'\)/g);
  if(pinned!==digest(contractBytes,'sha512'))fail('DIGEST_MISMATCH');
  const source=JSON.parse(contractBytes.toString('utf8')),roles=['gcrLauncher','gcrConnect','gcrOverlay'];
  if(!source.roles||Object.keys(source.roles).sort().join(',')!==roles.slice().sort().join(',')||roles.some(role=>!Array.isArray(source.roles[role])))fail('ROLES');
  const values=name=>one(new RegExp('\\$'+name+' = @\\(([^\\n]+)\\)','g'));
  const integers=name=>{const value=values(name);if(!/^\d+(?:\s*,\s*\d+)*$/.test(value))fail('COUNTS');return value.split(',').map(Number);};
  const counts=roles.map(role=>source.roles[role].length),optional=roles.map(role=>source.roles[role].filter(item=>item.optional===true).length);
  if(JSON.stringify(integers('totalCounts'))!==JSON.stringify(counts))fail('COUNTS_MISMATCH');
  if(JSON.stringify(integers('optionalCounts'))!==JSON.stringify(optional))fail('OPTIONAL_MISMATCH');
  const modules=values('allowedModules');
  if(!/^'[a-z0-9_.-]+'(?:\s*,\s*'[a-z0-9_.-]+')*$/.test(modules))fail('MODULES');
  const actual=[...modules.matchAll(/'([^']+)'/g)].map(match=>match[1]);
  const expected=[...new Set(roles.flatMap(role=>source.roles[role].map(item=>item.module)))].sort();
  if(JSON.stringify(actual)!==JSON.stringify(expected))fail('MODULES_MISMATCH');
  return {A:counts[0],B:counts[1],O:counts[2]};
}
function main(){
  const args=process.argv.slice(2);
  if(args.length&&!(args.length===2&&args[0]==='--root'))throw Error('Usage: node verify-package.js [--root EXTRACTED_SOURCE_ROOT]');
  const root=fs.realpathSync(args.length?path.resolve(args[1]):path.resolve(__dirname,'../..'));
  const bytes=fs.readFileSync(path.join(__dirname,'baseline-index.json'));
  if(digest(bytes,'sha512')!==INDEX_SHA512)throw Error('CHECKER_INDEX_CHANGED_OR_MIXED_VERSION');
  const index=JSON.parse(bytes.toString('utf8'));
  console.log('cozy-peace package recheck (read-only)');console.log('Source root: '+root);
  console.log('Baseline: '+index.baselineArchive);console.log('Node: '+process.version+' / '+process.platform+' '+process.arch);
  console.log('Declared Node support: '+index.nodeEngines);
  console.log('No files will be changed; no app modules or EXEs will be executed.\n');
  let failures=0;
  for(const item of index.files){
    try{stableHash(regular(root,item.path),item);}
    catch(e){failures++;console.error('[FILE] '+item.path+' : '+(e.code||e.message));}
  }
  for(const name of index.retiredExecutableSources){
    if(!safeRelative(name))throw Error('INVALID_RETIRED_PATH');
    if(fs.existsSync(path.join(root,name))){failures++;console.error('[RETIRED SOURCE PRESENT] '+name);}
  }
  if(failures){
    console.error('\nPACKAGE FILE CHECK FAILED: '+failures+' problem(s).');
    console.error('Use the COMPLETE matching archive in a new folder. Do not copy tools alone.');
    console.error('Preserve existing keys, DATA_DIR, policies and approval JSONs separately.');
    console.error('Do not replace a missing validation module with an empty stub.');
    return 1;
  }
  console.log('[PASS] '+index.files.length+' original package files match their SHA-512 values.');
  const apiCounts=VerifyApiSlotContract(
    fs.readFileSync(regular(root,'tools/Cozy.Check-ApiSlots.bat')),
    fs.readFileSync(regular(root,'cozy-peace/Railway/Cozy.Tests/Cozy.Startup/Cozy.Startup_Binding_Contracts.json')));
  console.log('[PASS] Embedded API slot contract equals native source contract: A='+apiCounts.A+' B='+apiCounts.B+' O='+apiCounts.O+'.');
  for(const ref of index.references){
    try{
      const source=regular(root,ref.file),from=ref.resolutionBase?regular(root,ref.resolutionBase):source,resolved=createRequire(from).resolve(ref.request);
      if(!inside(root,fs.realpathSync(resolved)))throw Error('MODULE_OUTSIDE_ROOT');
    }catch(e){failures++;console.error('[MODULE] '+ref.file+':'+ref.line+' -> '+ref.request+' : '+(e.code||e.message));}
  }
  if(failures){console.error('LOCAL MODULE CHECK FAILED: '+failures+' problem(s).');return 1;}
  console.log('[PASS] '+index.references.length+' static literal local module references resolve.');
  console.log('[INFO] '+index.dynamicSites.length+' computed module-call sites are listed in the index; this is not exhaustive runtime coverage.');
  const request=createRequire(path.join(root,'cozy-peace/Relay Server/package.json'));
  for(const [group,names]of Object.entries(index.dependencyGroups)){
    const missing=names.filter(name=>{try{request.resolve(name);return false;}catch{return true;}});
    if(missing.length)console.log('[DEPENDENCY INFO] '+group+' not installed/resolvable: '+missing.join(', '));
  }
  const boundaries=require('./check-source-boundaries').Run(path.join(root,'cozy-peace'));
  for(const [file,code]of boundaries.problems)console.error('[BOUNDARY] '+code+': '+file);
  if(!boundaries.passed)return 1;
  console.log('[PASS] Source folder/name and sensitive-material boundaries.');
  console.log('\nPACKAGE CHECK PASS');
  console.log('Scope: source files and static local references only.');
  console.log('Does not certify installed native add-ons, Windows BAT/Delphi execution, live deployment or publisher authenticity.');
  console.log('Unknown extra files, operating data and build outputs are not deleted or approved.');
  return 0;
}
module.exports={VerifyApiSlotContract};
if(require.main===module){try{process.exitCode=main();}catch(e){console.error('PACKAGE CHECK ERROR: '+(e.code||e.message));process.exitCode=2;}}
