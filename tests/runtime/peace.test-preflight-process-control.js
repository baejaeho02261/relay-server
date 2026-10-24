/* Real child-process lifecycle tests. Does not claim Windows or SQLite product coverage. */
'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process'),assert=require('node:assert/strict');
const helper=path.resolve(MODULE_RESOURCE_ROOT,"runtime/peace.test-owned-directory.js"),launcher=require("../../tools/bootstrap/peace.release-openssl-bootstrap");
const root=fs.mkdtempSync(path.join(os.tmpdir(),'preflight-control-contract-'));
let count=0;const owned=[];
function check(name,fn){fn();count++;console.log('PASS '+name);}
function runCase(name,body,{prefixCode='',options={}}={}){
 const file=path.join(root,name+'.js');
 fs.writeFileSync(file,`'use strict';\n${prefixCode}\nrequire(${JSON.stringify(helper)}).Main(__filename,'owned-contract-',async directory=>{${body}},${JSON.stringify(options)});\n`);
 const r=cp.spawnSync(process.execPath,[file],{encoding:'utf8',timeout:15000,shell:false,cwd:root});
 if(r.error)throw r.error;
 const match=/\[TEST_SANDBOX\] (.+)/.exec(r.stdout||'');assert(match,'test child must use owned directory');
 const directory=match[1].trim();owned.push(directory);return {...r,directory};
}
try{
 check('completed child exits before owned directory is removed',()=>{
  const r=runCase('normal',`const f=require('node:fs');f.writeFileSync(require('node:path').join(directory,'data'),'bytes');console.log('BODY_DONE');`);
  assert.equal(r.status,0,r.stderr);assert(!fs.existsSync(r.directory));assert(r.stdout.indexOf('BODY_DONE')<r.stdout.indexOf('[TEST_CLEANUP_OK]'));
 });
 check('unclosed child descriptor is released by process exit, not a production unlock API',()=>{
  const r=runCase('open-file',`const f=require('node:fs');const fd=f.openSync(require('node:path').join(directory,'open.sqlite'),'wx');f.writeSync(fd,'owned fixture');`);
  assert.equal(r.status,0,r.stderr);assert(!fs.existsSync(r.directory));
 });
 check('throw preserves original cause and still cleans only after child termination',()=>{
  const r=runCase('throws',`throw Object.assign(Error('PRIMARY_FIXTURE_ERROR'),{cause:Error('INNER_FIXTURE_CAUSE')});`);
  assert.equal(r.status,1);assert(r.stderr.includes('PRIMARY_FIXTURE_ERROR'));assert(r.stderr.includes('INNER_FIXTURE_CAUSE'));assert(r.stdout.includes('[TEST_CLEANUP_OK]'));
 });
 check('nonzero exit cannot become PASS after successful cleanup',()=>{
  const r=runCase('exit-code',`process.exitCode=7;`);assert.equal(r.status,1);assert(r.stderr.includes('status=7'));assert(!fs.existsSync(r.directory));
 });
 check('early process.exit(0) without callback completion is not test PASS',()=>{
  const r=runCase('early-zero',`process.exit(0);`);assert.equal(r.status,1);assert(r.stderr.includes('TEST_BODY_NOT_COMPLETED'));
 });
 check('timeout remains failure and process exit precedes cleanup',()=>{
  const r=runCase('hang',`await new Promise(()=>setInterval(()=>{},1000));`,{options:{timeoutMs:300}});assert.equal(r.status,1);assert(r.stderr.includes('ETIMEDOUT'));assert(r.stdout.includes('[TEST_CLEANUP_OK]'));
 });
 check('cleanup EPERM cannot become PASS, and does not hide primary failure',()=>{
  const r=runCase('cleanup-denied',`throw Error('PRIMARY_BEFORE_CLEANUP');`,{prefixCode:`if(process.argv.length===2)require('node:fs').rmSync=()=>{throw Object.assign(Error('TEST_ONLY_DENIED'),{code:'EPERM'});};`});
  assert.equal(r.status,1);assert(r.stderr.includes('PRIMARY_BEFORE_CLEANUP'));assert(r.stderr.includes('[TEST_CLEANUP_FAILED] EPERM'));assert(fs.existsSync(r.directory));
 });
 check('owner marker mismatch refuses deletion',()=>{
  const r=runCase('owner-mismatch',`const f=require('node:fs'),p=require('node:path');const a=p.join(directory,'.test-directory-owner.json');const o=JSON.parse(f.readFileSync(a));o.nonce='0'.repeat(48);f.writeFileSync(a,JSON.stringify(o));`);
  assert.equal(r.status,1);assert(r.stderr.includes('TEST_DIRECTORY_OWNER_MISMATCH'));assert(fs.existsSync(r.directory));
 });
 check('child cannot inherit authority or cloud credentials',()=>{
  const old=process.env.ADMIN_SECRET;process.env.ADMIN_SECRET='contract-only-not-a-secret';
  try{const r=runCase('environment',`require('node:assert/strict').equal(process.env.ADMIN_SECRET,undefined);require('node:assert/strict').equal(process.env.NODE_OPTIONS,undefined);require('node:assert/strict').equal(process.env.DATA_DIR,directory);`);assert.equal(r.status,0,r.stderr);}finally{if(old===undefined)delete process.env.ADMIN_SECRET;else process.env.ADMIN_SECRET=old;}
 });
 check('default OpenSSL arguments remain backwards compatible',()=>assert.deepEqual(launcher.parseArgs([]),{checkOnly:false,explicit:''}));
 check('noninteractive preflight auto is explicit',()=>assert.equal(launcher.parseArgs(['--preflight-auto']).preflightAuto,true));
 check('specified output preflight preserves exact path',()=>assert.equal(launcher.parseArgs(['--preflight','A B']).preflight,'A B'));
 check('ambiguous automatic and specified output is rejected',()=>assert.throws(()=>launcher.parseArgs(['--preflight-auto','--preflight','A']),/Usage/));
 check('check-only cannot silently run tests',()=>assert.throws(()=>launcher.parseArgs(['--check','--preflight-auto']),/EXCLUSIVE/));
 check('output selection skips prior evidence and never creates selected directory',()=>{
  const profile=path.join(root,'profile'),e=path.join(profile,'Documents','ReleaseEvidence');fs.mkdirSync(path.join(e,'preflight-04'),{recursive:true});fs.writeFileSync(path.join(e,'preflight-04','keep'),'unchanged');
  const next=launcher.nextEvidenceDirectory({USERPROFILE:profile});assert.equal(next,path.join(e,'preflight-05'));assert(!fs.existsSync(next));assert.equal(fs.readFileSync(path.join(e,'preflight-04','keep'),'utf8'),'unchanged');
 });
 check('wrong profile is rejected without selecting arbitrary working directory',()=>assert.throws(()=>launcher.nextEvidenceDirectory({USERPROFILE:'relative'}),/USER_PROFILE_DIRECTORY_REQUIRED/));
 console.log('Preflight control contract: '+count+' passed. Real processes/files; EPERM injection is synthetic; not Windows/SQLite-product proof.');
}finally{
 for(const directory of owned)if(path.dirname(directory)===fs.realpathSync(os.tmpdir())&&path.basename(directory).startsWith('owned-contract-'))fs.rmSync(directory,{recursive:true,force:true,maxRetries:6,retryDelay:100});
 fs.rmSync(root,{recursive:true,force:true,maxRetries:6,retryDelay:100});
}
