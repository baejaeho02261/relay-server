'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),net=require('node:net'),{spawn,spawnSync,execFileSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),temporary=fs.mkdtempSync(path.join(os.tmpdir(),'game-tls-86-'));let checks=0;
const originalEnv={...process.env};for(const name of ['CONNECT_TLS_CERT_FILE','CONNECT_TLS_KEY_FILE','CONNECT_TLS_SERVER_NAME'])delete originalEnv[name];
function Env(directory,extra={}){return {...originalEnv,DATA_DIR:directory,HA_ENABLED:'0',...extra};}
function Run(directory,script,extra={}){return spawnSync(process.execPath,['-e',script],{cwd:__dirname,env:Env(directory,extra),encoding:'utf8'});}
const publicScript="console.log(JSON.stringify(require('../services/connectTls').Public()))";
function Public(directory,extra={}){const out=Run(directory,publicScript,extra);assert.equal(out.status,0,out.stderr);return JSON.parse(out.stdout);}
function Copy(directory){const copy=fs.mkdtempSync(path.join(temporary,'copy-'));fs.cpSync(directory,copy,{recursive:true});return copy;}
function Fail(directory,pattern,extra={}){const out=Run(directory,publicScript,extra);assert.notEqual(out.status,0,out.stdout);assert.match(out.stderr,pattern);}
async function Check(name,fn){await fn();checks++;console.log('PASS '+name);}
function Cli(directory,args,extra={}){return new Promise(resolve=>{const child=spawn(process.execPath,['tools/tls-rotate.js',...args],{cwd:root,env:Env(directory,extra),stdio:['ignore','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);child.on('close',status=>resolve({status,stdout,stderr}));});}
async function Port(){const server=net.createServer();await new Promise(resolve=>server.listen(0,'0.0.0.0',resolve));const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;}
(async()=>{try{
 const fresh=path.join(temporary,'fresh');fs.mkdirSync(fresh);let initial;
 await Check('Fresh identity uses random neutral DNS CN/SAN and stable exact pin',()=>{
  initial=Public(fresh);assert.match(initial.tlsServerName,/^[a-f0-9]{32}\.invalid$/);assert.deepEqual(Public(fresh),initial);
  const files=Run(fresh,"const x=require('../services/connectTls').Load();console.log(JSON.stringify({certFile:x.certFile,keyFile:x.keyFile}))");assert.equal(files.status,0,files.stderr);const names=JSON.parse(files.stdout),cert=new crypto.X509Certificate(fs.readFileSync(names.certFile));
  assert.equal(cert.subject,'CN='+initial.tlsServerName);assert.equal(cert.subjectAltName,'DNS:'+initial.tlsServerName);assert.ok(!cert.subject.includes('Game'));if(process.platform!=='win32')assert.equal(fs.statSync(names.keyFile).mode&0o777,0o600);
 });
 await Check('Missing or corrupt generated marker, private key and generation fail closed',()=>{
  for(const kind of ['marker-missing','marker-corrupt','marker-changed','directory-missing','key-missing','bad-generation']){
   const directory=Copy(fresh),marker=path.join(directory,'connect-tls.sha256'),pointer=JSON.parse(fs.readFileSync(marker));
   if(kind==='marker-missing')fs.unlinkSync(marker);if(kind==='marker-corrupt')fs.writeFileSync(marker,'bad pin');if(kind==='marker-changed'){pointer.fingerprint='0'.repeat(64);fs.writeFileSync(marker,JSON.stringify(pointer));}if(kind==='directory-missing')fs.rmSync(path.join(directory,'connect-tls'),{recursive:true});if(kind==='key-missing')fs.unlinkSync(path.join(directory,'connect-tls',pointer.generation,'private-key.pem'));if(kind==='bad-generation'){pointer.generation='../oops';fs.writeFileSync(marker,JSON.stringify(pointer));}
   Fail(directory,/CONNECT_TLS_IDENTITY_(MISSING|INVALID|CHANGED)/);if(kind==='marker-missing')assert.equal(fs.existsSync(marker),false);
  }
 });
 const legacy=path.join(temporary,'legacy');fs.mkdirSync(path.join(legacy,'connect-tls'),{recursive:true});
 await Check('FIX85 legacy CN/SAN and pin survive upgrade without rotation',()=>{
  const key=path.join(legacy,'connect-tls','private-key.pem'),cert=path.join(legacy,'connect-tls','certificate.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-sha256','-nodes','-keyout',key,'-out',cert,'-days','5','-subj','/CN=GameConnect TLS','-addext','subjectAltName=DNS:game-connect.internal'],{stdio:'ignore'});
  const fp=crypto.createHash('sha256').update(new crypto.X509Certificate(fs.readFileSync(cert)).raw).digest('hex');fs.writeFileSync(path.join(legacy,'connect-tls.sha256'),fp+'\n');
  assert.deepEqual(Public(legacy),{tlsServerName:'game-connect.internal',tlsCertificateSha256:fp});assert.equal(fs.readFileSync(path.join(legacy,'connect-tls.sha256'),'utf8'),fp+'\n');const missing=Copy(legacy);fs.unlinkSync(path.join(missing,'connect-tls.sha256'));Fail(missing,/CONNECT_TLS_IDENTITY_MISSING/);
 });
 await Check('Explicit server name is honored and mismatch never repins',()=>{
  const directory=path.join(temporary,'explicit');fs.mkdirSync(directory);const named=Public(directory,{CONNECT_TLS_SERVER_NAME:'native.example.invalid'});assert.equal(named.tlsServerName,'native.example.invalid');assert.deepEqual(Public(directory),named);Fail(directory,/CONNECT_TLS_IDENTITY_INVALID/,{CONNECT_TLS_SERVER_NAME:'other.example.invalid'});assert.deepEqual(Public(directory),named);
 });
 await Check('Configured external certificate keeps explicit name/pin and refuses lost enrollment marker',()=>{
  const directory=path.join(temporary,'external');fs.mkdirSync(directory);const extra={CONNECT_TLS_CERT_FILE:path.join(legacy,'connect-tls','certificate.pem'),CONNECT_TLS_KEY_FILE:path.join(legacy,'connect-tls','private-key.pem'),CONNECT_TLS_SERVER_NAME:'game-connect.internal'};
  const first=Public(directory,extra);assert.equal(first.tlsServerName,'game-connect.internal');assert.deepEqual(Public(directory,extra),first);fs.unlinkSync(path.join(directory,'connect-tls.sha256'));Fail(directory,/CONNECT_TLS_IDENTITY_MISSING/,extra);
 });
 const ports={CONNECT_TCP_PORT:String(await Port()),WEB_ADMIN_PORT:String(await Port())};
 await Check('Rotation requires offline invocation and refuses a live listener',async()=>{
  assert.notEqual((await Cli(fresh,['rotate'],ports)).status,0);const server=net.createServer();await new Promise(resolve=>server.listen(Number(ports.CONNECT_TCP_PORT),'0.0.0.0',resolve));try{const out=await Cli(fresh,['rotate','--offline'],ports);assert.notEqual(out.status,0);assert.match(out.stderr,/TLS_ROTATION_SERVICE_MUST_BE_STOPPED/);assert.deepEqual(Public(fresh),initial);}finally{await new Promise(resolve=>server.close(resolve));}
 });
 let rotated,backup;
 await Check('Offline rotation atomically changes identity and retains private recovery backup',async()=>{
  const out=await Cli(legacy,['rotate','--offline'],ports);assert.equal(out.status,0,out.stderr);rotated=JSON.parse(out.stdout);backup=rotated.backupId;assert.match(backup,/^[a-f0-9]{48}$/);assert.match(rotated.tlsServerName,/^[a-f0-9]{32}\.invalid$/);assert.notEqual(rotated.tlsServerName,'game-connect.internal');assert.equal(Public(legacy).tlsCertificateSha256,rotated.tlsCertificateSha256);assert.equal(rotated.newLaunchersRequired,true);
  const privateFile=path.join(legacy,'connect-tls','backups',backup,'private-key.pem');assert.ok(fs.existsSync(privateFile));if(process.platform!=='win32')assert.equal(fs.statSync(privateFile).mode&0o777,0o600);
 });
 await Check('Interrupted-maintenance marker blocks startup; invalid restore cannot clear it',async()=>{
  const lock=path.join(legacy,'connect-tls.rotation-lock');fs.writeFileSync(lock,'interrupted\n');Fail(legacy,/CONNECT_TLS_ROTATION_IN_PROGRESS/);
  const out=await Cli(legacy,['restore','--offline','--backup','0'.repeat(48)],ports);assert.notEqual(out.status,0);assert.ok(fs.existsSync(lock));Fail(legacy,/CONNECT_TLS_ROTATION_IN_PROGRESS/);
 });
 await Check('Explicit offline restore recovers the old exact pin and clears interrupted lock',async()=>{
  const out=await Cli(legacy,['restore','--offline','--backup',backup],ports);assert.equal(out.status,0,out.stderr);const old=Public(legacy);assert.equal(old.tlsServerName,'game-connect.internal');assert.notEqual(old.tlsCertificateSha256,rotated.tlsCertificateSha256);assert.equal(fs.existsSync(path.join(legacy,'connect-tls.rotation-lock')),false);
 });
 console.log('Connect TLS identity: '+checks+' checks passed');
}finally{fs.rmSync(temporary,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
