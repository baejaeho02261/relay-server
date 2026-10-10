'use strict';
// Offline administrative maintenance only. No listener or native client can
// rotate its own pin. Keep one server replica and stop it before running this.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),net=require('node:net');
const config=require('../config/config'),identity=require('../services/connectTls');
const BACKUPS=path.join(identity.DIR,'backups');
function Die(code){throw Error(code);}
async function Offline(){
 if(config.HA_ENABLED)Die('TLS_ROTATION_SINGLE_WRITER_REQUIRED');
 const held=[];try{for(const port of new Set([config.CONNECT_TCP_PORT,config.WEB_ADMIN_PORT,...(config.HEALTH_PORT?[config.HEALTH_PORT]:[])])){
  if(!Number.isInteger(port)||port<1||port>65535)Die('TLS_ROTATION_PORT_INVALID');
  const server=net.createServer(socket=>socket.destroy());await new Promise((resolve,reject)=>{server.once('error',()=>reject(Error('TLS_ROTATION_SERVICE_MUST_BE_STOPPED')));server.listen({host:config.HOST,port,exclusive:true},resolve);});held.push(server);
 }return held;}catch(error){await Promise.all(held.map(server=>new Promise(resolve=>server.close(resolve))));throw error;}
}
function Install(pointer){
 const temporary=identity.MARKER+'.'+crypto.randomBytes(12).toString('hex')+'.pending';
 try{identity.Write(temporary,pointer);fs.renameSync(temporary,identity.MARKER);identity.Sync(config.DATA_DIR);}finally{fs.rmSync(temporary,{force:true});}
}
function Backup(current){
 fs.mkdirSync(BACKUPS,{recursive:true,mode:0o700});identity.Directory(BACKUPS);
 const id=crypto.randomBytes(24).toString('hex'),directory=path.join(BACKUPS,id);fs.mkdirSync(directory,{mode:0o700});
 identity.Write(path.join(directory,'certificate.pem'),current.cert);identity.Write(path.join(directory,'private-key.pem'),current.key);
 identity.Write(path.join(directory,'identity.json'),JSON.stringify({version:1,createdAt:Date.now(),serverName:current.serverName,fingerprint:current.fingerprint})+'\n');
 identity.Sync(directory);identity.Sync(BACKUPS);return id;
}
function RestoreGeneration(id){
 if(!/^[a-f0-9]{48}$/.test(id||''))Die('TLS_ROTATION_BACKUP_REQUIRED');
 identity.Directory(identity.DIR);identity.Directory(BACKUPS);const directory=path.join(BACKUPS,id);identity.Directory(directory);
 const cert=identity.Read(path.join(directory,'certificate.pem'),32768),key=identity.Read(path.join(directory,'private-key.pem'),16384);let metadata;
 try{metadata=JSON.parse(identity.Read(path.join(directory,'identity.json'),2048));}catch(_){Die('TLS_ROTATION_BACKUP_INVALID');}
 if(!metadata||metadata.version!==1||typeof metadata.serverName!=='string'||!/^[a-f0-9]{64}$/.test(metadata.fingerprint))Die('TLS_ROTATION_BACKUP_INVALID');
 identity.AssertPurpose(cert);const value=identity.Validate(cert,key,metadata.serverName);if(value.fingerprint!==metadata.fingerprint)Die('TLS_ROTATION_BACKUP_INVALID');
 identity.ReservePurpose(cert);const generation=crypto.randomBytes(24).toString('hex'),next=path.join(identity.DIR,generation);fs.mkdirSync(next,{mode:0o700});
 identity.Write(path.join(next,'certificate.pem'),cert);identity.Write(path.join(next,'private-key.pem'),key);identity.Sync(next);identity.Sync(identity.DIR);
 return {...value,pointer:Buffer.from(JSON.stringify({version:2,generation,fingerprint:value.fingerprint})+'\n')};
}
async function Main(){
 const args=process.argv.slice(2),action=args.shift();
 if(!['rotate','restore'].includes(action)||!args.includes('--offline')||args.some((arg,index)=>arg!=='--offline'&&arg!=='--backup'&&args[index-1]!=='--backup'))Die('Usage: node tools/tls-rotate.js rotate --offline | restore --offline --backup <backup-id>');
 if(process.env.CONNECT_TLS_CERT_FILE||process.env.CONNECT_TLS_KEY_FILE)Die('TLS_ROTATION_CONFIGURED_CERT_MANUAL_ONLY');
 require('../services/desktopSingleWriter').Acquire(config.DATA_DIR,{haEnabled:config.HA_ENABLED});
 const held=await Offline();let locked=false,installed=false,previousLock=false;
 try{
  if(action==='rotate'&&fs.existsSync(identity.ROTATION_LOCK))Die('TLS_ROTATION_RESTORE_REQUIRED');
  // Restore can clear a lock left after interrupted maintenance. Ports and the
  // single-writer requirement must still pass before touching any identity.
  if(action==='restore'&&fs.existsSync(identity.ROTATION_LOCK)){identity.Read(identity.ROTATION_LOCK,2048);previousLock=true;}
  if(!previousLock)identity.Write(identity.ROTATION_LOCK,JSON.stringify({action,pid:process.pid,at:Date.now()})+'\n');locked=true;identity.Sync(config.DATA_DIR);
  let next,backup='';
  if(action==='rotate'){
   const current=identity.ReadIdentity(true);backup=Backup(current);
   // Report the durable recovery ID before the only mutating publication step.
   process.stderr.write('TLS_BACKUP_ID='+backup+'\n');next=identity.Generate(identity.ConfiguredName()||identity.RandomName());
  }else next=RestoreGeneration(args[args.indexOf('--backup')+1]);
  installed=true;Install(next.pointer);
  const actual=identity.ReadIdentity();if(actual.fingerprint!==next.fingerprint)Die('TLS_ROTATION_PUBLICATION_INVALID');
  fs.unlinkSync(identity.ROTATION_LOCK);locked=false;identity.Sync(config.DATA_DIR);
  console.log(JSON.stringify({ok:true,action,backupId:backup||undefined,tlsServerName:actual.serverName,tlsCertificateSha256:actual.fingerprint,newLaunchersRequired:true}));
 }catch(error){
  // Before publication, the current identity is untouched. After publication,
  // retain the lock so startup cannot mask an uncertain durable outcome.
  if(locked&&!installed&&!previousLock){fs.unlinkSync(identity.ROTATION_LOCK);identity.Sync(config.DATA_DIR);}throw error;
 }finally{await Promise.all(held.map(server=>new Promise(resolve=>server.close(resolve))));}
}
Main().catch(error=>{console.error(error.message);process.exitCode=1;});
