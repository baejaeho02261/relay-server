'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Offline, single-writer maintenance. prepare stages a new same-name identity;
// activate installs only the generation already announced through the audited
// admin API. Neither action invents an authorization, deletes history or creates a signature.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),net=require('node:net');
const config=require("../../config/peace.runtime-configuration"),identity=require("../../services/network/peace.connect-tls");
async function Offline(){
 const held=[];
 try{
  for(const port of new Set([config.CONNECT_TCP_PORT,config.WEB_ADMIN_PORT,...(config.HEALTH_PORT?[config.HEALTH_PORT]:[])])){
   if(!Number.isInteger(port)||port<1||port>65535)throw Error('TLS_PIN_PORT_INVALID');
   const server=net.createServer(s=>s.destroy());
   await new Promise((resolve,reject)=>{server.once('error',()=>reject(Error('TLS_PIN_SERVER_MUST_BE_STOPPED')));server.listen({host:config.HOST,port,exclusive:true},resolve);});held.push(server);
  }
  return held;
 }catch(e){await Promise.all(held.map(s=>new Promise(resolve=>s.close(resolve))));throw e;}
}
function Prepare(){
 if(fs.existsSync(identity.ROTATION_LOCK))throw Error('TLS_PIN_MAINTENANCE_IN_PROGRESS');
 const current=identity.Load(),next=identity.Generate(current.serverName),pointer=require("../../services/protocol/peace.strict-json").Parse(next.pointer,{maxBytes:2048});
 return {stagedGeneration:pointer.generation,tlsServerName:next.serverName,currentCertificateSha256:current.fingerprint,nextCertificateSha256:next.fingerprint,expiresAt:next.expiresAt,activeCertificateChanged:false,nextStep:'Restart server, register this stagedGeneration and a future bounded window in the recent-reauthenticated admin API.'};
}
function Activate(){
 const contract=require("../../services/network/peace.desktop-tls-pin-transition"),row=require("../../services/bootstrap/peace.desktop-bootstrap-store").Load().tlsPinTransition;
 if(!row)throw Error('TLS_PIN_SCHEDULE_REQUIRED');contract.Validate(row);
 const current=identity.ReadIdentity(true),next=contract.Candidate(row.stagedGeneration,row.plan.tlsServerName);
 if(Date.now()<row.plan.notBefore)throw Error('TLS_PIN_WINDOW_NOT_STARTED');
 if(next.fingerprint!==row.plan.nextPin||![row.plan.currentPin,row.plan.nextPin].includes(current.fingerprint))throw Error('TLS_PIN_STAGED_IDENTITY_CHANGED');
 let resumed=false,published=false,locked=false;
 if(fs.existsSync(identity.ROTATION_LOCK)){
  const lock=require("../../services/protocol/peace.strict-json").Parse(identity.Read(identity.ROTATION_LOCK,2048),{maxBytes:2048});
  if(lock.action!=='pin-window-activate'||lock.stagedGeneration!==row.stagedGeneration||lock.generation!==row.generation)throw Error('TLS_PIN_OTHER_MAINTENANCE_PENDING');
  resumed=true;
 }
 if(!resumed)identity.Write(identity.ROTATION_LOCK,JSON.stringify({action:'pin-window-activate',generation:row.generation,stagedGeneration:row.stagedGeneration,at:Date.now()})+'\n');
 locked=true;identity.Sync(config.DATA_DIR);
 try{
  if(current.fingerprint!==row.plan.nextPin){
   // Preserve the prior pointer and leave both generations/keys intact.
   const history=path.join(identity.DIR,'pin-pointer-history');fs.mkdirSync(history,{recursive:true,mode:0o700});identity.Directory(history);
   const backup=path.join(history,'generation-'+row.generation+'-'+crypto.randomBytes(8).toString('hex')+'.json');
   identity.Write(backup,identity.Read(identity.MARKER,2048));identity.Sync(history);
   const pointer=Buffer.from(JSON.stringify({version:2,generation:row.stagedGeneration,fingerprint:next.fingerprint})+'\n');
   const temporary=identity.MARKER+'.pin-'+crypto.randomBytes(12).toString('hex')+'.pending';
   try{identity.Write(temporary,pointer);published=true;fs.renameSync(temporary,identity.MARKER);identity.Sync(config.DATA_DIR);}
   finally{fs.rmSync(temporary,{force:true});}
  }
  const actual=identity.ReadIdentity();if(actual.fingerprint!==row.plan.nextPin)throw Error('TLS_PIN_ACTIVATION_UNCERTAIN');
  fs.unlinkSync(identity.ROTATION_LOCK);locked=false;identity.Sync(config.DATA_DIR);
  return {generation:row.generation,stagedGeneration:row.stagedGeneration,tlsCertificateSha256:actual.fingerprint,activeCertificateChanged:current.fingerprint!==actual.fingerprint,clientsMustAlreadyTrustPlanOrUseNewLauncher:true,oldPlanCancelled:false};
 }catch(e){if(locked&&!published&&!resumed){fs.unlinkSync(identity.ROTATION_LOCK);identity.Sync(config.DATA_DIR);}throw e;}
}
async function Main(){
 const [action,...extra]=process.argv.slice(2);if(!['prepare','activate'].includes(action)||extra.length)throw Error('TLS_PIN_ARGUMENT_INVALID');
 if(config.HA_ENABLED)throw Error('TLS_PIN_SINGLE_WRITER_REQUIRED');
 if(process.env.CONNECT_TLS_CERT_FILE||process.env.CONNECT_TLS_KEY_FILE)throw Error('TLS_PIN_EXTERNAL_CERT_MANUAL_MAINTENANCE_REQUIRED');
 require("../../services/storage/peace.desktop-single-writer").Acquire(config.DATA_DIR,{haEnabled:config.HA_ENABLED});
 const held=await Offline();try{return {ok:true,action,...(action==='prepare'?Prepare():Activate())};}finally{await Promise.all(held.map(s=>new Promise(resolve=>s.close(resolve))));}
}
if(require.main===module){
 const file=path.join(MODULE_RESOURCE_ROOT,'tls-pin-'+new Date().toISOString().replace(/[:.]/g,'-')+'-'+crypto.randomBytes(6).toString('hex')+'.json');
 Main().then(result=>{fs.writeFileSync(file,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});console.log(file);}).catch(error=>{
  const result={ok:false,reason:/^[A-Z][A-Z0-9_]+$/.test(error.message)?error.message:'TLS_PIN_MAINTENANCE_FAILED'};
  try{fs.writeFileSync(file,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});console.error(file);}catch(_){}
  console.error(result.reason);process.exitCode=1;
 });
}
module.exports={Prepare,Activate,Offline};
