'use strict';
const fs=require('node:fs'),path=require('node:path');
const config=require("../../config/peace.runtime-configuration"),{WitnessFile}=require('./peace.recovery-witness-file');
let instance,root,remote;
const initialRemote=process.env.DESKTOP_RECOVERY_WITNESS_URL||'';
function Configured(){return !!(process.env.DESKTOP_RECOVERY_WITNESS_URL||'') || typeof process.env.DESKTOP_RECOVERY_WITNESS_DIR==='string'&&process.env.DESKTOP_RECOVERY_WITNESS_DIR.trim()!=='';}
function Required(){return process.env.DESKTOP_RECOVERY_WITNESS_REQUIRED==='1';}
function Resolve(directory){
  if(typeof directory!=='string'||!path.isAbsolute(directory))throw Error('RECOVERY_WITNESS_ABSOLUTE_PATH_REQUIRED');
  const dir=fs.realpathSync(directory),data=fs.realpathSync(config.DATA_DIR);
  const inside=(a,b)=>{const r=path.relative(a,b);return r===''||(!r.startsWith('..'+path.sep)&&r!=='..'&&!path.isAbsolute(r));};
  if(inside(dir,data)||inside(data,dir))throw Error('RECOVERY_WITNESS_MUST_BE_INDEPENDENT');
  if(!fs.lstatSync(dir).isDirectory())throw Error('RECOVERY_WITNESS_DIRECTORY_INVALID');
  return dir;
}
function Get(){
  if(initialRemote!==(process.env.DESKTOP_RECOVERY_WITNESS_URL||''))throw Error('RECOVERY_WITNESS_CONFIGURATION_CHANGED');
  if(initialRemote){
    const client=require('./peace.remote-witness-client'),settings=client.Config();
    if(remote){if(JSON.stringify(settings)!==root)throw Error('RECOVERY_WITNESS_CONFIGURATION_CHANGED');return remote;}
    const candidate=new client.RemoteWitness(settings);
    try{candidate.read();for(const name of require('./peace.remote-witness-protocol').DOMAINS)candidate.head(name);}
    catch(e){candidate.close();throw e;}
    remote=candidate;root=JSON.stringify(settings);return remote;
  }
  if(!Configured()){if(Required())throw Error('RECOVERY_WITNESS_REQUIRED');return null;}
  const wanted=Resolve(process.env.DESKTOP_RECOVERY_WITNESS_DIR.trim());
  if(instance){if(wanted!==root)throw Error('RECOVERY_WITNESS_CONFIGURATION_CHANGED');return instance;}
  require("../storage/peace.desktop-single-writer").AcquireWitness(wanted,{haEnabled:config.HA_ENABLED});
  const candidate=new WitnessFile(wanted);candidate.read();instance=candidate;root=wanted;return instance;
}
function Head(name){const w=Get();if(!w)return null;w.head(name);return {Open:x=>w.open(name,x),Prepare:(a,b)=>w.prepare(name,a,b),Settle:x=>w.settle(name,x)};}
function Status(){const w=Get();return w?{...w.status(),required:Required(),independence:initialRemote?'OPERATOR_PROVISIONED_SEPARATE_SERVER':'OPERATOR_PROVISIONED_SEPARATE_VOLUME',remoteAttestation:false}:{status:'NOT_CONFIGURED',required:Required(),wholeBackupRollbackProtected:false};}
// Shutdown never calls Get(): an unused adapter must not create a worker/store.
// Keep the closed instance fenced instead of reconnecting during final writes.
function Close(){return remote?remote.close():Promise.resolve();}
module.exports={Configured,Required,Resolve,Get,Head,Status,Close};
