'use strict';
// Ephemeral Windows integration server. Production wire/services, final EXEs;
// no fabricated native report, authentication bypass or operating DATA_DIR.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const [run,out,version]=process.argv.slice(2);let listener,timer;
function Write(name,value){const target=path.join(run,name),tmp=target+'.next';fs.writeFileSync(tmp,JSON.stringify(value),{mode:0o600});try{fs.renameSync(tmp,target);}catch(error){if(!['EPERM','EACCES','EBUSY'].includes(error.code))throw error;/* A Windows reader may briefly hold the old file; next tick retries. */}}
(async()=>{try{
 if(process.platform!=='win32'||!run||!out||!/^\d+(?:\.\d+){0,3}$/.test(version||''))throw Error('CI_WINDOWS_FIXTURE_REQUIRED');
 const root=fs.realpathSync(run);if(root!==path.resolve(run)||!fs.existsSync(path.join(root,'ci-owned-marker')))throw Error('CI_PRIVATE_ROOT_REQUIRED');const data=path.join(root,'server-data');if(fs.existsSync(data))throw Error('CI_DATA_DIR_NOT_EMPTY');fs.mkdirSync(data,{mode:0o700});
 for(const name of Object.keys(process.env))if(/SECRET|TOKEN|KEY|RAILWAY|CONNECT_TLS|VAPID|DESKTOP_|WEB_ADMIN_|DATA_DIR|HA_/.test(name))delete process.env[name];
 Object.assign(process.env,{DATA_DIR:data,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'1',WEB_ADMIN_PORT:'0',CONNECT_TCP_PORT:'1',HEALTH_PORT:'0',ENABLE_LEGACY_TCP_ADMIN:'0'});
 // Never publish audit rows, HWID, ephemeral tokens or license input in CI logs.
 console.log=()=>{};console.error=()=>{};
 require('../services/desktopSingleWriter').Acquire(data);require('../core/utils').EnsureDirs();require('../storage/database').LoadDatabase();require('../services/desktopMachinePolicy').Load();require('../services/desktopLicenses').ReconcileOperations();
 const {Provision,Status}=require('./fixture-services');const bootstrap=require('../services/desktopBootstrap');Provision(run,out,version);
 listener=require('../services/desktopConnect').CreateServer();await new Promise((resolve,reject)=>{listener.once('error',reject);listener.listen(0,'127.0.0.1',resolve);});process.env.DESKTOP_PUBLIC_PORT=String(listener.address().port);
 const license=require('../services/desktopLicenses').Create({requestId:crypto.randomUUID(),label:'Ephemeral Windows CI'},'ISOLATED_WINDOWS_CI');
 const issue=bootstrap.IssueLauncher({requestId:crypto.randomUUID(),label:'Ephemeral Windows CI',licenseId:license.license.id},'ISOLATED_WINDOWS_CI');
 const launchDir=path.join(run,'execution');fs.mkdirSync(launchDir);const launcher=path.join(launchDir,issue.downloadName);fs.writeFileSync(launcher,bootstrap.LauncherBytes(issue.launcherId),{flag:'wx',mode:0o600});
 Write('input.json',{launcher,licenseKey:license.licenseKey});Write('status.json',Status());let stopping=false;
 timer=setInterval(()=>{try{Write('status.json',Status());if(fs.existsSync(path.join(run,'stop.request'))&&!stopping){stopping=true;clearInterval(timer);listener.close(()=>process.exit(0));setTimeout(()=>process.exit(1),3000).unref();}}catch(_){Write('status.json',{version:1,ready:false,error:'CI_RUNTIME_STATUS_FAILED'});process.exit(1);}},200);
 setTimeout(()=>process.exit(1),300000).unref();process.stdout.write('CI_FIXTURE_READY\n');
}catch(error){if(run&&fs.existsSync(run))try{Write('status.json',{version:1,ready:false,error:/^[A-Z0-9_]{1,100}$/.test(error.message)?error.message:'CI_FIXTURE_FAILED'});}catch(_){}process.stderr.write('CI_FIXTURE_FAILED\n');process.exitCode=1;if(listener)listener.close();}})();
