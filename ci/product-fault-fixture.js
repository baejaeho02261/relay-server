'use strict';
// Manual fault fixture: never imported by production startup or CI evidence.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const [run,out,version,scenario,runId]=process.argv.slice(2);let listener,timer,adapter,proxy,lease;
function Write(name,value){const file=path.join(run,name),next=file+'.next';fs.writeFileSync(next,JSON.stringify(value),{mode:0o600});try{fs.renameSync(next,file);}catch(e){if(!['EPERM','EACCES','EBUSY'].includes(e.code))throw e;}}
async function Main(){
 if(process.platform!=='win32'||!/^\d+(?:\.\d+){0,3}$/.test(version||'')||!/^[a-f0-9-]{36}$/.test(runId||''))throw Error('PRODUCT_FAULT_WINDOWS_FIXTURE_REQUIRED');
 const root=fs.realpathSync(run);if(root!==path.resolve(run)||fs.readFileSync(path.join(root,'product-fault-marker'),'utf8')!=='GAME_PRODUCT_FAULT_V1'||!fs.existsSync(path.join(root,'ci-owned-marker')))throw Error('PRODUCT_FAULT_PRIVATE_ROOT_REQUIRED');
 if(!require('../tools/product-fault-tests').SCENARIOS.includes(scenario))throw Error('PRODUCT_FAULT_SCENARIO_INVALID');
 const data=path.join(root,'server-data');fs.mkdirSync(data,{mode:0o700});
 for(const name of Object.keys(process.env))if(/SECRET|TOKEN|KEY|RAILWAY|CONNECT_TLS|VAPID|DESKTOP_|WEB_ADMIN_|DATA_DIR|HA_|GAME_PRODUCT_FAULT/.test(name))delete process.env[name];
 Object.assign(process.env,{DATA_DIR:data,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'1',WEB_ADMIN_PORT:'0',CONNECT_TCP_PORT:'1',HEALTH_PORT:'0',ENABLE_LEGACY_TCP_ADMIN:'0',GAME_PRODUCT_FAULT_ROOT:root,GAME_PRODUCT_FAULT_FIXTURE:'1'});
 console.log=()=>{};console.error=()=>{};
 const contracts=require('../tools/product-fault-tests');
 if(contracts.HANDOFF.includes(scenario)||contracts.GPU.includes(scenario)||contracts.LEASE.includes(scenario)){
  // A deliberately separate test-process admission adapter. Normal production
  // admission ALWAYS rejects this marker; no environment switch changes it.
  const build=require('../services/peBuildConfiguration');
  if(typeof build.AssertIsolatedTestConfiguration!=='function')throw Error('PRODUCT_FAULT_ISOLATED_ADMISSION_UNAVAILABLE');
  build.AssertProductionConfiguration=bytes=>build.AssertIsolatedTestConfiguration(bytes,{requireMarker:true});
 }
 require('../services/desktopSingleWriter').Acquire(data);require('../core/utils').EnsureDirs();require('../storage/database').LoadDatabase();require('../services/desktopMachinePolicy').Load();require('../services/desktopLicenses').ReconcileOperations();
 const {Provision,Status}=require('./fixture-services'),boot=require('../services/desktopBootstrap'),store=require('../services/desktopBootstrapStore'),selected=Provision(run,out,version);
 const events=[];let replacementObserved=false,replacementDenied=false,reuseProof=null,tlsArmedAfterTransfer=false,tlsRecordCorrupted=false,tlsMutationCount=0;
 function Event(e){if(events.length<96)events.push(e);if(e.event==='tls-record-corrupted'){tlsRecordCorrupted=true;tlsMutationCount=e.mutationCount;}if(e.event==='service-rejected'&&e.action==='begin'&&((scenario==='signed-exe-replacement'&&e.error==='BOOTSTRAP_ARTIFACT_INVALID')||(scenario==='signed-json-replacement'&&e.error==='SECURITY_RELEASE_SIGNATURE')))replacementDenied=true;}
 adapter=require('./product-fault-adapter').Install({scenario,onEvent:Event});
 if(contracts.LEASE.includes(scenario))lease=require('./overlay-lease-fixture').Install({onEvent:Event});
 if(contracts.TLS.includes(scenario))require('../services/connectTls').Load().options.maxVersion='TLSv1.2';
 listener=require('../services/desktopConnect').CreateServer();adapter.Attach(listener);await new Promise((resolve,reject)=>{listener.once('error',reject);listener.listen(0,'127.0.0.1',resolve);});process.env.DESKTOP_PUBLIC_PORT=String(listener.address().port);
 if(contracts.TLS.includes(scenario)){proxy=await require('./product-fault-tls-proxy').Start(listener.address().port,Event);process.env.DESKTOP_PUBLIC_PORT=String(proxy.port);}
 const license=require('../services/desktopLicenses').Create({requestId:crypto.randomUUID(),label:'Isolated product fault'},'ISOLATED_PRODUCT_FAULT');
 const issue=boot.IssueLauncher({requestId:crypto.randomUUID(),label:'Isolated product fault',licenseId:license.license.id},'ISOLATED_PRODUCT_FAULT');
 const execution=path.join(root,'execution');fs.mkdirSync(execution);const launcher=path.join(execution,issue.downloadName);fs.writeFileSync(launcher,boot.LauncherBytes(issue.launcherId),{flag:'wx',mode:0o600});
 // The executable/metadata was legitimately signed and activated above. Replace
 // only this fixture's copy; a real A subsequently requests it via production TLS.
 if(scenario==='signed-exe-replacement'){
  const file=store.ArtifactPath(selected.B.id),bytes=fs.readFileSync(file);bytes[bytes.length-1]^=1;fs.writeFileSync(file,bytes);replacementObserved=crypto.createHash('sha512').update(fs.readFileSync(file)).digest('hex')!==selected.B.sha512;
 }else if(scenario==='signed-json-replacement'){
  store.Atomic(db=>{const row=db.artifacts[selected.B.id],signature=Buffer.from(row.releaseApproval.signature,'base64');signature[0]^=1;row.releaseApproval={...row.releaseApproval,signature:signature.toString('base64')};});
  replacementObserved=!require('../services/desktopSecurityAuthority').VerifyApproval(store.Load().artifacts[selected.B.id],require('../services/desktopSecurityAuthority').Policy());
 }
 function Current(){const leaseState=lease?.Status(),status=Status(),db=store.Load(),flows=Object.values(db.flows),overlays=Object.values(db.overlays||{}),terminal=x=>['CLOSED','REVOKED','EXPIRED'].includes(x.status);return {...status,runId,scenario,events,proof:reuseProof||adapter.Status(),replacementObserved,replacementDenied,tlsArmedAfterTransfer,tlsRecordCorrupted,tlsMutationCount,...(leaseState?{lease:leaseState}:{}),allAuthorityTerminal:flows.every(terminal)&&overlays.every(terminal),allRuntimeSecretsRetired:[...flows,...overlays].every(x=>['sessionNonce','handoffNonce','ticketNonce','downloadNonce','finishNonce','claimNonce'].every(k=>x[k]===undefined)),consumedCount:require('./product-fault-adapter').Snapshot().used};}
 Write('input.json',{launcher,licenseKey:license.licenseKey});Write('status.json',Current());let stopping=false;
 timer=setInterval(()=>{try{
  if(fs.existsSync(path.join(root,'reuse.request'))&&!reuseProof){const status=Current();if(!status.allAuthorityTerminal)throw Error('PRODUCT_FAULT_REUSE_BEFORE_TERMINAL');if(lease)lease.CheckReuse();reuseProof=adapter.Reuse();}
  if(proxy&&!tlsArmedAfterTransfer&&Status().transferCommitted&&fs.existsSync(path.join(root,'tls-arm.request'))){proxy.Arm();tlsArmedAfterTransfer=true;}
  Write('status.json',Current());
  if(fs.existsSync(path.join(root,'stop.request'))&&!stopping){stopping=true;clearInterval(timer);if(proxy)proxy.Close().then(()=>listener.close(()=>process.exit(0))).catch(()=>process.exit(1));else listener.close(()=>process.exit(0));setTimeout(()=>process.exit(1),3000).unref();}
 }catch(e){Write('status.json',{ready:false,error:/^[A-Z0-9_]+$/.test(e.message)?e.message:'PRODUCT_FAULT_RUNTIME_FAILED'});process.exit(1);}},100);
 setTimeout(()=>process.exit(1),540000).unref();process.stdout.write('PRODUCT_FAULT_FIXTURE_READY\n');
}
if(require.main===module)Main().catch(async error=>{try{Write('status.json',{ready:false,error:/^[A-Z0-9_]+$/.test(error.message)?error.message:'PRODUCT_FAULT_FIXTURE_FAILED'});}catch(_){}process.stderr.write('PRODUCT_FAULT_FIXTURE_FAILED\n');process.exitCode=1;clearInterval(timer);if(proxy)try{await proxy.Close();}catch(_){}if(listener)listener.close();setTimeout(()=>process.exit(1),3000).unref();});
module.exports={Main};
