"use strict";
// Read-only process/role checks. Does not initialize a database or witness.
function Run(args=process.argv.slice(2)){
 const role=args[0]||'authority',probe=args.includes('--probe-witness');
 if(args.slice(1).some(x=>x!=='--probe-witness')||probe&&role!=='authority')throw Error('ISOLATION_ARGUMENTS_INVALID');
 const isolation=require("../../services/security/peace.service-isolation").Check(role);let witness={status:'NOT_CONFIGURED',wholeBackupRollbackProtected:false};
 if(role==='authority'&&process.env.DESKTOP_RECOVERY_WITNESS_URL){
  const mod=require("../../services/recovery/peace.remote-witness-client"),config=mod.Config();
  witness={status:'REMOTE_CONFIG_VALID',installationId:config.installationId,connected:false,wholeBackupRollbackProtected:false};
  if(probe){const client=new mod.RemoteWitness(config);try{const s=client.status();for(const name of require("../../services/recovery/peace.remote-witness-protocol").DOMAINS)client.head(name);witness={...s,connected:true,actualProductionRestoreTestRun:false};}finally{client.close();}}
 }
 return {version:1,role,isolation,witness,mutatedFiles:false,provisionedServices:false};
}
if(require.main===module){try{console.log(JSON.stringify(Run(),null,2));}catch(e){console.error(JSON.stringify({ok:false,error:/^[A-Z0-9_]+$/.test(e.message)?e.message:'ISOLATION_CHECK_FAILED'}));process.exitCode=1;}}
module.exports={Run};
