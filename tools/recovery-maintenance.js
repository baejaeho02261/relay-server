'use strict';
// Offline server maintenance. Uses the SAME native DATA_DIR lock as server.js,
// plus a separate witness lock. Never runs an HTTP listener or resets a witness.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
function Validate(input){
 if(!input||Object.getPrototypeOf(input)!==Object.prototype||Object.keys(input).some(k=>!['version','dataDirectory','witnessDirectory','confirmIndependentStorage'].includes(k))||input.version!==1||typeof input.dataDirectory!=='string'||!path.isAbsolute(input.dataDirectory)||typeof input.witnessDirectory!=='string'||!path.isAbsolute(input.witnessDirectory)||typeof input.confirmIndependentStorage!=='boolean')throw Error('RECOVERY_MAINTENANCE_INPUT_INVALID');
 return input;
}
function ReadHead(file){const row=require('../services/strictJson').Parse(require('../services/durableFile').ReadRegular(file,4096),{maxBytes:4096});if(row.body.pending)throw Error('RECOVERY_LOCAL_HEAD_UNSETTLED');return row.body.current;}
function LoadStores(){
 const journal=require('../services/desktopJournal'),licenses=journal.Load();
 const machine=require('../services/desktopMachinePolicy');machine.Load();
 const bootstrap=require('../services/desktopBootstrapStore');bootstrap.Load();
 const integrity=require('../services/desktopIntegrityReports');integrity.List();
 return {DESKTOP_JOURNAL:licenses.exists?ReadHead(journal.FILE+'.head'):{seq:0,hash:'0'.repeat(64)},DESKTOP_MACHINE_POLICY:ReadHead(machine.FILE+'.head'),DESKTOP_BOOTSTRAP:ReadHead(path.join(bootstrap.DIR,'authority.json.head')),DESKTOP_INTEGRITY:ReadHead(integrity.FILE+'.head')};
}
function Run(command,input){
 Validate(input);if(!['enroll','check'].includes(command))throw Error('RECOVERY_MAINTENANCE_COMMAND_INVALID');
 if(command==='enroll'&&!input.confirmIndependentStorage)throw Error('RECOVERY_INDEPENDENT_STORAGE_CONFIRMATION_REQUIRED');
 // Do not silently use the source directory or create a mistyped server path.
 fs.realpathSync(input.dataDirectory);fs.realpathSync(input.witnessDirectory);
 process.env.DATA_DIR=input.dataDirectory;process.env.HA_ENABLED='0';
 delete process.env.DESKTOP_RECOVERY_WITNESS_DIR;delete process.env.DESKTOP_RECOVERY_WITNESS_REQUIRED;
 const lock=require('../services/desktopSingleWriter');lock.Acquire(input.dataDirectory,{haEnabled:false});
 const adapter=require('../services/desktopRecoveryWitness'),witness=adapter.Resolve(input.witnessDirectory);lock.AcquireWitness(witness,{haEnabled:false});
 const {WitnessFile}=require('../services/recoveryWitnessFile');
 if(command==='enroll'){
  const current=new WitnessFile(witness);
  // Check BEFORE loading/migrating DATA_DIR. There is no enrollment retry that
  // could bless an old backup when a previous witness already exists.
  if(fs.existsSync(current.file)||fs.existsSync(current.key))throw Error('RECOVERY_WITNESS_ALREADY_ENROLLED');
  const heads=LoadStores();current.enroll(heads);
 }
 process.env.DESKTOP_RECOVERY_WITNESS_DIR=witness;process.env.DESKTOP_RECOVERY_WITNESS_REQUIRED='1';
 // Every domain is checked even when a service has a cached startup snapshot.
 const heads=LoadStores(),external=adapter.Get();for(const [name,actual]of Object.entries(heads))external.open(name,actual);
 return {version:1,command,ok:true,checkedAt:new Date().toISOString(),witness:adapter.Status(),domains:Object.fromEntries(Object.entries(heads).map(([name,h])=>[name,{sequence:h.seq}])),deploymentAction:'Set DESKTOP_RECOVERY_WITNESS_DIR and DESKTOP_RECOVERY_WITNESS_REQUIRED=1 on the server; exclude the witness and live lock file from DATA_DIR restore.',independenceConfirmedByOperator:input.confirmIndependentStorage,physicalIndependenceVerified:false};
}
if(require.main===module){
 let result,code=0;const command=process.argv[2];
 try{if(process.argv.length!==4)throw Error('Usage: node recovery-maintenance.js enroll|check input.json');const input=require('../services/strictJson').Parse(require('../services/durableFile').ReadRegular(path.resolve(process.argv[3]),8192),{maxBytes:8192});result=Run(command,input);}
 catch(e){code=1;result={version:1,command:command||'',ok:false,error:/^[A-Z0-9_]+$/.test(e.message)?e.message:'RECOVERY_MAINTENANCE_FAILED',nativeCause:e.cause?.code||'',checkedAt:new Date().toISOString()};console.error(e.message);}
 const name='recovery-'+(command==='enroll'?'enroll':'check')+'-'+new Date().toISOString().replace(/[:.]/g,'-')+'-'+crypto.randomBytes(4).toString('hex')+'.json';
 try{require('../services/durableFile').Atomic(path.join(__dirname,name),Buffer.from(JSON.stringify(result,null,2)+'\n'),{createOnly:true});console.log(name);}catch(e){console.error('RECOVERY_RESULT_WRITE_FAILED');code=1;}
 process.exitCode=code;
}
module.exports={Validate,Run};
