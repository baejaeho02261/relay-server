'use strict';
// Stop the server before running this tool. The same OS lock rejects concurrent
// server/maintenance writers. Existing data and TLS pins are never reset.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
function Run(command,input){
 if(!input||Object.getPrototypeOf(input)!==Object.prototype||Object.keys(input).some(k=>!['version','dataDirectory','actor','request'].includes(k))||input.version!==1||typeof input.dataDirectory!=='string'||!path.isAbsolute(input.dataDirectory)||typeof input.actor!=='string'||!input.actor||input.actor.length>160)throw Error('CONNECT_ROTATION_INPUT_INVALID');
 if(!['status','prepare','activate','retire'].includes(command))throw Error('CONNECT_ROTATION_COMMAND_INVALID');
 const directory=fs.realpathSync(input.dataDirectory);for(const name of ['connect-transport-key.pem','connect-transport-key.id',path.join('desktop-bootstrap','authority.json')])if(!fs.existsSync(path.join(directory,name)))throw Error('CONNECT_ROTATION_EXISTING_SERVER_REQUIRED');process.env.DATA_DIR=directory;process.env.HA_ENABLED='0';
 require('../services/desktopSingleWriter').Acquire(directory,{haEnabled:false});require('../core/utils').EnsureDirs();
 const service=require('../services/desktopTransportRotation');
 const result=command==='status'?null:service.Run(command,input.request,input.actor);
 return {version:1,ok:true,command,result,current:service.Summary(),checkedAt:new Date().toISOString(),restartServerRequired:command!=='status',newLauncherRequiredAfterActivation:true,automaticClientPinReplacement:false};
}
if(require.main===module){
 let result,code=0;const command=process.argv[2];
 try{if(process.argv.length!==4)throw Error('Usage: node transport-key-maintenance.js status|prepare|activate|retire input.json');const input=require('../services/strictJson').Parse(require('../services/durableFile').ReadRegular(path.resolve(process.argv[3]),16384),{maxBytes:16384});result=Run(command,input);}
 catch(error){code=1;result={version:1,ok:false,command:command||'',error:/^[A-Z0-9_]+$/.test(error.message)?error.message:'CONNECT_ROTATION_FAILED'};console.error(error.message);}
 const filename='transport-key-'+String(command||'error').replace(/[^a-z]/g,'')+'-'+new Date().toISOString().replace(/[:.]/g,'-')+'-'+crypto.randomBytes(4).toString('hex')+'.json';
 try{require('../services/durableFile').Atomic(path.join(__dirname,filename),Buffer.from(JSON.stringify(result,null,2)+'\n'),{createOnly:true});console.log(filename);}catch(_){console.error('CONNECT_ROTATION_RESULT_WRITE_FAILED');code=1;}
 process.exitCode=code;
}
module.exports={Run};
