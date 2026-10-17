'use strict';
// Run on the server as its operator, with its real DATA_DIR. No server restart,
// no account deletion, no policy relaxation. Do not run on an end-user PC.
const fs=require('node:fs'),path=require('node:path');
try{
 const [command,sessionId,output]=process.argv.slice(2);
 if(command!=='issue'||!/^[A-F0-9]{16}$/.test(sessionId||'')||!output||process.argv.length!==5)throw Error('ADMIN_ENROLLMENT_USAGE');
 const file=path.resolve(output);if(fs.existsSync(file))throw Error('ADMIN_ENROLLMENT_OUTPUT_EXISTS');
 const result=require('../services/desktopAdminEnrollment').Issue(sessionId);
 fs.writeFileSync(file,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
 console.log('ADMIN_ENROLLMENT_APPROVAL_WRITTEN'); // Never print the secret token.
}catch(error){console.error(/^ADMIN_ENROLLMENT_[A-Z_]+$/.test(error.message)?error.message:'ADMIN_ENROLLMENT_APPROVAL_FAILED');process.exitCode=1;}
