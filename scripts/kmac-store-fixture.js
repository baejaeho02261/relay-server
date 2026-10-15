'use strict';
// Test-only child process for real, isolated integrity-report store restarts.
// The parent supplies a fresh temporary DATA_DIR and selects a fixed operation;
// arbitrary source code, production paths and application keys are not inputs.
const path=require('node:path');
function Run(action){
 if(!['load','save'].includes(action)||!process.env.DATA_DIR||!path.isAbsolute(process.env.DATA_DIR)||process.env.STORAGE_ENGINE!=='json'||process.env.HA_ENABLED!=='0')throw Error('KMAC_STORE_FIXTURE_ARGUMENTS');
 require('../core/utils').EnsureDirs();
 const reports=require('../services/desktopIntegrityReports');
 reports.Policy();
 if(action==='save')reports.SetPolicy({enabled:false,requiredModules:['ntdll.dll']},'TEST');
}
if(require.main===module){
 if(process.argv.length!==3)throw Error('KMAC_STORE_FIXTURE_ARGUMENTS');
 Run(process.argv[2]);
}
module.exports={Run};
