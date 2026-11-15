'use strict';
// Only an explicitly selected final-distribution directory. Do not scan the
// developer source tree as if it were the end-user distribution. Never executes it.
const fs=require('node:fs'),scanner=require("../../services/artifacts/peace.release-exposure");
if(require.main===module){try{if(process.argv.length!==4)throw Error("Usage: node tools/artifacts/peace.release-exposure.js FINAL_DISTRIBUTION_DIRECTORY NEW_REPORT.json");const report=scanner.ScanDirectory(process.argv[2]);fs.writeFileSync(process.argv[3],JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify({status:report.status,files:report.files.length,totalBytes:report.totalBytes,rawSecretsPrinted:false}));if(report.status!=='PASS')process.exitCode=1;}catch(e){console.error(/^EXPOSURE_[A-Z_]+$/.test(e.message)?e.message:'EXPOSURE_SCAN_FAILED');process.exitCode=1;}}
module.exports=scanner;
