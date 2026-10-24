'use strict';
let result={required:false,status:'NOT_CONFIGURED',platform:process.platform};
function Check(){
 const required=process.env.DESKTOP_STORAGE_ACL_REQUIRED==='1';
 if(!required)return result;
 const config=require("../../config/peace.runtime-configuration"),input={version:1,dataDirectory:config.DATA_DIR,serviceSid:process.env.DESKTOP_STORAGE_SERVICE_SID||''};
 if(process.env.DESKTOP_RECOVERY_WITNESS_DIR)input.witnessDirectory=process.env.DESKTOP_RECOVERY_WITNESS_DIR;
 const checked=require("../../tools/storage/peace.storage-acl").Verify(input);result={required:true,status:'VERIFIED',platform:process.platform,checkedAt:checked.checkedAt,entries:checked.entries};return result;
}
module.exports={Check,Status:()=>({...result})};
