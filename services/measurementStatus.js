'use strict';
const failures=Object.freeze(['READ_ERROR','FILE_CHANGED','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED']);
function IsFailure(status){return failures.includes(status);}
function IsStatus(status){return status==='MEASURED'||IsFailure(status);}
function FailureReason(status){
 if(!IsFailure(status))throw Error('MEASUREMENT_STATUS_INVALID');
 // Existing READ_ERROR records keep their public reason; typed failures are not collapsed.
 return status==='READ_ERROR'?'MEASUREMENT_UNAVAILABLE':status;
}
module.exports={IsFailure,IsStatus,FailureReason,failures};
