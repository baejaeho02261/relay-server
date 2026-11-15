'use strict';
// Bounded, server-assembled diagnostic summary. This never participates in the
// authorization decision. No paths, raw memory, credentials or exception text.
const phases=['UNKNOWN','MODULE_PATH','OPEN_FILE','FILE_SIZE_BUDGET','FILE_MEASUREMENT','PE_PLAN','CODE_SIZE_BUDGET','CODE_MEASUREMENT','EXPORT_MEASUREMENT','FINAL_BUDGET'];
const failures=new Set(['READ_ERROR','FILE_UNAVAILABLE','SKIPPED_LIMIT','NAME_TOO_LONG','FILE_CHANGED','COVERAGE_INSUFFICIENT','CANCELLED','DEADLINE_EXCEEDED']);
const token=x=>typeof x==='string'&&/^[A-Z_]{1,64}$/.test(x)?x:'UNKNOWN';
function Summarize(payload,rows,reasons){
 if(!Array.isArray(rows)||rows.length>1024)throw Error('SNAPSHOT_DIAGNOSTICS_INVALID');
 const incomplete=[];let failureCount=0;
 for(const r of rows){
  const failed=failures.has(r.status)||failures.has(r.codeStatus)||!r.fileSha512||!r.codeSha512||['READ_ERROR','UNSUPPORTED_EXPORT_LAYOUT'].includes(r.exportTableStatus);
  if(!failed)continue;failureCount++;
  if(incomplete.length>=16)continue;
  const safeName=typeof r.name==='string'&&r.name.length<=180&&!/[\\/:\x00-\x1f\x7f]/.test(r.name)?r.name:'unknown';
  const phase=Number.isInteger(r.failurePhase)&&r.failurePhase>=0&&r.failurePhase<phases.length?r.failurePhase:0;
  incomplete.push({name:safeName,status:token(r.status),codeStatus:token(r.codeStatus),exportStatus:token(r.exportTableStatus),phase:phases[phase]});
 }
 const elapsed=payload.measurementFinishedTick-payload.measurementStartedTick;
 return {version:1,totalModules:payload.totalModules,reportedMeasuredModules:payload.measuredModules,receivedModules:rows.length,failedModuleCount:failureCount,omittedFailureCount:Math.max(0,failureCount-incomplete.length),coverage:token(payload.coverage),generation:token(payload.moduleGenerationStatus),complete:payload.complete===true,truncated:payload.truncated===true,elapsedMs:Number.isSafeInteger(elapsed)&&elapsed>=0&&elapsed<=60000?elapsed:null,reasons:(reasons||[]).slice(0,16).map(token),incomplete};
}
module.exports={Summarize};
