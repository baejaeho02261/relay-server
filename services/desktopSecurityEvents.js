'use strict';
// Parse only server-owned outcome fields. Never forward evidence or token blobs.
function Classify(event) {
  if(event?.type==='AUDIT_WRITE_FAILED') return {entity:'AUDIT_STORAGE',reason:'AUDIT_WRITE_FAILED',severity:'CRITICAL',recovered:false,title:'감사 기록 저장 실패'};
  if(event?.type!=='DESKTOP_SECURITY_AUTHORITY') return null;
  let row;try{row=JSON.parse(event.detail);}catch(_){return null;}
  if(!row||typeof row!=='object'||Array.isArray(row))return null;
  if(!['OBSERVATION','HOLD','INVALIDATED'].includes(row.kind))return null;
  const raw=String(row.sessionId||row.flowId||'');
  if(!/^(?:(?:DS|BF)-)?[A-F0-9]{24}$/.test(raw))return null;
  const reason=String(row.reason||'');if(!/^[A-Z][A-Z0-9_]{1,79}$/.test(reason))return null;
  const stage=['A','B'].includes(row.stage)?row.stage:'?';
  const recovered=row.kind==='OBSERVATION'&&reason==='BASELINE_MATCH';
  const severity=reason==='IMAGE_DIGEST_MISMATCH'||reason==='SECURITY_OBSERVATION_MISMATCH'?'HIGH':'MEDIUM';
  return {entity:stage+':'+raw,reason,severity,recovered,title:recovered?'보안 관측 정상 복구':'서버 보안 확인 필요'};
}
module.exports={Classify};
