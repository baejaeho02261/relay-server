'use strict';
// Read-only, source-neutral event semantics for all registered NHW and Cozy
// kinds. Never changes admission, server authority, or recorded history.
// Disposition means sensor verdict; cause/effect means what the server did.
const CONFIRMED=new Set(['DETECTION','CORROBORATED_ANOMALY']);
const COVERAGE=new Set(['COVERAGE_WARNING','COVERAGE_DEGRADED']);
function Semantics(entry,event){
 if(!entry||!event)throw Error('SECURITY_EVENT_SEMANTICS_INVALID');
 const disposition=event.disposition||'UNRECORDED';
 const unavailable=entry.origin==='COZY'&&entry.signalClass==='UNKNOWN'||
  event.observationClass==='UNAVAILABLE_OR_INCOMPLETE'||
  entry.origin==='COZY'&&event.observationClass==='SENSOR_AVAILABILITY'||
  (event.provenance==='SERVER_COMPARISON'&&event.confidence===0&&event.correlation===false&&disposition==='OBSERVATION_UNRESOLVED');
 const policyRejected=entry.origin==='COZY'&&entry.signalClass==='POLICY_REJECTION';
 const detected=CONFIRMED.has(disposition)&&entry.signalClass!=='UNKNOWN'&&!unavailable&&!policyRejected;
 const pending=disposition==='OBSERVATION_UNRESOLVED';
 const warning=COVERAGE.has(disposition)||entry.signalClass==='UNKNOWN'&&entry.origin==='NHW';
 const kind=detected?'SECURITY_FINDING':unavailable?'MEASUREMENT_UNAVAILABLE':policyRejected?'POLICY_REJECTION':warning?'SENSOR_HEALTH':
  disposition==='EXPECTED_FIRST_PARTY'?'EXPECTED_OPERATION':
  disposition==='INTERNAL_EVIDENCE'?'INTERNAL_EVIDENCE':pending?'UNRESOLVED_EVIDENCE':'LEGACY_EVIDENCE';
 const causal=event.causalInvalidation===undefined?event.invalidated===true:event.causalInvalidation===true;
 // Missing measurement can deny execution under a required integrity policy,
 // but it is not proof of tampering. An unavailable sensor never becomes a
 // confirmed attack just because the same A/B/O session was revoked.
 const authorityAction=causal?(detected?'DETECTION_REVOKE':unavailable?'MEASUREMENT_DENIAL':policyRejected?'POLICY_DENIAL':
  warning?'COVERAGE_POLICY_REVOKE':'POLICY_REVOKE'):'EVIDENCE_ONLY';
 return {kind,authorityAction,securityFinding:detected,verificationIncomplete:unavailable,
   causedAuthorityChange:causal,sessionCurrentlyRevoked:event.sessionInvalidated===true};
}
module.exports={Semantics};
