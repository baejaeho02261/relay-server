'use strict';
// This is a server-local, one-use routing boundary, NOT an authorization token
// sent to clients. Existing service-specific credential/proof/Gate/Verify checks
// remain mandatory. Purpose and payload cannot change during queued proof work.
const crypto=require('node:crypto'),protocol=require("../protocol/peace.desktop-request-protocol");
const tickets=new WeakMap();
const ROUTES=Object.freeze({
 'bootstrap.keylessPolicy': ['bootstrap','PUBLIC_LIVE_V3_LAUNCHER','PUBLIC_DEVICE_POLICY_ONLY'],
 'bootstrap.keylessChallenge': ['bootstrap','EXACT_V3_FILE_AND_DEVICE_POLICY','BOUNDED_NONCE_NOT_AUTHORITY'],
 'bootstrap.keylessProve': ['bootstrap','DUAL_SIGNED_NONCE','REQUEST_ADMIN_APPROVAL_ONLY'],
 'bootstrap.keylessStatus': ['bootstrap','DUAL_SIGNED_BOUND_REQUEST','APPROVAL_STATUS_NO_RENEWAL'],
 'bootstrap.beginKeyless': ['bootstrap','DUAL_PROOF_AND_EXPLICIT_ADMIN_APPROVAL','CONSUME_ONCE_BOUND_FLOW'],
 'bootstrap.begin': ['bootstrap','LAUNCHER_TICKET_AND_COHORT','CREATE_BOUND_FLOW'],
 'bootstrap.download': ['bootstrap','DOWNLOAD_TICKET_LIVE_FLOW_COHORT','READ_EXACT_B_BYTES'],
 'bootstrap.finish': ['bootstrap','SIGNED_FINISH_AND_FRESH_MEASUREMENT','ISSUE_CHILD_HANDOFF'],
 'bootstrap.claim': ['bootstrap','SIGNED_CHILD_POSSESSION_AND_COHORT','ISSUE_BOUND_B_SESSION'],
 'bootstrap.status': ['bootstrap','SESSION_CAPABILITY','PROJECT_STATUS_NO_RENEWAL'],
 'bootstrap.close': ['bootstrap','RETAINED_SESSION_CAPABILITY','TERMINAL_ONLY'],
 'bootstrap.abort': ['bootstrap','DOWNLOAD_OR_SESSION_CAPABILITY','TERMINAL_ONLY'],
 'license.challenge': ['challenge','DEVICE_KEY_AND_BOUND_ACTION_HASH','ONE_USE_NONCE_NOT_LICENSE'],
 'license.redeem': ['execute','SIGNED_REQUEST_AND_B_GATE','CONSUME_LICENSE_ON_SERVER'],
 'license.verify': ['execute','SIGNED_REQUEST_LICENSE_BINDING_AND_B_GATE','RENEW_SERVER_LICENSE_LEASE'],
 'license.release': ['execute','SIGNED_REQUEST_AND_BOUND_LICENSE','TERMINAL_ONLY'],
 'license.overlay': ['execute','SIGNED_REQUEST_LICENSE_BINDING_AND_B_GATE','PREPARE_EXACT_O_DOWNLOAD'],
 'overlay.download': ['bootstrap','O_TICKET_PARENT_LICENSE_COHORT','READ_EXACT_O_BYTES'],
 'overlay.finish': ['bootstrap','SIGNED_PARENT_AND_EXACT_O','FINISH_CHILD_DOWNLOAD'],
 'overlay.claim': ['bootstrap','SIGNED_CHILD_POSSESSION_PARENT_LICENSE_COHORT','ISSUE_BOUND_O_SESSION'],
 'overlay.progress': ['bootstrap','SIGNED_O_SEQUENCE','DIAGNOSTIC_ONLY'],
 'overlay.verify': ['bootstrap','O_SESSION_LICENSE_COHORT_AND_FRESH_MEASUREMENTS','RENEW_BOUNDED_O_LEASE'],
 'overlay.commit': ['bootstrap','SIGNED_PARENT_AND_CURRENT_O_AUTHORITY','TRANSFER_ONCE'],
 'overlay.close': ['bootstrap','RETAINED_O_SESSION_CAPABILITY','TERMINAL_ONLY'],
 'overlay.abort': ['bootstrap','SIGNED_BOUND_PARENT','TERMINAL_ONLY'],
 'authority.challenge': ['security','AUTHENTICATED_STAGE_CONTEXT','MEASUREMENT_CHALLENGE_NOT_GRANT'],
 'authority.submit': ['security','SIGNED_CURRENT_STAGE_CHALLENGE','RECORD_CURRENT_MEASUREMENT'],
 'report.challenge': ['report','AUTHENTICATED_STAGE_CONTEXT','REPORT_CHALLENGE_NOT_GRANT'],
 'report.submit': ['report','SIGNED_CURRENT_STAGE_CHALLENGE','VALIDATE_COMPLETE_SNAPSHOT'],
 'lifecycle.challenge': ['bootstrap','RETAINED_BOUND_CONTEXT','DIAGNOSTIC_ONLY'],
 'lifecycle.report': ['bootstrap','ONE_USE_SIGNED_REPORT','DIAGNOSTIC_ONLY'],
 'device.policy': ['device','AUTHENTICATED_STAGE_CONTEXT','DEVICE_POLICY_ONLY'],
 'device.challenge': ['device','AUTHENTICATED_STAGE_CONTEXT','DEVICE_CHALLENGE_NOT_GRANT'],
 'device.complete': ['device','SIGNED_DEVICE_CHALLENGE','BIND_DEVICE_PROOF'],
 'device.tpmActivate': ['device','CURRENT_DEVICE_AND_TPM_PROOF','BIND_DEVICE_PROOF']
});
for(const row of Object.values(ROUTES))Object.freeze(row);
function Fail(code){const e=Error(code);e.desktopError=true;e.status=403;throw e;}
function Resolve(payload){const spec=protocol.Resolve(payload?.operation,payload?.body?.action);if(!Object.hasOwn(ROUTES,spec.name)||ROUTES[spec.name][0]!==payload.operation)Fail('PROTECTED_OPERATION_NOT_REGISTERED');return spec.name;}
const Fingerprint=p=>crypto.createHash('sha512').update('GAME-PROTECTED-DISPATCH-V1\n'+protocol.Stable(p)).digest('hex');
function Prepare(payload){const purpose=Resolve(payload),ticket=Object.freeze({});tickets.set(ticket,{purpose,fingerprint:Fingerprint(payload)});return ticket;}
function Execute(ticket,payload,handlers){const entry=tickets.get(ticket);tickets.delete(ticket);if(!entry)Fail('PROTECTED_OPERATION_TICKET_USED');if(entry.purpose!==Resolve(payload)||entry.fingerprint!==Fingerprint(payload))Fail('PROTECTED_OPERATION_CHANGED');const route=ROUTES[entry.purpose];if(!Object.hasOwn(handlers,route[0])||typeof handlers[route[0]]!=='function')Fail('PROTECTED_OPERATION_HANDLER_MISSING');return handlers[route[0]](payload.body);}
function Inventory(){return Object.entries(ROUTES).map(([purpose,[handler,authority,effect]])=>({purpose,handler,authority,effect,checksRunInService:true,clientNormalFlagAccepted:false}));}
module.exports={Prepare,Execute,Inventory};
