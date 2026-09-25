'use strict';
// Test-only fixture. Production cannot enable this bypass, even with the flag set.
const grants=new WeakMap();
const Enabled=()=>process.env.NODE_ENV==='test'&&process.env.MEMBER_BIOMETRIC_TEST_MODE==='1';
function Revoke(c){if(c)grants.delete(c);}
function Valid(c){
 if(!c)return false;
 const grant=grants.get(c);
 if(!Enabled()||!grant||grant.challenge!==c.deviceAuthChallengeId||
   !c.connected||c.disconnected||c.superseded||c.socket?.destroyed||
   !c.licenseAuthorized||!c.permissionsGranted||!c.deviceAuthVerified){Revoke(c);return false;}
 return true;
}
function Grant(c,accountId){
 if(!Enabled()||!c?.deviceAuthChallengeId||!accountId)return false;
 grants.set(c,{challenge:c.deviceAuthChallengeId,accountId});return true;
}
function RevokeMember(accountId){
 for(const c of require('../../core/state').clients.values())
  if(grants.get(c)?.accountId===accountId)Revoke(c);
}
module.exports={Enabled,Valid,Grant,Revoke,RevokeMember};
