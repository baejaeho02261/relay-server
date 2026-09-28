'use strict';
const state=require('../../core/state'),s=require('./store');
function IsEntry(license){return license?.entryPass===true;}
function Expired(license){return !license||(!IsEntry(license)&&Number(license.expiresAt)<=Date.now());}
function Convert(license){license.entryPass=true;license.expiresAt=0;license.accessType='';}
function Migrate(){
 let changed=false;
 for(const [key,license] of state.licenses){
  if(IsEntry(license))continue;
  if(!(license.tags||[]).includes('QR')&&!(license.tags||[]).includes('구매'))continue;
  for(const order of Object.values(s.DB().orders))if(order.licenseKey===key&&order.status==='ACTIVE'){
   const p=s.ProfileById(order.accountId);if(p&&!p.activeOrderId)p.activeOrderId=order.id;
  }
  Convert(license);changed=true;
 }
 return changed;
}
function ForClient(c,allowPreparation=false){
 if(!c||c.licenseAuthorized!==true)return null;
 const license=state.licenses.get(c.licenseKey)||require('../../license/licenseManager').GetBoundLicenseEntry(c.clientId)?.license;
 if(!license||license.boundClient!==c.clientId||license.suspended||Expired(license))return null;
 if(!IsEntry(license))return {accessType:license.accessType||'TYPE1',expiresAt:license.expiresAt};
 let p;try{p=s.DB().profiles[s.Subject(c)];}catch(_){return null;}
 if(!p||p.blocked)return null;
 const order=s.DB().orders[p.activeOrderId];
 if(!order||order.accountId!==p.id||order.mergedInto)return null;
 if(order.singleUse){
  if(order.preparedClientId!==c.clientId)return null;
  if(order.consumedAt){const session=require('../buildGate').ActiveSessionForClient(c.clientId);if(!session||session.orderId!==order.id||session.sessionId!==order.sessionId)return null;return {accessType:order.accessType,expiresAt:session.expiresAt,orderId:order.id};}
  if(!allowPreparation||order.status!=='PAID')return null;
  return {accessType:order.accessType,expiresAt:Date.now()+86400000,orderId:order.id,preparation:true};
 }
 // An old timed entitlement must be migrated before it can authorize a new session.
 return null;
}
module.exports={IsEntry,Expired,Convert,Migrate,ForClient};
