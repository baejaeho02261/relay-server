'use strict';
// Loaded only by product-fault-fixture.js. Production TLS, envelope parsing,
// proof verification and business services remain the authority. The adapter
// destroys the exact accepted socket only after a selected durable success.
const {AsyncLocalStorage}=require('node:async_hooks');
const crypto=require('node:crypto');
const sha=value=>crypto.createHash('sha512').update(JSON.stringify(value)).digest('hex');
const TARGETS=Object.freeze({'response-loss-redeem':{module:'desktopLicenses',action:'redeem'},'response-loss-claim-b':{module:'desktopBootstrap',action:'claim'},'response-loss-claim-o':{module:'desktopBootstrap',action:'overlayClaim'},'response-loss-transfer':{module:'desktopBootstrap',action:'overlayCommit'}});
function CommittedResult(action,result){
 // These two fields are current projections, not durable receipt identity.
 // The stored redemption receipt and every lease/token/identity field still
 // have to be byte-identical below. No volatile-field exception for claims.
 if(action==='redeem'){const {serverTime,revision,...committed}=result;return committed;}
 return result;
}
function Snapshot(){
 const db=require("../../services/bootstrap/peace.desktop-bootstrap-store").Load(),licenses=require("../../services/licensing/peace.desktop-licenses").DB();
 const flows=Object.values(db.flows),overlays=Object.values(db.overlays||{});
 // Hashes are local comparison material, never exported in status/report.
 return {used:Object.values(licenses.licenses).filter(x=>x.consumed).length,redeemReceipts:Object.values(licenses.receipts||{}).filter(x=>x.action==='redeem').length,flows:flows.length,overlays:overlays.length,
  redeemIdentity:sha(Object.values(licenses.receipts||{}).filter(x=>x.action==='redeem')),
  consumption:sha(Object.values(licenses.licenses).filter(x=>x.consumed).map(x=>[x.id,x.activatedAt,x.activationNonce,x.deviceId,x.bootstrapSessionId])),
  delegation:sha([...flows,...overlays].map(x=>[x.id,x.childNonce,x.delegatedClaimFingerprint,x.deviceId,x.parentDeviceId,x.claimedAt,x.transferredAt,x.handoffExpiresAt,x.sessionExpiresAt,x.delegatedClaimRecoveryUntil,x.claimRecoveryUntil,x.transferRecoveryUntil,x.sessionNonce,x.ticketNonce])),
  distinctChildren:[...flows,...overlays].filter(x=>x.childNonce).every(x=>x.deviceId!==x.parentDeviceId)};
}
function Install({scenario,onEvent=()=>{},snapshot=Snapshot,services}={}){
 if(!scenario)throw Error('PRODUCT_FAULT_SCENARIO_REQUIRED');
 const context=new AsyncLocalStorage(),target=TARGETS[scenario],calls=[],originals=[];
 const proof={requested:scenario,observed:false,droppedResponses:0,retryObserved:false,sameBusinessRequest:false,sameCommittedResult:false,noDoubleConsumption:false,noDuplicateDelegation:false,distinctChildren:false,reuseDenied:false,reuseChecks:0};
 let first,dropSocket,active=true;
 const resolve=name=>{if(services?.[name])return services[name];if(name==='desktopBootstrap')return require("../../services/bootstrap/peace.desktop-bootstrap");if(name==='desktopLicenses')return require("../../services/licensing/peace.desktop-licenses");throw Error('PRODUCT_FAULT_SERVICE_INVALID');};
 for(const name of ['desktopBootstrap','desktopLicenses']){
  const service=resolve(name),original=service.Execute;
  service.Execute=function(body){
   const socket=context.getStore();let result;
   if(socket&&active&&['begin','claim','overlayClaim','redeem','overlayCommit'].includes(body?.action)&&calls.length<16)calls.push({name,body:structuredClone(body)});
   try{result=original.apply(this,arguments);}catch(error){if(socket)onEvent({event:'service-rejected',action:body?.action,error:/^[A-Z0-9_]+$/.test(error.message)?error.message:'SERVICE_REJECTED'});throw error;}
   if(socket&&active){
    if(target?.module===name&&target.action===body.action){
     const after=snapshot(),request=sha(body),response=sha(CommittedResult(body.action,result));
     if(!first){first={request,response,after};dropSocket=socket;onEvent({event:'commit-observed',action:body.action});}
     else{proof.retryObserved=true;proof.sameBusinessRequest=request===first.request;proof.sameCommittedResult=response===first.response;proof.noDoubleConsumption=after.used===first.after.used&&after.redeemReceipts===first.after.redeemReceipts&&after.consumption===first.after.consumption&&after.redeemIdentity===first.after.redeemIdentity;proof.noDuplicateDelegation=after.flows===first.after.flows&&after.overlays===first.after.overlays&&after.delegation===first.after.delegation;proof.distinctChildren=after.distinctChildren;onEvent({event:'retry-observed',action:body.action});}
    }
   }
   return result;
  };
  originals.push(()=>{service.Execute=original;});
 }
 function Attach(server){server.prependListener('secureConnection',socket=>{
  const on=socket.on,end=socket.end;
  socket.on=function(event,listener){return on.call(this,event,event==='data'?function(...args){return context.run(socket,()=>listener.apply(this,args));}:listener);};
  socket.end=function(...args){if(active&&dropSocket===socket){dropSocket=null;proof.observed=true;proof.droppedResponses++;onEvent({event:'response-dropped',action:target.action});socket.destroy();return socket;}return end.apply(this,args);};
 });}
 function Reuse(){
  // Replay authentic previously accepted bodies through the unchanged service
  // after real clients are gone and server authority is terminal. No new proof,
  // token, clock jump or authorization is fabricated by this check.
  active=false;const before=snapshot();let denied=0;
  for(const {name,body} of calls){try{resolve(name).Execute(body);}catch(error){if(error.desktopError===true)denied++;}}
  const after=snapshot();proof.reuseChecks=calls.length;proof.reuseDenied=calls.length>0&&denied===calls.length&&sha(before)===sha(after);return {...proof};
 }
 return {Attach,Reuse,Status:()=>({...proof}),Dispose:()=>{active=false;for(const restore of originals)restore();},Context:context};
}
module.exports={TARGETS,Snapshot,CommittedResult,Install};
