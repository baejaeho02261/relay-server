'use strict';
// Explicit offline maintenance of the application RSA transport identity.
// TLS certificate rotation is independent. Existing clients keep their exact
// pin for a bounded retiring window; only newly issued A receives the new pin.
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const config=require('../config/config'),store=require('./desktopBootstrapStore'),disk=require('./durableFile');
const HASH=/^[a-f0-9]{64}$/,ID=/^[-A-Za-z0-9_]{8,80}$/,MAX_WINDOW=24*60*60*1000;
const DIR=path.join(config.DATA_DIR,'connect-transport-generations');
const plain=v=>v&&Object.getPrototypeOf(v)===Object.prototype;
const hash=v=>crypto.createHash('sha256').update(v).digest('hex');
function Fail(code){const e=Error(code);e.desktopError=true;e.status=409;throw e;}
function Fields(v,names){if(!plain(v)||Object.keys(v).some(k=>!names.includes(k))||names.some(k=>!Object.hasOwn(v,k)))Fail('CONNECT_ROTATION_INPUT_INVALID');}
function Validate(v){
 if(!plain(v)||Object.keys(v).sort().join(',')!=='activeKeyId,keys,receipts,revision,version'||v.version!==1||!Number.isSafeInteger(v.revision)||v.revision<1||!HASH.test(v.activeKeyId)||!plain(v.keys)||Object.keys(v.keys).length>32||!plain(v.receipts)||Object.keys(v.receipts).length>128)Fail('CONNECT_ROTATION_STORAGE_INVALID');
 let active=0;
 for(const [id,k]of Object.entries(v.keys)){
  if(!plain(k)||Object.keys(k).some(x=>!['keyId','generation','serverPublicKey','state','createdAt','activatedAt','retireAt','revokedAt'].includes(x))||id!==k.keyId||!HASH.test(id)||!['ACTIVE','PREPARED','RETIRING','REVOKED'].includes(k.state)||!(k.generation===''||/^[a-f0-9]{48}$/.test(k.generation))||typeof k.serverPublicKey!=='string'||k.serverPublicKey.length>500||hash(Buffer.from(k.serverPublicKey,'base64'))!==id||!Number.isSafeInteger(k.createdAt)||k.createdAt<1)Fail('CONNECT_ROTATION_STORAGE_INVALID');
  const parsed=require('./desktopLicenses').ParseKey(k.serverPublicKey);if(parsed.publicKey!==k.serverPublicKey)Fail('CONNECT_ROTATION_STORAGE_INVALID');
  if(k.state==='ACTIVE'){active++;if(id!==v.activeKeyId)Fail('CONNECT_ROTATION_STORAGE_INVALID');}
  if(['ACTIVE','RETIRING'].includes(k.state)&&(!Number.isSafeInteger(k.activatedAt)||k.activatedAt<k.createdAt))Fail('CONNECT_ROTATION_STORAGE_INVALID');
  if(k.state==='RETIRING'&&(!Number.isSafeInteger(k.retireAt)||k.retireAt<=k.activatedAt||k.retireAt-k.activatedAt>MAX_WINDOW))Fail('CONNECT_ROTATION_STORAGE_INVALID');
  if(k.state==='REVOKED'&&(!Number.isSafeInteger(k.revokedAt)||k.revokedAt<k.createdAt))Fail('CONNECT_ROTATION_STORAGE_INVALID');
 }
 if(active!==1)Fail('CONNECT_ROTATION_STORAGE_INVALID');
 for(const [id,r]of Object.entries(v.receipts))if(!ID.test(id)||!plain(r)||Object.keys(r).sort().join(',')!=='actorHash,fingerprint,result'||!HASH.test(r.actorHash)||!HASH.test(r.fingerprint)||!plain(r.result)||!HASH.test(r.result.keyId)||!Number.isSafeInteger(r.result.revision)||r.result.revision<1||r.result.revision>v.revision)Fail('CONNECT_ROTATION_STORAGE_INVALID');
 return v;
}
function State(){const value=store.Load().transportKeyRotation;return value===undefined?null:Validate(value);}
function KeyRecord(identity,at){return {keyId:identity.keyId,generation:'',serverPublicKey:identity.serverPublicKey,state:'ACTIVE',createdAt:at,activatedAt:at};}
function File(k){return path.join(DIR,k.generation+'.pem');}
function ReadIdentity(k,original){
 if(!k.generation){if(k.keyId!==original.keyId)Fail('CONNECT_ROTATION_STORAGE_INVALID');return original;}
 const st=fs.lstatSync(DIR);if(!st.isDirectory()||st.isSymbolicLink())Fail('CONNECT_SERVER_KEY_INVALID');
 const bytes=disk.ReadRegular(File(k),8192);let privateKey;
 try{privateKey=crypto.createPrivateKey(bytes);}finally{bytes.fill(0);}
 if(privateKey.asymmetricKeyType!=='rsa'||privateKey.asymmetricKeyDetails?.modulusLength!==2048)Fail('CONNECT_SERVER_KEY_INVALID');
 const publicKey=crypto.createPublicKey(privateKey),blob=require('./connectTransportKey').PublicBlob(publicKey),keyId=hash(blob);
 if(keyId!==k.keyId||blob.toString('base64')!==k.serverPublicKey)Fail('CONNECT_SERVER_KEY_CHANGED');
 require('./desktopKeyPurposes').Assert(publicKey,'SERVER_TRANSPORT');
 return {privateKey,publicKey,keyId,serverPublicKey:k.serverPublicKey};
}
function Active(original){const s=State();return s?ReadIdentity(s.keys[s.activeKeyId],original):original;}
function Resolve(id,original){
 const s=State();if(!s){if(id!==original.keyId)Fail('CONNECT_PIN_MISMATCH');return original;}
 const k=s.keys[id];if(!k||!['ACTIVE','RETIRING'].includes(k.state))Fail('CONNECT_PIN_MISMATCH');
 if(k.state==='RETIRING'&&require('./desktopDeadline').persistent.expired('RSA.retiring:'+id,k.activatedAt,k.retireAt))Fail('CONNECT_PIN_RETIRED');
 if(Date.now()<k.activatedAt)Fail('CONNECT_PIN_RETIRED');
 return ReadIdentity(k,original);
}
function AssertUse(id,payload){
 const identity=require('./connectTransportKey');Resolve(id,identity.Original());const k=State()?.keys[id];
 // Old A must be reissued. A retiring pin is never permission for a new flow.
 if(k?.state==='RETIRING'&&payload?.operation==='bootstrap'&&payload.body?.action==='begin')Fail('CONNECT_NEW_LAUNCHER_REQUIRED');
}
function Summary(){const original=require('./connectTransportKey').Original(),s=State();return {version:1,revision:s?.revision||0,activeKeyId:s?.activeKeyId||original.keyId,keys:s?Object.values(s.keys).map(k=>({...k,generation:undefined})):[],newLauncherRequiredAfterActivation:true,automaticClientPinReplacement:false,maxRetiringWindowMs:MAX_WINDOW};}
function Run(action,body,actor){
 const fields={prepare:['requestId','expectedRevision'],activate:['requestId','expectedRevision','keyId','fromKeyId','retireAt','confirmNewLauncherRequired'],retire:['requestId','expectedRevision','keyId','reasonCode']}[action];if(!fields)Fail('CONNECT_ROTATION_INPUT_INVALID');Fields(body,fields);
 if(!ID.test(body.requestId)||!Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0||typeof actor!=='string'||!actor||actor.length>160)Fail('CONNECT_ROTATION_INPUT_INVALID');
 // Maintenance and the normal server contend on exactly the same OS lock.
 require('./desktopSingleWriter').Acquire(config.DATA_DIR,{haEnabled:config.HA_ENABLED});
 const original=require('./connectTransportKey').Original(),at=Date.now(),previous=State(),fingerprint=hash(require('./desktopRequestProtocol').Stable({action,body})),actorHash=hash(actor),old=previous?.receipts[body.requestId];
 if(old){if(old.actorHash!==actorHash||old.fingerprint!==fingerprint)Fail('CONNECT_ROTATION_REQUEST_REUSED');require('./desktopOperationAudit').Drain();return structuredClone(old.result);}
 if(body.expectedRevision!==(previous?.revision||0))Fail('CONNECT_ROTATION_CONFLICT');
 const next=previous?structuredClone(previous):{version:1,revision:0,activeKeyId:original.keyId,keys:{[original.keyId]:KeyRecord(original,at)},receipts:{}};
 if(Object.keys(next.receipts).length>=128)Fail('CONNECT_ROTATION_CAPACITY');let target,generated;
 if(action==='prepare'){
  if(Object.values(next.keys).some(k=>k.state==='PREPARED')||Object.keys(next.keys).length>=32)Fail('CONNECT_ROTATION_CAPACITY');
  const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537}),blob=require('./connectTransportKey').PublicBlob(publicKey),keyId=hash(blob),generation=crypto.randomBytes(24).toString('hex');
  require('./desktopKeyPurposes').Reserve(publicKey,'SERVER_TRANSPORT');
  fs.mkdirSync(DIR,{recursive:true,mode:0o700});const stat=fs.lstatSync(DIR);if(!stat.isDirectory()||stat.isSymbolicLink())Fail('CONNECT_SERVER_KEY_INVALID');
  target={keyId,generation,serverPublicKey:blob.toString('base64'),state:'PREPARED',createdAt:at};
  const bytes=Buffer.from(privateKey.export({format:'pem',type:'pkcs8'}));try{disk.Atomic(File(target),bytes,{createOnly:true});generated=File(target);}finally{bytes.fill(0);}
  next.keys[keyId]=target;
 }else{
  if(!HASH.test(body.keyId)||!next.keys[body.keyId])Fail('CONNECT_ROTATION_KEY_INVALID');target=next.keys[body.keyId];
  if(action==='activate'){
   if(body.confirmNewLauncherRequired!==true||body.fromKeyId!==next.activeKeyId||target.state!=='PREPARED'||!Number.isSafeInteger(body.retireAt)||body.retireAt<at+1000||body.retireAt>at+MAX_WINDOW)Fail('CONNECT_ROTATION_ACTIVATION_INVALID');
   // Re-read and cryptographically validate BEFORE publishing a new active ID.
   ReadIdentity(target,original);const current=next.keys[next.activeKeyId];current.state='RETIRING';current.activatedAt=at;current.retireAt=body.retireAt;
   require('./desktopDeadline').persistent.expired('RSA.retiring:'+current.keyId,at,body.retireAt);
   target.state='ACTIVE';target.activatedAt=at;next.activeKeyId=target.keyId;
  }else{
   if(target.state==='ACTIVE'||!['RETIRING','PREPARED'].includes(target.state)||typeof body.reasonCode!=='string'||!/^KEY_COMPROMISED$|^WINDOW_COMPLETE$|^PREPARATION_CANCELLED$/.test(body.reasonCode))Fail('CONNECT_ROTATION_RETIRE_INVALID');
   if(body.reasonCode==='WINDOW_COMPLETE'&&(!target.retireAt||at<target.retireAt))Fail('CONNECT_ROTATION_WINDOW_ACTIVE');
   target.state='REVOKED';target.revokedAt=at;
  }
 }
 next.revision++;
 const result={version:1,action,keyId:target.keyId,serverPublicKey:target.serverPublicKey,state:target.state,revision:next.revision,activeKeyId:next.activeKeyId,newLauncherRequiredAfterActivation:true,...(action==='activate'?{retireAt:body.retireAt,retiringKeyId:body.fromKeyId}:{})};
 next.receipts[body.requestId]={actorHash,fingerprint,result};Validate(next);
 try{require('./desktopOperationAudit').Run('TRANSPORT_KEY_'+action.toUpperCase(),actor,{subject:target.keyId,revision:next.revision,state:target.state},db=>{if((db.transportKeyRotation?.revision||0)!==body.expectedRevision)Fail('CONNECT_ROTATION_CONFLICT');db.transportKeyRotation=next;});}
 catch(error){if(generated&&!/RESTART_REQUIRED|WITNESS/.test(error.message)){try{if(!State()?.keys[target.keyId])fs.unlinkSync(generated);}catch(_){}}throw error;}
 return result;
}
module.exports={Validate,State,Active,Resolve,AssertUse,Summary,Run,DIR,MAX_WINDOW};
