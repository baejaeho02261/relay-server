'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix75-resume-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':process.env.STORAGE_ENGINE||'json';require('../core/utils').EnsureDirs();
const state=require('../core/state'),db=require('../storage/database'),bio=require('../services/clientBiometric'),qr=require('../services/qrApproval'),da=require('../services/deviceAuth'),permissions=require('../services/clientPermissions');
const store=require('../services/member/store'),lifecycle=require('../services/member/oauthLifecycle'),license=require('../license/licenseManager'),build=require('../services/buildGate'),notifications=require('../relay/notifications');
const id='1234567890ABCDEF',key='ANDROID2-1234567890ABCDEF-1234567890ABCDEF',secret=crypto.randomBytes(32).toString('base64url'),token='B'.repeat(32),licenseKey='1111-2222-3333-4444';
const hmac=(key,value)=>crypto.createHmac('sha256',key).update(value).digest('hex').toUpperCase();
const socket=()=>({destroyed:false,lines:[],write(x){this.lines.push(x.trim());}});
let c={clientId:id,serverId:'',installationDeviceKey:key,installationToken:token,connected:true,socket:socket(),permissionsGranted:true,permissionSequence:1,deviceAuthVerified:true,deviceAuthChallengeId:'INITIAL',licenseAuthorized:true,licenseKey,accessType:'TYPE1',biometricVerified:false};
state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,secret);
state.licenses.set(licenseKey,{boundClient:id,expiresAt:Date.now()+86400000*30,suspended:false,accessType:'TYPE1'});
let account=require('./helpers/member-identity-fixture')(c);
const oldCheck=lifecycle.CheckAccount;lifecycle.CheckAccount=()=>Promise.resolve(); // Provider transport is separate; use real Ready against the fixture's verified grant.
require('../services/deviceControl').RecordCapabilities('CLIENT',id,'DEVICE_HMAC,BIOMETRIC_AUTH,BIOMETRIC_STRONG,QR_DEVICE_APPROVAL');
let dispatches=0;const oldDispatch=build.TryDispatchClient,oldNotify=notifications.NotifyServerAuthorized,oldUnauthorized=notifications.NotifyServerUnauthorized;
build.TryDispatchClient=()=>dispatches++;notifications.NotifyServerAuthorized=()=>{};notifications.NotifyServerUnauthorized=()=>{};
function prove(){assert.equal(bio.Begin(c).ok,true);const ch=state.clientBiometricChallenges.get(id);assert.ok(ch);assert.equal(bio.HandleProof(c,['BIOMETRIC_PROOF',ch.mode,ch.nonce,bio.Proof(secret,ch.mode,id,ch.nonce,ch.accessType)]),true);assert.equal(c.biometricVerified,true);}
function freshConnection(){
 c={...c,socket:socket(),deviceAuthVerified:false,permissionsGranted:false,permissionSequence:0,licenseAuthorized:false,licenseKey:'',biometricVerified:false,deviceAuthChallengeId:'',biometricResumeRequestId:''};state.clients.set(id,c);
 require('../services/deviceControl').RecordCapabilities('CLIENT',id,'DEVICE_HMAC,BIOMETRIC_AUTH,BIOMETRIC_STRONG,QR_DEVICE_APPROVAL');
 const issued=da.IssueChallenge('CLIENT',id);assert.equal(issued.ok,true,JSON.stringify(issued));const ch=state.deviceAuthChallenges.get(issued.challengeId);
 // A new connection must prove the retained device key, never the local page flag.
 c.biometricResumeRequestId='A'.repeat(32);assert.equal(bio.TryResume(c),false);
 assert.equal(da.HandleAuth('CLIENT',id,ch.challengeId,hmac(secret,`CLIENT|${id}|${ch.challengeId}|${ch.nonce}|${ch.issuedAt}`)),true);
 assert.equal(permissions.Handle(c,['CLIENT_PERMISSIONS','1','7',hmac(secret,`PERMISSIONS|${id}|${ch.challengeId}|1|7`)]),true);
 return c;
}
function request(){const nonce=crypto.randomBytes(16).toString('hex').toUpperCase();c.socket.lines=[];const result=qr.Resume(c,nonce);return {nonce,result,lines:[...c.socket.lines]};}
function resumed(){const r=request();assert.equal(r.result.ok,true);assert.equal(c.biometricVerified,true);assert.ok(r.lines.some(x=>x.startsWith('BIOMETRIC_RESUMED|')));assert.ok(r.lines.every(x=>!x.startsWith('BIOMETRIC_CHALLENGE|')));return r;}
function denied(mutate,restore=()=>{}){c.biometricResumeRequestId=crypto.randomBytes(16).toString('hex').toUpperCase();assert.equal(bio.TryResume(c),true,'positive baseline before each isolated denial');c.biometricVerified=false;c.biometricResumeRequestId='A'.repeat(32);mutate();const before=c.socket.lines.length;assert.equal(bio.TryResume(c),false);assert.equal(c.biometricVerified,false);assert.ok(c.socket.lines.slice(before).every(x=>!x.startsWith('BIOMETRIC_RESUMED|')));restore();}
try{
 prove();assert.equal(dispatches,1);const original=structuredClone(state.clientBiometricProfiles.get(id));
 assert.equal(original.resume.expiresAt,original.verifiedAt+bio.RESUME_TTL_MS);
 freshConnection();const beforeResumeDispatch=dispatches;const first=resumed();assert.equal(dispatches,beforeResumeDispatch,'resuming member access cannot fabricate a PC Build dispatch');
 const packet=first.lines.find(x=>x.startsWith('BIOMETRIC_RESUMED|')).split('|');
 assert.equal(packet[1],c.deviceAuthChallengeId);assert.equal(packet[2],first.nonce);assert.equal(packet[6],hmac(secret,`BIOMETRIC_RESUMED|${id}|${packet.slice(1,6).join('|')}`));
 assert.equal(state.clientBiometricProfiles.get(id).verifiedAt,original.verifiedAt,'reconnect does not extend proof lifetime');
 assert.equal(c.biometricResumeRequestId,'','server consumes one request intent');
 assert.equal(bio.TryResume(c),false,'a repeated call without fresh resume request does not authorize');
 const serialized=JSON.parse(JSON.stringify(db.BuildDatabaseObject()));assert.equal(db.SaveDatabase(),true);state.clientBiometricProfiles.clear();db.LoadDatabase();assert.ok(state.clientBiometricProfiles.has(id),'actual storage reload restores the proof lease');assert.equal(db.ImportDatabaseObject(serialized),true);account=store.DB().profiles[store.Subject(c)];
 assert.deepEqual(state.clientBiometricProfiles.get(id).resume,original.resume,'durable import preserves only the server-issued bound lease');
 freshConnection();resumed();assert.equal(state.clientBiometricProfiles.get(id).verificationCount,1);
 denied(()=>{c.deviceAuthVerified=false;},()=>{c.deviceAuthVerified=true;});
 denied(()=>{c.permissionsGranted=false;},()=>{c.permissionsGranted=true;});
 denied(()=>{c.licenseAuthorized=false;},()=>{c.licenseAuthorized=true;});
 const lic=state.licenses.get(licenseKey);denied(()=>{lic.suspended=true;},()=>{lic.suspended=false;});
 denied(()=>{state.disabledClients.add(id);},()=>{state.disabledClients.delete(id);});
 denied(()=>{state.serviceEnabled=false;},()=>{state.serviceEnabled=true;});
 denied(()=>{account.blocked=true;},()=>{account.blocked=false;});
 const link=lifecycle.Record(account),generation=link.generation,credentials=link.credentials;
 denied(()=>{link.generation='new-login-generation';},()=>{link.generation=generation;});
 denied(()=>{link.status='revoked';},()=>{link.status='active';});
 denied(()=>{delete link.credentials;},()=>{link.credentials=credentials;});
 denied(()=>{state.deviceSecrets.set('CLIENT:'+id,'rotated-secret');},()=>{state.deviceSecrets.set('CLIENT:'+id,secret);});
 const current=state.clientBiometricProfiles.get(id),binding=current.resume.binding;
 denied(()=>{current.resume.binding='0'.repeat(64);},()=>{current.resume.binding=binding;});
 const expiry=current.resume.expiresAt;denied(()=>{current.resume.expiresAt=Date.now()-1;},()=>{current.resume.expiresAt=expiry;});
 denied(()=>{current.resume.expiresAt=expiry+1;},()=>{current.resume.expiresAt=expiry;});
 const verifiedAt=current.verifiedAt;denied(()=>{current.verifiedAt=Date.now()+10000;current.resume.expiresAt=current.verifiedAt+bio.RESUME_TTL_MS;},()=>{current.verifiedAt=verifiedAt;current.resume.expiresAt=expiry;});
 denied(()=>{account.activeOrderId='ORD-NEW';store.DB().orders['ORD-NEW']={preparedAt:Date.now()};},()=>{delete account.activeOrderId;delete store.DB().orders['ORD-NEW'];});
 denied(()=>{c.installationDeviceKey='ANDROID2-FEDCBA0987654321-FEDCBA0987654321';},()=>{c.installationDeviceKey=key;});
 const other={...c,clientId:'FEDCBA0987654321',socket:socket()};state.clients.set(other.clientId,other);state.clientBiometricProfiles.set(other.clientId,structuredClone(current));state.deviceSecrets.set('CLIENT:'+other.clientId,secret);assert.equal(bio.TryResume(other),false,'copying a profile and secret to another client cannot resume');state.clients.delete(other.clientId);
 // A real new challenge cancels the old lease durably before it can be reused.
 const renewed=bio.Begin(c);assert.equal(renewed.ok,true,JSON.stringify(renewed));assert.equal(state.clientBiometricProfiles.get(id).resume,undefined);c.biometricResumeRequestId='C'.repeat(32);assert.equal(bio.TryResume(c),false);prove();
 for(const failSave of [()=>false,()=>{throw Error('disk failed');}]){const originalSave=db.SaveDatabase;db.SaveDatabase=failSave;try{assert.equal(bio.Begin(c).ok,false);assert.equal(c.biometricVerified,false);assert.equal(state.clientBiometricProfiles.get(id).resume,undefined);}finally{db.SaveDatabase=originalSave;}prove();}
 c.socket.lines=[];license.AuthorizeBoundClientByQr(c,'PURCHASE');assert.ok(c.socket.lines.some(x=>x.startsWith('BIOMETRIC_CHALLENGE|')));assert.ok(c.socket.lines.every(x=>!x.startsWith('BIOMETRIC_RESUMED|')));assert.equal(c.biometricVerified,false);assert.equal(state.clientBiometricProfiles.get(id).resume,undefined,'purchase proof requirement survives reconnect');
 prove();c.biometricVerified=false;c.socket.lines=[];qr.Resume(c);assert.ok(c.socket.lines.some(x=>x.startsWith('BIOMETRIC_CHALLENGE|')),'old clients without a request nonce receive their supported real biometric flow');
 console.log('FIX75 AUTH RESUME '+process.env.STORAGE_ENGINE+' PASS: real proof → fresh HMAC/permissions → nonce-signed reconnect, durable restart import, no proof extension/PC grant; expiry/tamper/cross-device/account+grant+key+order revocation fail closed; purchase and legacy paths require real biometric proof.');
}finally{build.TryDispatchClient=oldDispatch;notifications.NotifyServerAuthorized=oldNotify;notifications.NotifyServerUnauthorized=oldUnauthorized;lifecycle.CheckAccount=oldCheck;lifecycle.StopMonitor();fs.rmSync(temp,{recursive:true,force:true});}
