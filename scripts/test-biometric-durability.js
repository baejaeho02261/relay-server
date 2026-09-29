'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix71-biometric-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';
require('../core/utils').EnsureDirs();
const state=require('../core/state'),db=require('../storage/database'),bio=require('../services/clientBiometric'),installation=require('../services/clientInstallation');
const notifications=require('../relay/notifications'),build=require('../services/buildGate');
const originalSave=db.SaveDatabase,oldNotify=notifications.NotifyServerAuthorized,oldDispatch=build.TryDispatchClient;
let notified=0,dispatched=0,saves=0;notifications.NotifyServerAuthorized=()=>{notified++;};build.TryDispatchClient=()=>{dispatched++;};
const id='1234567890ABCDEF',deviceKey='ANDROID2-1234567890ABCDEF-1234567890ABCDEF',secret='real-test-secret',saved={id,serverId:'',createdAt:Date.now()};
const socket={destroyed:false,lines:[],write(s){this.lines.push(s);}};
const c={clientId:id,serverId:'',installationDeviceKey:deviceKey,installationToken:'B'.repeat(32),connected:true,socket,permissionsGranted:true,permissionSequence:1,deviceAuthVerified:true,deviceAuthChallengeId:'FRESH-DEVICE-CHALLENGE',licenseAuthorized:true,licenseKey:'1111-2222-3333-4444',accessType:'TYPE1',biometricVerified:false};
state.clients.set(id,c);state.clientIdentities.set(deviceKey,saved);state.deviceSecrets.set('CLIENT:'+id,secret);
state.licenses.set(c.licenseKey,{boundClient:id,expiresAt:Date.now()+60000,suspended:false,accessType:'TYPE1'});
require('./helpers/member-identity-fixture')(c);
require('../services/deviceControl').RecordCapabilities('CLIENT',id,'DEVICE_HMAC,BIOMETRIC_AUTH,BIOMETRIC_STRONG,QR_DEVICE_APPROVAL');
const rk=installation.RegistryKey(deviceKey);
function proof(){assert.equal(bio.Begin(c).ok,true);const ch=state.clientBiometricChallenges.get(id);return ['BIOMETRIC_PROOF',ch.mode,ch.nonce,bio.Proof(secret,ch.mode,id,ch.nonce,ch.accessType)];}
function snapshot(){return {saved:structuredClone(saved),registry:structuredClone(state.clientInstallations.get(rk)),profile:structuredClone(state.clientBiometricProfiles.get(id)),groups:[...state.accessGroupGuids]};}
function rejectSave(proofPacket,throws=false){const before=snapshot();socket.lines=[];db.SaveDatabase=()=>{saves++;if(throws)throw Error('disk unavailable');return false;};assert.equal(bio.HandleProof(c,proofPacket),false);assert.deepEqual(snapshot(),before);assert.equal(c.biometricVerified,false);assert.equal(notified,0);assert.equal(dispatched,0);assert.ok(socket.lines.some(x=>x.startsWith('BIOMETRIC_ERROR|STORAGE_SAVE_FAILED')));assert.ok(socket.lines.every(x=>!x.startsWith('BIOMETRIC_OK|')));assert.ok(state.clientBiometricChallenges.has(id));}
try{
 const first=proof();rejectSave(first);rejectSave(first,true);assert.equal(saves,2,'Only one save is attempted per proof');
 db.SaveDatabase=()=>{saves++;return originalSave();};assert.equal(bio.HandleProof(c,first),true);assert.equal(c.biometricVerified,true);assert.equal(notified,1);assert.equal(dispatched,1);assert.equal(saves,3);assert.equal(state.clientBiometricProfiles.get(id).verificationCount,1);assert.ok(saved.installationAuthorizedAt);assert.equal(state.clientInstallations.get(rk).authorized[0].clientId,id);assert.equal(state.clientBiometricChallenges.has(id),false);
 // Existing enrollment must also roll back counter/time and installation metadata on failure.
 notified=0;dispatched=0;const verify=proof();rejectSave(verify);assert.equal(state.clientBiometricProfiles.get(id).verificationCount,1);
 // A valid OS proof cannot enroll a profile after its license is revoked or expired.
 db.SaveDatabase=originalSave;c.licenseAuthorized=false;socket.lines=[];assert.equal(bio.HandleProof(c,verify),false);assert.equal(notified,0);assert.equal(dispatched,0);assert.ok(socket.lines.every(x=>!x.startsWith('BIOMETRIC_OK|')));
 console.log('FIX71 biometric durability PASS: one atomic persisted enrollment; save false/throw restores profile, install and group state; no BIOMETRIC_OK/server grant/Build dispatch on failure; retry succeeds once; expired/revoked license remains blocked.');
}finally{db.SaveDatabase=originalSave;notifications.NotifyServerAuthorized=oldNotify;build.TryDispatchClient=oldDispatch;fs.rmSync(temp,{recursive:true,force:true});}
