'use strict';
// Cross-layer source contracts for the native boundary. Delphi/Android execution
// is still required for OS picker, biometric and FMX control lifetime behavior.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const base=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(base,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'');
function routine(text,name){
 const all=[...text.matchAll(/^(?:function|procedure|constructor|destructor)\s+([\w.]+)/gm)],at=all.findIndex(x=>x[1]===name);
 assert.ok(at>=0,'Missing routine '+name);
 return text.slice(all[at].index,all[at+1]?.index??text.length).replace(/\{[\s\S]*?\}/g,'');
}
function before(text,first,last,why){const a=text.indexOf(first),b=text.indexOf(last);assert.ok(a>=0&&b>=0&&a<b,why);}
const auth=read('MoaPlayApp.AuthSteps.inc'),wire=read('MoaPlayMemberClient.pas');
const event=routine(wire,'TMoaPlayMemberClient.HandleIdentityEvent');
assert.match(event,/Length\(Parts\)<>4/);
assert.match(event,/Revision<=FLastIdentityRevision/,'reject replays before dispatch');
assert.match(event,/Length\(MAC\)<>64/);
before(event,'if Difference<>0 then Exit','FLastIdentityRevision:=Revision','forged event cannot advance replay counter');
before(event,'FLastIdentityRevision:=Revision',"FOnReply('identity.revoked'",'commit authenticated sequence before callback clears transport requests');
assert.match(event,/for I:=1 to 64 do Difference:=Difference or/,'compare every MAC character');
const expression=/RelayHmacSha256Hex\(FSecurity.Secret,([^;]+?)\)\)/.exec(event)?.[1];
assert.ok(expression,'native signed-event canonicalization is present');
const fields={FClientID:'ABCDEF0123456789',FChallengeID:'AUTH-72',"Parts[1]":'7201',"Parts[2]":'IDENTITY_ADMIN_REAUTH'};
const canonical=expression.split('+').map(term=>{const value=term.trim();if(/^'[^']*'$/.test(value))return value.slice(1,-1);assert.ok(Object.hasOwn(fields,value),value);return fields[value];}).join('');
const state=require('../core/state'),protocol=require('../services/member/protocol'),secret='fix72-wire-contract-secret';
const c={clientId:fields.FClientID,deviceAuthChallengeId:fields.FChallengeID,deviceAuthVerified:true};
state.deviceSecrets.set('CLIENT:'+c.clientId,secret);
try{
 const signature=protocol.Sign(c,'HUB_IDENTITY',[fields['Parts[1]'],fields['Parts[2]']]);
 assert.equal(crypto.createHmac('sha256',secret).update(canonical,'utf8').digest('hex').toUpperCase(),signature,'server sender and native verifier bind the same client/challenge/revision/reason');
 for(const patch of [{clientId:'OTHER'},{deviceAuthChallengeId:'OLD'}])assert.notEqual(protocol.Sign({...c,...patch},'HUB_IDENTITY',[fields['Parts[1]'],fields['Parts[2]']]),signature);
 for(const replacement of [['7202',fields['Parts[2]']],[fields['Parts[1]'],'IDENTITY_REVOKED']])assert.notEqual(protocol.Sign(c,'HUB_IDENTITY',replacement),signature);
}finally{state.deviceSecrets.delete('CLIENT:'+c.clientId);}
const suspend=routine(wire,'TMoaPlayMemberClient.SuspendIdentity'),deliver=routine(wire,'TMoaPlayMemberClient.Deliver');
assert.match(suspend,/FRequests.Clear/,'drop stale read callbacks');
assert.match(suspend,/FUploadTimer.Enabled:=False/,'stop multipart work');
assert.doesNotMatch(suspend,/FPending\w*\s*:=|SavePending|TFile\.Delete|FLastIdentityRevision\s*:=/,'identity suspension preserves durable financial recovery and signed sequence');
before(deliver,"= 'IDENTITY_REQUIRED'",'if (ID = FPendingID) and not Retry','reauth failure preserves pending request');
before(deliver,"= 'IDENTITY_PROVIDER_UNAVAILABLE'",'if (ID = FPendingID) and not Retry','temporary provider failure preserves pending request');
assert.match(deliver,/FOnReply\('identity.revoked',Payload\)/);
const revoke=routine(auth,'TMoaPlayForm.HubIdentityRevoked'),reset=routine(auth,'TMoaPlayForm.HubIdentityReset');
assert.match(revoke,/FState.BiometricAuthenticated:=False/);
assert.match(revoke,/CancelBiometricPrompt/);
assert.match(revoke,/FMember.SuspendIdentity/);
assert.match(revoke,/FHubCache.Clear/);assert.match(revoke,/FHubDrafts.Clear/);
before(revoke,"FHubPhotoContext:=''",'FreeAndNil(FHubPage)','reject outstanding native picker callbacks before page disposal');
before(revoke,'HubDetachEditors','FreeAndNil(FHubPage)','detach editor focus events before page disposal');
before(revoke,"FHubRenderedView:=''",'HubDetachEditors','prevent focus loss from repopulating erased drafts');
assert.match(revoke,/Inc\(FHubEditorEpoch\)/,'invalidate stale editor completion');
assert.doesNotMatch(revoke+reset,/(?:FDeviceAuthVerified|FPermissionsServerGranted|LicenseAuthenticated)\s*:=|ResetLiveAuthentication|ClearTransport|FUserProfile\.[\w]+\s*:=|FHubChargePendingID\s*:=|FHubPaymentOpenedID\s*:=/,'revocation must retain approved installation, QR and pending financial reconciliation');
const tick=routine(auth,'TMoaPlayForm.HubIdentityTick'),reply=routine(auth,'TMoaPlayForm.HubIdentityReply'),ready=routine(auth,'TMoaPlayForm.HubIdentityReady');
assert.match(tick,/not FForeground/);assert.match(tick,/FIdentityLinked or not FIdentityStatusKnown/,'linked-but-paused identities continue polling');
assert.match(reply,/FIdentityNextAt:=HubAuthTick\+15000/);
assert.match(routine(read('MoaPlayApp.Lifecycle.Construction.inc'),'TMoaPlayForm.FormActivated'),/FIdentityNextAt:=0;HubIdentityTick/);
before(reply,"if not Assigned(Identity)","if HubBool(Identity,'linked')",'malformed identity projection cannot trigger logout');
assert.match(ready,/FIdentityLinked and FIdentityProviderReady/,'provider freshness gates native member access');
assert.match(reply,/FIdentityProviderReady:=Identity.GetValue<Boolean>\('ready',True\)/);
const pause=reply.slice(reply.indexOf('if not FIdentityProviderReady then begin'),reply.indexOf('if not WasReady then begin'));
assert.match(pause,/ShowInitialAuthPage;Exit/);
assert.doesNotMatch(pause,/HubIdentityRevoked|HubIdentityReset|BiometricAuthenticated\s*:=|FBiometricNonce\s*:=/,'provider outage cannot erase linked identity or phone proof');
assert.match(read('MoaPlayApp.Ui.inc'),/FIdentityLinked and not FIdentityProviderReady/,'paused identity has a temporary status screen');
const bio=read('MoaPlayApp.Protocol.Biometric.inc'),build=read('MoaPlayApp.Protocol.Build.inc');
function packet(text,name){const start=text.indexOf("if ALine.StartsWith('"+name+"|')");assert.ok(start>=0,name);const end=text.indexOf("if ALine.StartsWith('",start+1);return text.slice(start,end<0?text.length:end);}
const biometricOK=packet(bio,'BIOMETRIC_OK');
before(biometricOK,'not HubIdentityReady','FState.BiometricAuthenticated := True','late biometric acknowledgement cannot restore a revoked identity');
for(const guard of ['not FBiometricProofPending',"FBiometricNonce=''","FBiometricMode=''"])before(biometricOK,guard,'FState.BiometricAuthenticated := True','biometric acknowledgement must complete the outstanding phone proof');
assert.match(packet(bio,'BIOMETRIC_CHALLENGE'),/not HubIdentityReady/);
assert.match(revoke,/FState.PendingRequestID:=''/,'discard revoked build request without touching durable member mutations');
for(const action of ['BUILD_WAITING','BUILD_ACCEPTED','BUILD_OK']){
 const code=packet(build,action);assert.match(code,/not HubIdentityReady/);assert.match(code,/not FState.BiometricAuthenticated/);
 assert.match(code,/FState.PendingRequestID(?:<>|=)''/);assert.match(code,/SameText\(Parts\[1\],\s*FState.PendingRequestID\)/,'build response must bind the outstanding local request');
}
assert.doesNotMatch(packet(build,'BUILD_OK'),/\(FState.PendingRequestID = ''\) or/,'an unsolicited old build success cannot revive a cleared lease');
console.log('FIX72 NATIVE AUTH PASS: actual server/native HMAC contract, replay/callback ordering, identity-only cleanup, durable pending retention, foreground/15s polling, provider readiness and late biometric/build gates. Delphi/Android runtime not executed.');
