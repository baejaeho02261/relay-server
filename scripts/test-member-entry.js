'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'moa-member-entry-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';
require('../core/utils').EnsureDirs();
const state=require('../core/state'),store=require('../services/member/store'),entry=require('../services/memberEntry'),qr=require('../services/qrApproval');
const auth=require('../services/deviceAuth'),permissions=require('../services/clientPermissions'),bio=require('../services/clientBiometric'),license=require('../license/licenseManager'),build=require('../services/buildGate'),api=require('../services/member/service'),lifecycle=require('../services/member/oauthLifecycle');
const id='1234567890ABCDEF',key='ANDROID2-1234567890ABCDEF-1234567890ABCDEF',secret='member-entry-real-device-secret',token='B'.repeat(32);
let licenseKey='1111-2222-3333-4444';
const mac=value=>crypto.createHmac('sha256',secret).update(value).digest('hex').toUpperCase();
const socket=()=>({destroyed:false,lines:[],write(x){this.lines.push(x.trim());return true;}});
let c={clientId:id,serverId:'',installationDeviceKey:key,installationToken:token,connected:true,socket:socket(),permissionsGranted:true,permissionSequence:1,deviceAuthVerified:true,deviceAuthChallengeId:'INITIAL',licenseAuthorized:false,licenseKey:'',accessType:'',biometricVerified:false};
state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,secret);
state.licenses.set(licenseKey,{boundClient:id,expiresAt:0,entryPass:true,suspended:false,tags:['QR']});
const account=require('./helpers/member-identity-fixture')(c),caps='DEVICE_HMAC,MEMBER_ENTRY,BIOMETRIC_AUTH,BIOMETRIC_STRONG,QR_DEVICE_APPROVAL';
require('../services/deviceControl').RecordCapabilities('CLIENT',id,caps);
const previousCheck=lifecycle.CheckAccount;lifecycle.CheckAccount=()=>Promise.resolve();
let buildCount=0;const oldDispatch=build.TryDispatchClient;build.TryDispatchClient=()=>{buildCount++;};
function request(){c.socket.lines=[];const nonce=crypto.randomBytes(16).toString('hex').toUpperCase();const result=qr.Resume(c,nonce);return {nonce,result,lines:c.socket.lines};}
function granted(){const r=request();assert.equal(r.result.ok,true,JSON.stringify(r.result));assert.equal(entry.Ready(c),true);assert.equal(api.Allowed(c),true);assert.equal(c.biometricVerified,false);assert.ok(r.lines.some(x=>x.startsWith('MEMBER_ENTRY_OK|')));assert.ok(r.lines.every(x=>!x.startsWith('BIOMETRIC_CHALLENGE|')));return r;}
function deny(mutate,restore){granted();mutate();assert.equal(entry.Ready(c),false);assert.equal(api.Allowed(c),false);assert.equal(c.biometricVerified,false);restore();}
try{
 // Real first-install QR issue -> rendered matrix -> admin inspection/approval.
 state.licenses.delete(licenseKey);
 const initial=request();assert.equal(initial.result.ok,true);assert.equal(c.licenseAuthorized,false);
 const issuedLine=initial.lines.find(x=>x.startsWith('QR_AUTH_CHALLENGE|'));assert.ok(issuedLine);
 const matrix=issuedLine.split('|'),side=Number(matrix[3]),pixels=(side+8)*5,data=new Uint8ClampedArray(pixels*pixels*4);
 for(let y=0;y<pixels;y++)for(let x=0;x<pixels;x++){const col=Math.floor(x/5)-4,row=Math.floor(y/5)-4,black=row>=0&&col>=0&&row<side&&col<side&&matrix[4][row*side+col]==='1',at=(y*pixels+x)*4;data[at]=data[at+1]=data[at+2]=black?0:255;data[at+3]=255;}
 const decoded=require('jsqr')(data,pixels,pixels);assert.ok(decoded);const scanned=qr.InspectPayload(decoded.data);
 const database=require('../storage/database'),saved=database.SaveDatabase;database.SaveDatabase=()=>false;
 try{assert.equal(qr.Approve(scanned.request.requestId,scanned.approvalToken,{},'TEST').reason,'STORAGE_SAVE_FAILED');assert.equal(state.licenses.size,0);assert.equal(c.licenseAuthorized,false);assert.ok(!c.memberEntryGrant);assert.ok(c.socket.lines.every(x=>!x.startsWith('MEMBER_ENTRY_OK|')));}finally{database.SaveDatabase=saved;}
 const approved=qr.Approve(scanned.request.requestId,scanned.approvalToken,{},'TEST');assert.equal(approved.ok,true);assert.equal(approved.delivered,true);licenseKey=c.licenseKey;
 assert.equal(entry.Ready(c),true);assert.equal(c.biometricVerified,false);assert.ok(c.socket.lines.some(x=>x.startsWith('MEMBER_ENTRY_OK|'+c.deviceAuthChallengeId+'|'+initial.nonce+'|')));assert.ok(c.socket.lines.every(x=>!x.startsWith('BIOMETRIC_CHALLENGE|')));
 const first=granted();assert.equal(state.clientBiometricProfiles.has(id),false,'first approved entry does not enroll a fake fingerprint');assert.equal(state.clientBiometricChallenges.has(id),false);assert.equal(buildCount,0,'entry never dispatches a PC Build');
 const fields=first.lines.find(x=>x.startsWith('MEMBER_ENTRY_OK|')).split('|');assert.equal(fields[1],c.deviceAuthChallengeId);assert.equal(fields[2],first.nonce);assert.equal(fields[3],'0');assert.equal(fields[4],mac('MEMBER_ENTRY_OK|'+id+'|'+fields.slice(1,4).join('|')));assert.equal(c.memberEntryRequestId,'');
 assert.ok(api.Execute(c,'ENTRY-HOME-READ','home'),'real member operations work without a phone proof');
 // Duplicated late QR poll does not discard the already consumed grant.
 const count=c.socket.lines.length;assert.equal(entry.Grant(c),true);assert.equal(c.socket.lines.length,count);assert.equal(entry.Ready(c),true);
 c={...c,socket:socket(),deviceAuthVerified:false,permissionsGranted:false,permissionSequence:0,licenseAuthorized:false,licenseKey:'',deviceAuthChallengeId:'',memberEntryGrant:null};state.clients.set(id,c);
 const issued=auth.IssueChallenge('CLIENT',id);assert.equal(issued.ok,true);const challenge=state.deviceAuthChallenges.get(issued.challengeId);assert.equal(entry.Ready(c),false);
 assert.equal(auth.HandleAuth('CLIENT',id,challenge.challengeId,mac('CLIENT|'+id+'|'+challenge.challengeId+'|'+challenge.nonce+'|'+challenge.issuedAt)),true);
 assert.equal(permissions.Handle(c,['CLIENT_PERMISSIONS','1','7',mac('PERMISSIONS|'+id+'|'+challenge.challengeId+'|1|7')]),true);
 const before=buildCount;granted();assert.equal(buildCount,before);assert.equal(state.clientBiometricProfiles.has(id),false,'reconnect still requires no fingerprint enrollment');
 deny(()=>{c.deviceAuthVerified=false;},()=>{c.deviceAuthVerified=true;});
 deny(()=>{c.permissionsGranted=false;},()=>{c.permissionsGranted=true;});
 deny(()=>{c.licenseAuthorized=false;},()=>{c.licenseAuthorized=true;});
 const lic=state.licenses.get(licenseKey);deny(()=>{lic.suspended=true;},()=>{lic.suspended=false;});
 deny(()=>state.disabledClients.add(id),()=>state.disabledClients.delete(id));
 deny(()=>{state.serviceEnabled=false;},()=>{state.serviceEnabled=true;});
 deny(()=>{account.blocked=true;},()=>{account.blocked=false;});
 const link=lifecycle.Record(account),generation=link.generation;deny(()=>{link.generation='OTHER-GENERATION';},()=>{link.generation=generation;});
 deny(()=>{link.status='revoked';},()=>{link.status='active';});
 deny(()=>{c.deviceAuthChallengeId='NEW-HANDSHAKE';},()=>{c.deviceAuthChallengeId=challenge.challengeId;});
 deny(()=>state.deviceSecrets.set('CLIENT:'+id,'rotated'),()=>state.deviceSecrets.set('CLIENT:'+id,secret));
 // A copied grant on another socket/installation cannot authorize it.
 granted();const clone={...c,socket:socket()};assert.equal(entry.Ready(clone),false);
 // An explicit PC preparation still receives a genuine phone challenge.
 granted();c.socket.lines=[];assert.equal(license.AuthorizeBoundClientByQr(c,'PURCHASE'),true);assert.equal(entry.Ready(c),true);assert.equal(c.biometricVerified,false);assert.ok(c.socket.lines.some(x=>x.startsWith('BIOMETRIC_CHALLENGE|')));assert.equal(buildCount,before);
 assert.throws(()=>api.Execute(c,'ENTRY-FAKE-START','order.start',{orderId:'not-prepared'}),/ORDER_NOT_FOUND/);
 const proof=state.clientBiometricChallenges.get(id);assert.ok(proof);assert.equal(bio.HandleProof(c,['BIOMETRIC_PROOF',proof.mode,proof.nonce,'0'.repeat(64)]),false);assert.equal(c.biometricVerified,false,'invalid proof cannot grant PC authority');
 // Explicit unlink revokes the ordinary grant and request nonce immediately.
 c.memberEntryRequestId='A'.repeat(32);lifecycle.RevokeAccount(account.id,'IDENTITY_LOGOUT','TEST');assert.equal(c.memberEntryGrant,null);assert.equal(c.memberEntryRequestId,'');assert.equal(api.Allowed(c),false);assert.equal(entry.Grant(c),false);
 console.log('MEMBER ENTRY '+process.env.STORAGE_ENGINE+' PASS: fresh and resumed QR-approved OAuth/device members enter without fingerprint; signed nonce grant; no fake proof/PC dispatch; replay, new socket, rotated key, permission/license/account/logout revocations denied; PC linking retains actual biometric challenge.');
}finally{build.TryDispatchClient=oldDispatch;lifecycle.CheckAccount=previousCheck;lifecycle.StopMonitor();fs.rmSync(temp,{recursive:true,force:true});}
