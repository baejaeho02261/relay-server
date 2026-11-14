'use strict';
// Server-console enrollment approval ONLY. No password-to-step-up fallback and
// no remotely supplied policy/identity. Tokens are consumed before a CREATE
// challenge; the finish grant is process-local, session-bound and one-use.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const deadline=require("../runtime/peace.desktop-deadline");
const pending=new WeakMap(),TTL=300000;
const PREFIX='/api/production/passkeys/register/';
const error=reason=>({ok:false,status:428,reason});
function Directory(){return path.join(require("../../config/peace.runtime-configuration").DATA_DIR,'.admin-enrollment');}
function SessionId(id){return typeof id==='string'&&/^[A-F0-9]{16}$/.test(id);}
function DirectorySafe(create=false){
 const root=Directory();if(create)fs.mkdirSync(root,{recursive:true,mode:0o700});
 const info=fs.lstatSync(root);if(!info.isDirectory()||info.isSymbolicLink())throw Error('ADMIN_ENROLLMENT_DIRECTORY_INVALID');
 return root;
}
function Cleanup(root){
 // Only our bounded, expired permit records. Never delete arbitrary server data.
 const names=fs.readdirSync(root);if(names.length>4096)throw Error('ADMIN_ENROLLMENT_CAPACITY');
 for(const name of names){if(!/^[a-f0-9]{64}\.json$/.test(name))continue;
  const file=path.join(root,name),info=fs.lstatSync(file);if(!info.isFile()||info.isSymbolicLink()||info.size>2048)continue;
  try{const row=require("../protocol/peace.strict-json").Parse(fs.readFileSync(file),{maxBytes:2048});
   if(row.version===1&&row.purpose==='PASSKEY_ENROLLMENT_ONLY'&&Number.isSafeInteger(row.expiresAt)&&row.expiresAt<=Date.now())fs.unlinkSync(file);
  }catch(_){/* malformed entries cannot authorize; leave for operator inspection */}
 }
}
function HasPending(session){const p=pending.get(session);return !!p&&p.phase==='FINISH'&&!deadline.Expired(p);}
function Consume(token,sessionId){
 if(typeof token!=='string'||!/^[a-f0-9]{64}$/.test(token)||!SessionId(sessionId))return false;
 const digest=crypto.createHash('sha256').update(token).digest('hex');let claimed,fd;
 try{
  const root=DirectorySafe(),file=path.join(root,digest+'.json');
  const before=fs.lstatSync(file);if(!before.isFile()||before.isSymbolicLink()||before.size>2048)return false;
  // Atomic rename prevents two requests/processes consuming the same permit.
  claimed=path.join(root,digest+'.used-'+crypto.randomBytes(8).toString('hex'));
  fs.renameSync(file,claimed);
  fd=fs.openSync(claimed,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size>2048||stat.dev!==before.dev||stat.ino!==before.ino)return false;
  const data=fs.readFileSync(fd);if(data.length!==stat.size)return false;
  const value=require("../protocol/peace.strict-json").Parse(data,{maxBytes:2048});const at=Date.now();
  return value&&Object.keys(value).sort().join(',')==='expiresAt,issuedAt,purpose,sessionId,tokenHash,version'&&
   value.version===1&&value.purpose==='PASSKEY_ENROLLMENT_ONLY'&&value.sessionId===sessionId&&value.tokenHash===digest&&
   Number.isSafeInteger(value.issuedAt)&&Number.isSafeInteger(value.expiresAt)&&value.expiresAt-value.issuedAt===TTL&&at>=value.issuedAt&&at<value.expiresAt;
 }catch(_){return false;}finally{if(fd!==undefined)fs.closeSync(fd);if(claimed)try{fs.unlinkSync(claimed);}catch(_){/* consumed names can never authorize */}}
}
function Authorize(session,method,pathname,body,token){
 const web=require("../../web/authentication/peace.web-auth");
 if(method!=='POST'||!session||session.role!=='admin'||!web.IsSessionActive(session))return error('ADMIN_SESSION_EXPIRED');
 if(pathname===PREFIX+'begin'){
  pending.delete(session);
  if(!body||Object.keys(body).length!==0||!Consume(token,session.id))return error('ADMIN_ENROLLMENT_APPROVAL_REQUIRED');
  pending.set(session,{sessionId:session.id,phase:'BEGIN',...deadline.After(TTL)});
  return {ok:true,mode:'SERVER_APPROVED_ENROLLMENT_ONLY'};
 }
 if(pathname===PREFIX+'finish'){
  const grant=pending.get(session);pending.delete(session);
  if(!grant||grant.phase!=='FINISH'||grant.sessionId!==session.id||deadline.Expired(grant)||body?.challengeId!==grant.challengeId)return error('ADMIN_ENROLLMENT_APPROVAL_REQUIRED');
  return {ok:true,mode:'SERVER_APPROVED_ENROLLMENT_ONLY'};
 }
 return error('ADMIN_PASSKEY_REQUIRED');
}
function Bind(session,result){
 const grant=pending.get(session);if(!grant)return;
 if(grant.phase!=='BEGIN'||!result?.ok||typeof result.challengeId!=='string'||deadline.Expired(grant)){pending.delete(session);return;}
 grant.challengeId=result.challengeId;grant.phase='FINISH';
}
// Operator-only CLI uses the same bounded format. Never imported by a route.
function Issue(sessionId){
 if(!SessionId(sessionId))throw Error('ADMIN_ENROLLMENT_SESSION_ID_INVALID');
 const root=DirectorySafe(true);Cleanup(root);const token=crypto.randomBytes(32).toString('hex'),tokenHash=crypto.createHash('sha256').update(token).digest('hex'),issuedAt=Date.now();
 fs.writeFileSync(path.join(root,tokenHash+'.json'),JSON.stringify({version:1,purpose:'PASSKEY_ENROLLMENT_ONLY',sessionId,tokenHash,issuedAt,expiresAt:issuedAt+TTL}),{flag:'wx',mode:0o600});
 return {token,sessionId,expiresAt:issuedAt+TTL};
}
module.exports={Authorize,Bind,Issue,HasPending};
