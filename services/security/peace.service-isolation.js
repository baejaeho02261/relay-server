"use strict";
// Deployment guard, not a replacement for kernel ACLs/namespaces. Strict mode
// checks the identity and the configured boundary from the actual process.
const fs=require('node:fs'),path=require('node:path');
const ROLES=['authority','gateway','packer','witness','release-signer'];
const SIGNING=['GAME_RELEASE_APPROVAL_KEY_B64','GAME_RELEASE_APPROVAL_KEY_FILE'];
const CLOUD=['RAILWAY_TOKEN','RAILWAY_API_TOKEN','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','GOOGLE_APPLICATION_CREDENTIALS','GITHUB_TOKEN','GH_TOKEN','DOCKER_AUTH_CONFIG'];
const ADMIN=['ADMIN_SECRET','OPERATOR_SECRET','VIEWER_SECRET','QR_APPROVAL_SECRET','MEMBER_OAUTH_TOKEN_KEY','GOOGLE_OAUTH_CLIENT_SECRET','KAKAO_OAUTH_CLIENT_SECRET'];
function Fail(code){throw Error(code);}
function List(env,key){let rows;try{rows=JSON.parse(env[key]||'[]');}catch(_){Fail('ISOLATION_PATH_CONFIG_INVALID');}if(!Array.isArray(rows)||rows.length>32||rows.some(p=>typeof p!=='string'||!path.isAbsolute(p)))Fail('ISOLATION_PATH_CONFIG_INVALID');return rows;}
function ChildEnvironment(env=process.env){
 // No inherited cloud tokens, admin secrets, server DB/witness configuration,
 // NODE_OPTIONS or arbitrary shell startup hooks in an untrusted tool process.
 const out={};for(const k of ['PATH','SystemRoot','WINDIR','TEMP','TMP','TMPDIR','LANG','LC_ALL','TZ'])if(env[k])out[k]=env[k];return out;
}
function Check(role,env=process.env){
 if(!ROLES.includes(role))Fail('ISOLATION_ROLE_INVALID');
 const blocked=role==='authority'?SIGNING:role==='release-signer'?[...ADMIN,...CLOUD,'DATA_DIR','DESKTOP_RECOVERY_WITNESS_URL',...SIGNING]:[...ADMIN,...CLOUD,...SIGNING,'DATA_DIR','DESKTOP_RECOVERY_WITNESS_URL','DESKTOP_RECOVERY_WITNESS_DIR'];
 if(blocked.some(k=>env[k]))Fail('ISOLATION_SECRET_SCOPE_VIOLATION');
 if(env.GAME_SERVICE_ROLE&&env.GAME_SERVICE_ROLE!==role)Fail('ISOLATION_ROLE_MISMATCH');
 const strict=env.GAME_ISOLATION_REQUIRED==='1';
 if(!strict)return {role,status:'NOT_ENFORCED',strict:false,actualHostIsolationVerified:false};
 if(env.GAME_SERVICE_ROLE!==role)Fail('ISOLATION_ROLE_REQUIRED');
 if(process.platform!=='linux')Fail('ISOLATION_PLATFORM_REQUIRES_EXTERNAL_ACL_REVIEW');
 if(!/^\d{1,10}$/.test(env.GAME_SERVICE_UID||'')||Number(env.GAME_SERVICE_UID)===0||process.getuid()!==Number(env.GAME_SERVICE_UID))Fail('ISOLATION_UID_MISMATCH');
 const status=fs.readFileSync('/proc/self/status','utf8');
 if(!/^NoNewPrivs:\s+1$/m.test(status)||!/^CapEff:\s+0+$/m.test(status))Fail('ISOLATION_PROCESS_PRIVILEGES');
 const readonly=List(env,'GAME_READONLY_PATHS_JSON'),forbidden=List(env,'GAME_FORBIDDEN_PATHS_JSON'),writable=List(env,'GAME_WRITABLE_PATHS_JSON');
 if(!readonly.length||!forbidden.length)Fail('ISOLATION_PATHS_REQUIRED');
 const findings=[];
 for(const p of readonly){fs.accessSync(p,fs.constants.R_OK);try{fs.accessSync(p,fs.constants.W_OK);Fail('ISOLATION_READONLY_PATH_WRITABLE');}catch(e){if(!['EACCES','EROFS','EPERM'].includes(e.code))throw e;}findings.push({path:p,access:'READ_ONLY'});}
 for(const p of forbidden){try{fs.accessSync(p,fs.constants.R_OK);Fail('ISOLATION_FORBIDDEN_PATH_READABLE');}catch(e){if(!['ENOENT','EACCES','EPERM'].includes(e.code))throw e;findings.push({path:p,access:e.code==='ENOENT'?'NOT_MOUNTED':'DENIED'});}}
 for(const p of writable){const s=fs.lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)Fail('ISOLATION_WRITABLE_DIRECTORY_UNSAFE');fs.accessSync(p,fs.constants.W_OK);findings.push({path:p,access:'PRIVATE_WRITABLE'});}
 const actualData=role==='authority'?env.DATA_DIR:role==='witness'?env.WITNESS_DATA_DIR:null;
 if(actualData&&(!path.isAbsolute(actualData)||!writable.includes(actualData)))Fail('ISOLATION_PRIMARY_STORAGE_NOT_CHECKED');
 if(role==='gateway'&&writable.length)Fail('ISOLATION_GATEWAY_PERSISTENT_STORAGE_FORBIDDEN');
 if(role==='authority'){
  if(env.WEB_ADMIN_TRANSPORT!=='direct'||env.WEB_ADMIN_GATEWAY!=='1'||!env.WEB_ADMIN_CLIENT_CA_FILE||!env.WEB_ADMIN_CLIENT_SPKI_SHA512)Fail('ISOLATION_PRIVATE_GATEWAY_REQUIRED');
  if(!env.DESKTOP_RECOVERY_WITNESS_URL||env.DESKTOP_RECOVERY_WITNESS_REQUIRED!=='1'||env.DESKTOP_RECOVERY_WITNESS_DIR)Fail('ISOLATION_REMOTE_WITNESS_REQUIRED');
 }
 return {role,status:'PROCESS_CHECKS_PASSED',strict:true,uid:process.getuid(),findings,actualHostIsolationVerified:false,note:'Process checks do not prove hypervisor, network firewall or independent backup administration.'};
}
module.exports={Check,ChildEnvironment,ROLES};
