'use strict';

const crypto=require('crypto');
const state=require('../core/state');
const {Now,SafeField}=require('../core/utils');
const deadline=require('./desktopDeadline');
const CHALLENGE_MS=5*60000, MAX_CHALLENGES=4096;
const challenges=new Map();
const B64=b=>Buffer.from(b).toString('base64url');
function Buf(value,max=8192,min=1){
 if(typeof value!=='string'||!value||value.length>Math.ceil(max*4/3)||!/^[A-Za-z0-9_-]+$/.test(value))throw Error('PASSKEY_BINARY_INVALID');
 const bytes=Buffer.from(value,'base64url');
 if(bytes.length<min||bytes.length>max||bytes.toString('base64url')!==value)throw Error('PASSKEY_BINARY_INVALID');
 return bytes;
}
function Body(value,fields){return !!value&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).every(k=>fields.includes(k));}

function Context(req){
    const host=String(req.headers.host||'').split(':')[0].toLowerCase();
    const rpId=String(process.env.WEBAUTHN_RP_ID||host).trim().toLowerCase();
    const proto=require('../web/webAuth').IsHttps(req)?'https':'http';
    const origin=String(process.env.WEBAUTHN_ORIGIN||`${proto}://${req.headers.host||host}`).replace(/\/$/,'');
    return{rpId,origin};
}
function ChallengeActive(item){return !!item&&!deadline.Expired(item)&&Now()>=item.createdAt;}
function NewChallenge(kind,role,sessionId,req){
 Cleanup();if(challenges.size>=MAX_CHALLENGES)return null;
 const ctx=Context(req),id=`PKC-${crypto.randomBytes(10).toString('hex').toUpperCase()}`,challenge=B64(crypto.randomBytes(32)),bounds=deadline.After(CHALLENGE_MS);
 const item={id,kind,role,sessionId:sessionId||'',challenge,...ctx,createdAt:bounds.expiresAt-CHALLENGE_MS,...bounds};challenges.set(id,item);return item;
}
function SaveCredentials(){if(require('../storage/database').SaveDatabase()===false)throw Error('PASSKEY_STORAGE_UNAVAILABLE');}
function CheckClientData(item,value,type){return require('./passkeyClientData').Check(item,value,type);}
function CheckAuthData(item,value,requireUv=true){const b=Buf(value);if(b.length<37)throw new Error('PASSKEY_AUTH_DATA_INVALID');const rpHash=crypto.createHash('sha256').update(item.rpId).digest();if(!crypto.timingSafeEqual(b.subarray(0,32),rpHash))throw new Error('PASSKEY_RP_INVALID');const flags=b[32];if(!(flags&1)||(requireUv&&!(flags&4)))throw new Error('PASSKEY_USER_VERIFICATION_REQUIRED');return{buffer:b,flags,signCount:b.readUInt32BE(33)};}
function CredentialsForRole(role){return Array.from(state.production.passkeyCredentials.values()).filter(x=>x.role===role&&!x.revokedAt);}
function RegistrationBegin(session,req){if(!session||session.role!=='admin')return{ok:false,reason:'ADMIN_REQUIRED'};const item=NewChallenge('CREATE','admin',session.id,req);if(!item)return{ok:false,status:503,reason:'PASSKEY_CAPACITY'};return{ok:true,challengeId:item.id,publicKey:{challenge:item.challenge,rp:{name:'Relay Operations',id:item.rpId},user:{id:B64(Buffer.from(`admin:${session.id}`)),name:'relay-admin',displayName:'Relay Administrator'},pubKeyCredParams:[{type:'public-key',alg:-7}],timeout:300000,attestation:'none',authenticatorSelection:{residentKey:'preferred',userVerification:'required'}}};}
function RegistrationFinish(session,req,body){if(!Body(body,['challengeId','clientDataJSON','authenticatorData','publicKeySpki','credentialId','name']))return{ok:false,reason:'PASSKEY_INPUT_INVALID'};const item=challenges.get(String(body.challengeId||''));if(!ChallengeActive(item)||item.kind!=='CREATE'||!session||session.role!=='admin'||item.sessionId!==session.id)return{ok:false,reason:'PASSKEY_CHALLENGE_INVALID'};try{CheckClientData(item,body.clientDataJSON,'webauthn.create');const auth=CheckAuthData(item,body.authenticatorData,true);const publicKey=Buf(body.publicKeySpki,1024);const parsed=crypto.createPublicKey({key:publicKey,type:'spki',format:'der'});if(parsed.asymmetricKeyType!=='ec'||parsed.asymmetricKeyDetails?.namedCurve!=='prime256v1')throw new Error('PASSKEY_KEY_TYPE_INVALID');const credentialId=String(body.credentialId||'');if(!credentialId||Buf(credentialId,1024,16).length<16)throw new Error('PASSKEY_CREDENTIAL_INVALID');const id=crypto.createHash('sha256').update(Buf(credentialId)).digest('hex').slice(0,24).toUpperCase();if(state.production.passkeyCredentials.has(id))throw new Error('PASSKEY_ALREADY_REGISTERED');const record={id,role:'admin',credentialId,publicKeySpki:B64(publicKey),rpId:item.rpId,name:SafeField(body.name||`Admin key ${id.slice(-6)}`).slice(0,64),createdAt:Now(),lastUsedAt:0,signCount:auth.signCount,revokedAt:0};if(!ChallengeActive(item))throw Error('PASSKEY_CHALLENGE_INVALID');challenges.delete(item.id);state.production.passkeyCredentials.set(id,record);try{SaveCredentials();}catch(error){state.production.passkeyCredentials.delete(id);throw error;}require('../storage/audit').LogEvent('PASSKEY_REGISTERED',`${id} / admin`);return{ok:true,credential:{...record,publicKeySpki:undefined}};}catch(error){return{ok:false,reason:error.message||'PASSKEY_REGISTRATION_FAILED'};}}
function LoginBegin(role,req){role=String(role||'').toLowerCase();const creds=CredentialsForRole(role);if(!creds.length)return{ok:false,reason:'PASSKEY_NOT_REGISTERED'};const item=NewChallenge('GET',role,'',req);if(!item)return{ok:false,status:503,reason:'PASSKEY_CAPACITY'};return{ok:true,challengeId:item.id,publicKey:{challenge:item.challenge,rpId:item.rpId,allowCredentials:creds.map(x=>({type:'public-key',id:x.credentialId})),timeout:300000,userVerification:'required'}};}
function LoginFinish(req,body){if(!Body(body,['challengeId','credentialId','clientDataJSON','authenticatorData','signature']))return{ok:false,reason:'PASSKEY_INPUT_INVALID'};const item=challenges.get(String(body.challengeId||''));if(!ChallengeActive(item)||item.kind!=='GET')return{ok:false,reason:'PASSKEY_CHALLENGE_INVALID'};const cred=CredentialsForRole(item.role).find(x=>x.credentialId===String(body.credentialId||''));if(!cred)return{ok:false,reason:'PASSKEY_CREDENTIAL_NOT_FOUND'};try{const clientData=CheckClientData(item,body.clientDataJSON,'webauthn.get');const auth=CheckAuthData(item,body.authenticatorData,true);const signed=Buffer.concat([auth.buffer,crypto.createHash('sha256').update(clientData.bytes).digest()]);const key=crypto.createPublicKey({key:Buf(cred.publicKeySpki,1024),type:'spki',format:'der'});if(!crypto.verify('sha256',signed,key,Buf(body.signature,144,8)))throw new Error('PASSKEY_SIGNATURE_INVALID');// A credential that always reports zero is valid. Once a positive counter
// is observed, zero must not reset the existing rollback/replay protection.
if((cred.signCount||auth.signCount)&&auth.signCount<=cred.signCount)throw new Error('PASSKEY_COUNTER_REPLAY');
if(!ChallengeActive(item))throw Error('PASSKEY_CHALLENGE_INVALID');
if(!Array.from(state.production.passkeyCredentials.values()).includes(cred)||cred.revokedAt)throw Error('PASSKEY_CREDENTIAL_NOT_FOUND');
const previous={signCount:cred.signCount,lastUsedAt:cred.lastUsedAt};cred.signCount=auth.signCount;cred.lastUsedAt=Now();challenges.delete(item.id);try{SaveCredentials();}catch(error){Object.assign(cred,previous);throw error;}require('../storage/audit').LogEvent('PASSKEY_AUTH',`${cred.id} / ${item.role}`);return{ok:true,role:item.role,credentialId:cred.id};}catch(error){return{ok:false,reason:error.message||'PASSKEY_AUTH_FAILED'};}}
function List(){return Array.from(state.production.passkeyCredentials.values()).map(x=>({id:x.id,role:x.role,name:x.name,createdAt:x.createdAt,lastUsedAt:x.lastUsedAt,signCount:x.signCount,revokedAt:x.revokedAt||0}));}
function Revoke(id,actor){const item=state.production.passkeyCredentials.get(String(id||'').toUpperCase());if(!item)return{ok:false,reason:'PASSKEY_NOT_FOUND'};const previous={...item};item.revokedAt=Now();item.revokedBy=SafeField(actor).slice(0,64);try{SaveCredentials();}catch(error){for(const key of Object.keys(item))if(!Object.hasOwn(previous,key))delete item[key];Object.assign(item,previous);return{ok:false,reason:error.message};}return{ok:true};}
function Cleanup(){for(const [k,v]of challenges)if(!ChallengeActive(v))challenges.delete(k);}
module.exports={RegistrationBegin,RegistrationFinish,LoginBegin,LoginFinish,List,Revoke,Cleanup};
