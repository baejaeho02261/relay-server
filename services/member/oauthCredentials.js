'use strict';
// Only encrypted provider credentials enter member storage. This key is never
// derived from an OAuth client secret and must be supplied identically to HA nodes.
const crypto=require('node:crypto');
function Key(){
 const raw=String(process.env.MEMBER_OAUTH_TOKEN_KEY||'').trim();
 if(/^[0-9a-f]{64}$/i.test(raw))return Buffer.from(raw,'hex');
 if(/^[A-Za-z0-9+/]{43}=$/.test(raw)){const key=Buffer.from(raw,'base64');if(key.length===32)return key;}
 return null;
}
function Seal(value,binding){
 const key=Key();if(!key)throw Error('IDENTITY_NOT_CONFIGURED');
 const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(binding));
 const data=Buffer.concat([cipher.update(JSON.stringify(value),'utf8'),cipher.final()]);
 return ['v1',iv.toString('base64url'),cipher.getAuthTag().toString('base64url'),data.toString('base64url')].join('.');
}
function Open(value,binding){
 const key=Key();if(!key)throw Error('IDENTITY_NOT_CONFIGURED');
 const parts=String(value||'').split('.');if(parts.length!==4||parts[0]!=='v1'||parts.slice(1).some(x=>!/^[A-Za-z0-9_-]+$/.test(x)))throw Error('IDENTITY_CREDENTIALS_UNAVAILABLE');
 const iv=Buffer.from(parts[1],'base64url'),tag=Buffer.from(parts[2],'base64url');if(iv.length!==12||tag.length!==16)throw Error('IDENTITY_CREDENTIALS_UNAVAILABLE');
 const decipher=crypto.createDecipheriv('aes-256-gcm',key,iv);decipher.setAAD(Buffer.from(binding));decipher.setAuthTag(tag);
 return JSON.parse(Buffer.concat([decipher.update(Buffer.from(parts[3],'base64url')),decipher.final()]).toString('utf8'));
}
function Normalize(result,previous={}){
 const now=Date.now(),token=value=>typeof value==='string'&&value.length>0&&value.length<=16000&&!/[\r\n]/.test(value);
 if(!token(result.access_token)||!Number.isFinite(Number(result.expires_in))||Number(result.expires_in)<=0)throw Error('IDENTITY_PROVIDER_INVALID_RESPONSE');
 const refresh=result.refresh_token===undefined?previous.refreshToken:result.refresh_token;
 if(!token(refresh))throw Error('IDENTITY_REAUTH_REQUIRED');
 return {accessToken:result.access_token,refreshToken:refresh,expiresAt:now+Math.min(Number(result.expires_in),86400)*1000,refreshExpiresAt:result.refresh_token_expires_in?now+Number(result.refresh_token_expires_in)*1000:previous.refreshExpiresAt||0};
}
module.exports={Key,Seal,Open,Normalize};
