'use strict';
// Validate exactly the signed bytes. Never parse then reserialize before hashing.
// Unknown non-security members are permitted for WebAuthn forward compatibility;
// cross-origin assertions are not enabled for this single-origin admin console.
const {Parse}=require("../protocol/peace.strict-json");
const MAX_BYTES=8192;
function Decode(value){
 if(typeof value!=='string'||!value||value.length>Math.ceil(MAX_BYTES*4/3)||!/^[A-Za-z0-9_-]+$/.test(value))throw Error('PASSKEY_CLIENT_DATA_INVALID');
 const bytes=Buffer.from(value,'base64url');
 if(!bytes.length||bytes.length>MAX_BYTES||bytes.toString('base64url')!==value)throw Error('PASSKEY_CLIENT_DATA_INVALID');
 return bytes;
}
function Check(item,value,type){
 let data;const bytes=Decode(value);
 try{data=Parse(bytes,{maxBytes:MAX_BYTES,maxNodes:256,maxDepth:8});}
 catch(_){throw Error('PASSKEY_CLIENT_DATA_INVALID');}
 if(!data||typeof data!=='object'||Array.isArray(data)||Object.getPrototypeOf(data)!==Object.prototype)throw Error('PASSKEY_CLIENT_DATA_INVALID');
 if(typeof data.type!=='string'||typeof data.challenge!=='string'||typeof data.origin!=='string'||
    data.type!==type||data.challenge!==item.challenge||data.origin!==item.origin)throw Error('PASSKEY_CHALLENGE_INVALID');
 if(Object.hasOwn(data,'crossOrigin')&&data.crossOrigin!==false||Object.hasOwn(data,'topOrigin'))throw Error('PASSKEY_CROSS_ORIGIN_FORBIDDEN');
 if(Object.hasOwn(data,'tokenBinding')){
  const t=data.tokenBinding;
  if(!t||typeof t!=='object'||Array.isArray(t)||!['supported','present'].includes(t.status)||Object.keys(t).some(k=>!['status','id'].includes(k))||
     t.status==='present'&&(typeof t.id!=='string'||!t.id)||t.status==='supported'&&Object.hasOwn(t,'id'))throw Error('PASSKEY_CLIENT_DATA_INVALID');
  // This deployment never negotiates Token Binding. Do not silently ignore an
  // asserted security binding that this server cannot verify.
  if(t.status==='present')throw Error('PASSKEY_TOKEN_BINDING_UNSUPPORTED');
 }
 return {data,bytes};
}
module.exports={Check,Decode,MAX_BYTES};
