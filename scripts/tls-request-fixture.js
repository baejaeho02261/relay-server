'use strict';
// Test client for the production native wire, never used by the server.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),tls=require('node:tls');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
async function Request(profile,operation,body){
 const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12),requestId=crypto.randomUUID();
 const aad=direction=>Buffer.from(['GAME-CONNECT-3',direction,requestId,profile.serverKeyId].join('\n'));
 try{
  const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(aad('REQUEST'));
  const clear=Buffer.from(JSON.stringify({operation,body}));let ciphertext;
  try{ciphertext=Buffer.concat([cipher.update(clear),cipher.final()]);}finally{clear.fill(0);}
  const frame={v:1,keyId:profile.serverKeyId,requestId,wrappedKey:crypto.publicEncrypt({key:require('../services/desktopLicenses').ParseKey(profile.serverPublicKey).key,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key).toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
  const bytes=await new Promise((resolve,reject)=>{
   const socket=tls.connect({host:profile.host,port:profile.port,servername:profile.tlsServerName,minVersion:'TLSv1.2',maxVersion:'TLSv1.2',rejectUnauthorized:false});
   let total=0;const chunks=[];const timer=setTimeout(()=>socket.destroy(Error('TEST_TLS_TIMEOUT')),10000);
   socket.once('secureConnect',()=>{
    const cert=socket.getPeerCertificate(),at=Date.now();
    if(!cert.raw||sha(cert.raw)!==profile.tlsCertificateSha256||tls.checkServerIdentity(profile.tlsServerName,cert)||at<Date.parse(cert.valid_from)||at>Date.parse(cert.valid_to))return socket.destroy(Error('TEST_TLS_PIN'));
    // CA validation is replaced by the out-of-band exact certificate pin.
    socket.write(JSON.stringify(frame)+'\n');
   });
   socket.on('data',chunk=>{total+=chunk.length;if(total>786432)return socket.destroy(Error('TEST_TLS_SIZE'));chunks.push(chunk);});
   socket.once('error',reject);socket.once('close',()=>{clearTimeout(timer);resolve(Buffer.concat(chunks));});
  });
  const response=JSON.parse(bytes.toString('utf8'));assert.equal(response.v,1);assert.equal(response.requestId,requestId);assert.notEqual(response.nonce,frame.nonce);
  const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(response.nonce,'base64'));decipher.setAAD(aad('RESPONSE'));decipher.setAuthTag(Buffer.from(response.tag,'base64'));
  const opened=Buffer.concat([decipher.update(Buffer.from(response.ciphertext,'base64')),decipher.final()]);
  try{return JSON.parse(opened.toString('utf8'));}finally{opened.fill(0);}
 }finally{key.fill(0);}
}
module.exports={Request};
