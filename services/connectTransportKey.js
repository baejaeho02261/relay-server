'use strict';
// The administrator distributes this server's public pin. Clients never learn
// or replace a trusted key from an unauthenticated connection (no TOFU).
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const config=require('../config/config');
const KEY_FILE=path.join(config.DATA_DIR,'connect-transport-key.pem'),ID_FILE=path.join(config.DATA_DIR,'connect-transport-key.id');
let cached;
function PublicBlob(publicKey){
 const jwk=publicKey.export({format:'jwk'}),exponent=Buffer.from(jwk.e,'base64url'),modulus=Buffer.from(jwk.n,'base64url'),header=Buffer.alloc(24);
 if(jwk.kty!=='RSA'||modulus.length!==256)throw Error('CONNECT_SERVER_KEY_INVALID');
 [0x31415352,2048,exponent.length,modulus.length,0,0].forEach((value,index)=>header.writeUInt32LE(value,index*4));return Buffer.concat([header,exponent,modulus]);
}
function SyncDirectory(){if(process.platform==='win32')return;const fd=fs.openSync(config.DATA_DIR,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Publish(file,value){
 fs.mkdirSync(config.DATA_DIR,{recursive:true,mode:0o700});const temporary=file+'.'+crypto.randomBytes(12).toString('hex')+'.tmp';
 let fd;try{fd=fs.openSync(temporary,'wx',0o600);fs.writeFileSync(fd,value);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
  // link is an exclusive publication: never overwrite an existing identity.
  fs.linkSync(temporary,file);SyncDirectory();
 }finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temporary);}catch(_){}}
}
function Load(){
 if(cached)return cached;
 const hasKey=fs.existsSync(KEY_FILE),hasId=fs.existsSync(ID_FILE);
 if(!hasKey&&hasId)throw Error('CONNECT_SERVER_KEY_MISSING');
 if(!hasKey){const {privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});try{Publish(KEY_FILE,privateKey.export({format:'pem',type:'pkcs8'}));}catch(error){if(error.code!=='EEXIST')throw error;}}
 const stat=fs.lstatSync(KEY_FILE);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>8192)throw Error('CONNECT_SERVER_KEY_INVALID');
 let privateKey;try{privateKey=crypto.createPrivateKey(fs.readFileSync(KEY_FILE));}catch(_){throw Error('CONNECT_SERVER_KEY_INVALID');}
 if(privateKey.asymmetricKeyType!=='rsa'||privateKey.asymmetricKeyDetails?.modulusLength!==2048)throw Error('CONNECT_SERVER_KEY_INVALID');
 if(process.platform!=='win32')fs.chmodSync(KEY_FILE,0o600);
 const publicKey=crypto.createPublicKey(privateKey);require('./desktopKeyPurposes').Reserve(publicKey,'SERVER_TRANSPORT');const blob=PublicBlob(publicKey),keyId=crypto.createHash('sha256').update(blob).digest('hex');
 if(fs.existsSync(ID_FILE)){const marker=fs.lstatSync(ID_FILE);if(!marker.isFile()||marker.isSymbolicLink()||marker.size!==65||fs.readFileSync(ID_FILE,'utf8')!==keyId+'\n')throw Error('CONNECT_SERVER_KEY_CHANGED');}
 else try{Publish(ID_FILE,keyId+'\n');}catch(error){if(error.code!=='EEXIST'||fs.readFileSync(ID_FILE,'utf8')!==keyId+'\n')throw error;}
 cached={privateKey,publicKey,keyId,serverPublicKey:blob.toString('base64')};return cached;
}
function Profile(){
 const {host,port,ready}=require('./connectEndpoint').Resolve();
 if(!ready)require('./desktopLicenses').Fail('CONNECT_PUBLIC_ENDPOINT_REQUIRED',503);
 const identity=Load();return {version:4,protocol:'GAME-CONNECT-4',host,port,serverKeyId:identity.keyId,serverPublicKey:identity.serverPublicKey,...require('./connectTls').Public()};
}
module.exports={Load,Profile,PublicBlob,KEY_FILE,ID_FILE};
