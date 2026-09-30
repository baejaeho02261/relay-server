'use strict';
// Native traffic always uses TLS. The issued launcher contains an exact leaf
// certificate SHA-256 pin; clients never trust a certificate learned on first use.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),tls=require('node:tls'),{execFileSync}=require('node:child_process');
const config=require('../config/config');
const DIR=path.join(config.DATA_DIR,'connect-tls'),MARKER=path.join(config.DATA_DIR,'connect-tls.sha256');
const CIPHERS='TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
let cached;
function Fail(code){const error=Error(code);error.desktopError=true;error.status=503;throw error;}
function Sync(directory){if(process.platform==='win32')return;const fd=fs.openSync(directory,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Write(file,data){const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,data);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Read(file,max){let stat;try{stat=fs.lstatSync(file);}catch(_){Fail('CONNECT_TLS_IDENTITY_MISSING');}if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>max)Fail('CONNECT_TLS_IDENTITY_INVALID');return fs.readFileSync(file);}
function ServerName(){const name=String(process.env.CONNECT_TLS_SERVER_NAME||'game-connect.internal').trim().toLowerCase();if(name.length>253||!name.split('.').every(part=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))||/^[\d.]+$/.test(name))Fail('CONNECT_TLS_NAME_INVALID');return name;}
function Generate(serverName){
 fs.mkdirSync(config.DATA_DIR,{recursive:true,mode:0o700});
 if(fs.existsSync(MARKER))Fail('CONNECT_TLS_IDENTITY_MISSING');
 const temporary=fs.mkdtempSync(path.join(config.DATA_DIR,'.connect-tls-'));fs.chmodSync(temporary,0o700);
 try{
  const key=path.join(temporary,'private-key.pem'),cert=path.join(temporary,'certificate.pem');
  // OpenSSL is supplied by the checked-in container. There is no shell expansion
  // and no downloaded key material, package, or custom certificate implementation.
  try{execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-sha256','-nodes','-keyout',key,'-out',cert,'-days','825','-subj','/CN=GameConnect TLS','-addext','subjectAltName=DNS:'+serverName,'-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-addext','extendedKeyUsage=serverAuth'],{stdio:'ignore',timeout:30000});}catch(_){Fail('CONNECT_TLS_OPENSSL_REQUIRED');}
  for(const file of [key,cert]){fs.chmodSync(file,0o600);const fd=fs.openSync(file,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
  Sync(temporary);fs.renameSync(temporary,DIR);Sync(config.DATA_DIR);
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
}
function Load(){
 if(cached){if(Date.now()<cached.validFrom||Date.now()>=cached.expiresAt)Fail('CONNECT_TLS_CERTIFICATE_EXPIRED');return cached;}
 const serverName=ServerName(),certSetting=String(process.env.CONNECT_TLS_CERT_FILE||'').trim(),keySetting=String(process.env.CONNECT_TLS_KEY_FILE||'').trim();
 if(!!certSetting!==!!keySetting)Fail('CONNECT_TLS_FILES_REQUIRED');
 if(!certSetting&&!fs.existsSync(DIR))Generate(serverName);
 if(!certSetting){const stat=fs.lstatSync(DIR);if(!stat.isDirectory()||stat.isSymbolicLink())Fail('CONNECT_TLS_IDENTITY_INVALID');}
 const certFile=certSetting?path.resolve(certSetting):path.join(DIR,'certificate.pem'),keyFile=keySetting?path.resolve(keySetting):path.join(DIR,'private-key.pem');
 const cert=Read(certFile,32768),key=Read(keyFile,16384);let leaf,privateKey;
 try{leaf=new crypto.X509Certificate(cert);privateKey=crypto.createPrivateKey(key);}catch(_){Fail('CONNECT_TLS_IDENTITY_INVALID');}
 if(privateKey.asymmetricKeyType!=='rsa'||privateKey.asymmetricKeyDetails?.modulusLength<2048||!leaf.checkPrivateKey(privateKey)||!leaf.checkHost(serverName,{wildcards:false,subject:'never'}))Fail('CONNECT_TLS_IDENTITY_INVALID');
 const validFrom=Date.parse(leaf.validFrom),expiresAt=Date.parse(leaf.validTo);if(!Number.isFinite(validFrom)||!Number.isFinite(expiresAt)||Date.now()<validFrom||Date.now()>=expiresAt)Fail('CONNECT_TLS_CERTIFICATE_EXPIRED');
 const fingerprint=crypto.createHash('sha256').update(leaf.raw).digest('hex');fs.mkdirSync(config.DATA_DIR,{recursive:true,mode:0o700});
 if(fs.existsSync(MARKER)){if(Read(MARKER,65).toString('ascii')!==fingerprint+'\n')Fail('CONNECT_TLS_IDENTITY_CHANGED');}
 else{try{Write(MARKER,fingerprint+'\n');Sync(config.DATA_DIR);}catch(error){if(error.code!=='EEXIST'||Read(MARKER,65).toString('ascii')!==fingerprint+'\n')throw error;}}
 if(!certSetting&&process.platform!=='win32')fs.chmodSync(keyFile,0o600);
 const options={key,cert,minVersion:'TLSv1.2',maxVersion:'TLSv1.3',ciphers:CIPHERS,honorCipherOrder:true,ecdhCurve:'X25519:prime256v1:secp384r1',secureOptions:crypto.constants.SSL_OP_NO_RENEGOTIATION|crypto.constants.SSL_OP_NO_TICKET,sessionTimeout:120};
 // Validate certificate/key and cipher availability at startup, before listening.
 tls.createSecureContext(options);
 cached={options,serverName,fingerprint,validFrom,expiresAt,certFile,keyFile};return cached;
}
function Public(){const value=Load();return {tlsServerName:value.serverName,tlsCertificateSha256:value.fingerprint};}
function Status(){try{const value=Load();return {ready:true,minVersion:'TLSv1.2',maxVersion:'TLSv1.3',serverName:value.serverName,certificateSha256:value.fingerprint,expiresAt:value.expiresAt,source:process.env.CONNECT_TLS_CERT_FILE?'configured':'persistent-generated'};}catch(error){return {ready:false,error:error.message,message:Messages[error.message]||'TLS 설정을 확인해 주세요.'};}}
const Messages={CONNECT_TLS_FILES_REQUIRED:'CONNECT_TLS_CERT_FILE과 CONNECT_TLS_KEY_FILE을 함께 지정하세요.',CONNECT_TLS_OPENSSL_REQUIRED:'OpenSSL을 설치하거나 제공된 Dockerfile로 배포하세요.',CONNECT_TLS_IDENTITY_MISSING:'기존 TLS 인증서 또는 개인 키가 없습니다. DATA_DIR의 인증서를 복원하세요.',CONNECT_TLS_IDENTITY_INVALID:'TLS 인증서, 개인 키 또는 서버 이름이 올바르지 않습니다.',CONNECT_TLS_IDENTITY_CHANGED:'TLS 인증서가 변경되었습니다. 변경을 검토하고 새 A를 발급하세요.',CONNECT_TLS_CERTIFICATE_EXPIRED:'TLS 인증서가 유효하지 않은 기간입니다. 인증서 교체 후 새 A를 발급하세요.',CONNECT_TLS_NAME_INVALID:'CONNECT_TLS_SERVER_NAME에 유효한 DNS 이름을 입력하세요.'};
module.exports={Load,Public,Status,Messages,CIPHERS,DIR,MARKER};
