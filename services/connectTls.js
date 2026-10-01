'use strict';
// The launcher pins the exact leaf certificate. Names are public TLS metadata,
// not secrets: random generated names remove product branding, not IP visibility.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),tls=require('node:tls'),{execFileSync}=require('node:child_process');
const config=require('../config/config');
const DIR=path.join(config.DATA_DIR,'connect-tls'),MARKER=path.join(config.DATA_DIR,'connect-tls.sha256'),ROTATION_LOCK=path.join(config.DATA_DIR,'connect-tls.rotation-lock');
const CIPHERS='TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
let cached;
function Fail(code){const error=Error(code);error.desktopError=true;error.status=503;throw error;}
function Sync(directory){if(process.platform==='win32')return;const fd=fs.openSync(directory,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Write(file,data){const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,data);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Read(file,max){let stat;try{stat=fs.lstatSync(file);}catch(_){Fail('CONNECT_TLS_IDENTITY_MISSING');}if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>max)Fail('CONNECT_TLS_IDENTITY_INVALID');return fs.readFileSync(file);}
function Directory(file){let stat;try{stat=fs.lstatSync(file);}catch(_){Fail('CONNECT_TLS_IDENTITY_MISSING');}if(!stat.isDirectory()||stat.isSymbolicLink())Fail('CONNECT_TLS_IDENTITY_INVALID');}
function Name(value){const name=String(value||'').trim().toLowerCase();if(!name||name.length>253||!name.split('.').every(part=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))||/^[\d.]+$/.test(name))Fail('CONNECT_TLS_NAME_INVALID');return name;}
function ConfiguredName(){return process.env.CONNECT_TLS_SERVER_NAME?Name(process.env.CONNECT_TLS_SERVER_NAME):'';}
function RandomName(){return crypto.randomBytes(16).toString('hex')+'.invalid';}
function CertificateName(leaf){
 const names=String(leaf.subjectAltName||'').split(', ').filter(value=>value.startsWith('DNS:')).map(value=>value.slice(4));
 // Multiple-name externally managed certificates need an explicit selection.
 if(names.length!==1)Fail('CONNECT_TLS_NAME_REQUIRED');return Name(names[0]);
}
function Validate(cert,key,serverName,allowExpired=false){
 let leaf,privateKey;try{leaf=new crypto.X509Certificate(cert);privateKey=crypto.createPrivateKey(key);}catch(_){Fail('CONNECT_TLS_IDENTITY_INVALID');}
 serverName=serverName||CertificateName(leaf);
 if(privateKey.asymmetricKeyType!=='rsa'||privateKey.asymmetricKeyDetails?.modulusLength<2048||!leaf.checkPrivateKey(privateKey)||!leaf.checkHost(serverName,{wildcards:false,subject:'never'}))Fail('CONNECT_TLS_IDENTITY_INVALID');
 const validFrom=Date.parse(leaf.validFrom),expiresAt=Date.parse(leaf.validTo);if(!Number.isFinite(validFrom)||!Number.isFinite(expiresAt)||!allowExpired&&(Date.now()<validFrom||Date.now()>=expiresAt))Fail('CONNECT_TLS_CERTIFICATE_EXPIRED');
 return {serverName,fingerprint:crypto.createHash('sha256').update(leaf.raw).digest('hex'),validFrom,expiresAt};
}
function Pointer(bytes){
 const text=bytes.toString('utf8');if(/^[a-f0-9]{64}\n$/.test(text))return {legacy:true,fingerprint:text.trim(),directory:DIR};
 let value;try{value=JSON.parse(text);}catch(_){Fail('CONNECT_TLS_IDENTITY_INVALID');}
 if(!value||Object.keys(value).sort().join(',')!=='fingerprint,generation,version'||value.version!==2||!/^[a-f0-9]{48}$/.test(value.generation)||!/^[a-f0-9]{64}$/.test(value.fingerprint))Fail('CONNECT_TLS_IDENTITY_INVALID');
 return {legacy:false,fingerprint:value.fingerprint,generation:value.generation,directory:path.join(DIR,value.generation)};
}
function ReadIdentity(allowExpired=false){
 const certSetting=String(process.env.CONNECT_TLS_CERT_FILE||'').trim(),keySetting=String(process.env.CONNECT_TLS_KEY_FILE||'').trim();
 if(!!certSetting!==!!keySetting)Fail('CONNECT_TLS_FILES_REQUIRED');
 const pointer=Pointer(Read(MARKER,512));if(!certSetting){Directory(DIR);Directory(pointer.directory);}
 if(certSetting&&!pointer.legacy)Fail('CONNECT_TLS_IDENTITY_CHANGED');
 const certFile=certSetting?path.resolve(certSetting):path.join(pointer.directory,'certificate.pem'),keyFile=keySetting?path.resolve(keySetting):path.join(pointer.directory,'private-key.pem');
 const cert=Read(certFile,32768),key=Read(keyFile,16384),details=Validate(cert,key,ConfiguredName(),allowExpired);
 if(details.fingerprint!==pointer.fingerprint)Fail('CONNECT_TLS_IDENTITY_CHANGED');
 if(certSetting&&!fs.existsSync(DIR)){fs.mkdirSync(DIR,{mode:0o700});Sync(config.DATA_DIR);}
 if(!certSetting&&process.platform!=='win32')fs.chmodSync(keyFile,0o600);
 return {...details,certFile,keyFile,cert,key,pointer};
}
function Generate(serverName){
 serverName=Name(serverName);
 fs.mkdirSync(config.DATA_DIR,{recursive:true,mode:0o700});
 if(fs.existsSync(DIR))Directory(DIR);else fs.mkdirSync(DIR,{mode:0o700});
 const generation=crypto.randomBytes(24).toString('hex'),temporary=fs.mkdtempSync(path.join(DIR,'.pending-')),destination=path.join(DIR,generation);fs.chmodSync(temporary,0o700);
 try{
  const keyFile=path.join(temporary,'private-key.pem'),certFile=path.join(temporary,'certificate.pem');
  // A standard maintained TLS provider creates the identity; no custom crypto.
  try{execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-sha256','-nodes','-keyout',keyFile,'-out',certFile,'-days','825','-subj','/CN='+serverName,'-addext','subjectAltName=DNS:'+serverName,'-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-addext','extendedKeyUsage=serverAuth'],{stdio:'ignore',timeout:30000});}catch(_){Fail('CONNECT_TLS_OPENSSL_REQUIRED');}
  for(const file of [keyFile,certFile]){fs.chmodSync(file,0o600);const fd=fs.openSync(file,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
  const details=Validate(Read(certFile,32768),Read(keyFile,16384),serverName);
  Sync(temporary);fs.renameSync(temporary,destination);Sync(DIR);
  return {pointer:Buffer.from(JSON.stringify({version:2,generation,fingerprint:details.fingerprint})+'\n'),...details};
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
}
function Initialize(){
 const certSetting=String(process.env.CONNECT_TLS_CERT_FILE||'').trim(),keySetting=String(process.env.CONNECT_TLS_KEY_FILE||'').trim();
 if(!!certSetting!==!!keySetting)Fail('CONNECT_TLS_FILES_REQUIRED');
 fs.mkdirSync(config.DATA_DIR,{recursive:true,mode:0o700});
 // Never reconstruct a lost pin from a previously persisted identity.
 if(fs.existsSync(DIR))Fail('CONNECT_TLS_IDENTITY_MISSING');
 if(certSetting){const details=Validate(Read(path.resolve(certSetting),32768),Read(path.resolve(keySetting),16384),ConfiguredName());fs.mkdirSync(DIR,{mode:0o700});Write(MARKER,details.fingerprint+'\n');}
 else{const next=Generate(ConfiguredName()||RandomName());Write(MARKER,next.pointer);}
 Sync(config.DATA_DIR);
}
function Load(){
 if(fs.existsSync(ROTATION_LOCK))Fail('CONNECT_TLS_ROTATION_IN_PROGRESS');
 if(cached){if(Date.now()<cached.validFrom||Date.now()>=cached.expiresAt)Fail('CONNECT_TLS_CERTIFICATE_EXPIRED');return cached;}
 if(!fs.existsSync(MARKER))Initialize();
 const value=ReadIdentity(),{key,cert}=value;
 const options={key,cert,minVersion:'TLSv1.2',maxVersion:'TLSv1.3',ciphers:CIPHERS,honorCipherOrder:true,ecdhCurve:'X25519:prime256v1:secp384r1',secureOptions:crypto.constants.SSL_OP_NO_RENEGOTIATION|crypto.constants.SSL_OP_NO_TICKET,sessionTimeout:120};
 tls.createSecureContext(options);cached={...value,options};return cached;
}
function Public(){const value=Load();return {tlsServerName:value.serverName,tlsCertificateSha256:value.fingerprint};}
function Status(){try{const value=Load();return {ready:true,minVersion:'TLSv1.2',maxVersion:'TLSv1.3',serverName:value.serverName,certificateSha256:value.fingerprint,expiresAt:value.expiresAt,source:process.env.CONNECT_TLS_CERT_FILE?'configured':'persistent-generated'};}catch(error){return {ready:false,error:error.message,message:Messages[error.message]||'TLS 설정을 확인해 주세요.'};}}
const Messages={CONNECT_TLS_FILES_REQUIRED:'CONNECT_TLS_CERT_FILE과 CONNECT_TLS_KEY_FILE을 함께 지정하세요.',CONNECT_TLS_OPENSSL_REQUIRED:'OpenSSL을 설치하거나 제공된 Dockerfile로 배포하세요.',CONNECT_TLS_IDENTITY_MISSING:'기존 TLS 인증서, 개인 키 또는 핀 기록이 없습니다. DATA_DIR의 TLS 백업을 복원하세요.',CONNECT_TLS_IDENTITY_INVALID:'TLS 인증서, 개인 키 또는 서버 이름이 올바르지 않습니다.',CONNECT_TLS_IDENTITY_CHANGED:'TLS 인증서가 변경되었습니다. 변경을 검토하고 새 A를 발급하세요.',CONNECT_TLS_CERTIFICATE_EXPIRED:'TLS 인증서가 유효하지 않은 기간입니다. 오프라인 인증서 교체 후 새 A를 발급하세요.',CONNECT_TLS_NAME_INVALID:'CONNECT_TLS_SERVER_NAME에 유효한 DNS 이름을 입력하세요.',CONNECT_TLS_NAME_REQUIRED:'여러 DNS 이름을 포함한 인증서는 CONNECT_TLS_SERVER_NAME을 지정하세요.',CONNECT_TLS_ROTATION_IN_PROGRESS:'TLS 교체가 진행 중이거나 중단되었습니다. 오프라인 교체 도구의 복원 명령을 실행하세요.'};
module.exports={Load,Public,Status,Messages,CIPHERS,DIR,MARKER,ROTATION_LOCK,ReadIdentity,Generate,RandomName,ConfiguredName,Read,Write,Sync,Pointer,Validate,Directory};
