'use strict';
const {parentPort}=require('node:worker_threads'),crypto=require('node:crypto');
parentPort.on('message',message=>{
 if(message.close){parentPort.close();return;}
 let value;
 try{
  const task=message.task;
  if(task.kind==='open'){
   let key,clear;
   try{key=crypto.privateDecrypt({key:task.privateKey,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},Buffer.from(task.wrappedKey));
    if(key.length!==32)throw Error('CONNECT_KEY_INVALID');
    const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(task.nonce),{authTagLength:16});decipher.setAAD(Buffer.from(task.aad));decipher.setAuthTag(Buffer.from(task.tag));
    clear=Buffer.concat([decipher.update(Buffer.from(task.ciphertext)),decipher.final()]);
    value={key,payload:require("../protocol/peace.strict-json").Parse(clear,{maxBytes:32768})};parentPort.postMessage({id:message.id,value});
   }finally{clear?.fill(0);key?.fill(0);}return;
  }
  if(task.kind==='verify'){
   if(!Array.isArray(task.jobs)||task.jobs.length<1||task.jobs.length>4)throw Error('WORK_TASK_INVALID');
   value=task.jobs.map(job=>{const message=Buffer.from(job.message),signature=Buffer.from(job.signature);
    try{if(message.length>65536||signature.length!==256||job.key.asymmetricKeyType!=='rsa'||job.key.asymmetricKeyDetails?.modulusLength!==2048)throw Error('WORK_TASK_INVALID');
     return crypto.verify('sha256',message,{key:job.key,padding:crypto.constants.RSA_PKCS1_PADDING},signature);
    }finally{message.fill(0);signature.fill(0);job.message.fill(0);job.signature.fill(0);}});
  }else if(task.kind==='tpm-attestation'){
   const tpm=require("../devices/peace.desktop-tpm-attestation"),secret=Buffer.from(task.secret),nonce=Buffer.from(task.nonce);
   try{if(secret.length!==32||nonce.length!==32)throw Error('WORK_TASK_INVALID');const verified=tpm.VerifyCertify(task.evidence,nonce,task.publicKey,task.trust);value={rootSha256:verified.rootSha256,notAfter:verified.notAfter,activationBlob:tpm.MakeCredential(verified.ekPublic,verified.akName,secret).toString('base64')};}
   finally{secret.fill(0);nonce.fill(0);task.secret.fill(0);task.nonce.fill(0);}
  }else if(task.kind==='server-policy-bind'){
   const bytes=Buffer.from(task.bytes);let bound;
   try{bound=require('../artifacts/peace.server-policy-protection').BindTemplate(bytes,task.role,task.profile);parentPort.postMessage({id:message.id,value:bound});}
   finally{bytes.fill(0);task.bytes.fill(0);bound?.bytes?.fill(0);if(bound?.serverPolicy)bound.serverPolicy.programBase64='';}
   return;
  }else if(task.kind==='exposure'){
   const bytes=Buffer.from(task.bytes);try{value=require("../artifacts/peace.release-exposure").ScanBytes(bytes);}finally{bytes.fill(0);task.bytes.fill(0);}
  }else if(task.kind==='pe'){
   const bytes=Buffer.from(task.bytes),integrity=require("../integrity/peace.desktop-integrity");
   try{value={exposure:require("../artifacts/peace.release-exposure").ScanBytes(bytes),digests:integrity.Digests(bytes),code:integrity.CodeImage(bytes),capabilities:require("../artifacts/peace.pe-capabilities").PeCapabilities(bytes)};}
   finally{bytes.fill(0);} // upload source remains with the single-writer parent
  }else throw Error('WORK_TASK_INVALID');
  parentPort.postMessage({id:message.id,value});
 }catch(error){parentPort.postMessage({id:message.id,error:(['BOOTSTRAP_PE_INVALID','CONNECT_KEY_INVALID'].includes(error.message)||error.desktopError&&/^(?:DEVICE_TPM|COZY_SERVER_POLICY|COZY_PROTECTION)_[A-Z_]+$/.test(error.message))?error.message:'WORK_TASK_FAILED'});}
});
