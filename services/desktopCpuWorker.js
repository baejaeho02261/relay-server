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
    value={key,payload:require('./strictJson').Parse(clear,{maxBytes:32768})};parentPort.postMessage({id:message.id,value});
   }finally{clear?.fill(0);key?.fill(0);}return;
  }
  if(task.kind==='pe'){
   const bytes=Buffer.from(task.bytes),integrity=require('./desktopIntegrity');
   try{value={digests:integrity.Digests(bytes),code:integrity.CodeImage(bytes),capabilities:require('./peCapabilities').PeCapabilities(bytes)};}
   finally{bytes.fill(0);} // upload source remains with the single-writer parent
  }else throw Error('WORK_TASK_INVALID');
  parentPort.postMessage({id:message.id,value});
 }catch(error){parentPort.postMessage({id:message.id,error:['BOOTSTRAP_PE_INVALID','CONNECT_KEY_INVALID'].includes(error.message)?error.message:'WORK_TASK_FAILED'});}
});
