'use strict';
const fs=require('node:fs'),https=require('node:https'),tls=require('node:tls');
const p=require('./peace.desktop-packing-protocol');
function Settings(){
 const names=['DESKTOP_PACKER_URL','DESKTOP_PACKER_CA_FILE','DESKTOP_PACKER_CERT_FILE','DESKTOP_PACKER_KEY_FILE','DESKTOP_PACKER_SPKI_SHA512','DESKTOP_PACKER_TOOL_SHA512','DESKTOP_PACKER_PROFILE_A_SHA512','DESKTOP_PACKER_PROFILE_B_SHA512','DESKTOP_PACKER_PROFILE_O_SHA512','DESKTOP_PACKER_INPUT_A_SHA512','DESKTOP_PACKER_INPUT_B_SHA512','DESKTOP_PACKER_INPUT_O_SHA512'];
 if(!names.some(k=>process.env[k]))return null;
 if(names.some(k=>!process.env[k]))p.Fail('PACKING_WORKER_CONFIG_INCOMPLETE',503);
 const url=new URL(process.env.DESKTOP_PACKER_URL);
 if(url.protocol!=='https:'||url.username||url.password||url.pathname!=='/'||url.search||url.hash)p.Fail('PACKING_WORKER_URL_INVALID',503);
 const pins=Object.fromEntries(names.filter(k=>k.endsWith('SHA512')).map(k=>[k,process.env[k]]));
 if(Object.values(pins).some(x=>!p.IsDigest(x)))p.Fail('PACKING_WORKER_PIN_INVALID',503);
 function pem(name){const file=process.env[name],st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.size>1024*1024)p.Fail('PACKING_TLS_FILE_INVALID',503);return fs.readFileSync(file);}
 return {url,pins,ca:pem(names[1]),cert:pem(names[2]),key:pem(names[3])};
}
function Status(){try{const c=Settings();c?.key.fill(0);return {configured:!!c,engine:'VMProtect external worker',components:['A','B','O'],output:'UNAPPROVED_CANDIDATE',protectionVerified:false,reason:c?'WORKER_NOT_PROBED':'PACKING_WORKER_NOT_CONFIGURED'};}catch(e){return {configured:false,reason:/^PACKING_[A-Z_]+$/.test(e.message)?e.message:'PACKING_WORKER_CONFIG_INVALID'};}}
function Pack(component,bytes,id,options={}){
 if(!['A','B','O'].includes(component)||!/^[a-f0-9]{32}$/.test(id))p.Fail('PACKING_REQUEST_INVALID');p.Pe(bytes);
 const c=Settings();if(!c)p.Fail('PACKING_WORKER_NOT_CONFIGURED',503);
 const input=p.Sha512(bytes),profile=c.pins['DESKTOP_PACKER_PROFILE_'+component+'_SHA512'];
 if(!p.Equal(input,c.pins['DESKTOP_PACKER_INPUT_'+component+'_SHA512'])){c.key.fill(0);p.Fail('PACKING_PROFILE_INPUT_MISMATCH',409);}
 return new Promise((resolve,reject)=>{
 let done=false,req;const timer=setTimeout(()=>finish(Error('PACKING_WORKER_TIMEOUT')),p.MAX_MS);timer.unref();
 function finish(error,value){if(done)return;done=true;clearTimeout(timer);c.key.fill(0);if(error){req?.destroy();reject(error);}else resolve(value);}
 req=https.request(new URL('/v1/pack/'+component,c.url),{method:'POST',signal:options.signal,agent:false,ca:c.ca,cert:c.cert,key:c.key,minVersion:'TLSv1.2',rejectUnauthorized:true,checkServerIdentity:(host,cert)=>{const error=tls.checkServerIdentity(host,cert);if(error)return error;try{if(!p.Equal(p.Spki(cert.raw),c.pins.DESKTOP_PACKER_SPKI_SHA512))return Error('PACKING_WORKER_PIN_MISMATCH');}catch(_){return Error('PACKING_WORKER_PIN_MISMATCH');}},headers:{'Content-Type':'application/octet-stream','Content-Length':bytes.length,'X-Packing-Id':id,'X-Input-Sha512':input,'X-Profile-Sha512':profile,'X-Tool-Sha512':c.pins.DESKTOP_PACKER_TOOL_SHA512}},async res=>{
  try{
   if(res.statusCode!==200){res.resume();throw Error('PACKING_WORKER_HTTP_'+res.statusCode);}
   if(res.headers['x-packing-id']!==id||!p.Equal(res.headers['x-input-sha512'],input)||!p.Equal(res.headers['x-profile-sha512'],profile)||!p.Equal(res.headers['x-tool-sha512'],c.pins.DESKTOP_PACKER_TOOL_SHA512))throw Error('PACKING_WORKER_BINDING_MISMATCH');
   const output=await p.ReadBody(res);if(done||options.signal?.aborted){output.fill(0);throw Error('PACKING_CANCELLED');}p.Pe(output);const outputHash=p.Sha512(output);
   if(!p.Equal(outputHash,res.headers['x-output-sha512'])||outputHash===input)throw Error('PACKING_OUTPUT_INVALID');
   finish(null,{bytes:output,sha512:outputHash,inputSha512:input,profileSha512:profile,toolSha512:c.pins.DESKTOP_PACKER_TOOL_SHA512});
  }catch(e){finish(e);}
 });
 req.once('error',e=>finish(e));
 // Do not upload application bytes before CA/name/SPKI verification completes.
 req.once('socket',socket=>socket.once('secureConnect',()=>{if(!socket.authorized)return finish(Error('PACKING_WORKER_TLS_FAILED'));if(!done)req.end(bytes);}));
 });
}
module.exports={Status,Pack};
