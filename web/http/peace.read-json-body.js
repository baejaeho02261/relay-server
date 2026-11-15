'use strict';
const {Parse}=require("../../services/protocol/peace.strict-json");
// Parse raw bytes: toString('utf8') would replace invalid UTF-8 before checking.
function ReadJsonBody(req,maxBytes=128*1024){
 if(!Number.isSafeInteger(maxBytes)||maxBytes<1)return Promise.reject(Error('BODY_LIMIT_INVALID'));
 return new Promise((resolve,reject)=>{
  const chunks=[];let size=0,done=false;
  function finish(error,value){if(done)return;done=true;chunks.length=0;error?reject(error):resolve(value);}
  req.on('data',chunk=>{
   if(done)return;
   if(!(chunk instanceof Uint8Array)){finish(Error('INVALID_JSON'));req.destroy();return;}
   size+=chunk.byteLength;
   if(size>maxBytes){finish(Error('BODY_TOO_LARGE'));req.destroy();return;}
   chunks.push(chunk);
  });
  req.once('end',()=>{
   if(done)return;
   try{
    const value=size?Parse(Buffer.concat(chunks,size),{maxBytes}):{};
    if(!value||typeof value!=='object'||Array.isArray(value))throw Error('INVALID_JSON');
    finish(null,value);
   }catch(_){finish(Error('INVALID_JSON'));}
  });
  req.once('aborted',()=>finish(Error('BODY_ABORTED')));
  req.once('error',()=>finish(Error('BODY_READ_FAILED')));
  req.once('close',()=>{if(!done)finish(Error('BODY_ABORTED'));});
 });
}
module.exports={ReadJsonBody};
