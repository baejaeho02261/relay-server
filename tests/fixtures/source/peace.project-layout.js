'use strict';
// Test/tool source lookup only. Every returned path is a real functional source
// location; no old-path aliases or duplicate sources are created.
const path=require('node:path'),Module=require('node:module');
const index=require('./project-layout-v2.json');
const relay=path.resolve(__dirname,'../../..'),native=path.resolve(relay,'../Railway');
function Resolve(name,files,physical,root){
 if(typeof name!=='string'||!name||name.includes('\\')||name.includes('..')||path.isAbsolute(name))throw Error('SOURCE_LAYOUT_NAME_INVALID');
 let relative=physical.includes(name)?name:files[name]||files[name+'.js'];
 if(!relative)throw Error('SOURCE_LAYOUT_ENTRY_UNKNOWN');
 return path.join(root,...relative.split('/'));
}
const RelayFile=name=>Resolve(name,index.relayFiles,index.relayPhysicalPaths,relay);
const NativeFile=name=>Resolve(name,index.nativeFiles,index.nativePhysicalPaths,native);
function MockRequire(file,overrides={}){
 const real=Module.createRequire(file),byTarget=new Map();
 for(const[key,value]of Object.entries(overrides)){
  if(!key.startsWith('.'))continue;
  let target;try{target=real.resolve(key);}catch(_){target=RelayFile(path.posix.basename(key));}
  byTarget.set(target,value);
 }
 return request=>{
  if(Object.hasOwn(overrides,request))return overrides[request];
  if(request.startsWith('.')){const resolved=real.resolve(request);if(byTarget.has(resolved))return byTarget.get(resolved);}
  return real(request);
 };
}
module.exports={RelayFile,NativeFile,MockRequire,relayRoot:relay,nativeRoot:native,layout:index};
