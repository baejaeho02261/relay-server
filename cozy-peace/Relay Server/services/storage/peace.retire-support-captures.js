'use strict';
// One-time feature retirement, retried on every start after a crash. No capture
// API, image reader, key derivation, timer or new capture state remains.
const fs=require('node:fs'),path=require('node:path');
const config=require('../../config/peace.runtime-configuration');
const durable=require('./peace.durable-file');
const NAME='support-captures',OWNED=/^[A-F0-9]{24}\.enc(?:\.[a-f0-9]{32}\.tmp)?$/;
function Invalid(){throw Error('RETIRED_SUPPORT_STORAGE_INVALID');}
function Same(a,b){return a.dev===b.dev&&a.ino===b.ino;}
function Directory(root,directory,expected){
 const st=fs.lstatSync(directory);
 if(!st.isDirectory()||st.isSymbolicLink()||fs.realpathSync(directory)!==path.join(root,NAME)||expected&&!Same(st,expected))Invalid();
 return st;
}
function Inventory(root,directory){
 let stat;
 try{stat=Directory(root,directory);}catch(error){if(error.code==='ENOENT')return null;throw error;}
 const entries=[];
 // No recursive deletion and no state-supplied filenames: only exact files
 // produced by the former encrypted capture writer are eligible for removal.
 const handle=fs.opendirSync(directory);
 try{for(let item;(item=handle.readSync());){
  if(entries.length>=4096||!OWNED.test(item.name))Invalid();
  const file=path.join(directory,item.name),before=fs.lstatSync(file);
  if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1)Invalid();
  entries.push({file,before});
 }}finally{handle.closeSync();}
 Directory(root,directory,stat);
 return {stat,entries};
}
function Retire(){
 const store=require('../bootstrap/peace.desktop-bootstrap-store');
 const needsState=Object.hasOwn(store.Load(),'supportCaptures');
 let needsFiles=true;
 try{fs.lstatSync(path.join(config.DATA_DIR,NAME));}catch(error){if(error.code!=='ENOENT')throw error;needsFiles=false;}
 // An absent retired feature is a read-only no-op. Readers and test clients
 // that initialize existing authority must not acquire a new writer lease.
 // Any actual metadata or disk retirement below still requires that lease.
 if(!needsState&&!needsFiles)return {removedState:false,removedFiles:0};
 // Sharing the existing authority lock prevents a second server from writing
 // old capture objects while the state and private directory are retired.
 require('./peace.desktop-single-writer').Acquire(config.DATA_DIR,{haEnabled:config.HA_ENABLED});
 const root=fs.realpathSync(config.DATA_DIR),directory=path.join(root,NAME);
 const inventory=Inventory(root,directory);
 const removedState=Object.hasOwn(store.Load(),'supportCaptures');
 // Commit capability/state removal through the normal journal before unlinking.
 // If unlinking fails or the process dies, the next start retries orphan files.
 if(removedState)store.Atomic(db=>{delete db.supportCaptures;});
 let removedFiles=0;
 if(inventory){
  for(const {file,before}of inventory.entries){
   Directory(root,directory,inventory.stat);
   const now=fs.lstatSync(file);
   if(!now.isFile()||now.isSymbolicLink()||now.nlink!==1||!Same(now,before))Invalid();
   fs.unlinkSync(file);removedFiles++;
  }
  Directory(root,directory,inventory.stat);
  durable.SyncDirectory(directory);
  fs.rmdirSync(directory);
  durable.SyncDirectory(root);
 }
 return {removedState,removedFiles};
}
module.exports={Retire};
