'use strict';
// A dedicated SQLite connection holds an EXCLUSIVE OS-backed file lock for the
// whole server process. The file's presence/PID is never the lock. Never delete,
// rename, back up or restore this coordination file while a server is running.
// Requires a local filesystem with SQLite locking support; this is not HA or a
// network-filesystem fencing protocol. Every server sharing DATA_DIR must use it.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {performance}=require('node:perf_hooks');
const NAME='.desktop-single-writer.sqlite';
const ACQUIRE_LIMITS=Object.freeze({attempts:12,budgetMs:250,minBackoffMs:5,maxBackoffMs:20});
const retrySignal=new Int32Array(new SharedArrayBuffer(4));
function Unavailable(cause){const failure=Error('DESKTOP_WRITER_LOCK_UNAVAILABLE');failure.cause=cause;return failure;}
function CreateLock(){
 let held;
 return function Acquire(directory,{haEnabled=false}={}){
  if(haEnabled)throw Error('DESKTOP_SINGLE_WRITER_REQUIRED');
  // The pinned native addon requires N-API 10; reject before loading it.
  if(Number(process.versions.napi)<10)throw Error('SQLITE_REQUIRES_NODE_22_14_OR_NEWER_NAPI10');
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  const root=fs.realpathSync(directory);
  if(held){if(held.root!==root)throw Error('DESKTOP_WRITER_ALREADY_BOUND');return;}
  const file=path.join(root,NAME);
  try{const fd=fs.openSync(file,'wx',0o600);fs.closeSync(fd);}
  catch(error){if(error.code!=='EEXIST')throw error;}
  const stat=fs.lstatSync(file);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1)throw Error('DESKTOP_WRITER_LOCK_INVALID');
  const deadline=performance.now()+ACQUIRE_LIMITS.budgetMs;
  let Database;
  try{Database=require('better-sqlite3');}catch(error){throw Unavailable(error);}
  for(let attempt=1;attempt<=ACQUIRE_LIMITS.attempts;attempt++){
   if(attempt>1&&performance.now()>=deadline)throw Error('DESKTOP_DATA_DIR_ALREADY_IN_USE');
   // A retry must still address the original coordination object. It never
   // removes/replaces a lock file or follows a newly substituted link.
   const current=fs.lstatSync(file);
   if(!current.isFile()||current.isSymbolicLink()||current.nlink!==1||current.dev!==stat.dev||current.ino!==stat.ino)throw Error('DESKTOP_WRITER_LOCK_INVALID');
   let db;
   try{
    db=new Database(file,{timeout:0});
    db.pragma('locking_mode = EXCLUSIVE');
    db.exec('BEGIN EXCLUSIVE');
    // Do not change journal mode before acquiring: simultaneous first starts
    // could otherwise contend while initializing an empty coordination file.
    if(db.pragma('journal_mode',{simple:true})!=='delete')throw Error('DESKTOP_WRITER_LOCK_INVALID');
    if(!db.inTransaction)throw Error('DESKTOP_WRITER_LOCK_INVALID');
    held={root,db};
    // Do not close from an exit listener: later listeners may still write.
    // Normal exit, SIGKILL and crashes release the OS locks with the process.
    return;
   }catch(error){
    // Two fresh openers can both hold transient read locks and both encounter
    // SQLITE_BUSY upgrading to EXCLUSIVE. Release this connection completely
    // before randomized retry; an active owner continues to reject all tries.
    if(db)try{db.close();}catch(closeError){throw Unavailable(closeError);}
    if(!['SQLITE_BUSY','SQLITE_LOCKED'].includes(error.code))throw Unavailable(error);
    const remaining=deadline-performance.now();
    if(attempt===ACQUIRE_LIMITS.attempts||remaining<=0)throw Error('DESKTOP_DATA_DIR_ALREADY_IN_USE');
    const delay=Math.min(remaining,crypto.randomInt(ACQUIRE_LIMITS.minBackoffMs,ACQUIRE_LIMITS.maxBackoffMs+1));
    Atomics.wait(retrySignal,0,0,delay);
   }
  }
  throw Error('DESKTOP_DATA_DIR_ALREADY_IN_USE');
 };
}
const Acquire=CreateLock(),AcquireWitness=CreateLock();
module.exports={Acquire,AcquireWitness,NAME,ACQUIRE_LIMITS};
