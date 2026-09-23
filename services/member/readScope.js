'use strict';
// Synchronous request-local row indexes. Never retain a viewer, permission
// decision, projected response, or raw row after this request returns.
let current=null,writes=0;
function Run(fn){const previous=current;current=new Map();try{return fn();}finally{current=previous;}}
function Reset(){if(current)current.clear();}
function Active(){return current!==null&&writes===0;}
function Write(fn){writes++;try{return fn();}finally{writes--;Reset();}}
function By(table,field,value){
 const db=require('./store').DB(),rows=db[table]||{};
 if(!Active())return Object.values(rows).filter(row=>row[field]===value);
 const key=table+':'+field;let index=current.get(key);
 if(!index||index.source!==rows||index.revision!==db.revision){
  const buckets=new Map();for(const row of Object.values(rows)){
   const bucket=buckets.get(row[field]);if(bucket)bucket.push(row);else buckets.set(row[field],[row]);
  }
  index={source:rows,revision:db.revision,buckets};current.set(key,index);
 }
 return index.buckets.get(value)||[];
}
module.exports={Run,Reset,By,Active,Write};
