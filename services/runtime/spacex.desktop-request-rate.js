'use strict';
// Separate per-device request budget, NOT the shared TCP connection budget.
// Denials never extend a bucket, and arbitrary device strings cannot grow RAM
// beyond the fixed capacity. Authorization is still performed by the handler.
const {performance}=require('node:perf_hooks');
class DeviceRate {
 constructor({clock=()=>performance.now(),limit=40,windowMs=60000,capacity=12000}={}){
  if(typeof clock!=='function'||![limit,windowMs,capacity].every(x=>Number.isSafeInteger(x)&&x>0))throw Error('CONNECT_RATE_OPTIONS_INVALID');
  this.clock=clock;this.limit=limit;this.windowMs=windowMs;this.capacity=capacity;this.entries=new Map();
 }
 Take(deviceId){
  if(typeof deviceId!=='string'||deviceId.length<1||deviceId.length>100)throw Error('CONNECT_FRAME_INVALID');
  const at=this.clock();if(!Number.isFinite(at))throw Error('CONNECT_RATE_LIMIT');
  let item=this.entries.get(deviceId);
  if(item&&item.until<=at){this.entries.delete(deviceId);item=undefined;}
  if(item){if(item.count>=this.limit)throw Error('CONNECT_RATE_LIMIT');item.count++;return;}
  if(this.entries.size>=this.capacity){for(const [id,value]of this.entries)if(value.until<=at)this.entries.delete(id);}
  if(this.entries.size>=this.capacity)throw Error('CONNECT_RATE_LIMIT');
  this.entries.set(deviceId,{count:1,until:at+this.windowMs});
 }
}
module.exports={DeviceRate};
