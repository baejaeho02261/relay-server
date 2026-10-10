 'use strict';
const assert=require('node:assert/strict'),{Parse,SecretEqual}=require('../services/strictJson');let count=0;
function pass(name,fn){fn();count++;console.log('PASS '+name);}
pass('strict UTF8, escaped duplicate keys, full grammar and safe numeric ranges',()=>{
 const bad=['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"a":1,}','{"a":01}','{"a":[1,]}','{"a":1}x','{"a":9007199254740992}','{"a":1e999}','{"a":"\\ud800"}','{"a":"\\udc00"}','{"__proto__":{}}','{"constructor":1}','{"a":NaN}'];
 for(const text of bad)assert.throws(()=>Parse(text),undefined,text);
 for(const bytes of [[0xc0,0xaf],[0xe0,0x80,0x80],[0xed,0xa0,0x80],[0xf4,0x90,0x80,0x80],[0xc2]])assert.throws(()=>Parse(Buffer.from(bytes)));
 assert.deepEqual(Parse(Buffer.from('{"a":9007199254740991,"b":"\\ud83d\\ude00","c":[true,null,-1.5]}')),{a:9007199254740991,b:'😀',c:[true,null,-1.5]});
 assert.throws(()=>Parse('{"a":1}',{maxBytes:1}));assert.throws(()=>Parse('{"a":'+ '['.repeat(34)+'0'+']'.repeat(34)+'}'));
});
pass('public values and secrets have separate equality contracts',()=>{assert(SecretEqual('abc','abc'));for(const value of ['abd','a',null,7])assert.equal(SecretEqual('abc',value),false);});
pass('mitigation setter results never replace actual queried states',()=>{
 const validate=require('../services/mitigationContract').Validate;
 const value={version:1,requestedMode:'observe',setAttempted:false,setSucceeded:false,setError:0};
 for(const name of ['dynamic','cfg','strictHandle','imageLoad'])Object.assign(value,{[name+'Queried']:true,[name+'Flags']:0,[name+'Error']:0});
 assert.equal(validate(value,'ALLOWED','DISABLED'),value);
 for(const patch of [{extra:1},{setSucceeded:true},{dynamicFlags:1},{cfgFlags:1},{dynamicFlags:-1},{imageLoadFlags:0x100000000},{cfgError:5}])assert.throws(()=>validate({...value,...patch},'ALLOWED','DISABLED'));
 const fail={...value,requestedMode:'prohibit',setAttempted:true,setSucceeded:false,setError:5};assert.equal(validate(fail,'ALLOWED','DISABLED'),fail);
 const changed={...value,requestedMode:'prohibit',setAttempted:true,setSucceeded:true,dynamicFlags:1};assert.equal(validate(changed,'PROHIBITED','DISABLED'),changed);assert.throws(()=>validate(changed,'ALLOWED','DISABLED'));
});
console.log(`Hardening protocol groups: ${count} passed`);
