 'use strict';
function Validate(value,dynamicCode,cfg){
 const fail=()=>{throw Error('MITIGATION_OBSERVATION_INVALID');};
 const v2=value?.version===2;
 const bool=['setAttempted','setSucceeded','dynamicQueried','cfgQueried','strictHandleQueried','imageLoadQueried'];
 const num=['setError',...['dynamic','cfg','strictHandle','imageLoad'].flatMap(x=>[x+'Flags',x+'Error'])];
 if(v2){bool.push('strictSetAttempted','strictSetSucceeded','imageSetAttempted','imageSetSucceeded');num.push('strictSetError','imageSetError');}
 const keys=['version','requestedMode',...bool,...num,...(v2?['profileId']:[])];
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!==keys.sort().join(',')||![1,2].includes(value.version)||!['observe','prohibit'].includes(value.requestedMode))fail();
 if(v2){if(!/^[a-f0-9]{128}$/.test(value.profileId||''))fail();for(const n of ['strict','image'])if(value[n+'SetSucceeded']&&(!value[n+'SetAttempted']||value[n+'SetError']!==0))fail();}
 for(const k of bool)if(typeof value[k]!=='boolean')fail();
 for(const k of num)if(!Number.isSafeInteger(value[k])||value[k]<0||value[k]>0xffffffff)fail();
 if(value.setSucceeded&&(!value.setAttempted||value.setError!==0)||value.requestedMode==='observe'&&(value.setAttempted||value.setSucceeded||value.setError!==0))fail();
 for(const x of ['dynamic','cfg','strictHandle','imageLoad'])if(value[x+'Queried']?value[x+'Error']!==0:value[x+'Flags']!==0)fail();
 if(dynamicCode!==(value.dynamicQueried?((value.dynamicFlags&7)===1?'PROHIBITED':'ALLOWED'):'UNAVAILABLE'))fail();
 if(cfg!==(value.cfgQueried?((value.cfgFlags&1)?'ENABLED':'DISABLED'):'UNAVAILABLE'))fail();
 return value;
}
module.exports={Validate};
