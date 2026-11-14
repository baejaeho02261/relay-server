'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'../..'),source=path.join(root,'contracts/runtime/peace.lifecycle-events-v1.json');
function enumName(prefix,name){return prefix+name.toLowerCase().split('_').map(x=>x[0].toUpperCase()+x.slice(1)).join('');}
function render(text){
 const spec=JSON.parse(text),statuses=[...new Set(spec.events.flatMap(e=>e.statuses))];
 const digest=crypto.createHash('sha512').update(text).digest('hex');
 const quote=x=>"'"+x+"'";
 const lines=['{ Generated from contracts/runtime/peace.lifecycle-events-v1.json; checked by server contract test. }','const',
 `  LifecycleContract = '${spec.contract}';`,`  LifecycleSchemaSha512 = '${digest}';`,`  LifecycleMaximumEvents = ${spec.maxEvents};`,
 `  LifecycleRoleNames: array[TLifecycleRole] of string = (${spec.roles.map(quote).join(',')});`,
 `  LifecycleEventNames: array[TLifecycleEvent] of string = (${spec.events.map(e=>quote(e.name)).join(',')});`,
 `  LifecycleStatusNames: array[TLifecycleStatus] of string = (${statuses.map(quote).join(',')});`,
 '  LifecycleEventStatuses: array[TLifecycleEvent] of TLifecycleStatuses = (',
 spec.events.map(e=>'    ['+e.statuses.map(s=>enumName('ls',s)).join(',')+']').join(',\n')+');',''];
 return '\uFEFF'+lines.join('\r\n').replace(/(?<!\r)\n/g,'\r\n');
}
const target=path.resolve(root,'../Railway/Cozy.Source/Cozy.Lifecycle/Cozy.Lifecycle.Events.inc');
if(require.main===module){const expected=render(fs.readFileSync(source,'utf8'));if(process.argv.includes('--check')){if(fs.readFileSync(target,'utf8')!==expected)throw Error('LIFECYCLE_SCHEMA_DRIFT');}else fs.writeFileSync(target,expected);console.log('LIFECYCLE_SCHEMA_OK');}
module.exports={render};
