'use strict';
// Evaluate the actual layout expressions and timeline from the shared FMX unit.
// This verifies geometry/timing, not an Android screenshot or Delphi compilation.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const file=path.resolve(__dirname,'../../MoaPlayApp_Android64/MoaPlayUiFeedback.pas'),source=fs.readFileSync(file,'utf8').replace(/\r/g,'');
const android=fs.readFileSync(path.resolve(__dirname,'../../MoaPlayApp_Android64/MoaPlayAndroidUi.pas'),'utf8');
assert.match(android,/procedure AndroidToast[\s\S]*?ShowMoaPlayMessage\(MessageText,LongDuration\)/);assert.doesNotMatch(android,/TJToast|makeText/);
const layout=source.slice(source.indexOf('procedure TMoaPlayMessageHost.LayoutMessage;'),source.indexOf('procedure TMoaPlayMessageHost.SetAvailableBottom'));
const expression=(lhs,n=0)=>[...layout.matchAll(new RegExp('(?:^|[;\\n ])'+lhs+':=([^;]+);','g'))][n]?.[1].trim();
function evaluate(text,variables){assert.ok(text);const js=text.replace(/FParent\./g,'parent.').replace(/FPanel\./g,'panel.').replace(/TStopwatch\.Frequency/g,'frequency').replace(/\bMax\(/g,'Math.max(').replace(/\bMin\(/g,'Math.min(').replace(/\bPower\(/g,'Math.pow(').replace(/\bEnsureRange\(/g,'clamp(');return Function(...Object.keys(variables),'clamp','return '+js)(...Object.values(variables),(v,a,b)=>Math.max(a,Math.min(b,v)));}
const radius=Number(source.match(/FPanel\.XRadius:=(\d+)/)[1]);assert.ok(radius>=8&&radius<=14,'rectangle retains modest corners instead of a pill');
assert.match(source,/FPanel\.HitTest:=False/);assert.match(source,/FPanel\.Stroke\.Kind:=TBrushKind\.None/);assert.match(source,/FTimer\.Interval:=16;FPanel\.Visible:=True/);assert.match(source,/FPanel\.Visible:=False;FEnteredAt:=0;FTimer\.Interval:=100/);
let checks=0;
for(const width of [240,320,360,412,480,800])for(const bottom of [160,360,740,1200])for(const height of [24,48,96]){
 const vars={parent:{Width:width,Height:bottom+120},FMeasuredHeight:height,Bottom:bottom,frequency:1000,FEnteredAt:1000,FExpires:4000,Stamp:1000};
 vars.W=evaluate(expression('W'),vars);vars.H=evaluate(expression('H'),vars);
 assert.ok(vars.W<=width-16&&vars.H<bottom);const x=(width-vars.W)/2;assert.ok(x>=8);
 let previous=0;
 for(const elapsed of [0,16,48,100,160,240,300]){vars.Stamp=1000+elapsed;vars.Progress=evaluate(expression('Progress',1),vars);vars.Progress=evaluate(expression('Progress',2),vars);assert.ok(vars.Progress>=previous&&vars.Progress<=1);previous=vars.Progress;vars.Slide=evaluate(expression('Slide'),vars);const y=evaluate(expression('Y'),vars);if(elapsed>=240)assert.ok(y+vars.H<=bottom-12+1e-6);checks++;}
 assert.equal(previous,1);
 for(const elapsed of [0,60,120,180]){vars.Stamp=4000+elapsed;vars.Progress=evaluate(expression('Progress',3),vars);vars.Progress=evaluate(expression('Progress',4),vars);assert.ok(vars.Progress<=previous&&vars.Progress>=0);previous=vars.Progress;checks++;}
 assert.equal(previous,0);
}
assert.match(source,/FTimer\.Enabled:=False/);assert.match(source,/TMonitor\.Enter\(MessageLock\)/);
console.log('TOAST PASS: '+checks+' production-expression animation/layout checks; lower inset, 12dp rectangle corners, noninteractive overlay, 240ms rise/180ms exit, idle timer restoration and shared Android routing. Device rendering not executed.');
