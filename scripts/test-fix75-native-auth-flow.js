'use strict';
// Execute the production Pascal state branches with lightweight FMX doubles.
// This is source-driven transition coverage, not a Delphi/Android runtime claim.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const base=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(base,name),'utf8').replace(/^\uFEFF/,'').replace(/\r/g,'').replace(/\{[\s\S]*?\}/g,'');
function routine(source,name){const rows=[...source.matchAll(/^(?:function|procedure|constructor|destructor)\s+([\w.]+)/gm)],i=rows.findIndex(x=>x[1]===name);assert.ok(i>=0,name);const text=source.slice(rows[i].index,rows[i+1]?.index??source.length);return text.slice(text.indexOf('\nbegin')+1);}
function branch(source,name,next){return source.slice(source.indexOf("if ALine.StartsWith('"+name+"|')"),source.indexOf("if ALine.StartsWith('"+next+"|')"));}
// Small explicit Pascal AST interpreter for the routines under test. Unsupported
// syntax fails the test instead of silently replacing production behavior.
function compile(text){
 const tokens=text.match(/'(?:''|[^'])*'|:=|<>|<=|>=|[A-Za-z_]\w*|\d+|[()[\].,;:+\-*\/=<>]/g)||[];let at=0;
 const is=x=>tokens[at]?.toLowerCase()===x;
 const take=x=>{if(x)assert.equal(tokens[at]?.toLowerCase(),x,'Expected '+x+' at '+tokens.slice(at,at+8).join(' '));return tokens[at++];};
 const precedence={or:1,and:2,'=':3,'<>':3,'<':3,'>':3,'<=':3,'>=':3,'+':4,'-':4,'*':5,'/':5};
 function expr(min=0){let a;if(is('not')){take();a={kind:'not',value:expr(6)};}else if(is('(')){take();a=expr();take(')');}else if(is('[')){take();const items=[];while(!is(']')){items.push(expr());if(!is(','))break;take();}take(']');a={kind:'array',items};}else{const t=take();assert.ok(t,'expression');a=t.startsWith("'")?{kind:'literal',value:t.slice(1,-1).replace(/''/g,"'")}:/^\d+$/.test(t)?{kind:'literal',value:Number(t)}:{kind:'id',name:t};}
  while(is('.')||is('[')||is('(')){if(is('.')){take();a={kind:'member',owner:a,name:take()};}else if(is('[')){take();const index=expr();take(']');a={kind:'index',owner:a,index};}else{take();const args=[];while(!is(')')){args.push(expr());if(!is(','))break;take();}take(')');a={kind:'call',callee:a,args};}}
  while(Object.hasOwn(precedence,tokens[at]?.toLowerCase())&&precedence[tokens[at].toLowerCase()]>=min){const op=take().toLowerCase();a={kind:'binary',op,left:a,right:expr(precedence[op]+1)};}return a;
 }
 function stmt(){if(is('begin')){take();const nodes=[];while(!is('end')){nodes.push(stmt());if(is(';'))take();}take('end');return {kind:'block',nodes};}if(is('if')){take();const condition=expr();take('then');const yes=stmt();let no=null;if(is('else')){take();no=stmt();}return {kind:'if',condition,yes,no};}const target=expr();if(is(':=')){take();return {kind:'assign',target,value:expr()};}return {kind:'invoke',target};}
 const nodes=[];while(at<tokens.length){if(is(';')){take();continue;}nodes.push(stmt());}return ctx=>{ctx.Result=false;try{for(const node of nodes)run(node,ctx);}catch(e){if(!e.pascalExit)throw e;}return ctx.Result;};
}
function reference(node,ctx){if(node.kind==='id')return [ctx,node.name];if(node.kind==='member')return [value(node.owner,ctx),node.name];if(node.kind==='index')return [value(node.owner,ctx),value(node.index,ctx)];throw Error('Not assignable '+node.kind);}
function value(n,c){
 if(n.kind==='literal')return n.value;if(n.kind==='array')return n.items.map(x=>value(x,c));
 if(n.kind==='id'){if(n.name==='True')return true;if(n.name==='False')return false;if(n.name==='nil')return null;assert.ok(n.name in c,'missing '+n.name);return c[n.name];}
 if(n.kind==='member'||n.kind==='index'){const [o,k]=reference(n,c);if(typeof o==='string'){if(k==='StartsWith')return x=>o.startsWith(x);if(k==='Split')return xs=>o.split(xs[0]);}const v=o[k];return typeof v==='function'?v.bind(o):v;}
 if(n.kind==='not')return !value(n.value,c);
 if(n.kind==='binary'){const a=value(n.left,c);if(n.op==='or')return a||value(n.right,c);if(n.op==='and')return a&&value(n.right,c);const b=value(n.right,c);return {'=':()=>a===b,'<>':()=>a!==b,'<':()=>a<b,'>':()=>a>b,'<=':()=>a<=b,'>=':()=>a>=b,'+':()=>a+b,'-':()=>a-b,'*':()=>a*b,'/':()=>a/b}[n.op]();}
 if(n.kind==='call'){if(n.callee.kind==='id'&&n.callee.name==='Exit'){if(n.args.length)c.Result=value(n.args[0],c);throw {pascalExit:true};}if(n.callee.kind==='id'&&n.callee.name==='TryStrToInt64'){const x=Number(value(n.args[0],c)),[o,k]=reference(n.args[1],c);o[k]=x;return Number.isSafeInteger(x);}const f=value(n.callee,c);assert.equal(typeof f,'function','Callable '+JSON.stringify(n.callee));return f(...n.args.map(x=>value(x,c)));}
 throw Error('Unknown expression '+n.kind);
}
function run(n,c){if(n.kind==='block'){for(const x of n.nodes)run(x,c);}else if(n.kind==='if'){if(value(n.condition,c))run(n.yes,c);else if(n.no)run(n.no,c);}else if(n.kind==='assign'){const [o,k]=reference(n.target,c);o[k]=value(n.value,c);}else if(n.kind==='invoke'){if(n.target.kind==='id'&&n.target.name==='Exit')throw {pascalExit:true};const v=value(n.target,c);if(typeof v==='function')v();}else throw Error('Unknown statement');}
const auth=read('MoaPlayApp.AuthSteps.inc'),wire=read('MoaPlayApp.Protocol.Biometric.inc');
const keep=compile(routine(auth,'TMoaPlayForm.KeepVerifiedPresentation')),end=compile(routine(auth,'TMoaPlayForm.EndAuthResume'));
const resumed=compile(branch(wire,'BIOMETRIC_RESUMED','BIOMETRIC_RESET')),proved=compile(branch(wire,'BIOMETRIC_OK','BIOMETRIC_ERROR'));
const challenge=compile(branch(wire,'BIOMETRIC_CHALLENGE','BIOMETRIC_OK'));
const secret='test-native-flow-secret',nonce='A'.repeat(32),authID='FRESH-AUTH-CHALLENGE';
const mac=text=>crypto.createHmac('sha256',secret).update(text).digest('hex').toUpperCase();
function context(){const c={Result:false,FAuthResumePending:true,FAuthResumeDeadline:13000,HubAuthTick:1000,FClosing:false,FReinstallBlocked:false,FReinstallProbe:false,FBiometricResumeRequestID:nonce,FCurrentScreen:'MAIN',FState:{ClientID:'1234567890ABCDEF',Connected:true,ServiceDisabled:false,ClientDisabled:false,VersionBlocked:false,IsClientTemporarilyKicked:false,LicenseAuthenticated:true,BiometricAuthenticated:false,AccessType:''},FIdentityLinked:true,FAuthStepsPanel:{Visible:false},FQrPanel:{Visible:false},FBiometricPanel:{Visible:false},FFinalPanel:{Visible:true,Enabled:true},FOfflinePanel:{Visible:false},FOfflineLabel:{Text:''},FPermissionAuthID:authID,HubIdentityReady:true,PermissionsReady:true,FDeviceAuthVerified:true,FSecurity:{Secret:secret},FBiometricNonce:'',FBiometricMode:'',FBiometricProofPending:false,FBiometricPromptActive:false,FBiometricTimeoutTimer:{Enabled:false},FBiometricReturnToMain:false,FMemberTestGranted:false,MemberAccessReady:false,FLoginToastSent:true,FBiometricPromptNonce:'',FGroupGuid:'',FUserProfile:{ResumeStage:'MAIN',GroupGuid:'',MarkLoginMetadata(a,g){this.GroupGuid=g;},MarkStage(stage){this.ResumeStage=stage;}},FRuntime:{Diagnostics:{Add(){}}},Assigned:x=>x!=null,Length:x=>x.length,UpperCase:x=>x.toUpperCase(),Trim:x=>x.trim(),SameText:(a,b)=>a.toUpperCase()===b.toUpperCase(),MemberCaption:x=>x,RelayHmacSha256Hex:(key,text)=>crypto.createHmac('sha256',key).update(text).digest('hex').toUpperCase(),SetStatusGraphic(){},MemberTestReset(){},ClearBuildSession(){},AndroidToast(){},SetBiometricProgress(){},QueueBiometricAuthentication(){c.queued=true;},CancelBiometricPrompt(){c.FBiometricProofPending=false;c.FBiometricPromptActive=false;},ShowBiometricPanel(){c.FCurrentScreen='BIOMETRIC';c.FBiometricPanel.Visible=true;c.FFinalPanel.Visible=false;},SetAuthorizedUI(){assert.ok(c.FState.BiometricAuthenticated&&c.HubIdentityReady);c.FCurrentScreen='MAIN';c.FFinalPanel.Visible=true;c.FFinalPanel.Enabled=true;c.FBiometricPanel.Visible=false;}};c.EndAuthResume=()=>end(c);return c;}
function packet(){const fields=[authID,nonce,'TYPE1','GROUP',String(Date.now()+86400000)];return 'BIOMETRIC_RESUMED|'+fields.join('|')+'|'+mac('BIOMETRIC_RESUMED|1234567890ABCDEF|'+fields.join('|'));}
let c=context();assert.equal(keep(c),true);assert.equal(c.FFinalPanel.Visible,true);assert.equal(c.FFinalPanel.Enabled,false);assert.equal(c.FState.BiometricAuthenticated,false);assert.equal(c.FQrPanel.Visible,false);assert.equal(c.FBiometricPanel.Visible,false);assert.equal(c.FAuthStepsPanel.Visible,false);
c.ALine=packet();resumed(c);assert.equal(c.FState.BiometricAuthenticated,true);assert.equal(c.FCurrentScreen,'MAIN');assert.equal(c.FAuthResumePending,false);assert.equal(c.FBiometricResumeRequestID,'');assert.equal(c.FFinalPanel.Enabled,true);
// Replay of the same valid packet is rejected after its one-use intent clears.
c.FState.BiometricAuthenticated=false;resumed(c);assert.equal(c.FState.BiometricAuthenticated,false);
for(const patch of [{FBiometricResumeRequestID:'B'.repeat(32)},{FPermissionAuthID:'OLD'},{HubIdentityReady:false},{PermissionsReady:false},{FDeviceAuthVerified:false},{FBiometricNonce:'REAL-NEW-PROOF'},{FBiometricProofPending:true},{FAuthResumeDeadline:0},{HubAuthTick:13000}]){c=context();Object.assign(c,patch);c.ALine=packet();resumed(c);assert.equal(c.FState.BiometricAuthenticated,false,JSON.stringify(patch));}
for(const index of [1,2,3,4,5,6]){c=context();const p=packet().split('|');p[index]=index===5?'1':p[index]+'0';c.ALine=p.join('|');resumed(c);assert.equal(c.FState.BiometricAuthenticated,false,'tampered signed field '+index);}
// Delayed timer scheduling cannot extend request freshness. A hold timeout
// itself retains intent so the transport timeout path decides when to reconnect.
c=context();c.HubAuthTick=13000;assert.equal(keep(c),false);assert.equal(c.FAuthResumePending,false);assert.equal(c.FBiometricResumeRequestID,nonce);c.ALine=packet();resumed(c);assert.equal(c.FState.BiometricAuthenticated,false);
c=context();c.FState.ServiceDisabled=true;assert.equal(keep(c),false);assert.equal(c.FBiometricResumeRequestID,'');
c=context();c.FFinalPanel.Visible=false;assert.equal(keep(c),true);assert.equal(c.FOfflinePanel.Visible,true);assert.equal(c.FAuthStepsPanel.Visible,false,'saved presentation metadata never flashes login or grants access');
// Renewed proof really displays and queues the platform biometric prompt.
c=context();c.ALine='BIOMETRIC_CHALLENGE|VERIFY|NEW-NONCE|TYPE1|99999999999';challenge(c);assert.equal(c.FCurrentScreen,'BIOMETRIC');assert.equal(c.FState.BiometricAuthenticated,false);assert.equal(c.FAuthResumePending,false);assert.equal(c.queued,true);
c.FBiometricProofPending=true;c.ALine='BIOMETRIC_OK|TYPE1|GROUP';proved(c);assert.equal(c.FCurrentScreen,'MAIN');assert.equal(c.FState.BiometricAuthenticated,true);assert.equal(c.FBiometricContinuePending,false);assert.equal(c.FUserProfile.ResumeStage,'MAIN');
for(const patch of [{HubIdentityReady:false},{FBiometricProofPending:false},{FBiometricNonce:''},{FBiometricMode:''}]){c=context();Object.assign(c,{FBiometricProofPending:true,FBiometricNonce:'N',FBiometricMode:'VERIFY'},patch);c.ALine='BIOMETRIC_OK|TYPE1|GROUP';proved(c);assert.equal(c.FState.BiometricAuthenticated,false,'late or unproved acknowledgment');}
console.log('FIX75 NATIVE FLOW PASS: production Pascal branches executed with FMX doubles; read-only main continuity, neutral restart, signed nonce/field tamper/replay/monotonic timeout denial, renewed real prompt and immediate server-proof main transition. Delphi/Android runtime not executed.');
