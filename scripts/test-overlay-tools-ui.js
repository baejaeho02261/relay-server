'use strict';
// Actual public deployment scripts and embedded offline workers; synthetic PE
// fixtures do not represent a native Windows build or execution result.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs');
const os=require('node:os'),path=require('node:path'),vm=require('node:vm'),{spawnSync}=require('node:child_process');
const {JSDOM}=require('jsdom');
const project=path.resolve(__dirname,'..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'overlay-tools-ui-'));
process.env.DATA_DIR=temp;process.env.HA_ENABLED='0';
const {PE,sha256}=require('./desktop-bootstrap-fixture'),{SignRelease}=require('../tools/sign-release-approval');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function worker(name,values){
 const source=fs.readFileSync(path.join(project,'tools',name),'utf8');
 const match=source.match(/\$script:Worker = @'\r?\n([\s\S]*?)\r?\n'@/);assert.ok(match,'embedded worker');
 const env={...process.env,...values};delete env.NODE_OPTIONS;delete env.NODE_PATH;
 return spawnSync(process.execPath,['--input-type=commonjs','-'],{input:match[1],encoding:'utf8',env});
}
function jsonFile(value){const text=JSON.stringify(value);return{size:Buffer.byteLength(text),text:async()=>text};}
(async()=>{
 let dom;
 try{
  const key=crypto.generateKeyPairSync('ed25519'),keyFile=path.join(temp,'offline.pem');
  fs.writeFileSync(keyFile,key.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
  let overlayApproval,overlayBytes;
  for(const component of ['A','B','O']){
   const bytes=PE(component),file=path.join(temp,component+'.exe'),output=path.join(temp,component+'.approval.json');fs.writeFileSync(file,bytes);
   const cli=SignRelease(component,'1.2.3',file,keyFile);
   assert.equal(cli.component,component);assert.equal(cli.sha256,sha256(bytes));assert.ok(!JSON.stringify(cli).includes('PRIVATE KEY'));
   const result=worker('Create_Approval.bat',{GC_APPROVAL_ACTION:'sign',GC_APPROVAL_COMPONENT:component,GC_APPROVAL_VERSION:'1.2.3',GC_APPROVAL_EXE:file,GC_APPROVAL_KEY:keyFile,GC_APPROVAL_OUTPUT:output});
   assert.equal(result.status,0,result.stderr);const approval=JSON.parse(fs.readFileSync(output,'utf8'));assert.equal(approval.component,component);assert.equal(approval.approval.signature,cli.approval.signature);
   const checked=worker('Check_Approval.bat',{GC_APPROVAL_ACTION:'inspect',GC_APPROVAL_COMPONENT:component,GC_APPROVAL_VERSION:'1.2.3',GC_APPROVAL_EXE:file,GC_APPROVAL_JSON:output});
   assert.equal(checked.status,0,checked.stderr);assert.equal(JSON.parse(checked.stdout).serverTrustChecked,false);
   if(component==='O'){
    overlayApproval=approval;overlayBytes=bytes;
    const swapped=worker('Check_Approval.bat',{GC_APPROVAL_ACTION:'inspect',GC_APPROVAL_COMPONENT:'B',GC_APPROVAL_VERSION:'1.2.3',GC_APPROVAL_EXE:file,GC_APPROVAL_JSON:output});assert.equal(swapped.status,1);assert.match(swapped.stderr,/UPLOAD_COMPONENT_MISMATCH/);
    const changed=JSON.parse(JSON.stringify(approval));changed.component='B';const bad=path.join(temp,'tampered.json');fs.writeFileSync(bad,JSON.stringify(changed));
    const forged=worker('Check_Approval.bat',{GC_APPROVAL_ACTION:'inspect',GC_APPROVAL_COMPONENT:'B',GC_APPROVAL_VERSION:'1.2.3',GC_APPROVAL_EXE:file,GC_APPROVAL_JSON:bad});assert.equal(forged.status,1);assert.match(forged.stderr,/SIGNATURE_INVALID/);
   }
  }
  dom=new JSDOM('<div id="content"></div><div id="modal-body"></div>',{url:'https://fixture.invalid/',runScripts:'outside-only'});
  const w=dom.window,requests=[];let close;
  Object.defineProperty(w,'crypto',{value:crypto.webcrypto});
  w.content=w.document.getElementById('content');w.session={role:'admin',csrf:'owner'};w.currentView='test';w.roleIsAdmin=()=>w.session.role==='admin';
  w.esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  w.renderCurrent=async()=>{};w.toast=()=>{};
  w.openModal=options=>{w.document.getElementById('modal-body').innerHTML=options.html;return new Promise(resolve=>{close=()=>{w.document.getElementById('modal-body').replaceChildren();resolve();};});};
  const candidates=['A','B','O'].map(c=>({id:'OLD_'+c,component:c,version:'1.0.0',sha256:'a'.repeat(64),active:true}));
  const listing={active:{A:'OLD_A',B:'OLD_B',O:'OLD_O'},candidates};
  w.api=async(url,options={})=>{
   requests.push({url,...options});
   if(url==='/api/desktop/bootstrap/security-operations')return listing;
   if(url.startsWith('/api/desktop/bootstrap/artifacts?')){const params=new URL(url,'https://fixture.invalid/').searchParams;assert.equal(params.get('component'),'O');assert.equal(options.headers['x-game-release-signature'],overlayApproval.approval.signature);const artifact={id:'NEW_O',component:'O',version:'1.2.3',sha256:sha256(overlayBytes)};candidates.push(artifact);return{artifact};}
   if(url.endsWith('/preview-pair'))return{preview:{...options.body,eligible:true,operationsRevision:4,policyRevision:5}};
   if(url.endsWith('/activate')){Object.assign(listing.active,{A:options.body.aId,B:options.body.bId,O:options.body.oId});return{ok:true};}
   if(url.endsWith('/deployment-note'))return{ok:true};
   throw Error('Unexpected request '+url);
  };
  new vm.Script(fs.readFileSync(path.join(project,'public/admin-desktop-workflow.js'),'utf8')).runInContext(dom.getInternalVMContext());
  assert.equal((await w.desktopApprovalRead(jsonFile(overlayApproval),'O')).component,'O');
  await assert.rejects(()=>w.desktopApprovalRead(jsonFile(overlayApproval),'B'));
  await assert.rejects(()=>w.desktopApprovalRead(jsonFile(null),'O'));
  await assert.rejects(()=>w.desktopApprovalRead(jsonFile({...overlayApproval,approval:{...overlayApproval.approval,signature:'bad'}}),'O'));
  await assert.rejects(()=>w.desktopApprovalRead({size:10,text:async()=>'-----BEGIN PRIVATE KEY-----'},'O'));
  const opened=w.showDesktopDeploymentWizard();await tick();
  const root=w.document.getElementById('desktop-deploy-wizard');assert.ok(root);assert.equal(root.querySelectorAll('[data-candidate]').length,3);assert.equal(root.querySelector('[data-candidate="O"]').value,'OLD_O');
  const exe={name:'GameOverlay.exe',size:overlayBytes.length,arrayBuffer:async()=>overlayBytes};
  Object.defineProperty(root.querySelector('[data-file="O"]'),'files',{value:[exe]});
  Object.defineProperty(root.querySelector('[data-approval="O"]'),'files',{value:[jsonFile(overlayApproval)]});
  root.querySelector('[data-version="O"]').value='1.2.3';await root.querySelector('#desktop-stage-selected').onclick();
  assert.equal(root.querySelector('[data-candidate="O"]').value,'NEW_O');
  await root.querySelector('#desktop-pair-preview').onclick();assert.equal(root.querySelector('#desktop-pair-publish').disabled,false);
  root.querySelector('#desktop-release-notes').value='Overlay study release';await root.querySelector('#desktop-pair-publish').onclick();
  const published=requests.find(r=>r.url.endsWith('/activate'));assert.equal(published.body.oId,'NEW_O');assert.equal(published.body.expectedRevision,4);
  assert.equal(requests.find(r=>r.url.endsWith('/deployment-note')).body.oId,'NEW_O');
  root.querySelector('[data-candidate="O"]').value='';root.querySelector('[data-candidate="O"]').dispatchEvent(new w.Event('change',{bubbles:true}));assert.equal(root.querySelector('#desktop-pair-publish').disabled,true);
  await root.querySelector('#desktop-pair-preview').onclick();assert.equal(requests.filter(r=>r.url.endsWith('/preview-pair')).at(-1).body.oId,'');
  close();await opened;
  console.log('OVERLAY TOOLS/UI PASS: A/B/O standalone signing and checking; signed component binding; private-key/malformed approval rejection; O candidate upload, selection, preview, deployment note and activation; explicit A/B-only compatibility.');
 }finally{dom?.window.close();fs.rmSync(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
