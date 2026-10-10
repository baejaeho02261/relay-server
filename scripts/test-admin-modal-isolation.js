'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{JSDOM}=require('jsdom');
const dom=new JSDOM('<div id="modal"><h1 id="title"></h1><div id="body"></div><button id="confirm"></button><button id="cancel"></button></div>',{runScripts:'outside-only'});
const w=dom.window,d=w.document,c=dom.getInternalVMContext();
vm.runInContext("const modalEl=document.getElementById('modal'),modalTitle=document.getElementById('title'),modalBody=document.getElementById('body'),modalConfirm=document.getElementById('confirm'),modalCancel=document.getElementById('cancel');function esc(v){return String(v??'')}",c);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../public/admin-modal.js'),'utf8'),c);
(async()=>{try{
 const parent=w.openModal({html:'<input id="draft" value="preserved">'}),draft=d.getElementById('draft');let clicks=0;draft.onclick=()=>clicks++;
 const owner=w.captureAdminModalOwner(),child=w.openModal({isolated:true,fields:[{name:'secret',type:'password',value:'temporary'}]});
 assert.equal(d.getElementById('draft'),draft);assert.equal(d.getElementById('modal').inert,true);
 const secret=d.querySelector('[data-modal-field="secret"]');d.querySelector('[data-modal-cancel]').click();assert.equal(await child,null);assert.equal(secret.value,'');assert.equal(d.getElementById('modal').inert,false);assert.equal(owner(),true);draft.click();assert.equal(clicks,1);
 const second=w.openModal({isolated:true,fields:[{name:'secret',type:'password'}]});w.closeAdminModals();assert.equal(await second,null);assert.equal(await parent,null);assert.equal(owner(),false);assert.equal(d.querySelector('.modal-isolated'),null);
 console.log('PASS Reauthentication preserves parent form/handlers; cancellation wipes input; logout closes both promises and invalidates owner.');
}finally{dom.window.close()}})().catch(e=>{console.error(e);process.exitCode=1});
