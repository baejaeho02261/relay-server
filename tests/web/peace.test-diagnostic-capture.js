'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM, VirtualConsole} = require('jsdom');
const {PNG} = require('pngjs');
const root = path.resolve(__dirname, '../..');
const html = fs.readFileSync(path.join(root,'public/diagnostics.html'),'utf8');
const script = fs.readFileSync(path.join(root,'public/scripts/diagnostics/peace.diagnostic-capture.js'),'utf8');
const token = 'A'.repeat(24)+'.'+'b'.repeat(64);
const tick = () => new Promise(resolve => setImmediate(resolve));
async function until(check) { for(let n=0;n<80;n++) { if(check())return; await tick(); } assert.fail('Timed out waiting for synthetic UI'); }
function fixture(options={}) {
  const errors=[], requests=[], streams=[], contexts=new Map(), urls=new Set();
  const console = new VirtualConsole(); console.on('jsdomError',e=>errors.push(e.message));
  const dom = new JSDOM(html,{url:'https://fixture.invalid/diagnostics.html#token='+token,runScripts:'outside-only',pretendToBeVisual:true,virtualConsole:console});
  const w=dom.window, d=w.document; let calls=0, draws=0, uploads=0, selectResolve=null, imageResolve=null, aborts=0, playReject=null, monotonic=0;
  Object.defineProperty(w,'isSecureContext',{value:true}); w.Blob=Blob; w.AbortController=AbortController;
  if(options.clockSkew)w.Date.now=()=>Date.now()+options.clockSkew;
  if(options.monotonic)w.performance.now=()=>monotonic;
  w.URL.createObjectURL=()=>{const url='blob:fixture/'+urls.size;urls.add(url);return url;}; w.URL.revokeObjectURL=url=>urls.delete(url);
  Object.defineProperty(w.HTMLVideoElement.prototype,'videoWidth',{get:()=>640});Object.defineProperty(w.HTMLVideoElement.prototype,'videoHeight',{get:()=>360});
  w.HTMLMediaElement.prototype.play=function(){if(!options.waitVideo)queueMicrotask(()=>this.onloadeddata?.());if(options.rejectPlayLater)return new Promise((_resolve,reject)=>{playReject=reject;});return Promise.resolve();};w.HTMLMediaElement.prototype.pause=function(){};
  w.HTMLCanvasElement.prototype.getContext=function(){
    if(!contexts.has(this)) {
      const canvas=this,context={fillStyle:'#000',data:null,width:0,height:0,
        ensure(){if(this.width!==canvas.width||this.height!==canvas.height){this.width=canvas.width;this.height=canvas.height;this.data=new Uint8Array(canvas.width*canvas.height*4);}},
        fillRect(x,y,width,height){this.ensure();for(let j=y;j<y+height;j++)for(let i=x;i<x+width;i++){const at=(j*canvas.width+i)*4;this.data[at]=this.data[at+1]=this.data[at+2]=0;this.data[at+3]=255;}},
        drawImage(){this.ensure();draws++;for(let at=0;at<this.data.length;at+=4){this.data[at]=41;this.data[at+1]=91;this.data[at+2]=149;this.data[at+3]=255;}}};contexts.set(this,context);
    }return contexts.get(this);
  };
  w.HTMLCanvasElement.prototype.toBlob=function(callback){const context=this.getContext('2d');context.ensure();const png=new PNG({width:this.width,height:this.height});png.data=Buffer.from(context.data);queueMicrotask(()=>callback(new Blob([PNG.sync.write(png)],{type:'image/png'})));};
  w.Image=function(){const element=d.createElement('img');Object.defineProperty(element,'naturalWidth',{value:320});Object.defineProperty(element,'naturalHeight',{value:180});Object.defineProperty(element,'src',{set(){imageResolve=()=>element.onload?.();if(!options.waitImage)queueMicrotask(imageResolve);}});return element;};
  function makeStream(){const video={kind:'video',readyState:'live',stops:0,stop(){this.stops++;this.readyState='ended';}},audio={kind:'audio',readyState:'live',stops:0,stop(){this.stops++;this.readyState='ended';}};const stream={getTracks:()=>[video,audio],getVideoTracks:()=>[video]};streams.push(stream);return stream;}
  Object.defineProperty(w.navigator,'mediaDevices',{value:{getDisplayMedia:async config=>{calls++;assert.equal(config.audio,false);assert.equal(config.video,true);if(options.waitSelect)return await new Promise(resolve=>{selectResolve=()=>resolve(makeStream());});return makeStream();}}});
  w.fetch=async(url,request)=>{
    assert.equal(w.location.hash,'');assert.equal(w.location.search,'');assert.ok(!url.includes(token));assert.equal(request.credentials,'omit');assert.equal(request.cache,'no-store');assert.equal(request.redirect,'error');assert.equal(request.referrerPolicy,'no-referrer');assert.equal(request.headers.Authorization,'Bearer '+token);
    requests.push({url,...request});request.signal.addEventListener('abort',()=>aborts++);
    if(url.endsWith('/status')) { const serverTime=Date.now();monotonic+=options.statusLatency||0;return {ok:true,json:async()=>({ok:true,status:options.statusUploaded&&uploads?'UPLOADED':options.statusReceiving&&uploads?'RECEIVING':'AVAILABLE',serverTime,expiresAt:serverTime+(options.remaining??600000),maxPngBytes:2097152,maxWidth:4096,maxHeight:4096,maxPixels:4194304,retentionHours:24,consentVersion:1,...(Object.hasOwn(options,'context')?{context:uploads&&Object.hasOwn(options,'retryContext')?options.retryContext:options.context}:{})})}; }
    assert.equal(url,'/api/diagnostic-capture/upload');uploads++;
    if(options.uploadHook)return options.uploadHook(url,request,uploads);
    return {ok:true,json:async()=>({ok:true})};
  };
  w.eval(script);
  const $=id=>d.getElementById(id),click=id=>$(id).click(),check=id=>{$(id).checked=true;$(id).dispatchEvent(new w.Event('change'));};
  return {w,d,$,click,check,requests,streams,urls,errors,contexts,get calls(){return calls;},get draws(){return draws;},get uploads(){return uploads;},get aborts(){return aborts;},select:()=>selectResolve?.(),image:()=>imageResolve?.(),rejectPlay:()=>playReject?.(Error('late cancelled video')),async ready(){await until(()=>$('capture-consent').disabled===false);},async capture(){check('capture-consent');click('capture-display');await until(()=>$('preview-panel').hidden===false);await tick();},close(){w.dispatchEvent(new w.Event('pagehide'));w.close();assert.deepEqual(errors,[]);}};
}
test('no capture or upload until separate explicit actions; fragment erased; all tracks stop after one frame',async()=>{
  const f=fixture();try{await f.ready();assert.equal(f.calls,0);assert.equal(f.uploads,0);assert.equal(f.w.location.href,'https://fixture.invalid/diagnostics.html');f.click('capture-display');assert.equal(f.calls,0);await f.capture();assert.equal(f.calls,1);assert.equal(f.draws,1);for(const track of f.streams[0].getTracks())assert.ok(track.stops>=1);assert.equal(f.uploads,0);f.click('capture-send');assert.equal(f.uploads,0);f.check('send-consent');f.click('capture-send');await until(()=>f.uploads===1);await until(()=>f.$('capture-preview').width===0);assert.match(f.$('diagnostic-status').textContent,/접수했습니다/);assert.equal(f.requests.at(-1).headers['X-Diagnostic-Consent'],'1');assert.match(f.requests.at(-1).headers['X-Diagnostic-Request'],/^[a-f0-9-]{36}$/); }finally{f.close();}
});
test('redaction changes transmitted pixels, removes prior consent and has no original restore path',async()=>{
  let received;const f=fixture({uploadHook:async(_u,r)=>{received=PNG.sync.read(Buffer.from(await r.body.arrayBuffer()));return {ok:true,json:async()=>({ok:true})};}});
  try{await f.ready();await f.capture();f.check('send-consent');for(const[id,value]of[['redact-x',10],['redact-y',20],['redact-width',30],['redact-height',40]])f.$(id).value=value;f.click('redact-apply');assert.equal(f.$('send-consent').checked,false);assert.equal(f.$('capture-send').disabled,true);f.check('send-consent');f.click('capture-send');await until(()=>received);const at=(20*received.width+10)*4;assert.deepEqual([...received.data.slice(at,at+4)],[0,0,0,255]);assert.deepEqual([...received.data.slice(0,4)],[41,91,149,255]);assert.equal(f.draws,1);}finally{f.close();}
});
test('redaction drag invalidates prior consent immediately and blocks send until committed',async()=>{
  const f=fixture();try{await f.ready();await f.capture();const canvas=f.$('capture-preview');canvas.getBoundingClientRect=()=>({left:0,top:0,width:640,height:360});f.check('send-consent');const down=new f.w.MouseEvent('pointerdown',{clientX:10,clientY:20,button:0});Object.defineProperty(down,'pointerId',{value:1});canvas.dispatchEvent(down);assert.equal(f.$('send-consent').checked,false);f.check('send-consent');assert.equal(f.$('capture-send').disabled,true);const staleCancel=new f.w.MouseEvent('pointercancel');Object.defineProperty(staleCancel,'pointerId',{value:2});canvas.dispatchEvent(staleCancel);assert.equal(f.$('capture-send').disabled,true);f.click('capture-send');assert.equal(f.uploads,0);const up=new f.w.MouseEvent('pointerup',{clientX:40,clientY:60,button:0});Object.defineProperty(up,'pointerId',{value:1});canvas.dispatchEvent(up);assert.equal(f.$('send-consent').checked,false);assert.equal(f.$('capture-send').disabled,true);assert.equal(f.uploads,0);}finally{f.close();}
});
test('cancelling selection retires late streams without any frame or transmission',async()=>{
  const f=fixture({waitSelect:true});try{await f.ready();f.check('capture-consent');f.click('capture-display');assert.equal(f.calls,1);f.click('capture-cancel');f.select();await tick();await tick();assert.equal(f.draws,0);assert.equal(f.uploads,0);for(const track of f.streams[0].getTracks())assert.ok(track.stops>=1);assert.equal(f.$('capture-preview').width,0);}finally{f.close();}
});
test('page departure while a stream waits for pixels stops all tracks and stale callbacks cannot draw',async()=>{
  const f=fixture({waitVideo:true});try{await f.ready();f.check('capture-consent');f.click('capture-display');await until(()=>f.streams.length===1);await tick();f.w.dispatchEvent(new f.w.Event('pagehide'));await tick();assert.equal(f.draws,0);assert.equal(f.uploads,0);for(const track of f.streams[0].getTracks())assert.ok(track.stops>=1);assert.equal(f.$('capture-preview').width,0);}finally{f.close();}
});
test('manual PNG decode is bounded before pixels and cancellation revokes object URLs',async()=>{
  const f=fixture({waitImage:true});try{await f.ready();f.check('capture-consent');const png=new PNG({width:320,height:180});const file=new Blob([PNG.sync.write(png)],{type:'image/png'});Object.defineProperty(f.$('capture-file'),'files',{value:[file],configurable:true});f.$('capture-file').dispatchEvent(new f.w.Event('change'));await until(()=>f.urls.size===1);f.click('capture-cancel');f.image();await tick();assert.equal(f.urls.size,0);assert.equal(f.draws,0);assert.equal(f.calls,0);assert.equal(f.uploads,0);assert.equal(f.$('capture-file').value,'');}finally{f.close();}
});
test('oversized PNG header is rejected before allocating decode URL',async()=>{
  const f=fixture();try{await f.ready();f.check('capture-consent');const bytes=Buffer.alloc(33);Buffer.from([137,80,78,71,13,10,26,10]).copy(bytes);bytes.writeUInt32BE(13,8);bytes.write('IHDR',12);bytes.writeUInt32BE(100000,16);bytes.writeUInt32BE(180,20);bytes[24]=8;bytes[25]=6;Object.defineProperty(f.$('capture-file'),'files',{value:[new Blob([bytes],{type:'image/png'})]});f.$('capture-file').dispatchEvent(new f.w.Event('change'));await until(()=>/PNG를 읽지 못했습니다/.test(f.$('diagnostic-status').textContent));assert.equal(f.urls.size,0);assert.equal(f.draws,0);assert.equal(f.uploads,0);}finally{f.close();}
});
test('late cancelled video rejection cannot retire a newer manual PNG decode',async()=>{
  const f=fixture({waitVideo:true,rejectPlayLater:true,waitImage:true});try{await f.ready();f.check('capture-consent');f.click('capture-display');await until(()=>f.streams.length===1);await tick();f.click('capture-cancel');f.check('capture-consent');const png=new PNG({width:320,height:180});Object.defineProperty(f.$('capture-file'),'files',{value:[new Blob([PNG.sync.write(png)],{type:'image/png'})]});f.$('capture-file').dispatchEvent(new f.w.Event('change'));await until(()=>f.urls.size===1);f.rejectPlay();await tick();assert.equal(f.urls.size,1);f.image();await until(()=>f.$('preview-panel').hidden===false);assert.equal(f.draws,1);assert.equal(f.uploads,0);}finally{f.close();}
});
test('lost upload response requires explicit retry with immutable PNG and exact request id',async()=>{
  const f=fixture({uploadHook:async(_u,_r,n)=>{if(n===1)throw Error('network lost');return {ok:true,json:async()=>({ok:true})};}});
  try{await f.ready();await f.capture();f.check('send-consent');f.click('capture-send');await until(()=>f.$('capture-retry').hidden===false);assert.equal(f.uploads,1);await tick();assert.equal(f.uploads,1);f.click('capture-retry');await until(()=>f.uploads===2);const sent=f.requests.filter(r=>r.url.endsWith('/upload'));assert.equal(sent[0].headers['X-Diagnostic-Request'],sent[1].headers['X-Diagnostic-Request']);assert.equal(sent[0].body,sent[1].body);await until(()=>f.$('capture-preview').width===0);}finally{f.close();}
});
test('status resolves an uncertain committed upload without resending; upload cancel does not promise recall',async()=>{
  const f=fixture({statusUploaded:true,uploadHook:async()=>{throw Error('response lost');}});try{await f.ready();await f.capture();f.check('send-consent');f.click('capture-send');await until(()=>!f.$('capture-retry').hidden);assert.match(f.$('diagnostic-status').textContent,/이미 접수되었을 수/);f.click('capture-retry');await until(()=>f.$('capture-preview').width===0);assert.equal(f.uploads,1);}finally{f.close();}
  const g=fixture({uploadHook:async()=>{throw Error('response lost');}});try{await g.ready();await g.capture();g.check('send-consent');g.click('capture-send');await until(()=>!g.$('capture-retry').hidden);g.click('capture-cancel');assert.match(g.$('diagnostic-status').textContent,/서버에 이미 도착했는지는/);assert.equal(g.$('capture-preview').width,0);}finally{g.close();}
});
test('RECEIVING status never starts another upload or an automatic polling loop',async()=>{
  const f=fixture({statusReceiving:true,uploadHook:async()=>{throw Error('network lost');}});try{await f.ready();await f.capture();f.check('send-consent');f.click('capture-send');await until(()=>!f.$('capture-retry').hidden);f.click('capture-retry');await until(()=>/기존 전송을 처리/.test(f.$('diagnostic-status').textContent));const requestCount=f.requests.length;assert.equal(f.uploads,1);await tick();await tick();assert.equal(f.requests.length,requestCount);assert.equal(f.$('capture-retry').hidden,false);assert.equal(f.$('capture-display').disabled,true);}finally{f.close();}
});
test('PC wall-clock skew does not reject a valid bounded server invitation',async()=>{
  for(const clockSkew of [-86400000,86400000]) { const f=fixture({clockSkew});try{await f.ready();await f.capture();assert.equal(f.draws,1);assert.equal(f.uploads,0);for(const track of f.streams[0].getTracks())assert.ok(track.stops>=1);}finally{f.close();} }
});
test('remaining lifetime is bounded and status transit time cannot extend it',async()=>{
  for(const options of [{monotonic:true,remaining:1000,statusLatency:1001},{remaining:600001},{remaining:0}]) {const f=fixture(options);try{await until(()=>/사용할 수 없습니다/.test(f.$('diagnostic-status').textContent));assert.equal(f.$('capture-consent').disabled,true);assert.equal(f.calls,0);assert.equal(f.uploads,0);}finally{f.close();}}
});
test('standalone page has no persistence, recording, external resources or automatic capture hooks',()=>{
  assert.doesNotMatch(script,/localStorage|sessionStorage|indexedDB|MediaRecorder|sendBeacon|serviceWorker\.register|console\.|toDataURL/);
  assert.doesNotMatch(html,/(?:src|href)=["']https?:/);assert.match(html,/name="referrer" content="no-referrer"/);
  assert.equal((script.match(/getDisplayMedia\(\{/g)||[]).length,1);assert.equal((script.match(/drawImage\(/g)||[]).length,1);
});

test('A/B/O run context is shown before consent and never starts capture itself',async()=>{
  for(const role of ['A','B','O']){
    const context={flowId:'F'.repeat(24),role},f=fixture({context});
    try{await f.ready();assert.match(f.$('diagnostic-context').textContent,new RegExp(role+' · 실행 '+context.flowId));assert.equal(f.$('capture-consent').checked,false);assert.equal(f.$('send-consent').checked,false);assert.equal(f.calls,0);assert.equal(f.uploads,0);f.w.dispatchEvent(new f.w.Event('pagehide'));assert.equal(f.$('diagnostic-context').textContent,'');}finally{f.close();}
  }
});
test('invalid or injected run contexts fail closed before consent',async()=>{
  for(const context of [null,[],{flowId:'F'.repeat(24),role:'X'},{flowId:'<img src=x>',role:'O'},{flowId:'F'.repeat(24),role:'A',sessionToken:'forbidden'}]){
    const f=fixture({context});try{await until(()=>/사용할 수 없습니다/.test(f.$('diagnostic-status').textContent));assert.equal(f.$('capture-consent').disabled,true);assert.equal(f.calls,0);assert.equal(f.uploads,0);assert.equal(f.$('diagnostic-context').textContent,'');}finally{f.close();}
  }
});
test('retry cannot send a preview under a different run association',async()=>{
  const f=fixture({context:{flowId:'F'.repeat(24),role:'O'},retryContext:{flowId:'E'.repeat(24),role:'A'},uploadHook:async()=>{throw Error('response lost');}});
  try{await f.ready();await f.capture();f.check('send-consent');f.click('capture-send');await until(()=>!f.$('capture-retry').hidden);f.click('capture-retry');await until(()=>/연결 정보가 달라/.test(f.$('diagnostic-status').textContent));assert.equal(f.uploads,1);assert.equal(f.$('capture-preview').width,0);assert.equal(f.$('capture-consent').disabled,true);}finally{f.close();}
});
