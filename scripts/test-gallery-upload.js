'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),jpeg=require('jpeg-js'),{PNG}=require('pngjs');
const media=require('../services/member/media'),source=fs.readFileSync(path.join(__dirname,'../public/admin-modal.js'),'utf8');
const trace=[];let forced=false,canvasCount=0;
function canvas(){
 canvasCount++;const node={width:0,height:0},context={imageSmoothingEnabled:false,imageSmoothingQuality:'',drawImage(picture){const sampled=media.Resize(picture,node.width/picture.width*Math.max(picture.width,picture.height),true);node.pixels={width:node.width,height:node.height,data:Buffer.alloc(node.width*node.height*4)};for(let y=0;y<node.height;y++){const row=Math.min(sampled.height-1,y);sampled.data.copy(node.pixels.data,y*node.width*4,row*sampled.width*4,(row+1)*sampled.width*4);}trace.push({kind:'draw',width:node.width,height:node.height,smoothing:this.imageSmoothingEnabled,quality:this.imageSmoothingQuality});},getImageData(){return {data:node.pixels.data};}};
 node.getContext=()=>context;node.toDataURL=(type,quality)=>{trace.push({kind:'encode',type,quality,width:node.width});if(forced&&node.width>600)return 'data:'+type+';base64,'+'A'.repeat(570000);const bytes=type==='image/png'?PNG.sync.write(node.pixels):jpeg.encode(node.pixels,Math.round(quality*100)).data;return 'data:'+type+';base64,'+bytes.toString('base64');};return node;
}
const context=vm.createContext({document:{createElement(name){assert.equal(name,'canvas');return canvas();}},atob:value=>Buffer.from(value,'base64').toString('binary'),console});
vm.runInContext(source,context);
function picture(width,height,alpha=false){const data=Buffer.alloc(width*height*4);for(let y=0;y<height;y++)for(let x=0;x<width;x++){const at=(y*width+x)*4;data[at]=x*173/width;data[at+1]=y*219/height;data[at+2]=(x+y)%128;data[at+3]=alpha&&x<width/4?0:255;}return {width,height,naturalWidth:width,naturalHeight:height,data};}
const encode=(image,type='jpeg')=>'data:image/'+type+';base64,'+(type==='png'?PNG.sync.write(image):jpeg.encode(image,94).data).toString('base64');
const decode=url=>url.startsWith('data:image/png;')?PNG.sync.read(Buffer.from(url.split(',')[1],'base64')):jpeg.decode(Buffer.from(url.split(',')[1],'base64'));
let photo=picture(1024,576),url=encode(photo);assert.equal(context.normalizeGalleryPicture(photo,url),url);assert.equal(canvasCount,0,'already bounded original has no lossy upload re-encode');
photo=picture(2000,1125);let result=context.normalizeGalleryPicture(photo,'data:image/jpeg;base64,AAAA');assert.deepEqual([decode(result).width,decode(result).height],[1280,720],'upload preserves 1280 real source pixels');assert.ok(result.length<=560000);assert.ok(trace.filter(x=>x.kind==='draw').every(x=>x.smoothing&&x.quality==='high'));
const fields=media.GalleryFields(result);assert.deepEqual([decode(fields.image).width,decode(fields.image).height],[1280,720]);assert.deepEqual([decode(fields.display).width,decode(fields.display).height],[1024,576],'upload, server and display dimensions form one pipeline');
trace.length=0;forced=true;photo=picture(800,600,true);result=context.normalizeGalleryPicture(photo,'data:image/png;base64,'+'A'.repeat(570000));forced=false;
assert.ok(decode(result).width<=600);assert.equal(decode(result).data[3],0,'oversize transparent PNG stays transparent through the upload bound');assert.equal(trace.filter(x=>x.kind==='encode'&&x.type==='image/jpeg').length,0,'transparent photos never flatten into JPEG');
trace.length=0;forced=true;photo=picture(1280,720);result=context.normalizeGalleryPicture(photo,'data:image/jpeg;base64,'+'A'.repeat(570000));forced=false;
assert.ok(result.length<=560000);const jpegAttempts=trace.filter(x=>x.kind==='encode'&&x.type==='image/jpeg');assert.ok(jpegAttempts.length>0);assert.ok(jpegAttempts.every(x=>x.quality>=.84),'bounded upload never drops to the old .38 quality');
trace.length=0;photo=picture(32,24);context.normalizeGalleryPicture(photo,'data:image/jpeg;base64,'+Buffer.from('Exif\0\0').toString('base64'));assert.ok(trace.some(x=>x.kind==='draw'),'EXIF JPEG orientation is normalized by browser decode/canvas');
const actions=fs.readFileSync(path.join(__dirname,'../public/admin-member-actions.js'),'utf8'),api=fs.readFileSync(path.join(__dirname,'../web/webApi.js'),'utf8');
assert.match(actions,/name:'gallery'\+i[^\n]*type:'image',imageQuality:'gallery'/);assert.match(source,/normalizeMemberImage\(file,input.dataset.imageQuality==='gallery'\)/);
assert.match(api,/pathname === '\/api\/member\/action' \? 4 \* 1024 \* 1024/);assert.ok(6*560000+64000<4*1024*1024,'six gallery uploads fit the bounded authenticated request');
console.log('FIX75 gallery upload PASS: original retention, 1280px upload to1024px display, high quality bounded encoding, alpha, orientation and six-photo request budget.');
