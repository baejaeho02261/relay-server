'use strict';
const s=require('./store'),jpeg=require('jpeg-js'),{PNG}=require('pngjs');
function Decode(value){
 const m=/^data:image\/(png|jpeg);base64,([A-Za-z0-9+/]+={0,2})$/.exec(value||'');
 if(!m||m[2].length>600000)s.Fail('CONTENT_IMAGE_INVALID');
 const b=Buffer.from(m[2],'base64');let image;
 try{
  if(m[1]==='png'){
   if(b.length<24||b.subarray(0,8).toString('hex')!=='89504e470d0a1a0a'||b.readUInt32BE(16)>1280||b.readUInt32BE(20)>1280)throw Error('size');
   image=PNG.sync.read(b,{checkCRC:true});
  }else image=jpeg.decode(b,{useTArray:true,maxResolutionInMP:1.7,maxMemoryUsageInMB:64});
  if(!image.width||!image.height||image.width>1280||image.height>1280)throw Error('size');
 }catch(_){s.Fail('CONTENT_IMAGE_INVALID');}
 return image;
}
function Resize(image,edge,preserveAlpha=false){
 const ratio=Math.min(1,edge/Math.max(image.width,image.height)),width=Math.max(1,Math.round(image.width*ratio)),height=Math.max(1,Math.round(image.height*ratio)),data=Buffer.alloc(width*height*4);
 // Bilinear sampling avoids the jagged text and hard edges of nearest-neighbour previews.
 for(let y=0;y<height;y++)for(let x=0;x<width;x++){
  const sx=Math.max(0,Math.min(image.width-1,(x+.5)*image.width/width-.5)),sy=Math.max(0,Math.min(image.height-1,(y+.5)*image.height/height-.5)),x0=Math.floor(sx),y0=Math.floor(sy),fx=sx-x0,fy=sy-y0,o=(y*width+x)*4;
  const points=[[(y0*image.width+x0)*4,(1-fx)*(1-fy)],[(y0*image.width+Math.min(x0+1,image.width-1))*4,fx*(1-fy)],[(Math.min(y0+1,image.height-1)*image.width+x0)*4,(1-fx)*fy],[(Math.min(y0+1,image.height-1)*image.width+Math.min(x0+1,image.width-1))*4,fx*fy]];
  if(preserveAlpha){
   let alpha=0;for(const [i,w]of points)alpha+=image.data[i+3]*w;
   for(let c=0;c<3;c++){let value=0;for(const [i,w]of points)value+=image.data[i+c]*(image.data[i+3]/255)*w;data[o+c]=alpha>0?Math.round(value*255/alpha):0;}data[o+3]=Math.round(alpha);
  }else{for(let c=0;c<3;c++){let value=0;for(const [i,w]of points){const alpha=image.data[i+3]/255;value+=(image.data[i+c]*alpha+255*(1-alpha))*w;}data[o+c]=Math.round(value);}data[o+3]=255;}
 }
 return {width,height,data};
}
function Encoded(image,edge,max){
 // Bound each wire image; detailed/noisy photos shrink instead of failing late.
 for(let pass=0;pass<6;pass++){
  const resized=Resize(image,Math.max(96,Math.floor(edge*Math.pow(0.8,pass))));
  for(let quality=88;quality>=64;quality-=12){const b=jpeg.encode(resized,quality).data;if(b.length<=max)return 'data:image/jpeg;base64,'+b.toString('base64');}
 }
 s.Fail('CONTENT_IMAGE_INVALID');
}
function HasAlpha(image){for(let index=3;index<image.data.length;index+=4)if(image.data[index]<255)return true;return false;}
function PostEncoded(image,edge,max){
 if(!HasAlpha(image))return Encoded(image,edge,max);
 // Cutout stickers keep alpha at every size. Premultiplied interpolation avoids
 // dark/white fringes; re-encoding also strips uploaded metadata/chunks.
 for(let pass=0;pass<12;pass++){
  const resized=Resize(image,Math.max(24,Math.floor(edge*Math.pow(.78,pass))),true),bytes=PNG.sync.write(resized,{colorType:6,inputColorType:6,deflateLevel:6});
  if(bytes.length<=max)return 'data:image/png;base64,'+bytes.toString('base64');
 }
 s.Fail('CONTENT_IMAGE_INVALID');
}
function Fields(value,previous={}){
 if(value===undefined)return {image:previous.image||'',imageThumb:previous.imageThumb||''};
 if(value==='')return {image:'',imageThumb:''};
 if(typeof value!=='string')s.Fail('CONTENT_IMAGE_INVALID');
 const image=Decode(value);return {image:Encoded(image,960,180000),imageThumb:Encoded(image,160,12000)};
}
function PostPosition(value,previous={}){
 if(value===undefined)return previous.imagePosition==='before'?'before':'after';
 if(!['before','after'].includes(value))s.Fail('INPUT_INVALID');return value;
}
function PostFields(value,previous={}){
 if(value===undefined)return {image:previous.image||'',imageFeed:previous.imageFeed||'',imageFeedVersion:previous.imageFeedVersion||0,imageThumb:previous.imageThumb||''};
 if(value==='')return {image:'',imageFeed:'',imageFeedVersion:2,imageThumb:''};
 if(typeof value!=='string')s.Fail('CONTENT_IMAGE_INVALID');const image=Decode(value);
 const original=value.startsWith('data:image/jpeg;base64,')&&Buffer.from(value.split(',')[1],'base64').length<=420000?value:PostEncoded(image,1280,420000);
 return {image:original,imageFeed:PostEncoded(image,720,70000),imageFeedVersion:2,imageThumb:PostEncoded(image,160,12000)};
}
function GalleryFields(value){
 if(typeof value!=='string')s.Fail('CONTENT_IMAGE_INVALID');
 const image=Decode(value),bytes=Buffer.from(value.split(',')[1],'base64');
 // Keep the validated full-resolution JPEG; PNG re-encoding retains its pixels
 // and alpha while dropping ancillary metadata. Originals and displays have
 // independent bounds, so generating a catalog image never replaces its source.
 let original;
 if(value.startsWith('data:image/jpeg;base64,')&&bytes.length<=420000)original=value;
 else if(value.startsWith('data:image/png;base64,')){
  const png=PNG.sync.write(image,{colorType:6,inputColorType:6,deflateLevel:6});
  if(png.length<=420000)original='data:image/png;base64,'+png.toString('base64');
 }
 return {image:original||PostEncoded(image,1280,420000),display:PostEncoded(image,1024,180000),displayVersion:1,thumb:PostEncoded(image,160,12000)};
}
const galleryCache=new Map();
function GalleryDisplay(entry){
 if(entry.displayVersion===1&&entry.display)return entry.display;
 const source=entry.image||entry.thumb||'';if(!source)return '';
 if(galleryCache.has(source))return galleryCache.get(source);
 let display='';try{display=PostEncoded(Decode(source),1024,180000);}catch(_){
  if(entry.thumb&&entry.thumb!==source)try{display=PostEncoded(Decode(entry.thumb),1024,180000);}catch(_){}
 }
 // Old galleries gain a density-appropriate display only in this bounded read
 // cache. Polling never migrates or re-encodes the stored original or thumbnail.
 if(galleryCache.size>=16)galleryCache.delete(galleryCache.keys().next().value);galleryCache.set(source,display);return display;
}
const previewCache=new Map(),legacyCache=new Map();
function LegacyFeedImage(post){
 const value=post.imageFeed||post.imageThumb||'';if(!value||value.length<=37360)return value;
 if(legacyCache.has(value))return legacyCache.get(value);
 let result;try{result=PostEncoded(Decode(value),480,28000);}catch(_){return post.imageThumb||'';}
 if(legacyCache.size>=16)legacyCache.delete(legacyCache.keys().next().value);legacyCache.set(value,result);return result;
}
function FeedImage(post){
 if(!post.image||post.imageFeedVersion===2)return post.imageFeed||post.imageThumb||'';
 if(previewCache.has(post.image))return previewCache.get(post.image);
 let value;try{value=PostEncoded(Decode(post.image),720,70000);}catch(_){return post.imageFeed||post.imageThumb||'';}
 if(previewCache.size>=16)previewCache.delete(previewCache.keys().next().value);previewCache.set(post.image,value);return value;
}
function Url(value){const text=s.Text(value,350);if(!text)return '';let url;try{url=new URL(text);}catch(_){s.Fail('CONTENT_URL_INVALID');}if(!['https:','http:'].includes(url.protocol)||url.username||url.password)s.Fail('CONTENT_URL_INVALID');return url.href;}
function GameDetails(value,previous={}){
 if(value===undefined)value=previous||{};
 if(!value||typeof value!=='object'||Array.isArray(value))s.Fail('INPUT_INVALID');
 const result={};for(const key of ['releaseDate','developer','publisher','genre','ageRating','language','platform'])result[key]=s.Text(value[key],120);
 // Official and social channels are no longer exposed by the game directory.

 return result;
}
module.exports={Fields,PostFields,PostPosition,GameDetails,FeedImage,LegacyFeedImage,GalleryFields,GalleryDisplay,Resize};
