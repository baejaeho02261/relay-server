'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),jpeg=require('jpeg-js'),{PNG}=require('pngjs');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix75-gallery-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const s=require('../services/member/store'),commerce=require('../services/member/commerce'),media=require('../services/member/media'),database=require('../storage/database');
const bytes=value=>Buffer.from(value.split(',')[1],'base64');
const decode=value=>value.startsWith('data:image/png;')?PNG.sync.read(bytes(value)):jpeg.decode(bytes(value),{useTArray:true});
const dimensions=value=>{const image=decode(value);return [image.width,image.height];};
function picture(width,height,alpha=false){
 const image={width,height,data:Buffer.alloc(width*height*4)};
 for(let y=0;y<height;y++)for(let x=0;x<width;x++){
  const at=(y*width+x)*4,panel=x>width*.2&&x<width*.8&&y>height*.2&&y<height*.8,grid=panel&&(x%24<2||y%24<2);
  image.data[at]=grid?225:Math.round(30+180*x/width);image.data[at+1]=grid?220:Math.round(35+170*y/height);image.data[at+2]=grid?240:panel?150:60;
  image.data[at+3]=alpha&&x<width*.15?0:255;
 }
 return image;
}
const asPNG=image=>'data:image/png;base64,'+PNG.sync.write(image).toString('base64');
const asJPEG=image=>'data:image/jpeg;base64,'+jpeg.encode(image,96).data.toString('base64');
function psnr(actual,expected){let sum=0;assert.deepEqual([actual.width,actual.height],[expected.width,expected.height]);for(let i=0;i<actual.data.length;i+=4)for(let c=0;c<3;c++)sum+=(actual.data[i+c]-expected.data[i+c])**2;return 10*Math.log10(255**2/(sum/(actual.width*actual.height*3)));}
function bounded(value,max){assert.ok(bytes(value).length<=max);const image=decode(value);assert.ok(image.width>0&&image.height>0&&image.width<=1280&&image.height<=1280);}
try{
 commerce.EnsureCatalog();
 const landscape=asJPEG(picture(1280,720)),portrait=asPNG(picture(720,1280)),cutout=asPNG(picture(800,600,true));
 assert.ok(bytes(landscape).length<=420000,'fixture exercises exact original preservation');
 const saved=commerce.SaveProduct({gameKey:'PUBG',description:'사진 품질 검증',genre:'배틀로얄',price:100,published:true,gallery:[landscape,portrait,cutout]}),row=s.DB().products[saved.id];
 assert.equal(row.gallery[0].image,landscape,'validated JPEG original is preserved byte for byte');
 assert.deepEqual(decode(row.gallery[1].image).data,decode(portrait).data,'bounded PNG retains all original pixels');
 assert.equal(decode(row.gallery[2].image).data[3],0,'original cutout keeps transparency');
 const catalog=commerce.Catalog({summary:true}).items.find(x=>x.id===saved.id);
 assert.deepEqual(dimensions(catalog.gallery[0].image),[1024,576],'landscape is a real 1024-pixel display with its complete aspect ratio');
 assert.deepEqual(dimensions(catalog.gallery[1].image),[576,1024],'portrait is not stretched or square-cropped');
 assert.deepEqual(dimensions(catalog.gallery[2].image),[800,600],'small original is never upscaled');
 assert.equal(decode(catalog.gallery[2].image).data[3],0,'catalog cutout keeps transparency');
 assert.deepEqual(dimensions(catalog.gallery[0].thumb),[160,90],'separate small fallback remains available');
 assert.ok(psnr(decode(catalog.gallery[0].image),media.Resize(decode(landscape),1024))>30,'display preserves actual color and fine grid detail');
 for(const gallery of row.gallery){bounded(gallery.image,420000);bounded(gallery.display,180000);bounded(gallery.thumb,12000);}
 assert.equal(commerce.Product({id:saved.id}).product.gallery[0].image,landscape,'detail uses the full-quality source');
 const preserved=JSON.stringify(row.gallery);commerce.SaveProduct({id:saved.id,gameKey:'PUBG',revision:row.revision,description:'설명 수정',genre:'배틀로얄',published:true});assert.equal(JSON.stringify(s.DB().products[saved.id].gallery),preserved,'an omitted upload preserves all original and display fields');
 const beforeInvalid=JSON.stringify(s.DB());
 const excessive=asPNG(picture(1281,4));
 for(const gallery of [[landscape,'data:image/png;base64,AAAA'],['https://invalid.example/photo.png'],['data:image/svg+xml;base64,PHN2Zy8+'],[null],[{}],Array(7).fill(landscape),[excessive]])assert.throws(()=>commerce.SaveProduct({id:saved.id,gameKey:'PUBG',description:'실패',genre:'배틀로얄',published:true,gallery}),/CONTENT_IMAGE_INVALID/);
 assert.equal(JSON.stringify(s.DB()),beforeInvalid,'invalid uploads cannot partially edit a gallery');
 const save=database.SaveDatabase;database.SaveDatabase=()=>false;
 try{assert.throws(()=>commerce.SaveProduct({id:saved.id,gameKey:'PUBG',description:'저장 실패',genre:'배틀로얄',published:true,gallery:[portrait]}),/STORAGE_SAVE_FAILED/);}finally{database.SaveDatabase=save;}
 assert.equal(JSON.stringify(s.DB()),beforeInvalid,'failed commits restore originals');
 // A realistic FIX74 row contains only the old 960-pixel source and tiny thumb.
 const old=media.Fields(landscape),legacy=s.DB().products[saved.id];legacy.gallery=[{image:old.image,thumb:old.imageThumb},{image:landscape,thumb:old.imageThumb}];
 const legacyBefore=JSON.stringify(s.DB());let writes=0;database.SaveDatabase=()=>{writes++;throw Error('read attempted database write');};
 try{
  const list=commerce.Catalog({summary:true}).items.find(x=>x.id===saved.id);
  assert.deepEqual(dimensions(list.gallery[0].image),[960,540],'legacy image is regenerated from its best surviving original');
  assert.deepEqual(dimensions(list.gallery[1].image),[1024,576],'legacy 160-pixel thumb does not determine display quality');
  assert.equal(commerce.Product({id:saved.id}).product.gallery[1].image,landscape);
  const encode=jpeg.encode;let encodes=0;jpeg.encode=(...args)=>{encodes++;return encode(...args);};
  try{commerce.Catalog({summary:true});assert.equal(encodes,0,'repeat reads use the bounded display cache');}finally{jpeg.encode=encode;}
 }finally{database.SaveDatabase=save;}
 assert.equal(writes,0);assert.equal(JSON.stringify(s.DB()),legacyBefore,'lazy regeneration never migrates, changes revisions or replaces stored bytes');
 assert.equal(media.GalleryDisplay({image:'javascript:invalid'}),'');assert.equal(media.GalleryDisplay({image:'data:image/png;base64,AAAA'}),'');
 assert.deepEqual(dimensions(media.GalleryDisplay({image:'broken',thumb:old.imageThumb})),[160,90],'broken original falls back without inventing pixels');
 const noise=picture(640,640);let seed=75;for(let i=0;i<noise.data.length;i+=4)for(let c=0;c<3;c++){seed=(Math.imul(seed,1664525)+1013904223)>>>0;noise.data[i+c]=seed>>>24;}
 const noisy='data:image/jpeg;base64,'+jpeg.encode(noise,55).data.toString('base64');assert.ok(bytes(noisy).length<=450000);const noisyFields=media.GalleryFields(noisy);bounded(noisyFields.display,180000);bounded(noisyFields.thumb,12000);bounded(noisyFields.image,420000);
 const fullGallery=Array(6).fill(noisyFields);legacy.gallery=fullGallery;s.DB().products['PRD-VALORANT'].gallery=fullGallery;
 assert.ok(Buffer.byteLength(JSON.stringify(commerce.Catalog({summary:true})))<3200000,'maximum catalog remains bounded well below the 8 MB response ceiling');
 commerce.SaveProduct({id:saved.id,gameKey:'PUBG',description:'사진 삭제',genre:'배틀로얄',published:true,gallery:[]});assert.deepEqual(commerce.Product({id:saved.id}).product.gallery,[],'explicit removal has no stale cached gallery');
 console.log('FIX75 gallery media PASS: decoded 1024-pixel aspect-preserving catalog, original JPEG/PNG preservation, visual quality, alpha, legacy lazy regeneration without writes, bounded noisy payloads, validation, rollback and removal');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
